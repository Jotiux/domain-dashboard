import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";

// --- Helpers para decidir el color/estado de cada tarjeta ---
// Usamos una paleta de estado fija: good (verde), warning (amarillo),
// critical (rojo) y neutral (gris) — cada una siempre va acompañada de un
// ícono y una palabra, nunca solo el color.
const STATUS = {
  good: { label: "OK", icon: "✓", className: "status-good" },
  warning: { label: "Atención", icon: "!", className: "status-warning" },
  critical: { label: "Problema", icon: "✕", className: "status-critical" },
  neutral: { label: "Info", icon: "i", className: "status-neutral" },
};

function expirationStatus(rdap) {
  if (!rdap.ok || !rdap.expiration) return "neutral";
  if (rdap.expiration.daysLeft < 0) return "critical";
  if (rdap.expiration.daysLeft <= 30) return "warning";
  return "good";
}

function spfStatus(spf) {
  if (!spf.ok) return "critical";
  if (spf.validation?.errors?.length > 0) return "critical";
  if (spf.validation?.warnings?.length > 0) return "warning";
  return "good";
}

function dmarcStatus(dmarc) {
  if (!dmarc.ok) return "critical";
  if (dmarc.validation?.errors?.length > 0) return "critical";
  if (dmarc.policy === "none") return "warning";
  if (dmarc.validation?.warnings?.length > 0) return "warning";
  return "good";
}

function ValidationList({ validation }) {
  if (!validation) return null;
  const { errors = [], warnings = [] } = validation;
  if (errors.length === 0 && warnings.length === 0) return null;

  return (
    <div style={{ marginTop: 8 }}>
      {errors.map((e, i) => (
        <p key={`err-${i}`} className="muted" style={{ color: "var(--critical)", marginBottom: 3 }}>
          ✕ {e}
        </p>
      ))}
      {warnings.map((w, i) => (
        <p key={`warn-${i}`} className="muted" style={{ color: "#8a5c00", marginBottom: 3 }}>
          ! {w}
        </p>
      ))}
    </div>
  );
}

function blacklistStatus(blacklists) {
  if (blacklists.isListed) return "critical";
  if (blacklists.hasUncertain) return "neutral";
  return "good";
}

// --- Recomendaciones: qué hacer cuando una tarjeta sale en amarillo o rojo ---
// Cada función devuelve un texto accionable, o null si no aplica (todo bien).
function expirationRecommendation(rdap, status) {
  if (status === "critical") {
    return "Este dominio ya expiró. Se recomienda renovarlo cuanto antes con tu registrador, antes de que se libere y alguien más pueda registrarlo.";
  }
  if (status === "warning") {
    return "El dominio está por expirar. Se recomienda renovarlo pronto para no perder el control sobre él.";
  }
  return null;
}

function registrationRecommendation(rdap) {
  if (!rdap.ok) {
    return "Verifica que el dominio esté escrito correctamente, o considera registrarlo si aún está disponible.";
  }
  return null;
}

function blacklistRecommendation(blacklists, status) {
  if (status === "critical") {
    const names = blacklists.listedIn.join(", ");
    return `El dominio está listado en: ${names}. Se recomienda revisar la causa (por ejemplo un sitio comprometido o envío masivo no autorizado) y solicitar la exclusión ("delisting") directamente en el sitio de esa lista.`;
  }
  if (status === "neutral" && blacklists.hasUncertain) {
    return "No se pudo verificar contra alguna de las listas en este momento. Intenta consultar de nuevo más tarde.";
  }
  return null;
}

function mxRecommendation(mx, status) {
  if (status === "critical") {
    return "El dominio no tiene registros MX activos, por lo que no puede recibir correo. Si necesitas usar correo con este dominio, agrega registros MX con tu proveedor de DNS.";
  }
  return null;
}

function spfRecommendation(spf, status) {
  if (status === "critical") {
    if (!spf.ok) {
      return "No se encontró un registro SPF. Se recomienda crear uno para indicar qué servidores están autorizados a enviar correo en nombre del dominio.";
    }
    return "Se recomienda corregir los errores de sintaxis señalados arriba, editando el registro SPF con tu proveedor de DNS.";
  }
  if (status === "warning") {
    return "Se recomienda revisar las advertencias señaladas arriba para evitar que el SPF falle de forma silenciosa.";
  }
  return null;
}

function dmarcRecommendation(dmarc, status) {
  if (status === "critical") {
    if (!dmarc.ok) {
      return "No se encontró un registro DMARC. Se recomienda publicar uno para proteger el dominio contra suplantación de identidad (phishing en su nombre).";
    }
    return "Se recomienda corregir los errores de sintaxis señalados arriba, editando el registro DMARC con tu proveedor de DNS.";
  }
  if (status === "warning") {
    return "Se recomienda avanzar gradualmente hacia una política más estricta (quarantine o reject) una vez que confirmes que tu correo legítimo se autentica bien, y agregar \"rua=\" si falta para empezar a recibir reportes.";
  }
  return null;
}

function Recommendation({ text }) {
  if (!text) return null;
  return (
    <p className="recommendation">
      💡 <strong>Qué hacer:</strong> {text}
    </p>
  );
}

function Badge({ status }) {
  const s = STATUS[status] || STATUS.neutral;
  return (
    <span className={`badge ${s.className}`}>
      <span aria-hidden="true">{s.icon}</span> {s.label}
    </span>
  );
}

function Card({ title, status, children }) {
  return (
    <div className="card">
      <div className="card-header">
        <h3>{title}</h3>
        <Badge status={status} />
      </div>
      <div className="card-body">{children}</div>
    </div>
  );
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleDateString("es-ES", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

// El TTL (Time To Live) indica cuántos segundos guarda un resolutor DNS la
// respuesta en caché antes de volver a consultarla — en la práctica, qué
// tan rápido se propaga un cambio en ese registro.
function formatTtl(seconds) {
  if (seconds === null || seconds === undefined) return null;
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} días`;
}

export default function Home() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState(null);
  const [copied, setCopied] = useState(false);
  const autoSearchedRef = useRef(false);

  async function runSearch(value) {
    const clean = value.trim();
    if (!clean) return;

    setLoading(true);
    setError("");
    setData(null);
    setCopied(false);

    try {
      const res = await fetch(`/api/lookup?domain=${encodeURIComponent(clean)}`);
      const json = await res.json();

      if (!res.ok) {
        setError(json.error || "No se pudo consultar el dominio");
      } else {
        setData(json);
        // Actualiza la URL (?domain=...) sin recargar la página, para que
        // el resultado se pueda compartir con un link directo.
        router.replace(
          { pathname: "/", query: { domain: json.domain } },
          undefined,
          { shallow: true }
        );
      }
    } catch (err) {
      setError("No se pudo conectar con el servidor. Intenta de nuevo.");
    } finally {
      setLoading(false);
    }
  }

  function handleSearch(e) {
    e.preventDefault();
    runSearch(domain);
  }

  // Si alguien abre un link tipo /?domain=ejemplo.com, precargamos el campo
  // y lanzamos la búsqueda automáticamente una sola vez.
  useEffect(() => {
    if (!router.isReady || autoSearchedRef.current) return;
    const fromUrl = router.query.domain;
    if (typeof fromUrl === "string" && fromUrl.trim()) {
      autoSearchedRef.current = true;
      setDomain(fromUrl);
      runSearch(fromUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady]);

  function handleCopyLink() {
    if (!data) return;
    const url = `${window.location.origin}/?domain=${encodeURIComponent(data.domain)}`;
    navigator.clipboard
      .writeText(url)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => {
        setError("No se pudo copiar el link automáticamente. Cópialo desde la barra del navegador.");
      });
  }

  return (
    <div className="page">
      <header className="hero">
        <h1>Consulta y Análisis de Dominios</h1>

        <form className="search-bar" onSubmit={handleSearch}>
          <input
            type="text"
            placeholder="ejemplo.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck="false"
          />
          <button type="submit" disabled={loading}>
            {loading ? "Buscando…" : "Buscar"}
          </button>
        </form>

        {error && <p className="error">{error}</p>}
      </header>

      {data && (
        <main className="results">
          <p className="results-meta">
            Resultados para <strong>{data.domain}</strong>
            {" · "}
            <button type="button" className="link-button" onClick={handleCopyLink}>
              {copied ? "¡Enlace copiado!" : "Copiar enlace para compartir"}
            </button>
          </p>

          <div className="grid">
            <Card title="Fecha de expiración" status={expirationStatus(data.expiration)}>
              {data.expiration.ok && data.expiration.expiration ? (
                <>
                  <p className="big">{formatDate(data.expiration.expiration.date)}</p>
                  <p className="muted">
                    {data.expiration.expiration.daysLeft < 0
                      ? "Este dominio ya expiró"
                      : `Faltan ${data.expiration.expiration.daysLeft} días`}
                  </p>
                </>
              ) : (
                <p className="muted">
                  {data.expiration.ok
                    ? "No se encontró fecha de expiración vía RDAP"
                    : data.expiration.error}
                </p>
              )}
              <Recommendation
                text={expirationRecommendation(
                  data.expiration,
                  expirationStatus(data.expiration)
                )}
              />
            </Card>

            <Card
              title="Registro del dominio"
              status={data.expiration.ok ? "neutral" : "critical"}
            >
              {data.expiration.ok ? (
                <>
                  <p className="muted">
                    <strong>Registrado:</strong>{" "}
                    {data.expiration.registered
                      ? formatDate(data.expiration.registered.date)
                      : "No disponible"}
                  </p>
                  <p className="muted">
                    <strong>Última modificación:</strong>{" "}
                    {data.expiration.lastChanged
                      ? formatDate(data.expiration.lastChanged.date)
                      : "No disponible"}
                  </p>
                  <p className="muted">
                    <strong>Registrador:</strong>{" "}
                    {data.expiration.registrar || "No disponible"}
                  </p>
                  {data.expiration.status && data.expiration.status.length > 0 && (
                    <p className="muted">
                      <strong>Estado:</strong> {data.expiration.status.join(", ")}
                    </p>
                  )}
                  {data.expiration.nameservers &&
                    data.expiration.nameservers.length > 0 && (
                      <>
                        <p className="muted" style={{ marginBottom: 2 }}>
                          <strong>Servidores de nombres (NS):</strong>
                        </p>
                        <ul className="list">
                          {data.expiration.nameservers.map((ns) => (
                            <li key={ns.host}>
                              {ns.host}
                              {ns.provider && (
                                <span className="muted"> — {ns.provider}</span>
                              )}
                            </li>
                          ))}
                        </ul>
                      </>
                    )}
                </>
              ) : (
                <p className="muted">{data.expiration.error}</p>
              )}
              <Recommendation text={registrationRecommendation(data.expiration)} />
            </Card>

            <Card
              title="Listas negras (Blacklists)"
              status={blacklistStatus(data.blacklists)}
            >
              <ul className="list">
                {data.blacklists.results.map((r) => (
                  <li key={r.name}>
                    {r.name}:{" "}
                    {r.listed === true
                      ? "❌ Listado"
                      : r.listed === false
                      ? "✅ Limpio"
                      : "⚠️ No se pudo verificar"}
                  </li>
                ))}
              </ul>
              <Recommendation
                text={blacklistRecommendation(
                  data.blacklists,
                  blacklistStatus(data.blacklists)
                )}
              />
            </Card>

            <Card title="Servidores MX" status={data.mx.ok ? "good" : "critical"}>
              {data.mx.ok ? (
                <>
                  <ul className="list">
                    {data.mx.records.map((r) => (
                      <li key={`${r.host}-${r.priority}`}>
                        {r.host} <span className="muted">(prioridad {r.priority})</span>
                        {formatTtl(r.ttl) && (
                          <span className="muted"> — TTL: {formatTtl(r.ttl)}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                  <p className="muted">Total de registros MX: {data.mx.total}</p>
                </>
              ) : (
                <p className="muted">{data.mx.error}</p>
              )}
              <Recommendation
                text={mxRecommendation(data.mx, data.mx.ok ? "good" : "critical")}
              />
            </Card>

            <Card title="Registro SPF" status={spfStatus(data.spf)}>
              {data.spf.ok ? (
                <>
                  <code className="record">{data.spf.record}</code>
                  {formatTtl(data.spf.ttl) && (
                    <p className="muted">TTL: {formatTtl(data.spf.ttl)}</p>
                  )}
                  <ValidationList validation={data.spf.validation} />
                </>
              ) : (
                <p className="muted">{data.spf.error}</p>
              )}
              <Recommendation text={spfRecommendation(data.spf, spfStatus(data.spf))} />
            </Card>

            <Card title="Registro DMARC" status={dmarcStatus(data.dmarc)}>
              {data.dmarc.ok ? (
                <>
                  <code className="record">{data.dmarc.record}</code>
                  {formatTtl(data.dmarc.ttl) && (
                    <p className="muted">TTL: {formatTtl(data.dmarc.ttl)}</p>
                  )}
                  <ValidationList validation={data.dmarc.validation} />
                </>
              ) : (
                <p className="muted">{data.dmarc.error}</p>
              )}
              <Recommendation
                text={dmarcRecommendation(data.dmarc, dmarcStatus(data.dmarc))}
              />
            </Card>
          </div>
        </main>
      )}

      <footer className="footer">
        <p>Demo gratuita — datos obtenidos vía RDAP y consultas DNS públicas.</p>
      </footer>
    </div>
  );
}
