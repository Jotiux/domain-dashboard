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

function dmarcStatus(dmarc) {
  if (!dmarc.ok) return "critical";
  if (dmarc.policy === "reject" || dmarc.policy === "quarantine") return "good";
  if (dmarc.policy === "none") return "warning";
  return "good";
}

function blacklistStatus(blacklists, mxBlacklist) {
  if (blacklists.isListed || (mxBlacklist && mxBlacklist.isListed)) return "critical";
  if (blacklists.hasUncertain || (mxBlacklist && mxBlacklist.hasUncertain)) return "neutral";
  return "good";
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
            </Card>

            <Card
              title="Listas negras (Blacklists)"
              status={blacklistStatus(data.blacklists, data.mxBlacklist)}
            >
              <p className="muted" style={{ marginBottom: 2 }}>
                <strong>Del dominio:</strong>
              </p>
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

              <p className="muted" style={{ marginTop: 10, marginBottom: 2 }}>
                <strong>Del servidor de correo (por IP):</strong>
              </p>
              {data.mxBlacklist && data.mxBlacklist.results.length > 0 ? (
                data.mxBlacklist.results.map((r) => (
                  <div key={r.host} style={{ marginBottom: 6 }}>
                    <p className="muted" style={{ marginBottom: 2 }}>
                      {r.host}
                      {r.ip ? ` (${r.ip})` : ""}
                    </p>
                    {r.checks && r.checks.length > 0 ? (
                      <ul className="list">
                        {r.checks.map((c) => (
                          <li key={c.name}>
                            {c.name}:{" "}
                            {c.listed === true
                              ? "❌ Listado"
                              : c.listed === false
                              ? "✅ Limpio"
                              : "⚠️ No se pudo verificar"}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="muted">{r.error}</p>
                    )}
                  </div>
                ))
              ) : (
                <p className="muted">No hay servidores MX que revisar</p>
              )}
            </Card>

            <Card
              title="Servidores MX"
              status={data.mx.ok ? (data.mx.hasMoreThanTwo ? "neutral" : "good") : "critical"}
            >
              {data.mx.ok ? (
                <>
                  <ul className="list">
                    {data.mx.top2.map((r) => (
                      <li key={r.host}>
                        {r.host} <span className="muted">(prioridad {r.priority})</span>
                      </li>
                    ))}
                  </ul>
                  <p className="muted">
                    {data.mx.hasMoreThanTwo
                      ? `Tiene más de 2 registros MX (total: ${data.mx.total})`
                      : `Total de registros MX: ${data.mx.total}`}
                  </p>
                </>
              ) : (
                <p className="muted">{data.mx.error}</p>
              )}
            </Card>

            <Card title="Registro SPF" status={data.spf.ok ? "good" : "critical"}>
              {data.spf.ok ? (
                <code className="record">{data.spf.record}</code>
              ) : (
                <p className="muted">{data.spf.error}</p>
              )}
            </Card>

            <Card title="Registro DMARC" status={dmarcStatus(data.dmarc)}>
              {data.dmarc.ok ? (
                <>
                  <code className="record">{data.dmarc.record}</code>
                  {data.dmarc.policy === "none" && (
                    <p className="muted">
                      Política "none": existe DMARC pero no está bloqueando nada
                      todavía.
                    </p>
                  )}
                </>
              ) : (
                <p className="muted">{data.dmarc.error}</p>
              )}
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
