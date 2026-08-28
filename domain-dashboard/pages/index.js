import { useState } from "react";

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

function expirationStatus(expiration) {
  if (!expiration.ok) return "neutral";
  if (expiration.daysLeft < 0) return "critical";
  if (expiration.daysLeft <= 30) return "warning";
  return "good";
}

function dmarcStatus(dmarc) {
  if (!dmarc.ok) return "critical";
  if (dmarc.policy === "reject" || dmarc.policy === "quarantine") return "good";
  if (dmarc.policy === "none") return "warning";
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
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState(null);

  async function handleSearch(e) {
    e.preventDefault();
    const clean = domain.trim();
    if (!clean) return;

    setLoading(true);
    setError("");
    setData(null);

    try {
      const res = await fetch(`/api/lookup?domain=${encodeURIComponent(clean)}`);
      const json = await res.json();

      if (!res.ok) {
        setError(json.error || "No se pudo consultar el dominio");
      } else {
        setData(json);
      }
    } catch (err) {
      setError("No se pudo conectar con el servidor. Intenta de nuevo.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <header className="hero">
        <h1>Consulta y Análisis de Dominios</h1>
        <p className="subtitle">
          Escribe un dominio y obtén en segundos su expiración, listas negras,
          servidores de correo (MX), SPF y DMARC — todo en un solo lugar.
        </p>

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
          </p>

          <div className="grid">
            <Card title="Fecha de expiración" status={expirationStatus(data.expiration)}>
              {data.expiration.ok ? (
                <>
                  <p className="big">{formatDate(data.expiration.date)}</p>
                  <p className="muted">
                    {data.expiration.daysLeft < 0
                      ? "Este dominio ya expiró"
                      : `Faltan ${data.expiration.daysLeft} días`}
                  </p>
                </>
              ) : (
                <p className="muted">{data.expiration.error}</p>
              )}
            </Card>

            <Card
              title="Listas negras (Blacklists)"
              status={
                data.blacklists.isListed
                  ? "critical"
                  : data.blacklists.hasUncertain
                  ? "neutral"
                  : "good"
              }
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
