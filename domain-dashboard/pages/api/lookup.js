// pages/api/lookup.js
// Esta es la función serverless: Vercel la despliega automáticamente como
// un endpoint (/api/lookup). Recibe ?domain=ejemplo.com y devuelve un JSON
// con los datos que pide el dashboard.

import {
  getExpiration,
  getMx,
  getSpf,
  getDmarc,
  getBlacklists,
  isValidDomain,
} from "../../lib/checks";

// --- Límite de peticiones (rate limit) ---
// 5 búsquedas por IP cada 60 segundos. Es un contador simple en memoria:
// gratis, sin dependencias externas, suficiente para una demo con tráfico
// normal. Ojo: al vivir en la memoria de la función, no es 100% exacto si
// Vercel reparte las peticiones entre varias instancias en paralelo bajo
// mucho tráfico — para producción con más usuarios conviene migrar a un
// contador compartido (por ejemplo con Upstash Redis, también gratuito).
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 5;
const requestLog = new Map(); // ip -> [timestamps]

function isRateLimited(ip) {
  const now = Date.now();

  // Limpieza ocasional para que el mapa no crezca sin control mientras la
  // función se mantenga "caliente".
  if (requestLog.size > 5000) {
    for (const [key, timestamps] of requestLog) {
      const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
      if (recent.length === 0) requestLog.delete(key);
      else requestLog.set(key, recent);
    }
  }

  const timestamps = (requestLog.get(ip) || []).filter(
    (t) => now - t < RATE_LIMIT_WINDOW_MS
  );
  timestamps.push(now);
  requestLog.set(ip, timestamps);

  return timestamps.length > RATE_LIMIT_MAX;
}

function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length > 0) {
    return fwd.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", ["GET"]);
    return res.status(405).json({ error: "Método no permitido" });
  }

  const ip = getClientIp(req);
  if (isRateLimited(ip)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({
      error: "Demasiadas búsquedas seguidas. Espera un minuto e intenta de nuevo.",
    });
  }

  const raw = (req.query.domain || "").toString().trim().toLowerCase();
  // Permite que el usuario pegue una URL completa (https://ejemplo.com/algo)
  const domain = raw.replace(/^https?:\/\//, "").split("/")[0];

  if (!domain || !isValidDomain(domain)) {
    return res.status(400).json({
      error: "Ingresa un dominio válido, por ejemplo: midominio.com",
    });
  }

  try {
    const [expiration, mx, spf, dmarc, blacklists] = await Promise.all([
      getExpiration(domain),
      getMx(domain),
      getSpf(domain),
      getDmarc(domain),
      getBlacklists(domain),
    ]);

    // Cache corto en el borde de Vercel: si dos personas consultan el mismo
    // dominio en pocos minutos, no repetimos todas las consultas.
    res.setHeader(
      "Cache-Control",
      "s-maxage=300, stale-while-revalidate=600"
    );

    return res.status(200).json({
      domain,
      checkedAt: new Date().toISOString(),
      expiration,
      mx,
      spf,
      dmarc,
      blacklists,
    });
  } catch (err) {
    return res.status(500).json({
      error: "Ocurrió un error inesperado al consultar el dominio",
    });
  }
}
