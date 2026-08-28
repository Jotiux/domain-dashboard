// pages/api/lookup.js
// Esta es la función serverless: Vercel la despliega automáticamente como
// un endpoint (/api/lookup). Recibe ?domain=ejemplo.com y devuelve un JSON
// con los 5 datos que pide el dashboard.

import {
  getExpiration,
  getMx,
  getSpf,
  getDmarc,
  getBlacklists,
  isValidDomain,
} from "../../lib/checks";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", ["GET"]);
    return res.status(405).json({ error: "Método no permitido" });
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
