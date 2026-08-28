// lib/checks.js
// Toda la lógica de consultas al dominio: expiración (RDAP), MX, SPF, DMARC
// y listas negras (blacklists). Cada función es independiente y nunca lanza
// una excepción hacia afuera: siempre devuelve { ok: true/false, ... } para
// que una falla puntual (por ejemplo, que el dominio no tenga DMARC) no tumbe
// el resto de la consulta.

import dns from "dns";

const dnsPromises = dns.promises;

// Los dominios .com/.net a veces demoran un poco en RDAP; le damos margen
// pero sin dejar la función colgada indefinidamente.
function withTimeout(promise, ms, timeoutMessage) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(timeoutMessage)), ms)
    ),
  ]);
}

// --- Fecha de expiración (vía RDAP, el reemplazo moderno y gratuito de WHOIS) ---
export async function getExpiration(domain) {
  try {
    const res = await withTimeout(
      fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        headers: { Accept: "application/rdap+json" },
      }),
      8000,
      "RDAP tardó demasiado en responder"
    );

    if (res.status === 404) {
      return { ok: false, error: "El dominio no existe o no está registrado" };
    }
    if (!res.ok) {
      return { ok: false, error: `RDAP respondió con estado ${res.status}` };
    }

    const data = await res.json();
    const events = Array.isArray(data.events) ? data.events : [];
    const expirationEvent = events.find(
      (e) => e.eventAction === "expiration"
    );

    if (!expirationEvent || !expirationEvent.eventDate) {
      return {
        ok: false,
        error: "El registrador no publica la fecha de expiración vía RDAP",
      };
    }

    const date = new Date(expirationEvent.eventDate);
    const daysLeft = Math.ceil((date.getTime() - Date.now()) / 86400000);

    return {
      ok: true,
      date: expirationEvent.eventDate,
      daysLeft,
    };
  } catch (err) {
    return { ok: false, error: "No se pudo consultar RDAP: " + err.message };
  }
}

// --- Registros MX ---
export async function getMx(domain) {
  try {
    const records = await withTimeout(
      dnsPromises.resolveMx(domain),
      8000,
      "Consulta MX tardó demasiado"
    );
    const sorted = [...records].sort((a, b) => a.priority - b.priority);

    // RFC 7505: un único registro "0 ." (exchange vacío/".") significa que
    // el dominio declara explícitamente que NO recibe correo.
    const isNullMx =
      sorted.length === 1 &&
      (sorted[0].exchange === "" || sorted[0].exchange === ".");

    if (isNullMx) {
      return {
        ok: false,
        error: "El dominio declara explícitamente que no recibe correo (Null MX)",
      };
    }

    return {
      ok: true,
      total: sorted.length,
      top2: sorted.slice(0, 2).map((r) => ({
        host: r.exchange,
        priority: r.priority,
      })),
      hasMoreThanTwo: sorted.length > 2,
    };
  } catch (err) {
    return {
      ok: false,
      error:
        err.code === "ENOTFOUND" || err.code === "ENODATA"
          ? "El dominio no tiene registros MX (no recibe correo)"
          : "No se pudo consultar MX: " + (err.code || err.message),
    };
  }
}

// --- SPF (registro TXT en la raíz del dominio) ---
export async function getSpf(domain) {
  try {
    const records = await withTimeout(
      dnsPromises.resolveTxt(domain),
      8000,
      "Consulta SPF tardó demasiado"
    );
    const flat = records.map((chunks) => chunks.join(""));
    const spf = flat.find((r) => r.toLowerCase().startsWith("v=spf1"));

    if (!spf) {
      return { ok: false, error: "No se encontró registro SPF" };
    }
    return { ok: true, record: spf };
  } catch (err) {
    return {
      ok: false,
      error:
        err.code === "ENOTFOUND" || err.code === "ENODATA"
          ? "No se encontró registro SPF"
          : "No se pudo consultar SPF: " + (err.code || err.message),
    };
  }
}

// --- DMARC (registro TXT en _dmarc.dominio) ---
export async function getDmarc(domain) {
  try {
    const records = await withTimeout(
      dnsPromises.resolveTxt(`_dmarc.${domain}`),
      8000,
      "Consulta DMARC tardó demasiado"
    );
    const flat = records.map((chunks) => chunks.join(""));
    const dmarc = flat.find((r) => r.toLowerCase().startsWith("v=dmarc1"));

    if (!dmarc) {
      return { ok: false, error: "No se encontró registro DMARC" };
    }

    const policyMatch = dmarc.match(/p=([a-zA-Z]+)/i);
    const policy = policyMatch ? policyMatch[1].toLowerCase() : null;

    return { ok: true, record: dmarc, policy };
  } catch (err) {
    return {
      ok: false,
      error:
        err.code === "ENOTFOUND" || err.code === "ENODATA"
          ? "No se encontró registro DMARC"
          : "No se pudo consultar DMARC: " + (err.code || err.message),
    };
  }
}

// --- Listas negras (blacklists) ---
// Se consultan directamente por DNS contra listas públicas gratuitas.
// Si el subdominio "dominio.lista.org" resuelve a una IP, está listado.
// Si da NXDOMAIN/ENODATA, no está listado.
const BLACKLIST_ZONES = [
  { name: "Spamhaus DBL", zone: "dbl.spamhaus.org" },
  { name: "SURBL", zone: "multi.surbl.org" },
];

async function checkZone(domain, zone) {
  try {
    await withTimeout(
      dnsPromises.resolve4(`${domain}.${zone}`),
      7000,
      "timeout"
    );
    return { listed: true };
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      return { listed: false };
    }
    return { listed: null, error: err.code || err.message };
  }
}

export async function getBlacklists(domain) {
  const results = await Promise.all(
    BLACKLIST_ZONES.map(async (bl) => {
      const r = await checkZone(domain, bl.zone);
      return { name: bl.name, ...r };
    })
  );

  const listedIn = results.filter((r) => r.listed === true).map((r) => r.name);
  const uncertain = results.filter((r) => r.listed === null);

  return {
    ok: true,
    results,
    isListed: listedIn.length > 0,
    listedIn,
    hasUncertain: uncertain.length > 0,
  };
}

// Validación simple de dominio antes de consultar nada.
export function isValidDomain(domain) {
  return /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/.test(domain);
}
