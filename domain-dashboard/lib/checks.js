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

// --- Información RDAP: expiración, fecha de registro y última modificación ---
//
// rdap.org es un proxy público cómodo, pero para algunos TLDs (sobre todo
// ccTLDs como .ec) puede ser lento o no encontrar el registro correcto.
// Para mejorar la confiabilidad, consultamos EN PARALELO:
//   1) el servidor RDAP oficial del registro de ese TLD (según el
//      "bootstrap" público que publica IANA), y
//   2) el proxy rdap.org como respaldo.
// Nos quedamos con la primera respuesta exitosa; si ambas fallan, mostramos
// el último error recibido.

let rdapBootstrapCache = null;
let rdapBootstrapFetchedAt = 0;
const RDAP_BOOTSTRAP_TTL = 6 * 60 * 60 * 1000; // 6 horas

// Descubre cuál es el servidor RDAP "oficial" de un TLD, usando el índice
// que publica IANA (data.iana.org/rdap/dns.json). Se cachea en memoria
// mientras la función serverless siga "caliente" para no pedirlo cada vez.
async function getNativeRdapBase(tld) {
  const now = Date.now();
  if (!rdapBootstrapCache || now - rdapBootstrapFetchedAt > RDAP_BOOTSTRAP_TTL) {
    try {
      const res = await withTimeout(
        fetch("https://data.iana.org/rdap/dns.json"),
        5000,
        "bootstrap RDAP tardó demasiado"
      );
      if (res.ok) {
        rdapBootstrapCache = await res.json();
        rdapBootstrapFetchedAt = now;
      }
    } catch {
      // Si falla, seguimos sin servidor nativo; el proxy rdap.org sigue
      // intentando de todas formas.
    }
  }

  const services = rdapBootstrapCache?.services || [];
  const entry = services.find(([tlds]) => tlds.includes(tld));
  return entry ? entry[1][0] : null;
}

function toDatedEvent(event) {
  if (!event || !event.eventDate) return null;
  const daysLeft = Math.ceil(
    (new Date(event.eventDate).getTime() - Date.now()) / 86400000
  );
  return { date: event.eventDate, daysLeft };
}

// Los datos de "quién es el registrador" vienen en formato vCard dentro de
// cada entidad RDAP: ["vcard", [ ["fn", {}, "text", "GoDaddy.com, LLC"], ... ]]
function findVcardValue(vcardArray, property) {
  if (!Array.isArray(vcardArray) || !Array.isArray(vcardArray[1])) return null;
  const field = vcardArray[1].find(
    (f) => Array.isArray(f) && f[0] === property
  );
  return field && typeof field[3] === "string" ? field[3] : null;
}

function getRegistrarName(data) {
  const entities = Array.isArray(data.entities) ? data.entities : [];
  const registrarEntity = entities.find(
    (e) => Array.isArray(e.roles) && e.roles.includes("registrar")
  );
  if (!registrarEntity) return null;
  return findVcardValue(registrarEntity.vcardArray, "fn");
}

// Heurística simple: identifica al proveedor de DNS a partir del hostname
// del servidor de nombres. No es una lista exhaustiva, pero cubre los
// proveedores más comunes; si no reconoce el patrón, devuelve null.
const NS_PROVIDER_PATTERNS = [
  [/\.cloudflare\.com$/i, "Cloudflare"],
  [/awsdns/i, "Amazon Route 53 (AWS)"],
  [/\.domaincontrol\.com$/i, "GoDaddy"],
  [/\.googledomains\.com$|\.google\.com$/i, "Google"],
  [/\.azure-dns\./i, "Microsoft Azure DNS"],
  [/\.dnsmadeeasy\.com$/i, "DNS Made Easy"],
  [/\.digitalocean\.com$/i, "DigitalOcean"],
  [/\.registrar-servers\.com$/i, "Namecheap"],
  [/\.cloudns\./i, "ClouDNS"],
  [/\.hostgator\.com$/i, "HostGator"],
  [/\.dreamhost\.com$/i, "DreamHost"],
  [/\.telconet\./i, "Telconet"],
  [/\.nic\.ec$/i, "NIC.EC"],
  [/\.ovh\.net$/i, "OVH"],
  [/\.dnsimple\.com$/i, "DNSimple"],
  [/\.name\.com$/i, "Name.com"],
];

function detectNsProvider(hostname) {
  const match = NS_PROVIDER_PATTERNS.find(([re]) => re.test(hostname));
  return match ? match[1] : null;
}

function getNameservers(data) {
  const list = Array.isArray(data.nameservers) ? data.nameservers : [];
  return list
    .map((ns) => ns.ldhName)
    .filter(Boolean)
    .map((host) => ({ host, provider: detectNsProvider(host) }));
}

// Traduce los códigos de estado RDAP más comunes a algo entendible; deja el
// resto tal cual (en inglés) para no perder información.
const STATUS_LABELS = {
  active: "Activo",
  "client transfer prohibited": "Protegido contra transferencias no autorizadas",
  "client delete prohibited": "Protegido contra eliminación",
  "client update prohibited": "Protegido contra modificaciones",
  "client hold": "En espera (clientHold) — puede no resolver",
  "server transfer prohibited": "Bloqueado por el registro contra transferencias",
  "server delete prohibited": "Bloqueado por el registro contra eliminación",
  "server update prohibited": "Bloqueado por el registro contra modificaciones",
  "pending delete": "Pendiente de eliminación",
  "pending transfer": "Pendiente de transferencia",
  "redemption period": "En periodo de recuperación (a punto de liberarse)",
};

function getStatusLabels(data) {
  const raw = Array.isArray(data.status) ? data.status : [];
  return raw.map((s) => STATUS_LABELS[s] || s);
}

function parseRdapDocument(data) {
  const events = Array.isArray(data.events) ? data.events : [];
  const findEvent = (action) => events.find((e) => e.eventAction === action);

  const expiration = toDatedEvent(findEvent("expiration"));
  const registered = toDatedEvent(findEvent("registration"));
  const lastChangedEvent = findEvent("last changed");
  const lastChanged = lastChangedEvent
    ? { date: lastChangedEvent.eventDate }
    : null;

  const registrar = getRegistrarName(data);
  const nameservers = getNameservers(data);
  const statusLabels = getStatusLabels(data);

  if (!expiration && !registered && !lastChanged) {
    return {
      ok: false,
      error: "El registrador no publica fechas vía RDAP para este dominio",
    };
  }

  return {
    ok: true,
    expiration,
    registered,
    lastChanged,
    registrar,
    nameservers,
    status: statusLabels,
  };
}

async function fetchRdap(url) {
  const res = await fetch(url, {
    headers: { Accept: "application/rdap+json" },
  });
  if (res.status === 404) {
    return { ok: false, error: "El dominio no existe o no está registrado" };
  }
  if (!res.ok) {
    return { ok: false, error: `RDAP respondió con estado ${res.status}` };
  }
  const data = await res.json();
  return parseRdapDocument(data);
}

// Se queda con la primera respuesta exitosa (ok:true); si todas fallan,
// resuelve con el último resultado (fallido) recibido.
function raceForSuccess(promises) {
  return new Promise((resolve) => {
    let remaining = promises.length;
    let lastResult = { ok: false, error: "No se pudo consultar RDAP" };
    promises.forEach((p) => {
      p.then((result) => {
        lastResult = result;
        if (result.ok) resolve(result);
        remaining -= 1;
        if (remaining === 0) resolve(lastResult);
      });
    });
  });
}

export async function getExpiration(domain) {
  const tld = domain.split(".").pop();

  const nativeAttempt = (async () => {
    try {
      const base = await getNativeRdapBase(tld);
      if (!base) {
        return { ok: false, error: `El TLD .${tld} no publica un servidor RDAP propio en IANA` };
      }
      const url = base.endsWith("/")
        ? `${base}domain/${domain}`
        : `${base}/domain/${domain}`;
      return await withTimeout(
        fetchRdap(url),
        7000,
        "El servidor RDAP del registro tardó demasiado"
      );
    } catch (err) {
      return { ok: false, error: "RDAP del registro falló: " + err.message };
    }
  })();

  const proxyAttempt = (async () => {
    try {
      return await withTimeout(
        fetchRdap(`https://rdap.org/domain/${encodeURIComponent(domain)}`),
        7000,
        "rdap.org tardó demasiado en responder"
      );
    } catch (err) {
      return { ok: false, error: "No se pudo consultar rdap.org: " + err.message };
    }
  })();

  return raceForSuccess([nativeAttempt, proxyAttempt]);
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

// --- Spamhaus ZEN sobre la IP del servidor de correo (MX) ---
// A diferencia de Spamhaus DBL/SURBL (que revisan el DOMINIO), ZEN revisa la
// IP real del servidor que entrega el correo — es la comprobación que usan
// las herramientas profesionales de entregabilidad, porque un dominio puede
// verse "limpio" y aun así su servidor de correo estar en una IP marcada
// como fuente de spam.
async function checkZenForIp(ip) {
  try {
    const reversed = ip.split(".").reverse().join(".");
    await withTimeout(
      dnsPromises.resolve4(`${reversed}.zen.spamhaus.org`),
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

// Recibe la lista de servidores MX (host + prioridad) que ya obtuvimos con
// getMx(), resuelve su IP y consulta Spamhaus ZEN para cada una.
export async function getMxBlacklist(mxHosts) {
  if (!Array.isArray(mxHosts) || mxHosts.length === 0) {
    return { ok: true, results: [], isListed: false, hasUncertain: false };
  }

  const results = [];
  for (const { host } of mxHosts) {
    try {
      const ips = await withTimeout(
        dnsPromises.resolve4(host),
        6000,
        "timeout"
      );
      const ip = ips[0];
      if (!ip) {
        results.push({ host, ip: null, listed: null, error: "Sin IPv4" });
        continue;
      }
      const r = await checkZenForIp(ip);
      results.push({ host, ip, ...r });
    } catch (err) {
      results.push({
        host,
        ip: null,
        listed: null,
        error: "No se pudo resolver la IP de este servidor",
      });
    }
  }

  const listed = results.filter((r) => r.listed === true);
  const uncertain = results.filter((r) => r.listed === null);

  return {
    ok: true,
    results,
    isListed: listed.length > 0,
    hasUncertain: uncertain.length > 0,
  };
}

// Validación simple de dominio antes de consultar nada.
export function isValidDomain(domain) {
  return /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/.test(domain);
}
