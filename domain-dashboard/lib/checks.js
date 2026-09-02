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

// --- TTL vía DNS-over-HTTPS (Google) ---
// Node no expone el TTL de registros MX/TXT de forma nativa (dns.promises
// solo lo da para A/AAAA con la opción {ttl:true}). Para no depender de
// librerías extra, usamos la API pública y gratuita de DNS-over-HTTPS de
// Google, que sí devuelve el TTL tal cual lo entrega el DNS del dominio.
// Si esta consulta falla por cualquier motivo, simplemente no mostramos el
// TTL — nunca rompe el resto de la información ya obtenida por vía normal.
const DOH_TYPE_NUMBERS = { MX: 15, TXT: 16 };

async function queryDoh(name, type) {
  try {
    const typeNumber = DOH_TYPE_NUMBERS[type];
    const res = await withTimeout(
      fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
        { headers: { Accept: "application/dns-json" } }
      ),
      5000,
      "Consulta DoH tardó demasiado"
    );
    if (!res.ok) return [];
    const data = await res.json();
    const answers = Array.isArray(data.Answer) ? data.Answer : [];
    return answers.filter((a) => a.type === typeNumber);
  } catch {
    return [];
  }
}

function findTtlForHost(dohAnswers, hostname) {
  const target = hostname.replace(/\.$/, "").toLowerCase();
  // La respuesta MX de DoH viene como "10 mx1.example.com." (prioridad y host).
  const match = dohAnswers.find((a) => {
    const parts = a.data.split(" ");
    const host = (parts[1] || parts[0] || "").replace(/\.$/, "").toLowerCase();
    return host === target;
  });
  return match ? match.TTL : null;
}

function normalizeForMatch(s) {
  return s.replace(/^"|"$/g, "").replace(/"\s*"/g, "").replace(/\s+/g, " ").trim().toLowerCase();
}

function findTtlForTxt(dohAnswers, recordText) {
  const target = normalizeForMatch(recordText);
  const match = dohAnswers.find((a) => normalizeForMatch(a.data) === target);
  return match ? match.TTL : null;
}

// --- Registros MX ---
export async function getMx(domain) {
  try {
    const [records, dohAnswers] = await Promise.all([
      withTimeout(
        dnsPromises.resolveMx(domain),
        8000,
        "Consulta MX tardó demasiado"
      ),
      queryDoh(domain, "MX"),
    ]);
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
      records: sorted.map((r) => ({
        host: r.exchange,
        priority: r.priority,
        ttl: findTtlForHost(dohAnswers, r.exchange),
      })),
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
    const [records, dohAnswers] = await Promise.all([
      withTimeout(
        dnsPromises.resolveTxt(domain),
        8000,
        "Consulta SPF tardó demasiado"
      ),
      queryDoh(domain, "TXT"),
    ]);
    const flat = records.map((chunks) => chunks.join(""));
    const spf = flat.find((r) => r.toLowerCase().startsWith("v=spf1"));

    if (!spf) {
      return { ok: false, error: "No se encontró registro SPF" };
    }
    return { ok: true, record: spf, ttl: findTtlForTxt(dohAnswers, spf) };
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
    const [records, dohAnswers] = await Promise.all([
      withTimeout(
        dnsPromises.resolveTxt(`_dmarc.${domain}`),
        8000,
        "Consulta DMARC tardó demasiado"
      ),
      queryDoh(`_dmarc.${domain}`, "TXT"),
    ]);
    const flat = records.map((chunks) => chunks.join(""));
    const dmarc = flat.find((r) => r.toLowerCase().startsWith("v=dmarc1"));

    if (!dmarc) {
      return { ok: false, error: "No se encontró registro DMARC" };
    }

    const policyMatch = dmarc.match(/p=([a-zA-Z]+)/i);
    const policy = policyMatch ? policyMatch[1].toLowerCase() : null;

    return {
      ok: true,
      record: dmarc,
      policy,
      ttl: findTtlForTxt(dohAnswers, dmarc),
    };
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

// --- Validación de sintaxis de SPF ---
// No es un parser 100% conforme al RFC 7208, pero detecta los errores y
// malas prácticas más comunes: mecanismos mal escritos, IPs inválidas,
// exceso del límite de 10 "lookups" DNS (la causa más frecuente de que un
// SPF falle silenciosamente), y falta del calificador "all" final.
const SPF_QUALIFIERS = new Set(["+", "-", "~", "?"]);

function isValidIPv4WithPrefix(value) {
  const [ip, prefix] = value.split("/");
  const octets = ip.split(".");
  if (octets.length !== 4) return false;
  if (!octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)) return false;
  if (prefix !== undefined && (!/^\d{1,2}$/.test(prefix) || Number(prefix) > 32)) {
    return false;
  }
  return true;
}

function isValidIPv6WithPrefix(value) {
  const [ip, prefix] = value.split("/");
  if (!ip.includes(":") || !/^[0-9a-fA-F:]+$/.test(ip)) return false;
  if (prefix !== undefined && (!/^\d{1,3}$/.test(prefix) || Number(prefix) > 128)) {
    return false;
  }
  return true;
}

function isValidDomainToken(value) {
  return value === "" || /^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(value);
}

export function validateSpfSyntax(record) {
  const errors = [];
  const warnings = [];
  if (!record) return { errors, warnings };

  const terms = record.trim().split(/\s+/);
  const version = terms.shift();

  if (version !== "v=spf1") {
    errors.push(`Debe empezar exactamente con "v=spf1" (se encontró "${version}")`);
  }

  let lookupCount = 0;
  let hasAll = false;

  terms.forEach((term, idx) => {
    let qualifier = "+";
    let rest = term;
    if (SPF_QUALIFIERS.has(term[0])) {
      qualifier = term[0];
      rest = term.slice(1);
    }

    if (rest === "all") {
      hasAll = true;
      if (qualifier === "+") {
        warnings.push(
          '"+all" permite que CUALQUIER servidor envíe correo en nombre del dominio — muy inseguro, se recomienda "-all" o "~all".'
        );
      }
      if (idx !== terms.length - 1) {
        warnings.push('"all" debería ser el último término; lo que va después se ignora.');
      }
      return;
    }

    const sep = rest.includes(":") ? ":" : rest.includes("=") ? "=" : null;
    const mechanism = sep ? rest.slice(0, rest.indexOf(sep)) : rest;
    const value = sep ? rest.slice(rest.indexOf(sep) + 1) : null;

    switch (mechanism) {
      case "ip4":
        if (!value || !isValidIPv4WithPrefix(value)) {
          errors.push(`"${term}" no es una IPv4 válida`);
        }
        break;
      case "ip6":
        if (!value || !isValidIPv6WithPrefix(value)) {
          errors.push(`"${term}" no es una IPv6 válida`);
        }
        break;
      case "a":
      case "mx":
        lookupCount++;
        if (value && !isValidDomainToken(value.split("/")[0])) {
          errors.push(`"${term}" tiene un dominio con formato inválido`);
        }
        break;
      case "ptr":
        lookupCount++;
        warnings.push('El mecanismo "ptr" está desaconsejado (lento y poco confiable) — mejor evitarlo.');
        break;
      case "include":
        lookupCount++;
        if (!value) errors.push(`"include:" necesita un dominio, ej. include:otrodominio.com`);
        break;
      case "exists":
        lookupCount++;
        if (!value) errors.push(`"exists:" necesita un dominio`);
        break;
      case "redirect":
        lookupCount++;
        if (!value) errors.push(`"redirect=" necesita un dominio`);
        break;
      case "exp":
        break;
      default:
        errors.push(`Mecanismo no reconocido: "${term}"`);
    }
  });

  if (!hasAll) {
    warnings.push(
      'No se encontró un mecanismo "all" al final — se recomienda terminar el registro con "-all" o "~all".'
    );
  }

  if (lookupCount > 10) {
    errors.push(
      `Usa ${lookupCount} mecanismos que requieren consulta DNS (a, mx, include, ptr, exists, redirect) — el límite es 10. Superarlo hace que el SPF falle ("permerror") para quien lo evalúe. Si algún "include" trae mecanismos anidados, el total real podría ser aún mayor.`
    );
  } else if (lookupCount >= 8) {
    warnings.push(
      `Usa ${lookupCount} de los 10 mecanismos de consulta DNS permitidos — está cerca del límite (los "include" pueden sumar más consultas anidadas que no se cuentan aquí).`
    );
  }

  return { errors, warnings };
}

// --- Validación de sintaxis de DMARC ---
const DMARC_POLICY_VALUES = new Set(["none", "quarantine", "reject"]);
const DMARC_ALIGNMENT_VALUES = new Set(["r", "s"]);
const DMARC_KNOWN_TAGS = new Set([
  "v", "p", "sp", "rua", "ruf", "adkim", "aspf", "pct", "fo", "rf", "ri", "psd", "np",
]);

function isValidMailtoList(value) {
  const clean = value.replace(/!\d+[kmgt]?/gi, "");
  return clean
    .split(",")
    .map((v) => v.trim())
    .every((v) => /^mailto:[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(v));
}

export function validateDmarcSyntax(record) {
  const errors = [];
  const warnings = [];
  if (!record) return { errors, warnings };

  const rawTags = record.split(";").map((t) => t.trim()).filter(Boolean);
  const tags = {};

  if (!rawTags[0] || !rawTags[0].toLowerCase().startsWith("v=")) {
    errors.push('La etiqueta "v=DMARC1" debe ser la primera del registro');
  }

  rawTags.forEach((t) => {
    const eq = t.indexOf("=");
    if (eq === -1) {
      errors.push(`"${t}" no tiene el formato esperado tag=valor`);
      return;
    }
    const key = t.slice(0, eq).trim().toLowerCase();
    const value = t.slice(eq + 1).trim();
    tags[key] = value;
    if (!DMARC_KNOWN_TAGS.has(key)) {
      warnings.push(`Etiqueta desconocida: "${key}"`);
    }
  });

  if (tags.v && tags.v.toUpperCase() !== "DMARC1") {
    errors.push(`La versión debe ser exactamente "DMARC1" (se encontró "${tags.v}")`);
  }

  if (!tags.p) {
    errors.push('Falta la etiqueta "p=" (política) — es obligatoria');
  } else if (!DMARC_POLICY_VALUES.has(tags.p.toLowerCase())) {
    errors.push(`"p=${tags.p}" no es válido — debe ser none, quarantine o reject`);
  } else if (tags.p.toLowerCase() === "none") {
    warnings.push('La política es "none": solo monitorea, no bloquea ni pone en cuarentena correo falsificado.');
  }

  if (tags.sp && !DMARC_POLICY_VALUES.has(tags.sp.toLowerCase())) {
    errors.push(`"sp=${tags.sp}" no es válido — debe ser none, quarantine o reject`);
  }

  if (!tags.rua) {
    warnings.push(
      'No hay etiqueta "rua=" — no se están recibiendo reportes agregados, así que no hay visibilidad de quién envía correo en nombre del dominio.'
    );
  } else if (!isValidMailtoList(tags.rua)) {
    errors.push(`"rua=${tags.rua}" no tiene el formato esperado (una o más direcciones mailto:, separadas por coma)`);
  }

  if (tags.ruf && !isValidMailtoList(tags.ruf)) {
    errors.push(`"ruf=${tags.ruf}" no tiene el formato esperado`);
  }

  if (tags.pct !== undefined) {
    const pct = Number(tags.pct);
    if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
      errors.push(`"pct=${tags.pct}" debe ser un número entero entre 0 y 100`);
    }
  }

  if (tags.adkim && !DMARC_ALIGNMENT_VALUES.has(tags.adkim.toLowerCase())) {
    errors.push(`"adkim=${tags.adkim}" debe ser "r" (relaxed) o "s" (strict)`);
  }
  if (tags.aspf && !DMARC_ALIGNMENT_VALUES.has(tags.aspf.toLowerCase())) {
    errors.push(`"aspf=${tags.aspf}" debe ser "r" (relaxed) o "s" (strict)`);
  }

  return { errors, warnings };
}

// --- Listas negras (blacklists) ---
// Se consultan directamente por DNS contra listas públicas gratuitas.
// Si el subdominio "consulta.lista.org" resuelve a una IP, está listado.
// Si da NXDOMAIN/ENODATA, no está listado.
//
// OJO con un detalle importante de Spamhaus (DBL y ZEN): cuando detecta
// que las consultas vienen de infraestructura compartida en la nube (como
// Vercel, AWS, etc.), en vez de un error normal responde con una IP especial
// que significa "tu consulta fue bloqueada/limitada" — NO que el dominio o
// la IP estén en la lista. Si tratáramos esa respuesta como "listado"
// tendríamos falsos positivos (esto es justo lo que pasaba antes). Por eso
// filtramos ese rango de IPs "de error" y lo reportamos como "no se pudo
// verificar" en vez de "listado".
const DNSBL_ERROR_CODES = new Set([
  "127.255.255.252", // nombre de consulta mal formado
  "127.255.255.254", // bloqueado: consulta vía resolutor público/compartido
  "127.255.255.255", // bloqueado: demasiadas consultas (rate limit)
]);

async function checkZone(query) {
  try {
    const ips = await withTimeout(dnsPromises.resolve4(query), 7000, "timeout");
    const realListing = ips.filter((ip) => !DNSBL_ERROR_CODES.has(ip));

    if (realListing.length === 0) {
      return {
        listed: null,
        error: "El proveedor de la lista limitó la consulta (no es una lista real)",
      };
    }
    return { listed: true };
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      return { listed: false };
    }
    return { listed: null, error: err.code || err.message };
  }
}

// Listas que revisan el DOMINIO en sí.
//
// Spamhaus DBL queda fuera a propósito: su mirror público bloquea con
// frecuencia las consultas que vienen de infraestructura compartida en la
// nube (como Vercel), así que casi siempre respondería "no se pudo
// verificar" — no aporta nada y puede parecer que algo está roto. SURBL no
// tiene esa restricción y sí responde de forma confiable.
const DOMAIN_BLACKLIST_ZONES = [{ name: "SURBL", zone: "multi.surbl.org" }];

export async function getBlacklists(domain) {
  const results = await Promise.all(
    DOMAIN_BLACKLIST_ZONES.map(async (bl) => {
      const r = await checkZone(`${domain}.${bl.zone}`);
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

// Nota para más adelante: se evaluó revisar también las IPs de envío de
// correo (por ejemplo las declaradas en el SPF) contra listas negras
// basadas en IP, pero se dejó pendiente a propósito — se retoma cuando el
// resto del dashboard esté más maduro.

// Validación simple de dominio antes de consultar nada.
export function isValidDomain(domain) {
  return /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$/.test(domain);
}
