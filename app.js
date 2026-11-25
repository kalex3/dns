function presentRecords(records, type, dnssec) {
  if (!dnssec) return records;
  const queried = TYPES.find(([name]) => name === type)?.[1];
  const hidden = new Set([46, 47, 50]);
  if (queried) hidden.delete(queried);
  return records.filter((record) => !hidden.has(record.type));
}

function typeLabel(code) {
  return TYPE_NAME[code] || String(code);
}

const LINK_TOKEN = /(?:(?<=[iI][pP]6:)|(?<![\w:]))(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])|(?<![\w.-])(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}(?![\w.-])|(?<![\w.-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(?=\.(?![\w-])|(?![\w.-]))/g;

function isIp(token) {
  return token.includes(":") || token.split(".").every((part) => /^\d+$/.test(part));
}

function isDefaultQuery(type) {
  return type === "DEFAULT" || type === "ANY";
}

function queryHref(name, link) {
  const params = new URLSearchParams();
  params.set("name", name);
  if (link.type && !isDefaultQuery(link.type)) params.set("type", link.type);
  return `#${params}`;
}

function reverseName(ip) {
  if (!ip.includes(":")) {
    const parts = ip.split(".");
    if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return "";
    return `${parts.reverse().join(".")}.in-addr.arpa`;
  }
  const halves = ip.split("::");
  if (halves.length > 2) return "";
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 && head.length !== 8) return "";
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 && missing < 1) return "";
  const parts = halves.length === 2 ? [...head, ...Array(missing).fill("0"), ...tail] : head;
  if (parts.length !== 8 || parts.some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) return "";
  const nibbles = parts.map((part) => part.padStart(4, "0")).join("").split("").reverse();
  return `${nibbles.join(".")}.ip6.arpa`;
}

function linksOn() {
  return document.querySelector("#links")?.checked !== false;
}

function setIpAnchor(anchor, token, link) {
  if (!(link && reverseName(token))) return false;
  anchor.href = queryHref(token, { ...link, type: "DEFAULT" });
  anchor.target = "";
  anchor.removeAttribute("rel");
  return true;
}

function externalLink(href, text) {
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.target = "_blank";
  anchor.rel = "noopener noreferrer";
  anchor.textContent = text;
  return anchor;
}

function cidrSuffix(text, end, ipv6) {
  const match = /^\/(\d{1,3})(?!\d)/.exec(text.slice(end));
  if (!match) return "";
  return Number(match[1]) <= (ipv6 ? 128 : 32) ? match[0] : "";
}

function appendSoft(node, text) {
  const parts = text.split(/([.:])/);
  for (const part of parts) {
    if (!part) continue;
    node.append(part);
    if (part === "." || part === ":") node.append(document.createElement("wbr"));
  }
}

function appendLinked(node, text, link) {
  if (!linksOn()) {
    appendSoft(node, text);
    return;
  }
  let cursor = 0;
  for (const match of text.matchAll(LINK_TOKEN)) {
    if (match.index > cursor) appendSoft(node, text.slice(cursor, match.index));
    const token = match[0];
    const anchor = document.createElement("a");
    if (isIp(token)) {
      const suffix = cidrSuffix(text, match.index + token.length, token.includes(":"));
      const shown = token + suffix;
      if (setIpAnchor(anchor, token, link)) {
        appendSoft(anchor, shown);
        node.append(anchor);
      } else appendSoft(node, shown);
      cursor = match.index + shown.length;
    } else if (link) {
      appendSoft(anchor, token);
      anchor.href = queryHref(token, link);
      node.append(anchor);
      cursor = match.index + token.length;
    } else {
      appendSoft(node, token);
      cursor = match.index + token.length;
    }
  }
  if (cursor < text.length) appendSoft(node, text.slice(cursor));
}

function writeLinked(node, text, link) {
  node._source = text;
  node.replaceChildren();
  appendLinked(node, text, link);
}

function relinkResult(result) {
  const link = result._queryLink;
  for (const node of result.querySelectorAll(".status, td")) {
    if (node._source == null) continue;
    writeLinked(node, node._source, link);
  }
}

function recordTable(records, link) {
  const table = document.createElement("table");
  table.className = "answers";
  const head = document.createElement("tr");
  for (const [label, className] of [["Name", ""], ["Type", "fit"], ["TTL", "num"], ["Data", ""]]) {
    const cell = document.createElement("th");
    cell.textContent = label;
    if (className) cell.className = className;
    head.append(cell);
  }
  table.append(head);
  for (const record of records) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    writeLinked(name, record.name, link);
    const type = document.createElement("td");
    type.className = "fit";
    type.textContent = typeLabel(record.type);
    const ttl = document.createElement("td");
    ttl.className = "num";
    ttl.textContent = String(record.ttl);
    const data = document.createElement("td");
    writeLinked(data, record.data, link);
    row.append(name, type, ttl, data);
    table.append(row);
  }
  return table;
}

function vcardValue(entity, key) {
  const row = entity?.vcardArray?.[1]?.find((item) => item[0] === key);
  const value = row?.[3];
  return value == null ? "" : String(value);
}

function entityByRole(entities, role) {
  for (const entity of entities || []) {
    if ((entity.roles || []).some((item) => item.toLowerCase() === role)) return entity;
    const nested = entityByRole(entity.entities, role);
    if (nested) return nested;
  }
  return null;
}

function eventDate(events, action) {
  const found = (events || []).find((event) => event.eventAction === action);
  if (!found?.eventDate) return "";
  const date = new Date(found.eventDate);
  if (Number.isNaN(date.getTime())) return found.eventDate;
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" }).format(date);
}

function whoisRows(pairs) {
  return pairs.filter(([, value]) => value);
}

function formatDomainWhois(data) {
  const registrar = entityByRole(data.entities, "registrar");
  const dnssec = data.secureDNS ? (data.secureDNS.delegationSigned ? "signed" : "unsigned") : "";
  return whoisRows([
    ["Name", data.ldhName || ""],
    ["Registrar", vcardValue(registrar, "fn")],
    ["Registered", eventDate(data.events, "registration")],
    ["Expires", eventDate(data.events, "expiration")],
    ["Updated", eventDate(data.events, "last changed")],
    ["Status", (data.status || []).join(", ")],
    ["Nameservers", (data.nameservers || []).map((ns) => ns.ldhName).filter(Boolean).join(", ")],
    ["DNSSEC", dnssec],
  ]);
}

function formatIpWhois(data) {
  const org = entityByRole(data.entities, "registrant");
  const abuse = entityByRole(data.entities, "abuse");
  const cidr = (data.cidr0_cidrs || []).map((item) => {
    if (item.v4prefix) return `${item.v4prefix}/${item.length}`;
    if (item.v6prefix) return `${item.v6prefix}/${item.length}`;
    return "";
  }).filter(Boolean);
  const range = cidr.join(", ") || (data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : "");
  return whoisRows([
    ["Network", data.name || ""],
    ["Range", range],
    ["Type", data.type || ""],
    ["Organization", vcardValue(org, "fn") || vcardValue(org, "org")],
    ["Abuse", vcardValue(abuse, "email")],
    ["Registered", eventDate(data.events, "registration")],
    ["Updated", eventDate(data.events, "last changed")],
  ]);
}

function ipFromInAddr(name) {
  const match = name.toLowerCase().replace(/\.$/, "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$/);
  if (!match) return "";
  const octets = match.slice(1).map(Number);
  if (octets.some((octet) => octet > 255)) return "";
  return octets.reverse().join(".");
}

function ipFromIp6Arpa(name) {
  const base = name.toLowerCase().replace(/\.$/, "");
  if (!base.endsWith(".ip6.arpa")) return "";
  const labels = base.slice(0, -".ip6.arpa".length).split(".");
  if (labels.length !== 32 || labels.some((label) => !/^[0-9a-f]$/.test(label))) return "";
  const hex = labels.reverse().join("");
  return hex.match(/.{4}/g).map((part) => parseInt(part, 16).toString(16)).join(":");
}

function whoisSubject(name) {
  const trimmed = name.trim().replace(/\.$/, "");
  if (isIp(trimmed) && reverseName(trimmed)) return { kind: "ip", query: trimmed };
  const v4 = ipFromInAddr(trimmed);
  if (v4) return { kind: "ip", query: v4 };
  const v6 = ipFromIp6Arpa(trimmed);
  if (v6) return { kind: "ip", query: v6 };
  return { kind: "domain", query: trimmed.toLowerCase() };
}

function ipv4Value(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((value, part) => value * 256 + Number(part), 0) >>> 0;
}

function ipv6Value(ip) {
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const parse = (text) => text ? text.split(":").map((part) => /^[0-9a-fA-F]{1,4}$/.test(part) ? parseInt(part, 16) : null) : [];
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  if (head.includes(null) || tail.includes(null)) return null;
  if (halves.length === 1 && head.length !== 8) return null;
  if (halves.length === 2 && head.length + tail.length > 7) return null;
  const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - tail.length).fill(0), ...tail] : head;
  if (groups.length !== 8) return null;
  return groups.reduce((value, part) => (value << 16n) + BigInt(part), 0n);
}

function reservedPrefix(cidr) {
  const slash = cidr.lastIndexOf("/");
  const addr = cidr.slice(0, slash);
  const length = Number(cidr.slice(slash + 1));
  const v6 = addr.includes(":");
  const value = v6 ? ipv6Value(addr) : ipv4Value(addr);
  const mask = v6
    ? ((1n << 128n) - 1n) ^ ((1n << (128n - BigInt(length))) - 1n)
    : (0xffffffff << (32 - length)) >>> 0;
  return { v6, length, mask, network: v6 ? value & mask : (value & mask) >>> 0 };
}

function rfcSpec(item) {
  if (item[0] === "errata") return { errata: item[1] };
  return { rfc: item[0], section: item[1] || "" };
}

// A prefix with no name is allocated inside a reserved parent and stays on WHOIS.
const RESERVED = [
  ["0.0.0.0/8", "\"This network\"", [[791, "3.2"]]],
  ["0.0.0.0/32", "\"This host on this network\"", [[1122, "3.2.1.3"]]],
  ["10.0.0.0/8", "Private-Use", [[1918]]],
  ["100.64.0.0/10", "Shared Address Space", [[6598]]],
  ["127.0.0.0/8", "Loopback", [[1122, "3.2.1.3"]]],
  ["169.254.0.0/16", "Link Local", [[3927]]],
  ["172.16.0.0/12", "Private-Use", [[1918]]],
  ["192.0.0.0/24", "IETF Protocol Assignments", [[6890, "2.1"]]],
  ["192.0.0.0/29", "IPv4 Service Continuity Prefix", [[7335]]],
  ["192.0.0.8/32", "IPv4 dummy address", [[7600]]],
  ["192.0.0.9/32"],
  ["192.0.0.10/32"],
  ["192.0.0.170/32", "NAT64/DNS64 Discovery", [[8880], [7050, "2.2"]]],
  ["192.0.0.171/32", "NAT64/DNS64 Discovery", [[8880], [7050, "2.2"]]],
  ["192.0.2.0/24", "Documentation (TEST-NET-1)", [[5737]]],
  ["192.88.99.0/24", "Deprecated (6to4 Relay Anycast)", [[7526]]],
  ["192.88.99.2/32", "6a44-relay anycast address", [[6751]]],
  ["192.168.0.0/16", "Private-Use", [[1918]]],
  ["198.18.0.0/15", "Benchmarking", [[2544]]],
  ["198.51.100.0/24", "Documentation (TEST-NET-2)", [[5737]]],
  ["203.0.113.0/24", "Documentation (TEST-NET-3)", [[5737]]],
  ["224.0.0.0/4", "Multicast", [[1112, "4"]]],
  ["240.0.0.0/4", "Reserved", [[1112, "4"]]],
  ["255.255.255.255/32", "Limited Broadcast", [[8190], [919, "7"]]],
  ["::1/128", "Loopback Address", [[4291]]],
  ["::/128", "Unspecified Address", [[4291]]],
  ["::ffff:0:0/96", "IPv4-mapped Address", [[4291]]],
  ["64:ff9b:1::/48", "IPv4-IPv6 translation", [[8215]]],
  ["100::/64", "Discard-Only Address Block", [[6666]]],
  ["100:0:0:1::/64", "Dummy IPv6 Prefix", [[9780]]],
  ["2001::/23", "IETF Protocol Assignments", [[2928]]],
  ["2001::/32"],
  ["2001:1::1/128"],
  ["2001:1::2/128"],
  ["2001:1::3/128"],
  ["2001:2::/48", "Benchmarking", [[5180], ["errata", 1752]]],
  ["2001:3::/32"],
  ["2001:4:112::/48"],
  ["2001:10::/28", "Deprecated (previously ORCHID)", [[4843]]],
  ["2001:20::/28"],
  ["2001:30::/28"],
  ["2001:db8::/32", "Documentation", [[3849]]],
  ["3fff::/20", "Documentation", [[9637]]],
  ["5f00::/16", "Segment Routing (SRv6) SIDs", [[9602]]],
  ["fc00::/7", "Unique-Local", [[4193], [8190]]],
  ["fe80::/10", "Link-Local Unicast", [[4291]]],
  ["ff00::/8", "Multicast", [[4291, "2.7"]]],
].map(([prefix, name, refs]) => ({
  ...reservedPrefix(prefix),
  name: name || "",
  refs: (refs || []).map(rfcSpec),
}));

function reservedAddress(ip) {
  const v6 = ip.includes(":");
  const value = v6 ? ipv6Value(ip) : ipv4Value(ip);
  if (value == null) return null;
  let best = null;
  for (const entry of RESERVED) {
    if (entry.v6 !== v6 || (best && entry.length <= best.length)) continue;
    const network = v6 ? value & entry.mask : (value & entry.mask) >>> 0;
    if (network === entry.network) best = entry;
  }
  return best?.name ? best : null;
}

function rfcHref(ref) {
  if (ref.errata) return `https://www.rfc-editor.org/errata/eid${ref.errata}`;
  const url = `https://www.rfc-editor.org/rfc/rfc${ref.rfc}`;
  return ref.section ? `${url}#section-${ref.section}` : url;
}

function rfcText(ref) {
  if (ref.errata) return `RFC errata ${ref.errata}`;
  return ref.section ? `RFC ${ref.rfc}, Section ${ref.section}` : `RFC ${ref.rfc}`;
}

function showReserved(result, entry) {
  const heading = document.createElement("h2");
  heading.dataset.reserved = "1";
  heading.textContent = "Reserved";
  const note = document.createElement("p");
  note.dataset.reserved = "1";
  if (entry.name === "Reserved") note.append("Reserved by ");
  else if (entry.name.startsWith("Deprecated")) note.append(entry.name, " by ");
  else note.append("Reserved for ", entry.name, " by ");
  entry.refs.forEach((ref, index) => {
    if (index > 0) note.append(index === entry.refs.length - 1 ? " and " : ", ");
    note.append(externalLink(rfcHref(ref), rfcText(ref)));
  });
  note.append(".");
  result.append(heading, note);
}

async function fetchRdap(url) {
  let response;
  try {
    response = await fetch(url);
  } catch {
    throw new Error("WHOIS lookup failed. Try again");
  }
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("WHOIS lookup failed. Try again");
  return { data: await response.json(), url: response.url };
}

async function loadWhois(subject) {
  if (subject.kind === "ip") {
    const found = await fetchRdap(`https://rdap.org/ip/${subject.query}`);
    return found ? { rows: formatIpWhois(found.data), url: found.url } : null;
  }
  const labels = subject.query.split(".").filter(Boolean);
  for (let i = 0; i <= labels.length - 2; i++) {
    const found = await fetchRdap(`https://rdap.org/domain/${labels.slice(i).join(".")}`);
    if (found) return { rows: formatDomainWhois(found.data), url: found.url };
  }
  return null;
}

function whoisTable(rows, link) {
  const table = document.createElement("table");
  table.className = "whois";
  table.dataset.whois = "1";
  for (const [label, value] of rows) {
    const row = document.createElement("tr");
    const head = document.createElement("th");
    head.textContent = label;
    const cell = document.createElement("td");
    writeLinked(cell, value, link);
    row.append(head, cell);
    table.append(row);
  }
  return table;
}

function formatIpinfo(data) {
  return whoisRows([
    ["IP", data.ip || ""],
    ["Hostname", data.hostname || ""],
    ["Anycast", data.anycast ? "yes" : ""],
    ["Bogon", data.bogon ? "yes" : ""],
    ["City", data.city || ""],
    ["Region", data.region || ""],
    ["Country", data.country || ""],
    ["Coordinates", data.loc || ""],
    ["Organization", data.org || ""],
    ["Postal", data.postal || ""],
    ["Timezone", data.timezone || ""],
  ]);
}

async function loadIpinfo(ip) {
  let response;
  try {
    response = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`);
  } catch {
    throw new Error("ipinfo.io lookup failed. Try again");
  }
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("ipinfo.io lookup failed. Try again");
  return formatIpinfo(await response.json());
}

async function showIpinfo(result, ip, link, token) {
  const heading = document.createElement("h2");
  heading.dataset.ipinfo = "1";
  heading.append(externalLink(`https://ipinfo.io/${encodeURIComponent(ip)}`, "IPinfo"));
  const note = document.createElement("p");
  note.dataset.ipinfo = "1";
  note.textContent = "Looking up…";
  result.append(heading, note);
  try {
    const rows = await loadIpinfo(ip);
    if (result._ipinfoToken !== token) return;
    if (!rows?.length) {
      note.textContent = "No ipinfo.io record";
      return;
    }
    const table = whoisTable(rows, link);
    table.dataset.ipinfo = "1";
    delete table.dataset.whois;
    note.replaceWith(table);
  } catch (err) {
    if (result._ipinfoToken !== token) return;
    note.textContent = err.message || "ipinfo.io lookup failed. Try again";
    note.className = "error-text";
  }
}

async function showWhois(result, subject, link, token) {
  const heading = document.createElement("h2");
  heading.textContent = "WHOIS";
  heading.dataset.whois = "1";
  const note = document.createElement("p");
  note.dataset.whois = "1";
  note.textContent = "Looking up…";
  result.append(heading, note);
  try {
    const found = await loadWhois(subject);
    if (result._whoisToken !== token) return;
    if (!found?.rows?.length) {
      note.textContent = "No WHOIS record";
      return;
    }
    heading.replaceChildren(externalLink(found.url, "WHOIS"));
    note.replaceWith(whoisTable(found.rows, link));
  } catch (err) {
    if (result._whoisToken !== token) return;
    note.textContent = err.message || "WHOIS lookup failed. Try again";
    note.className = "error-text";
  }
}

function showResult(result, message) {
  result.hidden = false;
  result._queryLink = message.link || null;
  result.replaceChildren();
  const status = document.createElement("p");
  status.className = message.bad ? "status error-text" : message.warn ? "status warning-text" : "status";
  writeLinked(status, message.text, message.link);
  result.append(status);
  if (!message.sections) return;
  for (const section of message.sections) {
    if (!section.records.length) continue;
    const heading = document.createElement("h2");
    heading.textContent = section.title;
    result.append(heading, recordTable(section.records, message.link));
  }
}

function init() {
  const form = document.querySelector("#lookup");
  const nameInput = document.querySelector("#name");
  const typeSelect = document.querySelector("#type");
  const providerSelect = document.querySelector("#provider");
  const customWrap = document.querySelector("#custom-wrap");
  const customInput = document.querySelector("#custom");
  const dnssecInput = document.querySelector("#dnssec");
  const autoUrlInput = document.querySelector("#auto-url");
  const whoisInput = document.querySelector("#whois");
  const linksInput = document.querySelector("#links");
  const ipinfoInput = document.querySelector("#ipinfo");
  const button = document.querySelector("#go");
  const result = document.querySelector("#result");

  for (const name of ["DEFAULT", ...TYPES.map(([typeName]) => typeName).filter((typeName) => typeName !== "ANY")]) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    typeSelect.append(option);
  }
  for (const provider of PROVIDERS) {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = provider.label;
    option.translate = false;
    providerSelect.append(option);
  }

  const savedProvider = localStorage.getItem("doh.provider");
  const savedType = localStorage.getItem("doh.type");
  typeSelect.value = "DEFAULT";
  if (PROVIDERS.some((provider) => provider.id === savedProvider)) providerSelect.value = savedProvider;
  if (savedType && !isDefaultQuery(savedType) && TYPES.some(([name]) => name === savedType)) typeSelect.value = savedType;
  customInput.value = localStorage.getItem("doh.custom") || "";
  dnssecInput.checked = localStorage.getItem("doh.dnssec") === "off";
  autoUrlInput.checked = localStorage.getItem("doh.autourl") === "on";
  whoisInput.checked = localStorage.getItem("doh.whois") !== "off";
  linksInput.checked = localStorage.getItem("doh.links") !== "off";
  ipinfoInput.checked = localStorage.getItem("doh.ipinfo") !== "off";
  linksInput.addEventListener("change", () => {
    localStorage.setItem("doh.links", linksInput.checked ? "on" : "off");
    relinkResult(result);
  });
  ipinfoInput.addEventListener("change", () => {
    localStorage.setItem("doh.ipinfo", ipinfoInput.checked ? "on" : "off");
    for (const node of result.querySelectorAll("[data-ipinfo]")) node.remove();
    if (!ipinfoInput.checked || result._reserved || result._whoisSubject?.kind !== "ip") return;
    const token = (result._ipinfoToken || 0) + 1;
    result._ipinfoToken = token;
    showIpinfo(result, result._whoisSubject.query, result._queryLink, token);
  });
  whoisInput.addEventListener("change", () => {
    localStorage.setItem("doh.whois", whoisInput.checked ? "on" : "off");
    for (const node of result.querySelectorAll("[data-whois]")) node.remove();
    if (!whoisInput.checked || result._reserved || !result._whoisSubject) return;
    const token = (result._whoisToken || 0) + 1;
    result._whoisToken = token;
    showWhois(result, result._whoisSubject, result._queryLink, token);
  });
  function syncCustom() {
    const custom = providerSelect.value === "custom";
    customWrap.hidden = !custom;
    customInput.required = custom;
  }
  providerSelect.addEventListener("change", syncCustom);
  syncCustom();

  function writeHash() {
    const params = new URLSearchParams();
    const name = nameInput.value.trim();
    if (name) {
      params.set("name", name);
      if (!isDefaultQuery(typeSelect.value)) params.set("type", typeSelect.value);
    }
    const next = params.toString();
    const target = next ? `${location.pathname}${location.search}#${next}` : `${location.pathname}${location.search}`;
    if (`${location.pathname}${location.search}${location.hash}` !== target) history.replaceState(null, "", target);
  }

  function applyHash() {
    const params = new URLSearchParams(location.hash.slice(1));
    const name = params.get("name");
    if (!name || !name.trim()) return false;
    nameInput.value = name;
    const type = params.get("type");
    typeSelect.value = type && !isDefaultQuery(type) && TYPES.some(([typeName]) => typeName === type) ? type : "DEFAULT";
    return true;
  }

  function maybeWriteHash() {
    if (autoUrlInput.checked) writeHash();
  }
  autoUrlInput.addEventListener("change", () => {
    localStorage.setItem("doh.autourl", autoUrlInput.checked ? "on" : "off");
  });
  for (const field of [nameInput, typeSelect, providerSelect, customInput, dnssecInput, autoUrlInput]) {
    field.addEventListener("input", maybeWriteHash);
    field.addEventListener("change", maybeWriteHash);
  }
  window.addEventListener("hashchange", () => {
    if (!applyHash()) return;
    button.disabled = false;
    form.requestSubmit();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const provider = PROVIDERS.find((item) => item.id === providerSelect.value);
    const type = typeSelect.value;
    const dnssecOn = !dnssecInput.checked;
    const lookupToken = (result._lookupToken || 0) + 1;
    result._lookupToken = lookupToken;
    const whoisToken = lookupToken;
    result._whoisToken = whoisToken;
    result._ipinfoToken = lookupToken;
    writeHash();
    localStorage.setItem("doh.provider", provider.id);
    localStorage.setItem("doh.type", type);
    localStorage.setItem("doh.custom", customInput.value.trim());
    localStorage.setItem("doh.dnssec", dnssecOn ? "on" : "off");
    button.disabled = true;
    button.classList.add("busy");
    button.textContent = "Looking Up…";
    const started = performance.now();
    let lookedUp = "";
    const link = { type, provider: provider.id, url: customInput.value.trim(), dnssec: dnssecOn ? "on" : "off" };
    try {
      const queryType = isDefaultQuery(type) && isAddress(nameInput.value) ? "PTR" : type;
      const name = queryName(nameInput.value, queryType);
      lookedUp = name;
      const url = provider.id === "custom" ? customInput.value.trim() : provider.url;
      const typeCode = TYPES.find(([typeName]) => typeName === queryType)?.[1];
      const message = isDefaultQuery(queryType)
        ? await resolveAny(url, name, dnssecOn)
        : await resolveDns(url, name, typeCode, dnssecOn);
      if (result._lookupToken !== lookupToken) return;
      if (dnssecOn && !isDefaultQuery(queryType)) {
        message.dnssec = await validateMessage(url, name, typeCode, message, new Map());
      }
      if (result._lookupToken !== lookupToken) return;
      const elapsed = Math.max(1, Math.round(performance.now() - started));
      const rcode = RCODES[message.rcode] || `RCODE ${message.rcode}`;
      const notes = [rcode];
      if (dnssecOn && message.dnssec?.state === "secure") notes.push("DNSSEC");
      else if (dnssecOn && message.dnssec?.state === "insecure") notes.push("unsigned");
      else if (dnssecOn && message.dnssec) notes.push(message.dnssec.reason || "DNSSEC validation failed");
      else if (message.ad) notes.push("DNSSEC");
      if (message.tc) notes.push("truncated");
      if (!message.ra) notes.push("recursion unavailable");
      notes.push(`${elapsed}\u00a0ms`, provider.label);
      const bad = message.rcode !== 0 || (dnssecOn && message.dnssec && message.dnssec.state !== "secure" && message.dnssec.state !== "insecure");
      const answers = presentRecords(message.answers, queryType, dnssecOn);
      const authority = presentRecords(message.authority, queryType, dnssecOn);
      showResult(result, {
        text: `${name} ${queryType} · ${notes.join(" · ")}`,
        bad,
        warn: !bad && answers.length === 0,
        link,
        sections: answers.length
          ? [{ title: "Answers", records: answers }]
          : [{ title: "Authority", records: authority }],
      });
      if (!bad && answers.length === 0 && authority.length === 0) {
        const status = result.querySelector(".status");
        status._source += " · no records";
        status.append(" · no records");
      }
    } catch (err) {
      if (result._lookupToken !== lookupToken) return;
      showResult(result, {
        text: err.message || "Lookup failed. Try again",
        bad: true,
        link,
      });
    } finally {
      if (result._lookupToken === lookupToken) {
        button.disabled = false;
        button.classList.remove("busy");
        button.textContent = "Look Up";
      }
    }
    if (result._lookupToken !== lookupToken) return;
    result._whoisSubject = lookedUp ? whoisSubject(lookedUp) : null;
    result._reserved = result._whoisSubject?.kind === "ip" ? reservedAddress(result._whoisSubject.query) : null;
    if (result._reserved) {
      showReserved(result, result._reserved);
      return;
    }
    if (lookedUp && whoisInput.checked) showWhois(result, result._whoisSubject, link, whoisToken);
    if (ipinfoInput.checked && result._whoisSubject?.kind === "ip") showIpinfo(result, result._whoisSubject.query, link, lookupToken);
  });

  if (applyHash()) form.requestSubmit();
}

if (typeof document !== "undefined") init();
