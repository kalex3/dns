const TYPES = [
  ["A", 1],
  ["AAAA", 28],
  ["CNAME", 5],
  ["MX", 15],
  ["NS", 2],
  ["TXT", 16],
  ["SOA", 6],
  ["PTR", 12],
  ["SRV", 33],
  ["CAA", 257],
  ["HTTPS", 65],
  ["SVCB", 64],
  ["HINFO", 13],
  ["LOC", 29],
  ["NAPTR", 35],
  ["CERT", 37],
  ["DNAME", 39],
  ["DS", 43],
  ["SSHFP", 44],
  ["IPSECKEY", 45],
  ["RRSIG", 46],
  ["NSEC", 47],
  ["DNSKEY", 48],
  ["NSEC3", 50],
  ["TLSA", 52],
  ["SMIMEA", 53],
  ["CDS", 59],
  ["CDNSKEY", 60],
  ["OPENPGPKEY", 61],
  ["SPF", 99],
  ["URI", 256],
  ["ANY", 255],
];

const TYPE_NAME = Object.fromEntries(TYPES.map(([name, code]) => [code, name]));

const DEFAULT_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "HTTPS"];

const RCODES = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"];

const PROVIDERS = [
  { id: "cloudflare", label: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { id: "quad9", label: "Quad9", url: "https://dns.quad9.net/dns-query" },
  { id: "google", label: "Google", url: "https://dns.google/dns-query" },
  { id: "custom", label: "Custom", url: "" },
];

function encodeName(name) {
  if (name === ".") return [0];
  const labels = name.replace(/\.$/, "").split(".");
  const bytes = [];
  for (const label of labels) {
    if (!label) throw new Error("That name cannot be used. Enter a hostname, such as example.com");
    const raw = new TextEncoder().encode(label);
    if (raw.length > 63) throw new Error("A label in that name is too long");
    bytes.push(raw.length, ...raw);
  }
  bytes.push(0);
  if (bytes.length > 255) throw new Error("That name is too long");
  return bytes;
}

function buildQuery(name, typeCode, dnssec = false) {
  const id = crypto.getRandomValues(new Uint8Array(2));
  const question = encodeName(name);
  question.push((typeCode >> 8) & 0xff, typeCode & 0xff, 0x00, 0x01);
  const packet = [
    id[0], id[1],
    0x01, dnssec ? 0x10 : 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, dnssec ? 0x01 : 0x00,
    ...question,
  ];
  if (dnssec) packet.push(0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00);
  return new Uint8Array(packet);
}

function bytesToBase64Url(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  u8() {
    if (this.offset >= this.bytes.length) throw new Error("The response was cut short");
    return this.bytes[this.offset++];
  }

  u16() {
    return (this.u8() << 8) | this.u8();
  }

  u32() {
    return ((this.u16() << 16) | this.u16()) >>> 0;
  }

  name() {
    const labels = [];
    let pos = this.offset;
    let jumped = false;
    for (let guard = 0; guard < 128; guard++) {
      if (pos >= this.bytes.length) throw new Error("The response was cut short");
      const length = this.bytes[pos];
      if (length === 0) {
        if (!jumped) this.offset = pos + 1;
        return labels.join(".");
      }
      if ((length & 0xc0) === 0xc0) {
        if (pos + 1 >= this.bytes.length) throw new Error("The response was cut short");
        const pointer = ((length & 0x3f) << 8) | this.bytes[pos + 1];
        if (!jumped) this.offset = pos + 2;
        jumped = true;
        pos = pointer;
        continue;
      }
      if ((length & 0xc0) !== 0) throw new Error("The response could not be read");
      const start = pos + 1;
      labels.push(new TextDecoder().decode(this.bytes.slice(start, start + length)));
      pos = start + length;
      if (!jumped) this.offset = pos;
    }
    throw new Error("The response could not be read");
  }
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function ipv4(bytes) {
  return [...bytes].join(".");
}

function ipv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  let start = -1;
  let length = 0;
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] !== "0") continue;
    let end = i + 1;
    while (end < parts.length && parts[end] === "0") end++;
    if (end - i > length) {
      start = i;
      length = end - i;
    }
    i = end - 1;
  }
  if (length < 2) return parts.join(":");
  return `${parts.slice(0, start).join(":")}::${parts.slice(start + length).join(":")}`;
}

function textAt(bytes) {
  return new TextDecoder().decode(bytes);
}

function base64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

function base32Hex(bytes) {
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(value >> bits) & 31];
    }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function countedBytes(reader, end) {
  const length = reader.u8();
  if (reader.offset + length > end) throw new Error("The response was cut short");
  const bytes = reader.bytes.slice(reader.offset, reader.offset + length);
  reader.offset += length;
  return bytes;
}

function charString(reader, end) {
  return textAt(countedBytes(reader, end));
}

function characterStrings(reader, end) {
  const parts = [];
  while (reader.offset < end) parts.push(JSON.stringify(charString(reader, end)));
  return parts.join(" ");
}

function typeBitmap(reader, end) {
  const names = [];
  while (reader.offset < end) {
    const window = reader.u8();
    const length = reader.u8();
    if (reader.offset + length > end) throw new Error("The response was cut short");
    for (let i = 0; i < length; i++) {
      const bits = reader.u8();
      for (let bit = 0; bit < 8; bit++) {
        if (bits & (0x80 >> bit)) names.push(typeLabel(window * 256 + i * 8 + bit));
      }
    }
  }
  return names.join(" ");
}

function dnsTime(seconds) {
  const date = new Date(seconds * 1000);
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`;
}

function locSize(byte) {
  const centimeters = (byte >> 4) * 10 ** (byte & 0x0f);
  return `${(centimeters / 100).toFixed(2)}m`;
}

function locCoord(value, positive, negative) {
  let milliseconds = value - 2147483648;
  const hemisphere = milliseconds < 0 ? negative : positive;
  if (milliseconds < 0) milliseconds = -milliseconds;
  const degrees = Math.floor(milliseconds / 3600000);
  const minutes = Math.floor((milliseconds % 3600000) / 60000);
  const seconds = ((milliseconds % 60000) / 1000).toFixed(3);
  return `${degrees} ${minutes} ${seconds} ${hemisphere}`;
}

function decodeRdata(reader, type, end) {
  if (type === 1 && end - reader.offset === 4) return ipv4([reader.u8(), reader.u8(), reader.u8(), reader.u8()]);
  if (type === 28 && end - reader.offset === 16) {
    const bytes = [];
    for (let i = 0; i < 16; i++) bytes.push(reader.u8());
    return ipv6(bytes);
  }
  if (type === 5 || type === 2 || type === 12 || type === 39) return reader.name() || ".";
  if (type === 15) return `${reader.u16()} ${reader.name() || "."}`;
  if (type === 16 || type === 99 || type === 13) return characterStrings(reader, end);
  if (type === 6) {
    const mname = reader.name() || ".";
    const rname = reader.name() || ".";
    const serial = reader.u32();
    const refresh = reader.u32();
    const retry = reader.u32();
    const expire = reader.u32();
    const minimum = reader.u32();
    return `${mname} ${rname} ${serial} ${refresh} ${retry} ${expire} ${minimum}`;
  }
  if (type === 29 && end - reader.offset === 16 && reader.bytes[reader.offset] === 0) {
    reader.u8();
    const size = locSize(reader.u8());
    const horizontal = locSize(reader.u8());
    const vertical = locSize(reader.u8());
    const latitude = locCoord(reader.u32(), "N", "S");
    const longitude = locCoord(reader.u32(), "E", "W");
    const altitude = `${((reader.u32() - 10000000) / 100).toFixed(2)}m`;
    return `${latitude} ${longitude} ${altitude} ${size} ${horizontal} ${vertical}`;
  }
  if (type === 33) return `${reader.u16()} ${reader.u16()} ${reader.u16()} ${reader.name() || "."}`;
  if (type === 35) {
    const order = reader.u16();
    const preference = reader.u16();
    const flags = JSON.stringify(charString(reader, end));
    const service = JSON.stringify(charString(reader, end));
    const regexp = JSON.stringify(charString(reader, end));
    return `${order} ${preference} ${flags} ${service} ${regexp} ${reader.name() || "."}`;
  }
  if (type === 37) {
    const certType = reader.u16();
    const keyTag = reader.u16();
    const algorithm = reader.u8();
    const names = { 1: "PKIX", 2: "SPKI", 3: "PGP", 4: "IPKIX", 5: "ISPKI", 6: "IPGP", 7: "ACPKIX", 8: "IACPKIX", 253: "URI", 254: "OID" };
    const body = certType === 253 || certType === 254
      ? JSON.stringify(charString(reader, end))
      : base64(reader.bytes.slice(reader.offset, end));
    return `${names[certType] || certType} ${keyTag} ${algorithm} ${body}`;
  }
  if (type === 43 || type === 59) {
    const keyTag = reader.u16();
    const algorithm = reader.u8();
    const digestType = reader.u8();
    return `${keyTag} ${algorithm} ${digestType} ${hex(reader.bytes.slice(reader.offset, end))}`;
  }
  if (type === 44 || type === 52 || type === 53) {
    const first = reader.u8();
    const second = reader.u8();
    const third = type === 44 ? "" : ` ${reader.u8()}`;
    return `${first} ${second}${third} ${hex(reader.bytes.slice(reader.offset, end))}`;
  }
  if (type === 45) {
    const precedence = reader.u8();
    const gatewayType = reader.u8();
    const algorithm = reader.u8();
    let gateway = ".";
    if (gatewayType === 1) gateway = ipv4([reader.u8(), reader.u8(), reader.u8(), reader.u8()]);
    if (gatewayType === 2) {
      const bytes = [];
      for (let i = 0; i < 16; i++) bytes.push(reader.u8());
      gateway = ipv6(bytes);
    }
    if (gatewayType === 3) gateway = reader.name() || ".";
    const key = base64(reader.bytes.slice(reader.offset, end));
    return key ? `${precedence} ${gatewayType} ${algorithm} ${gateway} ${key}` : `${precedence} ${gatewayType} ${algorithm} ${gateway}`;
  }
  if (type === 46) {
    const covered = typeLabel(reader.u16());
    const algorithm = reader.u8();
    const labels = reader.u8();
    const ttl = reader.u32();
    const expiration = dnsTime(reader.u32());
    const inception = dnsTime(reader.u32());
    const keyTag = reader.u16();
    const signer = reader.name() || ".";
    return `${covered} ${algorithm} ${labels} ${ttl} ${expiration} ${inception} ${keyTag} ${signer} ${base64(reader.bytes.slice(reader.offset, end))}`;
  }
  if (type === 47) return `${reader.name() || "."} ${typeBitmap(reader, end)}`;
  if (type === 48 || type === 60) {
    const flags = reader.u16();
    const protocol = reader.u8();
    const algorithm = reader.u8();
    return `${flags} ${protocol} ${algorithm} ${base64(reader.bytes.slice(reader.offset, end))}`;
  }
  if (type === 50) {
    const algorithm = reader.u8();
    const flags = reader.u8();
    const iterations = reader.u16();
    const salt = countedBytes(reader, end);
    const hash = countedBytes(reader, end);
    return `${algorithm} ${flags} ${iterations} ${salt.length ? hex(salt) : "-"} ${hash.length ? base32Hex(hash) : "-"} ${typeBitmap(reader, end)}`;
  }
  if (type === 61) return base64(reader.bytes.slice(reader.offset, end));
  if (type === 256) return `${reader.u16()} ${reader.u16()} ${JSON.stringify(textAt(reader.bytes.slice(reader.offset, end)))}`;
  if (type === 257) {
    const flags = reader.u8();
    const tagLength = reader.u8();
    if (reader.offset + tagLength > end) throw new Error("The response was cut short");
    const tag = textAt(reader.bytes.slice(reader.offset, reader.offset + tagLength));
    reader.offset += tagLength;
    const value = textAt(reader.bytes.slice(reader.offset, end));
    return `${flags} ${tag} ${JSON.stringify(value)}`;
  }
  if (type === 64 || type === 65) {
    const priority = reader.u16();
    const target = reader.name() || ".";
    const params = [];
    while (reader.offset + 4 <= end) {
      const key = reader.u16();
      const length = reader.u16();
      if (reader.offset + length > end) throw new Error("The response was cut short");
      params.push(`${key}=${hex(reader.bytes.slice(reader.offset, reader.offset + length))}`);
      reader.offset += length;
    }
    return [String(priority), target, ...params].join(" ");
  }
  return hex(reader.bytes.slice(reader.offset, end));
}

function readRecords(reader, count) {
  const records = [];
  for (let i = 0; i < count; i++) {
    const name = reader.name();
    const type = reader.u16();
    reader.u16();
    const ttl = reader.u32();
    const length = reader.u16();
    const rdataAt = reader.offset;
    const end = rdataAt + length;
    const rdata = reader.bytes.slice(rdataAt, end);
    const data = decodeRdata(reader, type, end);
    reader.offset = end;
    records.push({ name: name || ".", type, ttl, data, rdata, rdataAt, message: reader.bytes });
  }
  return records;
}

function parseMessage(buffer) {
  const reader = new Reader(new Uint8Array(buffer));
  reader.u16();
  const flags = reader.u16();
  if ((flags & 0x8000) === 0) throw new Error("The provider did not return a DNS response");
  const questions = reader.u16();
  const answers = reader.u16();
  const authority = reader.u16();
  const additional = reader.u16();
  for (let i = 0; i < questions; i++) {
    reader.name();
    reader.u16();
    reader.u16();
  }
  return {
    rcode: flags & 0x000f,
    tc: (flags & 0x0200) !== 0,
    ra: (flags & 0x0080) !== 0,
    ad: (flags & 0x0020) !== 0,
    answers: readRecords(reader, answers),
    authority: readRecords(reader, authority),
    additional: readRecords(reader, additional).filter((record) => record.type !== 41),
  };
}

function asciiName(name) {
  const trimmed = name.trim().replace(/\.$/, "");
  if (!trimmed || /[\s/?#\\]/.test(trimmed)) throw new Error("That name cannot be used. Enter a hostname, such as example.com");
  try {
    return new URL(`http://${trimmed}`).hostname;
  } catch {
    throw new Error("That name cannot be used. Enter a hostname, such as example.com");
  }
}

function ptrName(input) {
  const v4 = input.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const octets = v4.slice(1).map(Number);
    if (octets.every((octet) => octet <= 255)) return `${octets.reverse().join(".")}.in-addr.arpa`;
  }
  if (!input.includes(":")) return asciiName(input);
  const halves = input.toLowerCase().split("::");
  if (halves.length > 2) throw new Error("That address cannot be used. Enter a full IPv4 or IPv6 address");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (left.length + right.length > 7) throw new Error("That address cannot be used. Enter a full IPv4 or IPv6 address");
  const groups = halves.length === 1
    ? left
    : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  if (groups.length !== 8) throw new Error("That address cannot be used. Enter a full IPv4 or IPv6 address");
  const nibbles = groups.map((group) => group.padStart(4, "0")).join("");
  if (!/^[0-9a-f]{32}$/.test(nibbles)) throw new Error("That address cannot be used. Enter a full IPv4 or IPv6 address");
  return `${nibbles.split("").reverse().join(".")}.ip6.arpa`;
}

function isAddress(raw) {
  const name = raw.trim();
  if (!name.includes(":") && !/^(\d{1,3}\.){3}\d{1,3}$/.test(name)) return false;
  try {
    const reverse = ptrName(name);
    return reverse.endsWith(".in-addr.arpa") || reverse.endsWith(".ip6.arpa");
  } catch {
    return false;
  }
}

function queryName(raw, type) {
  const name = raw.trim();
  if (!name) throw new Error("Enter a name");
  return type === "PTR" ? ptrName(name) : asciiName(name);
}

async function resolveDns(providerUrl, name, typeCode, dnssec = false) {
  const endpoint = new URL(providerUrl);
  if (endpoint.protocol !== "https:") throw new Error("The provider URL has to start with https://");
  endpoint.searchParams.set("dns", bytesToBase64Url(buildQuery(name, typeCode, dnssec)));
  let response;
  try {
    response = await fetch(endpoint);
  } catch {
    const origin = globalThis.location?.origin || "null";
    let text = `Failed to fetch ${endpoint.host}: CORS blocked a simple GET from origin ${origin} because the response has no Access-Control-Allow-Origin header.`;
    if (endpoint.hostname.endsWith(".quad9.net")) {
      text += " Quad9 omits that header on HTTP/3 and sends Access-Control-Allow-Origin: * on HTTP/2.";
    }
    throw new Error(text);
  }
  if (!response.ok) throw new Error(`The provider returned ${response.status}. Try again, or pick another provider`);
  return parseMessage(await response.arrayBuffer());
}

async function resolveAny(providerUrl, name, dnssec = false) {
  const settled = await Promise.all(DEFAULT_TYPES.map(async (type) => {
    const typeCode = TYPES.find(([typeName]) => typeName === type)[1];
    try {
      return { typeCode, message: await resolveDns(providerUrl, name, typeCode, dnssec) };
    } catch (err) {
      return { err };
    }
  }));
  if (dnssec && settled.some((item) => item.err)) throw settled.find((item) => item.err).err;
  const messages = settled.filter((item) => item.message).map((item) => item.message);
  if (!messages.length) throw settled[0].err;
  let dnssecVerdict = null;
  if (dnssec) {
    const cache = new Map();
    const verdicts = [];
    for (const item of settled) {
      if (!item.message) continue;
      verdicts.push(await validateMessage(providerUrl, name, item.typeCode, item.message, cache) || { state: "indeterminate", reason: "DNSSEC proof missing" });
    }
    dnssecVerdict = combineDnssec(verdicts);
  }
  const answers = [];
  const seen = new Set();
  for (const message of messages) {
    for (const record of message.answers) {
      const key = `${record.name}\n${record.type}\n${record.data}`;
      if (seen.has(key)) continue;
      seen.add(key);
      answers.push(record);
    }
  }
  const sameRcode = messages.every((message) => message.rcode === messages[0].rcode);
  return {
    rcode: answers.length ? 0 : sameRcode ? messages[0].rcode : messages.find((message) => message.rcode !== 0)?.rcode ?? 0,
    tc: messages.some((message) => message.tc),
    ra: messages.every((message) => message.ra),
    ad: messages.every((message) => message.ad),
    answers,
    authority: answers.length ? [] : messages.find((message) => message.authority.length)?.authority ?? [],
    dnssec: dnssecVerdict,
  };
}
