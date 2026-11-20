const ROOT_ANCHORS = [
  { keyTag: 20326, algorithm: 8, digestType: 2, digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" },
  { keyTag: 38696, algorithm: 8, digestType: 2, digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16" },
];

function normName(name) {
  const bare = name.replace(/\.$/, "").toLowerCase();
  return bare || ".";
}

function sameName(a, b) {
  return normName(a) === normName(b);
}

function parentName(name) {
  const norm = normName(name);
  if (norm === ".") return ".";
  const labels = norm.split(".");
  labels.shift();
  return labels.length ? labels.join(".") : ".";
}

function labelCount(name) {
  const norm = normName(name);
  return norm === "." ? 0 : norm.split(".").length;
}

function canonicalName(name) {
  const labels = normName(name) === "." ? [] : normName(name).split(".");
  const bytes = [];
  for (const label of labels) {
    const raw = new TextEncoder().encode(label);
    bytes.push(raw.length, ...raw);
  }
  bytes.push(0);
  return new Uint8Array(bytes);
}

function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function compareBytes(a, b) {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function readerAt(record) {
  const reader = new Reader(record.message);
  reader.offset = record.rdataAt;
  return reader;
}

function recordEnd(record) {
  return record.rdataAt + record.rdata.length;
}

function canonicalRdata(record) {
  const reader = readerAt(record);
  const end = recordEnd(record);
  if ([2, 5, 12, 39].includes(record.type)) return canonicalName(reader.name() || ".");
  if (record.type === 15) {
    const preference = reader.u16();
    return concatBytes([new Uint8Array([(preference >> 8) & 0xff, preference & 0xff]), canonicalName(reader.name() || ".")]);
  }
  if (record.type === 6) {
    const mname = canonicalName(reader.name() || ".");
    const rname = canonicalName(reader.name() || ".");
    return concatBytes([mname, rname, record.message.slice(reader.offset, end)]);
  }
  if (record.type === 33 || record.type === 64 || record.type === 65) {
    const headLength = record.type === 33 ? 6 : 2;
    const head = record.message.slice(reader.offset, reader.offset + headLength);
    reader.offset += headLength;
    return concatBytes([head, canonicalName(reader.name() || "."), record.message.slice(reader.offset, end)]);
  }
  if (record.type === 47) {
    const next = canonicalName(reader.name() || ".");
    return concatBytes([next, record.message.slice(reader.offset, end)]);
  }
  return record.rdata;
}

function parseRrsig(record) {
  const reader = readerAt(record);
  const end = recordEnd(record);
  return {
    record,
    typeCovered: reader.u16(),
    algorithm: reader.u8(),
    labels: reader.u8(),
    originalTtl: reader.u32(),
    expiration: reader.u32(),
    inception: reader.u32(),
    keyTag: reader.u16(),
    signer: reader.name() || ".",
    signature: record.message.slice(reader.offset, end),
  };
}

function parseDnskey(record) {
  return {
    record,
    rdata: record.rdata,
    algorithm: record.rdata[3],
    keyTag: keyTag(record.rdata),
    publicKey: record.rdata.slice(4),
  };
}

function keyTag(rdata) {
  let acc = 0;
  for (let i = 0; i < rdata.length; i++) acc += (i & 1) ? rdata[i] : rdata[i] << 8;
  acc += (acc >> 16) & 0xffff;
  return acc & 0xffff;
}

function signedOwner(name, labels) {
  const parts = normName(name) === "." ? [] : normName(name).split(".");
  if (labels >= parts.length) return parts.join(".") || ".";
  return ["*", ...parts.slice(parts.length - labels)].join(".");
}

function signedBytes(sig, rrset) {
  const owner = canonicalName(signedOwner(rrset.name, sig.labels));
  const header = new Uint8Array(18);
  const view = new DataView(header.buffer);
  view.setUint16(0, sig.typeCovered);
  header[2] = sig.algorithm;
  header[3] = sig.labels;
  view.setUint32(4, sig.originalTtl);
  view.setUint32(8, sig.expiration);
  view.setUint32(12, sig.inception);
  view.setUint16(16, sig.keyTag);
  const rdata = rrset.records.map(canonicalRdata).sort(compareBytes);
  const records = rdata.map((item) => concatBytes([
    owner,
    new Uint8Array([(rrset.type >> 8) & 0xff, rrset.type & 0xff, 0x00, 0x01]),
    new Uint8Array([(sig.originalTtl >>> 24) & 0xff, (sig.originalTtl >>> 16) & 0xff, (sig.originalTtl >>> 8) & 0xff, sig.originalTtl & 0xff]),
    new Uint8Array([(item.length >> 8) & 0xff, item.length & 0xff]),
    item,
  ]));
  return concatBytes([header, canonicalName(sig.signer), ...records]);
}

function rsaParts(bytes) {
  let offset = 0;
  let length = bytes[offset++];
  if (length === 0) {
    length = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
  }
  return { e: bytes.slice(offset, offset + length), n: bytes.slice(offset + length) };
}

async function verifySignature(sig, rrset, key) {
  try {
    const data = signedBytes(sig, rrset);
    if (sig.algorithm === 8) {
      const { e, n } = rsaParts(key.publicKey);
      const cryptoKey = await crypto.subtle.importKey("jwk", {
        kty: "RSA", n: bytesToBase64Url(n), e: bytesToBase64Url(e), alg: "RS256", ext: true,
      }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      return crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, sig.signature, data);
    }
    if (sig.algorithm === 13 || sig.algorithm === 14) {
      const size = sig.algorithm === 13 ? 32 : 48;
      const curve = sig.algorithm === 13 ? "P-256" : "P-384";
      const hash = sig.algorithm === 13 ? "SHA-256" : "SHA-384";
      const cryptoKey = await crypto.subtle.importKey("jwk", {
        kty: "EC", crv: curve, x: bytesToBase64Url(key.publicKey.slice(0, size)), y: bytesToBase64Url(key.publicKey.slice(size, size * 2)), ext: true,
      }, { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
      return crypto.subtle.verify({ name: "ECDSA", hash }, cryptoKey, sig.signature, data);
    }
    if (sig.algorithm === 15) {
      const cryptoKey = await crypto.subtle.importKey("raw", key.publicKey, { name: "Ed25519" }, false, ["verify"]);
      return crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, sig.signature, data);
    }
  } catch {
    return false;
  }
  return null;
}

async function verifyRrset(rrset, sigRecords, keys) {
  const sigs = sigRecords.map(parseRrsig).filter((sig) => sig.typeCovered === rrset.type && sameName(sig.record.name, rrset.name));
  if (!sigs.length) return { state: "bogus", reason: "DNSSEC signature missing" };
  const usable = sigs.filter((sig) => keys.some((key) => key.keyTag === sig.keyTag && key.algorithm === sig.algorithm));
  if (!usable.length) return { state: "bogus", reason: "DNSSEC key missing" };
  let unsupported = false;
  let expired = "";
  const now = Math.floor(Date.now() / 1000);
  for (const sig of usable) {
    if (now < sig.inception) { expired = "DNSSEC signature is not valid yet"; continue; }
    if (now > sig.expiration) { expired = "DNSSEC signature expired"; continue; }
    const key = keys.find((item) => item.keyTag === sig.keyTag && item.algorithm === sig.algorithm);
    const result = await verifySignature(sig, rrset, key);
    if (result === true) return { state: "secure", wildcard: sig.labels < labelCount(rrset.name) };
    if (result === null) unsupported = true;
  }
  if (expired && !unsupported) return { state: "bogus", reason: expired };
  if (unsupported) return { state: "indeterminate", reason: "DNSSEC algorithm is not supported" };
  return { state: "bogus", reason: "DNSSEC signature invalid" };
}

async function dsDigest(owner, rdata, digestType) {
  const hash = { 1: "SHA-1", 2: "SHA-256", 4: "SHA-384" }[digestType];
  if (!hash) return null;
  return new Uint8Array(await crypto.subtle.digest(hash, concatBytes([canonicalName(owner), rdata])));
}

async function keyMatchesDs(key, dsRecord) {
  const reader = readerAt(dsRecord);
  const tag = reader.u16();
  const algorithm = reader.u8();
  const digestType = reader.u8();
  const digest = dsRecord.message.slice(reader.offset, recordEnd(dsRecord));
  if (key.keyTag !== tag || key.algorithm !== algorithm) return false;
  const computed = await dsDigest(dsRecord.name, key.rdata, digestType);
  return computed && equalBytes(computed, digest);
}

async function loadDnskey(providerUrl, zone) {
  const message = await resolveDns(providerUrl, normName(zone), 48, true);
  const records = message.answers.filter((record) => record.type === 48 && sameName(record.name, zone) && record.rdata[2] === 3);
  const sigs = message.answers.filter((record) => record.type === 46 && sameName(record.name, zone));
  if (!records.length) return null;
  return { rrset: { name: records[0].name, type: 48, records }, sigs, keys: records.map(parseDnskey) };
}

async function authenticateRoot(providerUrl) {
  const dnskey = await loadDnskey(providerUrl, ".");
  if (!dnskey) return { state: "indeterminate", reason: "DNSSEC proof missing" };
  const trusted = [];
  for (const key of dnskey.keys) {
    for (const anchor of ROOT_ANCHORS) {
      if (anchor.algorithm !== key.algorithm || anchor.keyTag !== key.keyTag) continue;
      const digest = await dsDigest(".", key.rdata, anchor.digestType);
      if (digest && equalBytes(digest, hexToBytes(anchor.digest))) trusted.push(key);
    }
  }
  if (!trusted.length) return { state: "bogus", reason: "DNSSEC root key is not trusted" };
  const signed = await verifyRrset(dnskey.rrset, dnskey.sigs, trusted);
  if (signed.state !== "secure") return signed;
  return { state: "secure", keys: dnskey.keys };
}

function authenticate(providerUrl, zone, cache) {
  const name = normName(zone);
  if (!cache.has(name)) cache.set(name, name === "." ? authenticateRoot(providerUrl) : authenticateZone(providerUrl, name, cache));
  return cache.get(name);
}

async function authenticateZone(providerUrl, zone, cache) {
  const parent = await authenticate(providerUrl, parentName(zone), cache);
  if (parent.state !== "secure") return parent;
  const message = await resolveDns(providerUrl, zone, 43, true);
  const dsRecords = message.answers.filter((record) => record.type === 43 && sameName(record.name, zone));
  if (dsRecords.length) {
    const dsSet = { name: dsRecords[0].name, type: 43, records: dsRecords };
    const signedDs = await verifyRrset(dsSet, message.answers.filter((record) => record.type === 46), parent.keys);
    if (signedDs.state !== "secure") return signedDs;
    const dnskey = await loadDnskey(providerUrl, zone);
    if (!dnskey) return { state: "indeterminate", reason: "DNSSEC proof missing" };
    const matched = [];
    for (const key of dnskey.keys) {
      if (await Promise.all(dsRecords.map((ds) => keyMatchesDs(key, ds))).then((results) => results.some(Boolean))) matched.push(key);
    }
    if (!matched.length) return { state: "bogus", reason: "DNSSEC key does not match DS" };
    const signedKey = await verifyRrset(dnskey.rrset, dnskey.sigs, matched);
    if (signedKey.state !== "secure") return signedKey;
    return { state: "secure", keys: dnskey.keys };
  }
  return proveNoDs(zone, parent.keys, message);
}

function nsecTypes(record) {
  const reader = readerAt(record);
  reader.name();
  return bitmapTypes(reader, recordEnd(record));
}

function bitmapTypes(reader, end) {
  const types = new Set();
  while (reader.offset < end) {
    const window = reader.u8();
    const length = reader.u8();
    for (let i = 0; i < length; i++) {
      const bits = reader.u8();
      for (let bit = 0; bit < 8; bit++) if (bits & (0x80 >> bit)) types.add(window * 256 + i * 8 + bit);
    }
  }
  return types;
}

function parseNsec3(record) {
  const reader = readerAt(record);
  const end = recordEnd(record);
  const algorithm = reader.u8();
  const flags = reader.u8();
  const iterations = reader.u16();
  const salt = countedBytes(reader, end);
  const nextHash = countedBytes(reader, end);
  const ownerHash = base32HexDecode(record.name.split(".")[0]);
  return { record, algorithm, flags, iterations, salt, nextHash, ownerHash, types: bitmapTypes(reader, end) };
}

function base32HexDecode(text) {
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of text.toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

async function nsec3Hash(name, salt, iterations) {
  let digest = new Uint8Array(await crypto.subtle.digest("SHA-1", concatBytes([salt, canonicalName(name)])));
  for (let i = 0; i < iterations; i++) {
    digest = new Uint8Array(await crypto.subtle.digest("SHA-1", concatBytes([salt, digest])));
  }
  return digest;
}

function hashCovered(owner, next, target) {
  if (!owner || !next || compareBytes(owner, next) === 0) return false;
  if (compareBytes(owner, next) < 0) return compareBytes(owner, target) < 0 && compareBytes(target, next) < 0;
  return compareBytes(target, next) < 0 || compareBytes(owner, target) < 0;
}

async function proveNoDs(zone, parentKeys, message) {
  const records = [...message.answers, ...message.authority];
  const sigs = records.filter((record) => record.type === 46);
  const nsecs = records.filter((record) => record.type === 47);
  for (const record of nsecs) {
    const types = nsecTypes(record);
    if (!sameName(record.name, zone)) continue;
    const signed = await verifyRrset({ name: record.name, type: 47, records: [record] }, sigs, parentKeys);
    if (signed.state !== "secure") return signed.state === "bogus" ? signed : { state: "indeterminate", reason: "DNSSEC proof missing" };
    if (types.has(2) && !types.has(43)) return { state: "insecure" };
    if (!types.has(2) && !types.has(43)) return { state: "not-zone" };
  }
  const nsec3s = records.filter((record) => record.type === 50).map(parseNsec3).filter((item) => item.algorithm === 1 && item.iterations <= 150 && item.ownerHash);
  for (const item of nsec3s) {
    const signed = await verifyRrset({ name: item.record.name, type: 50, records: [item.record] }, sigs, parentKeys);
    if (signed.state !== "secure") continue;
    const qhash = await nsec3Hash(zone, item.salt, item.iterations);
    if (equalBytes(item.ownerHash, qhash)) {
      if (item.types.has(2) && !item.types.has(43)) return { state: "insecure" };
      if (!item.types.has(2) && !item.types.has(43)) return { state: "not-zone" };
    }
  }
  const verified = [];
  for (const item of nsec3s) {
    const signed = await verifyRrset({ name: item.record.name, type: 50, records: [item.record] }, sigs, parentKeys);
    if (signed.state === "secure") verified.push(item);
  }
  if (verified.length) {
    const params = verified[0];
    let name = normName(zone);
    let nextCloser = null;
    while (true) {
      const hash = await nsec3Hash(name, params.salt, params.iterations);
      const match = verified.find((item) => equalBytes(item.ownerHash, hash) && equalBytes(item.salt, params.salt) && item.iterations === params.iterations);
      if (match && nextCloser) {
        const nextHash = await nsec3Hash(nextCloser, params.salt, params.iterations);
        const cover = verified.find((item) => (item.flags & 1) && hashCovered(item.ownerHash, item.nextHash, nextHash));
        if (cover) return { state: "insecure" };
        break;
      }
      if (match || name === ".") break;
      nextCloser = name;
      name = parentName(name);
    }
  }
  if (nsecs.length || nsec3s.length) return { state: "indeterminate", reason: "DNSSEC proof missing" };
  return { state: "indeterminate", reason: "DNSSEC proof missing" };
}

async function validateDenial(providerUrl, qname, qtype, message, cache) {
  const records = [...message.answers, ...message.authority];
  const sigs = records.filter((record) => record.type === 46);
  const nsecs = records.filter((record) => record.type === 47);
  for (const record of nsecs) {
    const signer = sigs.map(parseRrsig).find((sig) => sig.typeCovered === 47 && sameName(sig.record.name, record.name));
    if (!signer) continue;
    const zone = await authenticate(providerUrl, signer.signer, cache);
    if (zone.state !== "secure") continue;
    const types = nsecTypes(record);
    const signed = await verifyRrset({ name: record.name, type: 47, records: [record] }, sigs, zone.keys);
    if (signed.state !== "secure") continue;
    if (sameName(record.name, qname) && !types.has(qtype) && !types.has(5)) return { state: "secure" };
  }
  const nsec3s = records.filter((record) => record.type === 50).map(parseNsec3).filter((item) => item.algorithm === 1 && item.iterations <= 150 && item.ownerHash);
  const verified = [];
  let zoneKeys = null;
  for (const item of nsec3s) {
    const signer = sigs.map(parseRrsig).find((sig) => sig.typeCovered === 50 && sameName(sig.record.name, item.record.name));
    if (!signer) continue;
    const zone = await authenticate(providerUrl, signer.signer, cache);
    if (zone.state !== "secure") continue;
    const signed = await verifyRrset({ name: item.record.name, type: 50, records: [item.record] }, sigs, zone.keys);
    if (signed.state !== "secure") continue;
    zoneKeys = zone;
    verified.push(item);
    const qhash = await nsec3Hash(qname, item.salt, item.iterations);
    if (equalBytes(item.ownerHash, qhash) && !item.types.has(qtype) && !item.types.has(5)) return { state: "secure" };
  }
  if (!verified.length) return { state: "indeterminate", reason: "DNSSEC proof missing" };
  const paramSets = [];
  for (const item of verified) {
    if (!paramSets.some((params) => sameNsec3(params, item))) paramSets.push(item);
  }
  for (const params of paramSets) {
    let name = normName(qname);
    let nextCloser = null;
    while (zoneKeys) {
      const hash = await nsec3Hash(name, params.salt, params.iterations);
      const match = verified.find((item) => sameNsec3(item, params) && equalBytes(item.ownerHash, hash));
      if (match && nextCloser) {
        const nextHash = await nsec3Hash(nextCloser, params.salt, params.iterations);
        const star = await nsec3Hash(normName(name) === "." ? "*." : `*.${normName(name)}`, params.salt, params.iterations);
        const covers = (target) => verified.some((item) => sameNsec3(item, params) && (item.flags & 1) === 0 && hashCovered(item.ownerHash, item.nextHash, target));
        if (covers(nextHash) && covers(star)) return { state: "secure" };
        break;
      }
      if (match || name === ".") break;
      nextCloser = name;
      name = parentName(name);
    }
  }
  return { state: "indeterminate", reason: "DNSSEC proof missing" };
}

function sameNsec3(a, b) {
  return a.iterations === b.iterations && equalBytes(a.salt, b.salt);
}

function combineDnssec(states) {
  if (!states.length) return { state: "indeterminate", reason: "DNSSEC proof missing" };
  return states.find((state) => state.state === "bogus")
    || states.find((state) => state.state === "indeterminate")
    || states.find((state) => state.state === "insecure")
    || (states.every((state) => state.state === "secure") ? { state: "secure" } : { state: "indeterminate", reason: "DNSSEC proof missing" });
}

function groupRrsets(records) {
  const groups = new Map();
  for (const record of records) {
    if (record.type === 46) continue;
    const key = `${normName(record.name)} ${record.type}`;
    if (!groups.has(key)) groups.set(key, { name: record.name, type: record.type, records: [] });
    groups.get(key).records.push(record);
  }
  return [...groups.values()];
}

async function validateRrset(providerUrl, rrset, sigs, message, cache) {
  const signer = signerOf(rrset, sigs);
  if (!signer) return missingSignature(providerUrl, rrset.name, cache);
  const zone = await authenticate(providerUrl, signer, cache);
  if (zone.state === "not-zone") return { state: "indeterminate", reason: "DNSSEC proof missing" };
  if (zone.state !== "secure") return zone;
  const signed = await verifyRrset(rrset, sigs, zone.keys);
  if (signed.state !== "secure") return signed;
  if (signed.wildcard) {
    const denial = await validateDenial(providerUrl, rrset.name, rrset.type, message, cache);
    if (denial.state !== "secure") return { state: "indeterminate", reason: "DNSSEC wildcard proof missing" };
  }
  return { state: "secure" };
}

function signerOf(rrset, sigs) {
  const sig = sigs.map(parseRrsig).find((item) => item.typeCovered === rrset.type && sameName(item.record.name, rrset.name));
  return sig ? sig.signer : "";
}

async function missingSignature(providerUrl, name, cache) {
  let zone = normName(name);
  while (true) {
    const result = await authenticate(providerUrl, zone, cache);
    if (result.state === "not-zone") {
      if (zone === ".") return { state: "indeterminate", reason: "DNSSEC proof missing" };
      zone = parentName(zone);
      continue;
    }
    if (result.state === "secure") return { state: "bogus", reason: "DNSSEC signature missing" };
    return result;
  }
}

async function validateMessage(providerUrl, qname, qtype, message, cache) {
  if (message.rcode !== 0 && message.rcode !== 3) return null;
  const sigs = [...message.answers, ...message.authority].filter((record) => record.type === 46);
  const rrsets = groupRrsets(message.answers);
  const states = [];
  for (const rrset of rrsets) states.push(await validateRrset(providerUrl, rrset, sigs, message, cache));
  if (!rrsets.length) states.push(await validateDenial(providerUrl, qname, qtype, message, cache));
  return combineDnssec(states);
}
