import http from "node:http";
import { readFile } from "node:fs/promises";
import { privateKey, Fault, BASE } from "./protocol.mjs";
import { createService } from "./service.mjs";
const seed = await readFile(
  process.env.BSN_KEY_FILE || "/etc/bsn-np/signing.key",
);
if (seed.length !== 32) throw Error("Expected 32-byte signing seed");
const key = privateKey(seed);
seed.fill(0);
async function fetchAccount(account) {
  const r = await fetch("https://horizon.stellar.org/accounts/" + account, {
    signal: AbortSignal.timeout(8000),
    redirect: "error",
  });
  if (r.status === 404) throw new Fault("account_not_found", 404);
  if (!r.ok) throw new Fault("stellar_unavailable", 503);
  const chunks = [];
  let n = 0;
  for await (const c of r.body) {
    n += c.length;
    if (n > 262144) throw new Fault("stellar_response_too_large", 502);
    chunks.push(c);
  }
  const a = JSON.parse(Buffer.concat(chunks).toString());
  if (a.account_id !== account || !a.data)
    throw new Fault("invalid_stellar_response", 502);
  return a.data;
}
const service = await createService({
  key,
  file: process.env.BSN_DB_FILE || "/var/lib/bsn-np/records.json",
  fetchAccount,
});
const { createAuthSite } = await import("./auth.mjs");
const authSite = await createAuthSite(
  service,
  process.env.BSN_AUTH_DIR || "/var/lib/bsn-np",
);
const origins = new Set([
  "https://onym.predhit.com",
  "https://atlas.predhit.com",
]);
const allowed = new Set([
  "configuration-status",
  "preview",
  "resolve-subject",
  "resolve-name",
  "request-issuance",
  "renew-record",
  "accept-record",
  "disavow-record",
  "revoke-record",
]);
const rates = new Map();
const server = http.createServer(async (req, res) => {
  if (authSite(req, res)) return;
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  const origin = req.headers.origin;
  if (origin) {
    if (!origins.has(origin)) {
      res.writeHead(403);
      res.end('{"error":"origin_not_allowed"}');
      return;
    }
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  try {
    const ip = req.headers["x-real-ip"] || req.socket.remoteAddress,
      now = Date.now();
    let rate = rates.get(ip);
    if (!rate || now - rate.t > 60000) {
      rate = { t: now, n: 0 };
      rates.set(ip, rate);
    }
    if (++rate.n > 120) throw new Fault("rate_limited", 429);
    const path = new URL(req.url, "http://localhost").pathname.replace(
      /^\/bsn-np\//,
      "",
    );
    if (req.method === "GET") {
      if (
        path === "manifest.json" ||
        path === "profile.json" ||
        path === "policy.json"
      ) {
        res.end(JSON.stringify(service[path.split(".")[0]]));
        return;
      }
      if (path === "health") {
        res.end('{"status":"ok"}');
        return;
      }
      if (path === "guide") {
        res.writeHead(308, { Location: "/bsn-np/guide/" });
        res.end();
        return;
      }
      if (path === "guide/") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader(
          "Content-Security-Policy",
          "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        );
        res.end(await readFile(new URL("./guide.html", import.meta.url)));
        return;
      }
      if (path === "protocol.md") {
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end(await readFile(new URL("./protocol.md", import.meta.url)));
        return;
      }
      if (path === "") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader(
          "Content-Security-Policy",
          "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        );
        res.end(
          `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>BSN Naming Provider</title><style>body{max-width:760px;margin:10vh auto;padding:24px;background:#f4f7fa;color:#172435;font:18px/1.65 system-ui}h1{font-size:42px}a{color:#205de7}code{overflow-wrap:anywhere}li{margin:14px 0}</style><h1>Ваше имя из BSN — в Onym</h1><p><a href="account">Войти через Onym и настроить имя →</a></p><p>Провайдер читает тег <code>Name</code> вашего Stellar-аккаунта и выдаёт подписанную запись имени для идентичности Onym.</p><p><a href="guide/">Как связать имя из BSN с Onym и показать его в чатах — по шагам, с примерами API →</a></p><ol><li>Откройте «Моя идентичность → Имя из BSN» в <a href="https://onym.predhit.com/">Onym Web</a>.</li><li>Введите свой Stellar-адрес. Если нужна связь, добавьте тег <code>OwnershipFull</code> (или свободный номер) со значением, которое покажет клиент.</li><li>Проверьте имя и подтвердите публикацию связи. Запрос подписывается внутри вашего браузера.</li></ol><p>Изменить имя можно только в Stellar. Одинаковые имена допустимы: аккаунт и источник остаются видны. Провайдер не получает приватных ключей.</p><p><a href="manifest.json">Манифест</a> · <a href="profile.json">Профиль</a> · <a href="policy.json">Политика</a> · <a href="protocol.md">Протокол API</a></p></html>`,
        );
        return;
      }
      throw new Fault("not_found", 404);
    }
    const op = path.startsWith("v1/") ? path.slice(3) : "";
    if (req.method !== "POST" || !allowed.has(op))
      throw new Fault("not_found", 404);
    const chunks = [];
    let n = 0;
    for await (const c of req) {
      n += c.length;
      if (n > 16384) throw new Fault("request_too_large", 413);
      chunks.push(c);
    }
    let b;
    try {
      b = JSON.parse(Buffer.concat(chunks).toString());
    } catch {
      throw new Fault("invalid_json");
    }
    if (!b || Array.isArray(b) || typeof b !== "object")
      throw new Fault("invalid_json");
    res.end(JSON.stringify(await service.call(op, b)));
  } catch (e) {
    res.writeHead(e instanceof Fault ? e.status : 503);
    res.end(
      JSON.stringify({
        error: e instanceof Fault ? e.code : "service_unavailable",
        ...(e instanceof Fault ? e.detail : {}),
      }),
    );
  }
});
setInterval(() => {
  for (const [k, v] of rates) if (Date.now() - v.t > 60000) rates.delete(k);
}, 60000).unref();
server.listen(Number(process.env.PORT || 4181), "127.0.0.1", () =>
  console.log("BSN naming provider listening on " + server.address().port),
);
