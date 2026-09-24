import express from "express";
import Provider from "oidc-provider";
import * as oidc from "openid-client";
import {
  SignJWT,
  jwtVerify,
  importJWK,
  exportJWK,
  generateKeyPair,
} from "jose";
import { randomBytes, createHash, createHmac } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  Account,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";
import { BASE, stellarAddress, validAccount } from "./protocol.mjs";
export const ISSUER = "https://atlas.predhit.com/auth";
export const SCOPE = "urn:onym:scope:signing-key";
export const CLAIM = "urn:onym:claim:signing-key";
const CALLBACK = BASE + "account/callback";
const CLIENT = "atlas-bsn";
const WEB = "https://onym.predhit.com/preview/";
const rnd = () => randomBytes(32).toString("base64url");
const hash = (s) => createHash("sha256").update(s).digest("base64url");
const esc = (s) =>
  String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const page = (title, body) =>
  `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><script src="/bsn-np/account-ui.js" defer></script><style>body{max-width:780px;margin:4vh auto;padding:24px;background:#f5f7fb;color:#172435;font:17px/1.65 system-ui}a{color:#195be8}h1{line-height:1.15}button,.button{display:inline-block;padding:12px 20px;background:#195be8;color:white;border:0;border-radius:10px;font:inherit;text-decoration:none;cursor:pointer}input,textarea{box-sizing:border-box;width:100%;padding:12px;font:inherit;margin:10px 0;border:1px solid #aab8cd;border-radius:8px}code{overflow-wrap:anywhere}article{background:white;border:1px solid #dce2ed;border-radius:16px;padding:22px;margin:20px 0}small{color:#56677d}</style><a href="/bsn-np/">← BSN provider</a><h1>${esc(title)}</h1>${body}</html>`;
export function verifyProofFields(
  p,
  h,
  request,
  compact,
  now = Math.floor(Date.now() / 1000),
) {
  const pub = h.jwk?.x && Buffer.from(h.jwk.x, "base64url");
  if (
    h.typ !== "onym-auth-proof+jwt" ||
    h.alg !== "EdDSA" ||
    h.jwk?.kty !== "OKP" ||
    h.jwk?.crv !== "Ed25519" ||
    h.jwk.d ||
    pub?.length !== 32
  )
    throw Error("invalid_key");
  const subject = "onym:key:" + pub.toString("hex");
  if (
    p.iss !== subject ||
    p.sub !== subject ||
    p.aud !== ISSUER ||
    p.client_id !== CLIENT ||
    p.request_id !== request.request_id ||
    p.request_hash !== hash(compact) ||
    p.challenge !== request.challenge ||
    !["approve", "deny"].includes(p.decision) ||
    !Number.isInteger(p.iat) ||
    p.iat > now + 30 ||
    p.iat < now - 120 ||
    !Number.isInteger(p.exp) ||
    p.exp <= now ||
    p.exp > request.exp ||
    p.exp > p.iat + 90 ||
    !/^[-\w]{20,100}$/.test(p.jti)
  )
    throw Error("invalid_proof");
  return subject;
}
export async function createAuthSite(service, directory = "/var/lib/bsn-np") {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  let keys;
  const keyfile = directory + "/auth-keys.json";
  try {
    keys = JSON.parse(await readFile(keyfile, "utf8"));
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    const a = await generateKeyPair("ES256", { extractable: true }),
      b = await generateKeyPair("ES256", { extractable: true });
    keys = {
      op: {
        ...(await exportJWK(a.privateKey)),
        kid: rnd(),
        use: "sig",
        alg: "ES256",
      },
      rp: {
        ...(await exportJWK(b.privateKey)),
        kid: rnd(),
        use: "sig",
        alg: "ES256",
      },
      cookie: rnd(),
      pairwise: rnd(),
    };
    await writeFile(keyfile, JSON.stringify(keys), { mode: 0o600, flag: "wx" });
  }
  const opKey = await importJWK(keys.op, "ES256"),
    rpKey = await importJWK(keys.rp, "ES256");
  const { d: unused, ...rpPublic } = keys.rp;
  const db = new DatabaseSync(directory + "/auth.sqlite");
  db.exec(
    "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS auth (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires INTEGER NOT NULL);",
  );
  const get = (k) => {
    const r = db
      .prepare("SELECT value FROM auth WHERE key=? AND expires>?")
      .get(k, Date.now());
    return r ? JSON.parse(r.value) : undefined;
  };
  const put = (k, v, secs) =>
    db
      .prepare("INSERT OR REPLACE INTO auth VALUES (?,?,?)")
      .run(k, JSON.stringify(v), Date.now() + secs * 1000);
  const del = (k) => db.prepare("DELETE FROM auth WHERE key=?").run(k);
  class Adapter {
    constructor(name) {
      this.name = name;
    }
    async upsert(id, payload, ttl) {
      put(this.name + ":" + id, payload, ttl || 3600);
    }
    async find(id) {
      return get(this.name + ":" + id);
    }
    async destroy(id) {
      del(this.name + ":" + id);
    }
    async consume(id) {
      const result = db.prepare("UPDATE auth SET value=json_set(value,'$.consumed',?) WHERE key=? AND expires>? AND json_extract(value,'$.consumed') IS NULL").run(Math.floor(Date.now()/1000),this.name+":"+id,Date.now());
      if (result.changes !== 1) throw new Error("token_already_consumed");
    }
    async findByUid(uid) {
      return this.lookup("uid", uid);
    }
    async findByUserCode(code) {
      return this.lookup("userCode", code);
    }
    lookup(field, value) {
      for (const r of db
        .prepare("SELECT value FROM auth WHERE key LIKE ? AND expires>?")
        .all(this.name + ":%", Date.now())) {
        const p = JSON.parse(r.value);
        if (p[field] === value) return p;
      }
    }
    async revokeByGrantId(id) {
      for (const r of db
        .prepare("SELECT key,value FROM auth WHERE expires>?")
        .all(Date.now()))
        if (JSON.parse(r.value).grantId === id) del(r.key);
    }
  }
  const provider = new Provider(ISSUER, {
    adapter: Adapter,
    jwks: { keys: [keys.op] },
    cookies: {
      keys: [keys.cookie],
      long: { secure: true, sameSite: "lax" },
      short: { secure: true, sameSite: "lax" },
    },
    clients: [
      {
        client_id: CLIENT,
        client_name: "BSN Naming Provider",
        redirect_uris: [CALLBACK],
        initiate_login_uri: BASE + "login",
        response_types: ["code"],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [rpPublic] },
        id_token_signed_response_alg: "ES256",
        subject_type: "pairwise",
      },
    ],
    subjectTypes: ["pairwise"],
    pairwiseIdentifier: async (ctx, accountId, client) =>
      createHmac("sha256", keys.pairwise)
        .update(client.clientId + "\0" + accountId)
        .digest("hex"),
    claims: { openid: ["sub"], [SCOPE]: [CLAIM] },
    scopes: ["openid", SCOPE],
    findAccount: async (ctx, id) => ({
      accountId: id,
      claims: async () => ({ sub: id, [CLAIM]: id }),
    }),
    pkce: { required: () => true },
    features: {
      claimsParameter: { enabled: true },
      devInteractions: { enabled: false },
      pushedAuthorizationRequests: {
        enabled: true,
        requirePushedAuthorizationRequests: true,
      },
    },
    interactions: { url: (ctx, i) => "/auth/interaction/" + i.uid },
    ttl: {
      AccessToken: 300,
      IdToken: 300,
      AuthorizationCode: 60,
      Interaction: 300,
      Session: 3600,
      Grant: 3600,
    },
  });
  provider.proxy = true;
  const rates = new Map();
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", "loopback");
  app.use((req, res, next) => {
    const ip = req.headers["x-real-ip"] || req.socket.remoteAddress,
      now = Date.now();
    let rate = rates.get(ip);
    if (!rate || now - rate.time > 60000) {
      rate = { time: now, count: 0 };
      rates.set(ip, rate);
    }
    if (++rate.count > 180)
      return res.status(429).json({ error: "rate_limited" });
    res.set({
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy":
        "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    });
    if (req.headers.origin) {
      if (
        req.headers.origin !== "https://onym.predhit.com" &&
        req.headers.origin !== "https://atlas.predhit.com"
      )
        return res.status(403).json({ error: "origin_not_allowed" });
      res.set({
        "Access-Control-Allow-Origin": req.headers.origin,
        Vary: "Origin",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      });
    }
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
  app.get("/bsn-np/account-ui.js", async (req, res) => {
    res
      .type("application/javascript")
      .send(
        await readFile(new URL("./account-ui.js", import.meta.url), "utf8"),
      );
  });
  const json = express.json({ limit: "16kb" }),
    form = express.urlencoded({ extended: false, limit: "16kb" });
  const cookie = (req, name) =>
    req.headers.cookie
      ?.split(";")
      .map((s) => s.trim())
      .find((s) => s.startsWith(name + "="))
      ?.slice(name.length + 1);
  const setcookie = (res, name, value, maxAge = 3600000) =>
    res.cookie(name, value, {
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      path: "/bsn-np/",
      maxAge,
    });
  const session = (req) => get("site:" + cookie(req, "bsn_session"));
  const csrf = (req, s) => {
    if (
      !s ||
      req.headers.origin !== "https://atlas.predhit.com" ||
      req.body.csrf !== s.csrf
    )
      throw Error("csrf");
  };
  let config;
  async function rp() {
    return (config ||= await oidc.discovery(
      new URL(ISSUER),
      CLIENT,
      {
        token_endpoint_auth_method: "private_key_jwt",
        id_token_signed_response_alg: "ES256",
      },
      oidc.PrivateKeyJwt(rpKey),
    ));
  }
  app.get("/bsn-np/login", async (req, res) => {
    if (req.query.iss && req.query.iss !== ISSUER) throw Error("issuer");
    if (
      req.query.target_link_uri &&
      req.query.target_link_uri !== BASE + "account"
    )
      throw Error("target");
    const tx = {
        state: oidc.randomState(),
        nonce: oidc.randomNonce(),
        verifier: oidc.randomPKCECodeVerifier(),
      },
      id = rnd();
    const url = await oidc.buildAuthorizationUrlWithPAR(await rp(), {
      redirect_uri: CALLBACK,
      scope: "openid " + SCOPE,
      claims: JSON.stringify({ id_token: { [CLAIM]: { essential: true } } }),
      state: tx.state,
      nonce: tx.nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(tx.verifier),
      code_challenge_method: "S256",
      prompt: "login",
    });
    put("rp:" + id, tx, 300);
    setcookie(res, "bsn_login", id, 300000);
    res.redirect(url.href);
  });
  app.get("/bsn-np/account/callback", async (req, res) => {
    const id = cookie(req, "bsn_login"),
      tx = get("rp:" + id);
    if (!tx) throw Error("login_expired");
    del("rp:" + id);
    const tokens = await oidc.authorizationCodeGrant(
      await rp(),
      new URL(req.originalUrl, "https://atlas.predhit.com"),
      {
        pkceCodeVerifier: tx.verifier,
        expectedState: tx.state,
        expectedNonce: tx.nonce,
        idTokenExpected: true,
      },
    );
    const claims = tokens.claims();
    if (!/^onym:key:[a-f0-9]{64}$/.test(claims?.[CLAIM]))
      throw Error("missing_key");
    const sid = rnd();
    put(
      "site:" + sid,
      { subject: claims[CLAIM], sub: claims.sub, csrf: rnd() },
      3600,
    );
    setcookie(res, "bsn_session", sid);
    setcookie(res, "bsn_login", "", 0);
    res.redirect("/bsn-np/account");
  });
  app.get("/auth/interaction/:uid", async (req, res) => {
    const i = await provider.interactionDetails(req, res);
    if (i.uid !== req.params.uid || i.params.client_id !== CLIENT)
      throw Error("interaction");
    let reqId = get("interaction:" + i.uid);
    if (!reqId || !get("challenge:" + reqId)) {
      reqId = rnd();
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: ISSUER,
        aud: "urn:onym:authenticator",
        request_id: reqId,
        client_id: CLIENT,
        rp_origin: "https://atlas.predhit.com",
        redirect_uri: CALLBACK,
        scope: i.params.scope,
        oidc_nonce: i.params.nonce,
        code_challenge: i.params.code_challenge,
        code_challenge_method: "S256",
        challenge: rnd(),
        interaction: "fresh-key-proof",
        resume_uri: ISSUER + "/interaction/" + i.uid,
        display_code: String(randomBytes(4).readUInt32BE() % 1000000).padStart(
          6,
          "0",
        ),
        iat: now,
        exp: now + 120,
      };
      const compact = await new SignJWT(payload)
        .setProtectedHeader({
          alg: "ES256",
          kid: keys.op.kid,
          typ: "onym-auth-request+jwt",
        })
        .sign(opKey);
      put("challenge:" + reqId, { payload, compact, uid: i.uid }, 120);
      put("interaction:" + i.uid, reqId, 120);
    }
    const c = get("challenge:" + reqId);
    if (c.result) return finishInteraction(req, res, i, reqId, c);
    res
      .type("html")
      .send(
        page(
          "Войти через Onym",
          `<p>Вход на <strong>atlas.predhit.com</strong> для настройки имени BSN.</p><p>Сравните код в Onym: <strong>${c.payload.display_code}</strong></p><p><a class="button" href="${WEB}#auth=${reqId}">Открыть Onym и подтвердить</a></p><p>Если Onym открыт в другой вкладке, скопируйте ссылку этой кнопки в поле «Вход на сайт» в разделе «Сервисы». После подтверждения вернитесь сюда.</p><form method="post" action="/auth/interaction/${esc(i.uid)}/finish"><input type="hidden" name="request_id" value="${reqId}"><button>Я подтвердил вход в Onym</button></form>`,
        ),
      );
  });
  app.get("/auth/onym-auth/requests/:id", (req, res) => {
    const c = get("challenge:" + req.params.id);
    if (!c) return res.status(410).json({ error: "request_expired" });
    res.json({ request: c.compact });
  });
  app.post("/auth/onym-auth/responses", json, async (req, res) => {
    const compact = req.body.proof;
    if (typeof compact !== "string" || compact.length > 16000)
      throw Error("invalid_proof");
    const { payload, protectedHeader } = await jwtVerify(
      compact,
      async (h) => {
        if (h.alg !== "EdDSA" || h.jwk?.d) throw Error("invalid_key");
        return importJWK(h.jwk, "EdDSA");
      },
      {
        algorithms: ["EdDSA"],
        issuer: undefined,
        audience: ISSUER,
        typ: "onym-auth-proof+jwt",
        clockTolerance: 0,
      },
    );
    const c = get("challenge:" + payload.request_id);
    if (!c || c.result) throw Error("expired_or_used");
    const subject = verifyProofFields(
      payload,
      protectedHeader,
      c.payload,
      c.compact,
    );
    // No await between replay check and consumption.
    const fresh = get("challenge:" + payload.request_id);
    if (!fresh || fresh.result) throw Error("replayed");
    c.result = { subject, decision: payload.decision };
    put(
      "challenge:" + payload.request_id,
      c,
      Math.max(1, c.payload.exp - Math.floor(Date.now() / 1000)),
    );
    res.status(204).end();
  });
  app.post("/auth/interaction/:uid/finish", form, async (req, res) => {
    if (req.headers.origin !== "https://atlas.predhit.com")
      throw Error("origin");
    const i = await provider.interactionDetails(req, res),
      id = get("interaction:" + i.uid),
      c = get("challenge:" + id);
    if (i.uid !== req.params.uid || id !== req.body.request_id || !c?.result)
      throw Error("not_approved");
    await finishInteraction(req, res, i, id, c);
  });
  async function finishInteraction(req, res, i, id, c) {
    del("challenge:" + id);
    del("interaction:" + i.uid);
    if (c.result.decision === "deny")
      return provider.interactionFinished(
        req,
        res,
        { error: "access_denied", error_description: "User declined" },
        { mergeWithLastSubmission: false },
      );
    const grant = new provider.Grant({
      accountId: c.result.subject,
      clientId: CLIENT,
    });
    grant.addOIDCScope(i.params.scope);
    grant.addOIDCClaims([CLAIM]);
    const grantId = await grant.save();
    await provider.interactionFinished(
      req,
      res,
      { login: { accountId: c.result.subject }, consent: { grantId } },
      { mergeWithLastSubmission: false },
    );
  }
  app.get("/bsn-np/account", async (req, res) => {
    const s = session(req);
    if (!s) return res.redirect("/bsn-np/login");
    const setup = await service.getSetup(s.subject);
    const t = esc(s.csrf);
    const active = await service.getAcceptedName(s.subject);
    if (active)
      return res.type("html").send(page(
        "Ваше имя BSN",
        `<h2>${esc(active.displayName)}</h2><p>Имя подключено и принято в Onym.</p><p>Stellar-аккаунт: <code>${esc(active.stellarAccount)}</code></p><p>Имя получено из тега <code>${esc(active.nameTag)}</code>, связь подтверждена тегом <code>${esc(active.bindingTag)}</code>.</p><p>Идентичность Onym: <code>${esc(s.subject)}</code></p><p>Запись действует до ${esc(new Date(active.expiresAt).toLocaleString("ru-RU", { timeZone: "UTC" }))} UTC.</p><p>Чтобы изменить само имя, измените тег имени в этом Stellar-аккаунте, затем проверьте и примите обновлённое имя в Onym. Другой адрес здесь указывать не требуется.</p><p><a class="button" href="${WEB}#services=return">Вернуться в Onym →</a></p><form method="post" action="/bsn-np/account/logout"><input type="hidden" name="csrf" value="${t}"><button>Выйти</button></form>`,
      ));
    res
      .type("html")
      .send(
        page(
          "Настройка имени BSN",
          `<p>Вы вошли с идентичностью <code>${esc(s.subject)}</code>.</p><p>Значение для тега связи Stellar: <code>${stellarAddress(s.subject.slice(9))}</code></p><form method="post" action="/bsn-np/account/save"><input type="hidden" name="csrf" value="${t}"><label>Ваш Stellar-адрес<input name="account" value="${esc(setup?.account || "")}" required pattern="G[A-Z2-7]{55}"></label><button>Сохранить и проверить</button></form><p><a href="${WEB}#services=return">Вернуться в Onym →</a></p><p>В Onym нажмите «Проверить имя», проверьте предложение и подтвердите его принятие.</p><form method="post" action="/bsn-np/account/logout"><input type="hidden" name="csrf" value="${t}"><button>Выйти</button></form>`,
        ),
      );
  });
  app.post("/bsn-np/account/save", form, async (req, res) => {
    const s = session(req);
    csrf(req, s);
    const account = req.body.account?.trim();
    if (!validAccount(account)) throw Error("invalid_stellar_account");
    await service.saveSetup(s.subject, account);
    let ev;
    try {
      ev = await service.call("preview", {
        subject: s.subject,
        stellarAccount: account,
      });
    } catch (e) {
      return res
        .type("html")
        .send(
          page(
            "Настройка сохранена",
            `<p>Проверка Stellar: ${esc(e.code || "временно недоступна")}. Исправьте данные аккаунта и повторите проверку.</p><a href="/bsn-np/account">К настройке</a>`,
          ),
        );
    }
    if (ev.eligible)
      return res
        .type("html")
        .send(
          page(
            "Имя готово",
            `<p>Ваше имя: <strong>${esc(ev.displayName)}</strong>.</p><p>Теперь вернитесь в клиент, запросите и примите подписанную запись.</p><a class="button" href="${WEB}#services=return">Вернуться в Onym</a>`,
          ),
        );
    const response = await fetch(
      "https://horizon.stellar.org/accounts/" + account,
      { signal: AbortSignal.timeout(8000), redirect: "error" },
    );
    if (!response.ok) throw Error("stellar_unavailable");
    const source = await response.json();
    if (source.account_id !== account || !/^\d+$/.test(source.sequence))
      throw Error("stellar_response");
    const target = stellarAddress(s.subject.slice(9));
    let tag = "OwnershipFull";
    for (let j = 1; Object.hasOwn(source.data, tag); j++) {
      if (j > 1000) throw Error("no_free_tag");
      tag = "OwnershipFull" + j;
    }
    const xdr = new TransactionBuilder(new Account(account, source.sequence), {
      fee: "1000",
      networkPassphrase: Networks.PUBLIC,
    })
      .addOperation(Operation.manageData({ name: tag, value: target }))
      .setTimeout(900)
      .build()
      .toXDR();
    const uri =
      "web+stellar:tx?xdr=" +
      encodeURIComponent(xdr) +
      "&network_passphrase=" +
      encodeURIComponent(Networks.PUBLIC);
    res
      .type("html")
      .send(
        page(
          "Подтвердите связь в Stellar",
          `<p>Настройка сохранена. Добавьте тег <code>${tag}</code> со значением <code>${target}</code>.</p><p>Подготовлена неподписанная транзакция основной сети Stellar на одну операцию manageData. Она не перезаписывает существующий тег. Максимальная комиссия — 0,0001 XLM; для нового тега потребуется дополнительный резерв сети. Срок — 15 минут.</p><textarea readonly rows="6">${esc(xdr)}</textarea><p><a class="button" href="${esc(uri)}">Открыть в Stellar-кошельке</a></p><p>Подпишите и отправьте транзакцию своим кошельком. Приватный ключ сюда вводить не нужно.</p><a href="/bsn-np/account">Проверить после отправки →</a><p><a href="${WEB}#services=return">Вернуться в Onym</a></p>`,
        ),
      );
  });
  app.post("/bsn-np/account/logout", form, (req, res) => {
    const s = session(req);
    csrf(req, s);
    del("site:" + cookie(req, "bsn_session"));
    setcookie(res, "bsn_session", "", 0);
    res.redirect("/bsn-np/");
  });
  app.get(["/auth", "/auth/"], (req, res) =>
    res
      .type("html")
      .send(
        page(
          "Вход через Onym",
          '<p>Сервер аутентификации OpenID Connect для сервисов Onym.</p><p><a href="/bsn-np/account">Настроить имя BSN</a> · <a href="/auth/.well-known/openid-configuration">OpenID configuration</a> · <a href="/onym-auth/">Описание протокола</a></p>',
        ),
      ),
  );
  app.use("/auth", provider.callback());
  app.use((err, req, res, next) => {
    if (process.env.NODE_ENV === "test") console.error(err);
    if (res.headersSent) return next(err);
    res
      .status(400)
      .type("html")
      .send(
        page(
          "Не удалось завершить действие",
          '<p>Запрос истёк, уже использован или не прошёл проверку. Начните вход заново.</p><a href="/bsn-np/account">Вернуться к настройке</a>',
        ),
      );
  });
  setInterval(() => {
    db.prepare("DELETE FROM auth WHERE expires<?").run(Date.now());
    for (const [ip, r] of rates)
      if (Date.now() - r.time > 60000) rates.delete(ip);
  }, 60000).unref();
  return (req, res) => {
    if (
      !/^(?:\/auth(?:\/|$)|\/bsn-np\/(?:account(?:\/|$)|account-ui\.js(?:\?|$)|login(?:\?|$)))/.test(
        req.url,
      )
    )
      return false;
    app(req, res);
    return true;
  };
}
