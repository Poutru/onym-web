import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, extname, sep } from "node:path";
const root = resolve(fileURLToPath(new URL("../dist/", import.meta.url)));
const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
};
const csp =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' https: wss:; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const limiter = new Map();
const server = http.createServer(async (req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", csp);
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/api/service-document") {
      const target = url.searchParams.get("url") || "";
      const allowed =
        /^(https:\/\/atlas\.predhit\.com\/(?:manifest\.json|catalogs\/public-services\.json|bsn-np\/manifest\.json|simple-backup\/(?:manifest\.json|terms\/[a-f0-9]{64}\.json))|https:\/\/(?:authority|relayer|backup)\.onym\.app\/manifest\.json|https:\/\/discovery\.onym\.app\/manifests\/(?:onym-courier|onym-blossom)\.json)$/;
      if (req.method !== "GET" || !allowed.test(target)) {
        res.writeHead(400);
        res.end('{"error":"unsupported_document"}');
        return;
      }
      const up = await fetch(target, {
        redirect: "error",
        signal: AbortSignal.timeout(10000),
      });
      if (!up.ok) {
        res.writeHead(502);
        res.end('{"error":"upstream_unavailable"}');
        return;
      }
      let length = 0;
      const parts = [];
      for await (const part of up.body) {
        length += part.length;
        if (length > 2000000) throw Error("document_too_large");
        parts.push(part);
      }
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(Buffer.concat(parts));
      return;
    }
    if (url.pathname === "/api/chain") {
      if (req.method !== "POST") {
        res.writeHead(405);
        res.end();
        return;
      }
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) {
        res.writeHead(403);
        res.end();
        return;
      }
      const ip = req.socket.remoteAddress,
        now = Date.now();
      let count = limiter.get(ip);
      if (!count || now - count.since > 60000) {
        count = { since: now, n: 0 };
        limiter.set(ip, count);
      }
      if (++count.n > 120) {
        res.writeHead(429);
        res.end();
        return;
      }
      let body = "";
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 4096) {
          res.writeHead(413);
          res.end();
          return;
        }
      }
      let b;
      try {
        b = JSON.parse(body);
      } catch {
        b = null;
      }
      if (
        !b ||
        typeof b !== "object" ||
        !/^C[A-Z2-7]{55}$/.test(b.contractID) ||
        b.contractType !== "tyranny" ||
        !["testnet", "public"].includes(b.network) ||
        !["get_commitment", "get_history"].includes(b.function) ||
        typeof b.payload?.group_id !== "string" ||
        !/^[A-Za-z0-9+/]{43}=$/.test(b.payload.group_id) ||
        Buffer.from(b.payload.group_id, "base64").length !== 32
      ) {
        res.writeHead(400);
        res.end('{"error":"invalid_read_request"}');
        return;
      }
      // Reconstruct only allowed fields: never proxy arbitrary methods, endpoints or credentials.
      const payload = {
        group_id: b.payload.group_id,
        ...(b.function === "get_history" ? { max_entries: 64 } : {}),
      };
      const upstream = await fetch("https://relayer.onym.app", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contractID: b.contractID,
          contractType: "tyranny",
          network: b.network,
          function: b.function,
          payload,
        }),
        redirect: "error",
        signal: AbortSignal.timeout(15000),
      });
      let bytes = 0;
      const chunks = [];
      for await (const chunk of upstream.body) {
        bytes += chunk.length;
        if (bytes > 2_000_000) throw Error("oversized");
        chunks.push(chunk);
      }
      res.writeHead(upstream.status, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(Buffer.concat(chunks));
      return;
    }
    if (!["GET", "HEAD"].includes(req.method)) {
      res.writeHead(405);
      res.end();
      return;
    }
    const path = resolve(root, "." + decodeURIComponent(url.pathname));
    if (path !== root && !path.startsWith(root + sep)) {
      res.writeHead(403);
      res.end();
      return;
    }
    let file = path;
    try {
      if ((await stat(file)).isDirectory()) file = resolve(file, "index.html");
    } catch {
      file = resolve(root, "index.html");
    }
    const content = await readFile(file);
    res.writeHead(200, {
      "Content-Type": types[extname(file)] || "application/octet-stream",
      "Cache-Control": file.includes(sep + "assets" + sep)
        ? "public, max-age=31536000, immutable"
        : "no-cache",
    });
    res.end(req.method === "HEAD" ? undefined : content);
  } catch {
    if (!res.headersSent)
      res.writeHead(502, { "Content-Type": "application/json" });
    res.end('{"error":"service_unavailable"}');
  }
});
setInterval(() => {
  for (const [key, value] of limiter)
    if (Date.now() - value.since > 60000) limiter.delete(key);
}, 60000).unref();
server.listen(
  Number(process.env.PORT || 4173),
  process.env.HOST || "127.0.0.1",
  () => console.log("Onym Web listening on port " + server.address().port),
);
