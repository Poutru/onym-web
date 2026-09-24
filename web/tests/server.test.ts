import { beforeAll, afterAll, it, expect } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";

let child: ChildProcess;
let base: string;
beforeAll(async () => {
  child = spawn(process.execPath, ["server/index.mjs"], {
    cwd: fileURLToPath(new URL("../", import.meta.url)),
    env: { ...process.env, HOST: "127.0.0.1", PORT: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  base = await new Promise<string>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(Error(`Server exited: ${code}`)));
    child.stdout!.on("data", (chunk) => {
      const match = String(chunk).match(/listening on port (\d+)/);
      if (match) resolve(`http://127.0.0.1:${match[1]}`);
    });
  });
});
afterAll(async () => {
  if (child && child.exitCode === null) {
    const exited = new Promise<void>((resolve) =>
      child.once("exit", () => resolve()),
    );
    child.kill();
    await exited;
  }
});
it("serves the production HTML and its hashed JavaScript with security headers", async () => {
  const res = await fetch(base);
  expect(res.status).toBe(200);
  expect(res.headers.get("content-security-policy")).toContain(
    "frame-ancestors 'none'",
  );
  const html = await res.text();
  expect(html).toContain('id="root"');
  const asset = html.match(/src="((?:\/preview)?\/assets\/[^" ]+\.js)"/)?.[1];
  expect(asset).toBeTruthy();
  const js = await fetch(base + asset!.replace(/^\/preview/, ""));
  expect(js.status).toBe(200);
  expect(js.headers.get("content-type")).toContain("javascript");
  expect((await js.text()).length).toBeGreaterThan(1000);
});
it("rejects chain writes and malformed JSON without forwarding them", async () => {
  expect((await fetch(base + "/api/chain")).status).toBe(405);
  for (const body of ['{"function":"transfer"}', "null", "{bad"]) {
    const res = await fetch(base + "/api/chain", { method: "POST", body });
    expect(res.status).toBe(400);
  }
  const crossOrigin = await fetch(base + "/api/chain", {
    method: "POST",
    headers: { Origin: "https://unrelated.example" },
    body: "{}",
  });
  expect(crossOrigin.status).toBe(403);
});
it("refuses arbitrary URLs in the public service document proxy", async () => {
  const r = await fetch(
    base +
      "/api/service-document?url=" +
      encodeURIComponent("http://127.0.0.1/secret"),
  );
  expect(r.status).toBe(400);
  const credentials = await fetch(
    base +
      "/api/service-document?url=" +
      encodeURIComponent("https://evil.example/manifest.json"),
  );
  expect(credentials.status).toBe(400);
});
