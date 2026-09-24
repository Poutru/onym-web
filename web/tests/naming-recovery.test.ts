import { it, expect, vi, afterEach } from "vitest";
import { Client } from "../src/client";
import { defaultSettings } from "../src/state";
import { hex } from "../src/bytes";
import { resolveName } from "../src/naming";
vi.mock("../src/naming", async (load) => ({
  ...await load<typeof import("../src/naming")>(),
  namingManifest: vi.fn(async () => ({ policy: "test" })),
  resolveName: vi.fn(),
}));
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });
function client() {
  return new Client({ version: 1, phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", name: "Local", groups: [], pending: [], settings: defaultSettings }, null, new Uint8Array(16), () => {}, () => {}, () => {});
}
it("restores a previously accepted name after seed import in preview", async () => {
  vi.stubEnv("BASE_URL", "/preview/");
  const c = client();
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  const record = { displayName: "Existing name", stellarAccount: "account", expiresAt, sequence: 3 };
  vi.mocked(resolveName).mockResolvedValue({ expiresAt, records: [{ status: "active", record, acceptance: { expiresAt } }] } as any);
  const save = vi.spyOn(c, "save").mockResolvedValue();
  await c.refreshNames();
  expect(c.displayName).toBe("Existing name");
  expect(c.state.naming).toMatchObject({ enabled: true, account: "account" });
  expect(c.nameFor(hex(c.identity.signingPublic))).toEqual(record);
  expect(save).toHaveBeenCalledOnce();
});
it("respects explicit disabling and does not enable default recovery in stable", async () => {
  vi.mocked(resolveName).mockClear();
  vi.stubEnv("BASE_URL", "/");
  await client().refreshNames();
  vi.stubEnv("BASE_URL", "/preview/");
  const c = client();
  c.state.naming = { enabled: false, account: "" };
  await c.refreshNames();
  expect(resolveName).not.toHaveBeenCalled();
});
