import { it, expect } from "vitest";
import {
  TransactionBuilder,
  Networks,
  Transaction,
} from "@stellar/stellar-sdk/base";
import { buildBindingTransaction } from "../src/stellarBinding";
const account = "GCPJUXPETZEIJNEAAEO2LGZIA6IQNNWGOHPNP4ZQECDS6IKKIGJO5LFV";
const target = "GB5DHQE43N7VD7TSHJAAHUXSQJZM3XEPULHT25FDOSS7F3TPWH6NYJ7A";
const source = {
  account_id: account,
  sequence: "123456",
  data: {
    OwnershipFull: btoa(account),
    OwnershipFull1: btoa(account),
    OwnershipFull2: btoa(account),
    Name: btoa("Valerij Utrosin"),
  },
};
it("creates one unsigned mainnet ManageData, preserving existing tags and incrementing current sequence", () => {
  const result = buildBindingTransaction(
    source,
    target,
    100,
    5000000,
    1800000000000,
  );
  const tx = TransactionBuilder.fromXDR(
    result.xdr,
    Networks.PUBLIC,
  ) as Transaction;
  expect(tx.source).toBe(account);
  expect(tx.sequence).toBe("123457");
  expect(tx.signatures).toHaveLength(0);
  expect(tx.operations).toHaveLength(1);
  expect(tx.fee).toBe("100");
  expect(tx.memo.type).toBe("none");
  expect(tx.timeBounds?.maxTime).toBe("1800000900");
  const op = tx.operations[0];
  expect(op.type).toBe("manageData");
  if (op.type !== "manageData") throw Error("unexpected");
  expect(op.name).toBe("OwnershipFull3");
  expect(new TextDecoder().decode(op.value!)).toBe(target);
  expect(op.source).toBeUndefined();
  expect(source.sequence).toBe("123456");
  expect(Object.keys(source.data)).toHaveLength(4);
  const uri = new URL(result.uri);
  expect(uri.protocol).toBe("web+stellar:");
  expect(uri.pathname).toBe("tx");
  expect(uri.searchParams.get("xdr")).toBe(result.xdr);
  expect(uri.searchParams.get("network_passphrase")).toBe(Networks.PUBLIC);
  expect(uri.searchParams.has("callback")).toBe(false);
});
it("uses the first free tag, refuses duplicates, invalid addresses and excessive fees", () => {
  expect(
    buildBindingTransaction({ ...source, data: {} }, target, 100, 5000000).tag,
  ).toBe("OwnershipFull");
  expect(() =>
    buildBindingTransaction(
      { ...source, data: { OwnershipFull9: btoa(target) } },
      target,
      100,
      5000000,
    ),
  ).toThrow("уже есть");
  expect(() =>
    buildBindingTransaction(source, target.slice(0, -1) + "B", 100, 5000000),
  ).toThrow("адрес");
  expect(() =>
    buildBindingTransaction(source, target, 100001, 5000000),
  ).toThrow("комиссию");
});
