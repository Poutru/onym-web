import {
  Account,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
} from "@stellar/stellar-sdk/base";
import { z } from "zod";
import { limitedJson } from "./transport";
const sourceSchema = z.object({
  account_id: z.string(),
  sequence: z.string().regex(/^\d+$/),
  data: z.record(z.string(), z.string()),
});
export function buildBindingTransaction(
  source: z.infer<typeof sourceSchema>,
  target: string,
  fee: number,
  reserve: number,
  now = Date.now(),
) {
  if (
    !StrKey.isValidEd25519PublicKey(source.account_id) ||
    !StrKey.isValidEd25519PublicKey(target)
  )
    throw Error("Неверный Stellar-адрес");
  if (
    !Number.isSafeInteger(fee) ||
    fee < 100 ||
    fee > 100000 ||
    !Number.isSafeInteger(reserve) ||
    reserve < 0
  )
    throw Error(
      "Не удалось определить безопасную комиссию сети. Повторите позже.",
    );
  for (const [key, value] of Object.entries(source.data))
    if (/^OwnershipFull\d*$/.test(key) && atob(value) === target)
      throw Error("Связь уже есть в Stellar. Нажмите «Проверить имя».");
  let tag = "OwnershipFull";
  for (let i = 1; Object.hasOwn(source.data, tag); i++) {
    if (i > 1000) throw Error("Не найден свободный тег связи");
    tag = "OwnershipFull" + i;
  }
  const expiresAt = Math.floor(now / 1000) + 900;
  const tx = new TransactionBuilder(
    new Account(source.account_id, source.sequence),
    {
      fee: String(fee),
      networkPassphrase: Networks.PUBLIC,
      timebounds: { minTime: 0, maxTime: expiresAt },
    },
  )
    .addOperation(Operation.manageData({ name: tag, value: target }))
    .build();
  const xdr = tx.toXDR();
  const uri =
    "web+stellar:tx?xdr=" +
    encodeURIComponent(xdr) +
    "&network_passphrase=" +
    encodeURIComponent(Networks.PUBLIC) +
    "&msg=" +
    encodeURIComponent("Link BSN name to Onym identity");
  return {
    xdr,
    uri,
    tag,
    target,
    account: source.account_id,
    expiresAt: expiresAt * 1000,
    feeXlm: (fee / 1e7).toFixed(7),
    reserveXlm: (reserve / 1e7).toFixed(7),
  };
}
export type BindingTransaction = ReturnType<typeof buildBindingTransaction>;
export async function prepareBindingTransaction(
  account: string,
  target: string,
) {
  if (!StrKey.isValidEd25519PublicKey(account))
    throw Error("Проверьте Stellar-адрес");
  const [raw, fees, ledger] = await Promise.all([
    limitedJson("https://horizon.stellar.org/accounts/" + account),
    limitedJson("https://horizon.stellar.org/fee_stats"),
    limitedJson("https://horizon.stellar.org/ledgers?order=desc&limit=1"),
  ]);
  const source = sourceSchema.parse(raw);
  if (source.account_id !== account)
    throw Error("Stellar вернул другой аккаунт");
  const f = z
    .object({
      last_ledger_base_fee: z.string(),
      fee_charged: z.object({ p90: z.string() }),
    })
    .parse(fees);
  const l = z
    .object({
      _embedded: z.object({
        records: z
          .array(
            z.object({
              base_reserve_in_stroops: z.number().int().nonnegative(),
            }),
          )
          .min(1),
      }),
    })
    .parse(ledger);
  return buildBindingTransaction(
    source,
    target,
    Math.max(Number(f.last_ledger_base_fee), Number(f.fee_charged.p90)),
    l._embedded.records[0].base_reserve_in_stroops,
  );
}
