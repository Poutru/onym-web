import React, { useState } from "react";
import type { Client } from "./client";
import { nameOffer, NAMING_NS, NAMING_URL, type NameRecord } from "./naming";
import type { BindingTransaction } from "./stellarBinding";
import { hex } from "./bytes";
export function BSNName({
  client,
  run,
  busy,
}: {
  client: Client;
  run: (f: () => Promise<void>) => Promise<void>;
  busy: boolean;
}) {
  const [account, setAccount] = useState(client.state.naming?.account || "");
  const [offer, setOffer] = useState<NameRecord | null>(null);
  const [missing, setMissing] = useState<{
    name: string;
    tag: string;
    value: string;
  } | null>(null);
  const [transaction, setTransaction] = useState<BindingTransaction | null>(
    null,
  );
  async function prepare() {
    setTransaction(null);
    const { prepareBindingTransaction } = await import("./stellarBinding");
    const result = await prepareBindingTransaction(
      account.trim(),
      client.identity.stellarAccount,
    );
    if (client.live) setTransaction(result);
  }
  async function check() {
    setOffer(null);
    setMissing(null);
    setTransaction(null);
    const result = await nameOffer(account.trim(), client.identity);
    if (!client.live) return;
    if (result.missing) {
      setMissing(result);
      await prepare();
    } else setOffer(result.record);
  }
  function downloadXdr() {
    if (!transaction) return;
    const url = URL.createObjectURL(
      new Blob([transaction.xdr], { type: "text/plain" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "bsn-onym-link-unsigned.xdr";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const active = client.nameFor(hex(client.identity.signingPublic));
  return (
    <section className="card bsn-panel">
      <h2>Имя из BSN</h2>
      <p>
        Используйте имя из тега <code>Name</code> вашего Stellar-аккаунта.
      </p>
      {active ? (
        <p className="bsn-active">
          <strong>{active.displayName}</strong>
          <br />
          <small>
            @{NAMING_NS} · {active.stellarAccount.slice(0, 6)}…
            {active.stellarAccount.slice(-6)}
          </small>
        </p>
      ) : client.state.naming?.record ? (
        <p className="fine">
          Сейчас имя BSN не подтверждено или его отображение отключено.
          Используется локальное имя. Проверьте связь и срок записи.
        </p>
      ) : null}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run(check);
        }}
      >
        <label>
          Stellar-адрес BSN
          <input
            disabled={busy}
            value={account}
            onChange={(e) => {
              setAccount(e.target.value);
              setOffer(null);
              setMissing(null);
              setTransaction(null);
            }}
            placeholder="GCPJUXPETZEIJNEAAEO2LGZIA6IQNNWGOHPNP4ZQECDS6IKKIGJO5LFV"
            maxLength={56}
            required
            spellCheck={false}
          />
        </label>
        <p className="fine">
          «Проверить имя» передаст провайдеру этот адрес и ваш публичный ключ
          Onym. Запрос будет подписан в браузере; связь ещё не публикуется.
        </p>
        <button className="secondary" disabled={busy}>
          Проверить имя
        </button>
        <button
          type="button"
          className="secondary"
          disabled={busy || !account.trim() || !!active}
          onClick={() =>
            void run(async () => {
              setOffer(null);
              setMissing({
                name: "",
                tag: "OwnershipFull",
                value: client.identity.stellarAccount,
              });
              await prepare();
            })
          }
        >
          Создать транзакцию привязки
        </button>
      </form>
      {missing && (
        <div className="bsn-help">
          <h3>
            {missing.name
              ? "Найдено имя: " + missing.name
              : "Привязка аккаунта BSN"}
          </h3>
          <p>
            Готовая транзакция добавит один свободный тег связи. Подпишите и
            отправьте её кошельком этого Stellar-аккаунта.
          </p>
          {transaction && (
            <>
              <p>
                <strong>{transaction.tag}</strong>
                <br />
                <code className="pre">{transaction.target}</code>
              </p>
              <p className="fine">
                Основная сеть Stellar. Комиссия: {transaction.feeXlm} XLM.
                Дополнительный резерв под тег: {transaction.reserveXlm} XLM.
                Существующие теги не меняются.
              </p>
              <label>
                Готовая транзакция XDR
                <textarea
                  readOnly
                  value={transaction.xdr}
                  rows={4}
                  spellCheck={false}
                />
              </label>
              <div className="actions">
                <button
                  className="secondary"
                  disabled={busy || transaction.expiresAt <= Date.now()}
                  onClick={() =>
                    void run(async () => {
                      await navigator.clipboard.writeText(transaction.xdr);
                    })
                  }
                >
                  Скопировать XDR
                </button>
                <button
                  className="secondary"
                  disabled={transaction.expiresAt <= Date.now()}
                  onClick={downloadXdr}
                >
                  Скачать XDR
                </button>
              </div>
              {transaction.expiresAt > Date.now() ? (
                <p>
                  <a href={transaction.uri}>Открыть в Stellar-кошельке ↗</a>
                </p>
              ) : (
                <p role="alert">Срок транзакции истёк. Сформируйте новую.</p>
              )}
              <p className="fine">
                Действует до{" "}
                {new Date(transaction.expiresAt).toLocaleTimeString("ru")}.
                Открытие по ссылке требует кошелька с поддержкой SEP-7. В другом
                кошельке импортируйте XDR. Если за это время отправили другую
                транзакцию с этого аккаунта, сформируйте новую.
              </p>
            </>
          )}
          <button
            className="secondary"
            disabled={busy}
            onClick={() => void run(prepare)}
          >
            {transaction ? "Сформировать заново" : "Сформировать транзакцию"}
          </button>
          <button disabled={busy} onClick={() => void run(check)}>
            Я отправил — проверить связь
          </button>
          <details>
            <summary>Добавить тег вручную</summary>
            <p>
              Создайте свободный OwnershipFullN со значением{" "}
              <code>{missing.value}</code>.
            </p>
            <a href="https://eurmtl.me/bsn" target="_blank" rel="noreferrer">
              Открыть редактор BSN ↗
            </a>
          </details>
        </div>
      )}
      {offer && (
        <div className="bsn-help">
          <h3>{offer.displayName}</h3>
          <p>@{NAMING_NS}</p>
          <p className="fine">
            Действует до {new Date(offer.expiresAt).toLocaleDateString("ru")}.
            Вы подтверждаете именно это имя. При изменении тега потребуется
            новое подтверждение.
          </p>
          <p>
            Приняв имя, вы публично связываете этот Stellar-аккаунт с вашим
            ключом Onym. Другие клиенты смогут проверить связь. BSN-провайдер
            также будет получать публичные ключи участников открытого чата для
            проверки их имён.
          </p>
          <button
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await client.useName(offer);
                if (client.live) {
                  setOffer(null);
                  setMissing(null);
                }
              })
            }
          >
            Принять имя и опубликовать связь
          </button>
        </div>
      )}
      <label className="check">
        <input
          type="checkbox"
          checked={!!client.state.naming?.enabled}
          disabled={busy}
          onChange={(e) =>
            void run(() => client.toggleNaming(e.target.checked))
          }
        />
        Показывать проверенные имена BSN
      </label>
      <p className="fine">
        Для проверки провайдер получает публичные ключи участников открытого
        чата (до 20 за обновление). При отключении проверок отображаются
        локальные имена. Подписи и актуальность записей проверяются отдельно от
        доставки сообщений.
      </p>
      {client.state.naming?.record && (
        <button
          className="secondary"
          disabled={busy}
          onClick={() => void run(() => client.removeName())}
        >
          Отозвать привязку имени
        </button>
      )}
      <p className="fine">
        <a href={NAMING_URL} target="_blank" rel="noreferrer">
          BSN Naming Provider ↗
        </a>{" "}
        · Основная сеть Stellar
      </p>
    </section>
  );
}
