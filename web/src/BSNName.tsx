import React, { useState } from "react";
import type { Client } from "./client";
import { nameOffer, NAMING_NS, NAMING_URL, type NameRecord } from "./naming";
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
          setOffer(null);
          setMissing(null);
          void run(async () => {
            const result = await nameOffer(account.trim(), client.identity);
            if (!client.live) return;
            if (result.missing) setMissing(result);
            else setOffer(result.record);
          });
        }}
      >
        <label>
          Stellar-адрес BSN
          <input
            value={account}
            onChange={(e) => {
              setAccount(e.target.value);
              setOffer(null);
              setMissing(null);
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
      </form>
      {missing && (
        <div className="bsn-help">
          <h3>Найдено имя: {missing.name}</h3>
          <p>
            Добавьте в этом Stellar-аккаунте тег <code>OwnershipFull</code>.
            Если он занят, используйте свободный номер:{" "}
            <code>OwnershipFull3</code>, <code>OwnershipFull4</code> и т. д.
            Существующие теги сохраняйте.
          </p>
          <label>
            Значение тега — адрес вашей идентичности Onym
            <code className="pre">{missing.value}</code>
          </label>
          <button
            className="secondary"
            onClick={() =>
              void run(async () => {
                await navigator.clipboard.writeText(missing.value);
              })
            }
          >
            Скопировать значение
          </button>
          <p>
            <a href="https://eurmtl.me/bsn" target="_blank" rel="noreferrer">
              Открыть редактор BSN ↗
            </a>
          </p>
          <p className="fine">
            Изменение подтверждается вашим Stellar-кошельком. После сохранения
            снова нажмите «Проверить имя».
          </p>
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
