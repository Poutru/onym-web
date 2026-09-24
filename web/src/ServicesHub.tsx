import React, { useState, useEffect } from "react";
import type { Client } from "./client";
import {
  ATLAS,
  ATLAS_KEY,
  inspectSource,
  loadCatalog,
  type Service,
  documentAt,
  verifyDocument,
} from "./services";
import {
  configuredName,
  NAMING_URL,
  namingManifest,
  type NameRecord,
} from "./naming";
import { AUTH_ISSUER, loginRequest, answerLogin } from "./authentication";
import { hex } from "./bytes";
import { backupConnection } from "./remoteBackup";
import { readVault } from "./vault";
const roles: Record<string, string> = {
  "transport.message": "Реле сообщений",
  notary: "Реле контрактов",
  "storage.backup": "Резервное копирование",
  "naming.association": "Провайдер имён",
  "blob.storage": "Файлы",
  moderation: "Модерация",
};
export function LoginApproval({
  client,
  run,
  busy,
}: {
  client: Client;
  run: (f: () => Promise<void>) => Promise<void>;
  busy: boolean;
}) {
  const [id, setId] = useState(
      new URLSearchParams(location.hash.slice(1)).get("auth") || "",
    ),
    [req, setReq] = useState<Awaited<ReturnType<typeof loginRequest>>>(),
    [done, setDone] = useState(false);
  useEffect(() => {
    const changed = () => {
      setDone(false);
      setReq(undefined);
      setId(new URLSearchParams(location.hash.slice(1)).get("auth") || "");
    };
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  useEffect(() => {
    if (id) void run(async () => setReq(await loginRequest(id)));
  }, [id]);
  return (
    <details className="card" open={!!id}>
      <summary>Вход на сайт через Onym</summary>
      {!req ? (
        <>
          <p>Вставьте ссылку подтверждения со страницы входа.</p>
          <input
            aria-label="Ссылка входа"
            onChange={(e) => {
              try {
                const u = new URL(e.target.value);
                if (u.origin !== location.origin) throw Error();
                setId(new URLSearchParams(u.hash.slice(1)).get("auth") || "");
              } catch {}
            }}
          />
        </>
      ) : done ? (
        <>
          <p>Вход подтверждён. Продолжите на сайте провайдера.</p>
          <a className="button" href={String(req.payload.resume_uri)}>
            Продолжить вход на сайте BSN
          </a>
        </>
      ) : (
        <>
          <h4>Войти на atlas.predhit.com?</h4>
          <p>
            BSN получит публичный ключ выбранной идентичности, чтобы связать её
            со Stellar-аккаунтом. Это постоянный идентификатор, по которому сайт
            сможет сопоставить ваши данные.
          </p>
          <p>
            Идентичность: <strong>{client.state.name}</strong>
          </p>
          <code>{hex(client.identity.signingPublic)}</code>
          <p>
            Код на странице входа:{" "}
            <strong>{String(req.payload.display_code)}</strong>. Подтверждайте
            только начатый вами вход.
          </p>
          <div className="actions">
            <button
              disabled={busy}
              className="primary"
              onClick={() =>
                run(async () => {
                  await answerLogin(req, client.identity, true);
                  setDone(true);
                  history.replaceState(null, "", location.pathname);
                })
              }
            >
              Войти и передать публичный ключ
            </button>
            <button
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await answerLogin(req, client.identity, false);
                  setDone(true);
                })
              }
            >
              Отмена
            </button>
          </div>
        </>
      )}
    </details>
  );
}
export function Services({
  client,
  run,
  busy,
}: {
  client: Client;
  run: (f: () => Promise<void>) => Promise<void>;
  busy: boolean;
}) {
  const source = client.state.services?.source || {
    url: ATLAS,
    key: ATLAS_KEY,
  };
  const [url, setUrl] = useState(source.url),
    [items, setItems] = useState<Service[]>([]),
    [warnings, setWarnings] = useState<string[]>([]),
    [status, setStatus] = useState(""),
    [offer, setOffer] = useState<NameRecord>(),
    [snapshots, setSnapshots] = useState<any[]>([]);
  const selected = client.state.services?.selected || {};
  async function refresh() {
    const r = await loadCatalog(source);
    setItems(r.services);
    setWarnings(r.failures);
    client.state.services = {
      source: { ...source, sequence: r.sequence },
      selected,
    };
    await client.save();
  }
  async function checkName() {
    setOffer(undefined);
    const result = await configuredName(client.identity);
    if (result.state === "active") {
      await client.toggleNaming(true);
      setStatus("Уже принятое имя загружено: " + result.record!.displayName);
      return;
    }
    setStatus(
      result.state === "ready"
        ? "Имя проверено. Подтвердите принятие."
        : result.state === "pending"
          ? "Ожидается корректная связь и имя в Stellar."
          : "Сначала настройте имя на сайте.",
    );
    setOffer(result.record);
  }
  useEffect(() => {
    void run(async () => {
      await refresh();
      if (
        selected["naming.association"] &&
        (location.hash === "#services=return" || client.state.naming?.enabled !== false)
      ) {
        await checkName();
        history.replaceState(null, "", location.pathname);
      }
    });
  }, []);
  async function choose(s: Service) {
    const m = s.manifest;
    if (m.seat === "transport.message") {
      if (
        m.implementationProfileId !==
        "onym:message-implementation:nostr-courier-v1"
      )
        throw Error("Профиль реле не поддерживается");
      const relay = m.endpoints?.find((e: any) =>
        e.uri?.startsWith("wss://"),
      )?.uri;
      if (!relay) throw Error("Нет адреса реле");
      await client.settings({ ...client.state.settings, relays: [relay] });
    } else if (m.seat === "notary") {
      if (m.componentId !== "onym:component:onym-relayer")
        throw Error("Для этого реле укажите адрес вручную ниже");
      await client.settings({
        ...client.state.settings,
        relayer: "/api/chain",
      });
    } else if (m.seat === "naming.association") {
      if (s.url !== NAMING_URL + "manifest.json")
        throw Error(
          "Этот профиль имени пока не поддерживается. Сервис показан из каталога, подключение недоступно.",
        );
      await namingManifest();
    } else if (m.seat === "storage.backup") {
      backupConnection(s, client.identity);
    } else throw Error("Эта возможность ещё не поддерживается веб-клиентом");
    client.state.services = { source, selected: { ...selected, [m.seat]: s } };
    await client.save();
    setStatus("Подключено: " + (m.name || m.componentId));
    if (m.seat === "naming.association") {
      await client.toggleNaming(true);
      await checkName();
    }
  }
  const naming = selected["naming.association"],
    backup = selected["storage.backup"];
  return (
    <>
      <LoginApproval client={client} run={run} busy={busy} />
      <h2>Сервисы из Discovery</h2>
      <p>
        Preview использует отдельное хранилище. Можно импортировать
        зашифрованную копию основной версии.
      </p>
      <div className="card">
        <h3>Каталог сервисов</h3>
        <label>
          Адрес манифеста Discovery
          <input value={url} onChange={(e) => setUrl(e.target.value)} />
        </label>
        <div className="actions">
          <button
            disabled={busy}
            onClick={() =>
              run(async () => {
                const inspected = await inspectSource(url);
                if (
                  !confirm(
                    "Подключить каталог " +
                      url +
                      "?\nКлюч оператора: " +
                      inspected.key +
                      "\nСверьте ключ с владельцем каталога.",
                  )
                )
                  return;
                client.state.services = {
                  source: { url, key: inspected.key },
                  selected,
                };
                await client.save();
                const r = await loadCatalog(client.state.services.source);
                setItems(r.services);
                setWarnings(r.failures);
              })
            }
          >
            Подключить каталог
          </button>
          <button disabled={busy} onClick={() => run(refresh)}>
            Обновить
          </button>
        </div>
        <small>Подключён: {source.url}</small>
      </div>
      {warnings.length > 0 && (
        <details>
          <summary>
            Не удалось проверить некоторые сервисы ({warnings.length})
          </summary>
          {warnings.map((w) => (
            <p key={w}>{w}</p>
          ))}
        </details>
      )}
      {items.map((s) => (
        <div className="card" key={s.manifest.componentId}>
          <small>{roles[s.manifest.seat] || s.manifest.seat}</small>
          <h3>
            {s.manifest.name ||
              (s.manifest.componentId === "onym:component:atlas-bsn-np"
                ? "BSN — имена из Stellar"
                : s.manifest.componentId.replace("onym:component:", ""))}
          </h3>
          <p>
            {selected[s.manifest.seat]?.manifest.componentId ===
            s.manifest.componentId
              ? "Выбран"
              : "Доступен в каталоге"}
          </p>
          {s.manifest.configuration?.required_before_use && (
            <p>
              Перед использованием нужна настройка на сайте:{" "}
              {s.manifest.configuration.description}
            </p>
          )}
          <a href={s.url} target="_blank" rel="noreferrer">
            Манифест
          </a>{" "}
          <button
            disabled={
              busy ||
              ![
                "transport.message",
                "notary",
                "storage.backup",
                "naming.association",
              ].includes(s.manifest.seat)
            }
            onClick={() => run(() => choose(s))}
          >
            Выбрать
          </button>
          {![
            "transport.message",
            "notary",
            "storage.backup",
            "naming.association",
          ].includes(s.manifest.seat) && (
            <small> Пока не поддерживается веб-клиентом</small>
          )}
        </div>
      ))}
      {naming && (
        <div className="card">
          <h3>Настройка провайдера имён</h3>
          <p>{naming.manifest.configuration?.description}</p>
          <button
            disabled={busy}
            className="primary"
            onClick={() =>
              run(async () => {
                const m = await namingManifest();
                if (
                  m.authentication?.issuer !== AUTH_ISSUER ||
                  m.configuration?.initiate_login_uri !==
                    "https://atlas.predhit.com/bsn-np/login"
                )
                  throw Error("Адрес настройки изменился");
                await client.save();
                location.assign(
                  m.configuration.initiate_login_uri +
                    "?iss=" +
                    encodeURIComponent(AUTH_ISSUER),
                );
              })
            }
          >
            Настроить на сайте
          </button>{" "}
          <button disabled={busy} onClick={() => run(checkName)}>
            Проверить имя
          </button>
          {offer && (
            <article>
              <h3>{offer.displayName}</h3>
              <p>Источник: {offer.namespace}</p>
              <code>{offer.stellarAccount}</code>
              <p>Принятие опубликует связь имени с вашей идентичностью Onym.</p>
              <button
                disabled={busy}
                onClick={() =>
                  run(async () => {
                    await client.useName(offer);
                    setOffer(undefined);
                    setStatus("Имя принято и используется в чатах.");
                  })
                }
              >
                Принять имя
              </button>
            </article>
          )}
          <p>
            <button
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await client.removeName();
                  setOffer(undefined);
                  setStatus("Принятие имени отозвано.");
                })
              }
            >
              Отозвать принятое имя
            </button>{" "}
            <button
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await client.toggleNaming(false);
                  const copy = { ...selected };
                  delete copy["naming.association"];
                  client.state.services = { source, selected: copy };
                  await client.save();
                  setOffer(undefined);
                })
              }
            >
              Отключить провайдера
            </button>
          </p>
        </div>
      )}
      {backup && (
        <div className="card">
          <h3>Резервная копия веб-клиента</h3>
          <p>
            Архив зашифрован вашим паролем. Формат веб-версии; восстановление в
            мобильном клиенте не поддерживается. Основная версия и preview имеют
            отдельные локальные хранилища.
          </p>
          <a
            href={
              backup.manifest.endpoints[0].uri +
              "/terms/" +
              backup.manifest.declaredTerms.slice(7) +
              ".json"
            }
            target="_blank"
            rel="noreferrer"
          >
            Условия сервиса
          </a>
          <div className="actions">
            <button
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await backupConnection(backup, client.identity).terms();
                  if (
                    !confirm(
                      "Загрузить зашифрованную копию на " +
                        backup.manifest.name +
                        "? Ознакомьтесь с условиями сервиса.",
                    )
                  )
                    return;
                  await client.save();
                  await backupConnection(backup, client.identity).upload(
                    await readVault(),
                  );
                  setStatus("Зашифрованная копия загружена.");
                })
              }
            >
              Сохранить копию на сервере
            </button>
            <button
              disabled={busy}
              onClick={() =>
                run(async () => {
                  const list = await backupConnection(
                    backup,
                    client.identity,
                  ).list();
                  if (!Array.isArray(list))
                    throw Error("Неверный список архивов");
                  setSnapshots(
                    list
                      .filter((s: any) => s.status === "retained")
                      .slice(0, 100),
                  );
                })
              }
            >
              Показать копии
            </button>
          </div>
          {snapshots.map((s) => (
            <p key={s.snapshotReference?.digest}>
              {s.retainedAt}{" "}
              <button
                disabled={busy}
                onClick={() =>
                  run(async () => {
                    const e = await backupConnection(
                      backup,
                      client.identity,
                    ).download(s.snapshotReference.digest);
                    const u = URL.createObjectURL(
                      new Blob([JSON.stringify(e)], {
                        type: "application/json",
                      }),
                    );
                    const a = document.createElement("a");
                    a.href = u;
                    a.download = "onym-web-encrypted-backup.json";
                    a.click();
                    setTimeout(() => URL.revokeObjectURL(u), 1000);
                  })
                }
              >
                Скачать
              </button>
            </p>
          ))}
        </div>
      )}
      {status && <p role="status">{status}</p>}
      <h2>Ручные настройки сети</h2>
    </>
  );
}
