import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import { Client } from "./client";
import { newPhrase, identityFromPhrase } from "./identity";
import {
  createVault,
  unlockVault,
  readVault,
  writeVault,
  parseVault,
  resetPreviewVault,
} from "./vault";
import { stateSchema, defaultSettings, type State } from "./state";
import { hex, b64 } from "./bytes";
import { parseInviteLink, offerLink } from "./wire";
import { secureUrl } from "./transport";
import "./style.css";
import { Services, LoginApproval } from "./ServicesHub";
import { BSNName } from "./BSNName";
import { NAMING_NS } from "./naming";
import { unb64 } from "./bytes";
const errorText = (e: unknown) =>
  e instanceof Error ? e.message : "Не удалось выполнить действие";
function download(value: unknown) {
  const blob = new Blob([JSON.stringify(value)], { type: "application/json" }),
    url = URL.createObjectURL(blob),
    a = document.createElement("a");
  a.href = url;
  a.download = "onym-web-encrypted-backup.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function App() {
  const [ready, setReady] = useState(false),
    [exists, setExists] = useState(false),
    [blocked, setBlocked] = useState(false),
    [mode, setMode] = useState<"create" | "import">("create"),
    [password, setPassword] = useState(""),
    [repeat, setRepeat] = useState(""),
    [name, setName] = useState(""),
    [phrase, setPhrase] = useState(""),
    [generated, setGenerated] = useState(""),
    [saved, setSaved] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [client, setClient] = useState<Client | null>(null),
    [, redraw] = useState(0),
    [tab, setTab] = useState(
      location.hash.includes("auth=") || location.hash.includes("services=")
        ? "settings"
        : "chats",
    ),
    [selected, setSelected] = useState(""),
    [link, setLink] = useState(""),
    [draft, setDraft] = useState(""),
    [connection, setConnection] = useState("Отключено"),
    [showPhrase, setShowPhrase] = useState(false);
  const live = useRef<Client | null>(null),
    closing = useRef<Promise<void>>(Promise.resolve()),
    file = useRef<HTMLInputElement>(null),
    bottom = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let release: () => void = () => {};
    let gone = false;
    if (!navigator.locks) {
      setError("Нужен современный браузер с Web Locks и Web Crypto.");
      setReady(true);
      setBlocked(true);
      return;
    }
    void navigator.locks.request(
      import.meta.env.BASE_URL === "/preview/"
        ? "onym-web-preview-vault"
        : "onym-web-vault",
      { ifAvailable: true },
      async (lock) => {
        if (!lock) {
          if (!gone) {
            setBlocked(true);
            setReady(true);
          }
          return;
        }
        if (gone) return;
        try {
          setExists(!!(await readVault()));
          setReady(true);
        } catch (e) {
          setError(errorText(e));
          setBlocked(true);
          setReady(true);
        }
        await new Promise<void>((r) => {
          release = r;
          if (gone) r();
        });
      },
    );
    return () => {
      gone = true;
      release();
    };
  }, []);
  useEffect(() => {
    const channel = new BroadcastChannel("onym-web-preview-auth");
    channel.onmessage = (e) => {
      if (
        typeof e.data?.requestId !== "string" ||
        !/^[\w-]{43}$/.test(e.data.requestId)
      )
        return;
      if (blocked) return;
      location.hash = "auth=" + e.data.requestId;
      setTab("settings");
    };
    if (blocked) {
      const requestId = new URLSearchParams(location.hash.slice(1)).get("auth");
      if (requestId) channel.postMessage({ requestId });
    }
    const onHash = () => {
      if (
        location.hash.includes("auth=") ||
        location.hash.includes("services=")
      )
        setTab("settings");
    };
    window.addEventListener("hashchange", onHash);
    return () => {
      channel.close();
      window.removeEventListener("hashchange", onHash);
    };
  }, [blocked]);
  function clearSecrets() {
    setPassword("");
    setRepeat("");
    setPhrase("");
    setGenerated("");
    setSaved(false);
    setShowPhrase(false);
    setDraft("");
    setLink("");
  }
  function lock() {
    const c = live.current;
    live.current = null;
    setClient(null);
    clearSecrets();
    setConnection("Отключено");
    setNotice("Хранилище заблокировано.");
    if (c) closing.current = c.close();
  }
  useEffect(() => {
    if (!client) return;
    let idle: ReturnType<typeof setTimeout>,
      hidden: ReturnType<typeof setTimeout>;
    const reset = () => {
      clearTimeout(idle);
      idle = setTimeout(lock, 5 * 60 * 1000);
    };
    const visibility = () => {
      clearTimeout(hidden);
      if (document.hidden) hidden = setTimeout(lock, 60000);
    };
    const pagehide = () => lock();
    reset();
    window.addEventListener("pointerdown", reset);
    window.addEventListener("keydown", reset);
    window.addEventListener("pagehide", pagehide);
    document.addEventListener("visibilitychange", visibility);
    return () => {
      clearTimeout(idle);
      clearTimeout(hidden);
      window.removeEventListener("pointerdown", reset);
      window.removeEventListener("keydown", reset);
      window.removeEventListener("pagehide", pagehide);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [client]);
  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [
    selected,
    client?.state.groups.find((g) => g.group_id === selected)?.messages.length,
  ]);
  useEffect(() => {
    if (!client) return;
    const refresh = () => {
      void client.refreshNames(tab === "chats" ? selected : undefined);
      redraw((n) => n + 1);
    };
    refresh();
    const timer = setInterval(refresh, 30000);
    const expiryTimer = setInterval(() => redraw((n) => n + 1), 1000);
    return () => {
      clearInterval(timer);
      clearInterval(expiryTimer);
    };
  }, [client, selected, tab, client?.state.naming?.enabled]);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  function enter(state: State, key: CryptoKey, salt: Uint8Array) {
    const c = new Client(
      state,
      key,
      salt,
      () => redraw((n) => n + 1),
      setNotice,
      setConnection,
    );
    live.current = c;
    setClient(c);
    clearSecrets();
    setExists(true);
    setNotice("");
    c.start();
  }
  async function auth(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      await closing.current;
      if (exists) {
        const envelope = await readVault();
        const opened = await unlockVault(envelope, password);
        enter(stateSchema.parse(opened.data), opened.key, opened.salt);
      } else {
        if (password !== repeat) throw Error("Пароли не совпадают.");
        if (mode === "create" && !saved)
          throw Error("Сохраните фразу восстановления.");
        const input = mode === "create" ? generated : phrase;
        const identity = identityFromPhrase(input);
        const state: State = {
          version: 1,
          phrase: identity.phrase,
          name: name.trim() || "Моя идентичность",
          settings: defaultSettings,
          groups: [],
          pending: [],
        };
        const vault = await createVault(state, password);
        await writeVault(vault.envelope);
        enter(state, vault.key, vault.salt);
      }
    });
  }
  async function exportBackup() {
    await run(async () => {
      if (client) await client.save();
      const e = await readVault();
      if (!e) throw Error("Нет сохранённого хранилища");
      download(e);
      setNotice(
        "Скачан зашифрованный архив. Для открытия нужен текущий пароль.",
      );
    });
  }
  async function importBackup(f: File) {
    await run(async () => {
      if (f.size > 32_000_000) throw Error("Файл слишком большой");
      const envelope = parseVault(JSON.parse(await f.text()));
      const opened = await unlockVault(envelope, password),
        state = stateSchema.parse(opened.data);
      if (
        exists &&
        !confirm(
          "Заменить локальное хранилище содержимым этого архива? Сначала сохраните текущую копию.",
        )
      )
        return;
      await writeVault(envelope);
      enter(state, opened.key, opened.salt);
    });
  }
  const g = client?.state.groups.find((g) => g.group_id === selected);
  const me = client ? hex(client.identity.blsPublic) : "";
  let preview: ReturnType<typeof parseInviteLink> | null = null;
  let previewError = "";
  try {
    if (link.trim()) preview = parseInviteLink(link);
  } catch (e) {
    previewError =
      e instanceof Error && !e.message.startsWith("[")
        ? e.message
        : "Приглашение повреждено или имеет неподдерживаемый формат. Скопируйте ссылку целиком.";
  }
  const flash = (
    <>
      {error && (
        <div role="alert" className="alert error">
          {error}
          <button aria-label="Закрыть ошибку" onClick={() => setError("")}>
            ×
          </button>
        </div>
      )}
      {notice && (
        <div role="status" className="alert">
          {notice}
          <button
            aria-label="Закрыть уведомление"
            onClick={() => setNotice("")}
          >
            ×
          </button>
        </div>
      )}
    </>
  );
  if (!ready) return <div className="loading">Открываем Onym…</div>;
  if (blocked)
    return (
      <div className="loading">
        <h1>Хранилище уже открыто</h1>
        <p>
          {error ||
            (location.hash.includes("auth=")
              ? "Запрос входа передан в уже открытую вкладку Onym Preview. Перейдите туда, откройте «Подключения» и подтвердите вход. Если вкладка заблокирована, сначала разблокируйте её."
              : "Закройте другую вкладку Onym Preview и обновите эту страницу.")}
        </p>
      </div>
    );
  if (!client)
    return (
      <main className="welcome">
        <section className="story">
          <div className="brand">
            <img src="/mark.svg" alt="" />
            onym <span>web</span>
          </div>
          <div>
            <div className="eyebrow">ВАШИ КЛЮЧИ. ВАШИ РАЗГОВОРЫ.</div>
            <h1>
              Ближе к людям.
              <br />
              <em>Без лишних посредников.</em>
            </h1>
            <p>
              Onym в браузере. Ваша идентичность и переписка хранятся на этом
              устройстве — под вашим паролем.
            </p>
            <div className="orbit">
              <div className="orbit-line" />
              <span className="orb a">вы</span>
              <span className="orb b">друзья</span>
              <span className="orb c">сообщество</span>
              <span className="orb d">идеи</span>
            </div>
          </div>
          <div className="story-foot">
            Независимый веб-клиент · открытый код
          </div>
        </section>
        <section className="auth">
          <div className="auth-inner">
            <span className="pill">Preview · отдельное хранилище</span>
            <h2>{exists ? "С возвращением" : "Ваш Onym начинается здесь"}</h2>
            <p className="muted">
              {exists
                ? "Введите пароль от локального хранилища."
                : "Создайте идентичность или восстановите её по фразе из мобильного Onym."}
            </p>
            {flash}
            {!exists && (
              <div className="segmented">
                <button
                  className={mode === "create" ? "active" : ""}
                  onClick={() => {
                    setMode("create");
                    setGenerated("");
                  }}
                >
                  Создать
                </button>
                <button
                  className={mode === "import" ? "active" : ""}
                  onClick={() => setMode("import")}
                >
                  Импортировать
                </button>
              </div>
            )}
            <form onSubmit={auth}>
              {!exists && (
                <>
                  <label>
                    Как вас называть
                    <input
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      maxLength={60}
                      placeholder="Ваше имя"
                      autoComplete="nickname"
                    />
                  </label>
                  {mode === "import" ? (
                    <label>
                      Фраза восстановления
                      <textarea
                        value={phrase}
                        onChange={(e) => setPhrase(e.target.value)}
                        placeholder="12 или 24 английских слова"
                        autoComplete="off"
                        spellCheck={false}
                      />
                      <small>
                        Импорт ключей не восстанавливает старую переписку.
                      </small>
                    </label>
                  ) : (
                    <div className="phrase-box">
                      {!generated ? (
                        <button
                          type="button"
                          className="secondary full"
                          onClick={() => {
                            setGenerated(newPhrase());
                            setSaved(false);
                          }}
                        >
                          Создать фразу восстановления
                        </button>
                      ) : (
                        <>
                          <div className="words">
                            {generated.split(" ").map((w, i) => (
                              <span key={i}>
                                <small>{i + 1}</small>
                                {w}
                              </span>
                            ))}
                          </div>
                          <label className="check">
                            <input
                              type="checkbox"
                              checked={saved}
                              onChange={(e) => setSaved(e.target.checked)}
                            />
                            Я сохранил фразу в безопасном месте
                          </label>
                        </>
                      )}
                    </div>
                  )}
                </>
              )}
              <label>
                {exists ? "Пароль" : "Пароль для этого браузера"}
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={exists ? undefined : 12}
                  maxLength={1024}
                  autoComplete={exists ? "current-password" : "new-password"}
                  required
                  placeholder={
                    exists ? "Введите пароль" : "Не менее 12 символов"
                  }
                />
              </label>
              {!exists && (
                <label>
                  Повторите пароль
                  <input
                    type="password"
                    value={repeat}
                    onChange={(e) => setRepeat(e.target.value)}
                    autoComplete="new-password"
                    required
                  />
                </label>
              )}
              <button
                className="primary full"
                disabled={busy || (!exists && mode === "create" && !generated)}
              >
                {busy
                  ? "Шифрование…"
                  : exists
                    ? "Разблокировать"
                    : "Открыть Onym"}{" "}
                <span>→</span>
              </button>
            </form>
            <button
              className="text-button"
              disabled={busy || !password}
              onClick={() => file.current?.click()}
            >
              Восстановить из зашифрованного файла
            </button>
            <input
              ref={file}
              hidden
              type="file"
              accept="application/json,.json"
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (f) void importBackup(f);
              }}
            />
            {exists && (
              <button className="text-button" onClick={exportBackup}>
                Скачать зашифрованную копию
              </button>
            )}
            <p className="fine">
              Пароль защищает данные только в этом браузере. Очистка данных
              сайта удалит локальную копию. Для ранней версии рекомендуем
              отдельную тестовую идентичность.
            </p>
          </div>
        </section>
        {exists && import.meta.env.BASE_URL === "/preview/" && <div className="card"><p>Чтобы открыть другую идентичность, можно очистить только хранилище Preview. Основная версия останется нетронутой.</p><button className="secondary" disabled={busy} onClick={()=>run(async()=>{
          if(!confirm("Очистить локальные данные Preview? Сначала сохраните зашифрованную копию, если эти ключи или переписка вам нужны. Данные основной версии не изменятся."))return;
          await closing.current; await resetPreviewVault(); setExists(false);clearSecrets();setNotice("Хранилище Preview очищено.");
        })}>Очистить хранилище Preview</button></div>}
      </main>
    );
  return (
    <div className="workspace">
      <aside className="rail">
        <div className="brand">
          <img src="/mark.svg" alt="" />
          onym <span>web</span>
        </div>
        <nav>
          {[
            ["chats", "◉", "Переписка"],
            ["join", "＋", "Присоединиться"],
            ["identity", "◎", "Моя идентичность"],
            ["settings", "⚙", "Подключения"],
          ].map(([key, icon, label]) => (
            <button
              key={key}
              className={tab === key ? "selected" : ""}
              onClick={() => {
                setTab(key);
                setError("");
              }}
            >
              <span>{icon}</span>
              {label}
            </button>
          ))}
        </nav>
        <div className="rail-bottom">
          <div className="network">
            <i className={connection === "Подключено" ? "online" : ""} />
            {connection}
          </div>
          <button className="person" onClick={() => setTab("identity")}>
            <span className="avatar">
              {client.displayName[0].toUpperCase()}
            </span>
            <span>
              {client.displayName}
              {client.nameFor(hex(client.identity.signingPublic)) && (
                <small className="bsn-source">BSN</small>
              )}
              <small>Ключи на устройстве</small>
            </span>
          </button>
          <button className="secondary full" onClick={lock}>
            Заблокировать
          </button>
        </div>
      </aside>
      <main className="content">
        <header className="topbar">
          <span>
            {tab === "chats"
              ? "Ваши разговоры"
              : tab === "join"
                ? "Новый разговор"
                : tab === "identity"
                  ? "Моя идентичность"
                  : "Подключения"}
          </span>
          <span className="pill">Onym Web · Preview</span>
        </header>
        <div className="flashes">{flash}</div>
        {tab === "chats" ? (
          <div className="chat-layout">
            <section className="threads">
              <div className="section-top">
                <h2>Переписка</h2>
                <button
                  className="round"
                  aria-label="Присоединиться к группе"
                  onClick={() => setTab("join")}
                >
                  ＋
                </button>
              </div>
              {client.state.groups.length === 0 ? (
                <p className="muted small">
                  Здесь появятся группы, к которым вы присоединитесь.
                </p>
              ) : (
                client.state.groups.map((group) => (
                  <button
                    key={group.group_id}
                    className={
                      "thread " + (selected === group.group_id ? "active" : "")
                    }
                    onClick={() => setSelected(group.group_id)}
                  >
                    <span className="avatar">{group.name[0]}</span>
                    <span>
                      <strong>{group.name}</strong>
                      <small>
                        {group.messages.at(-1)?.variant.body ||
                          "Начните разговор"}
                      </small>
                    </span>
                  </button>
                ))
              )}
              {(client.state.offers ?? [])
                .filter((o) => o.status === "new")
                .map((o) => (
                  <div className="card" key={o.group_id + o.sender}>
                    <span className="eyebrow">Приглашение</span>
                    <h3>{o.group_name || "Группа Onym"}</h3>
                    <p className="small">
                      {o.inviter_alias || "Участник Onym"} приглашает вас
                    </p>
                    {o.invitation_message && (
                      <p className="small pre">{o.invitation_message}</p>
                    )}
                    <button
                      className="primary full"
                      onClick={() => {
                        setLink(offerLink(o));
                        setTab("join");
                      }}
                    >
                      Открыть приглашение
                    </button>
                    <button
                      className="text-button"
                      disabled={busy}
                      onClick={() =>
                        run(() => client.dismissOffer(o.group_id, o.sender))
                      }
                    >
                      Отклонить
                    </button>
                  </div>
                ))}
              {client.state.pending.map((p) => (
                <div className="pending" key={p.groupId}>
                  <strong>{p.name}</strong>
                  <small>Запрос сохранён · ожидаем приглашение</small>
                </div>
              ))}
            </section>
            {!g ? (
              <section className="empty">
                <div className="empty-symbol">↗</div>
                <h2>
                  Разговор начинается
                  <br />с приглашения
                </h2>
                <p>
                  Вставьте ссылку на группу из мобильного Onym.
                  <br />
                  После одобрения администратора она появится здесь.
                </p>
                <button className="primary" onClick={() => setTab("join")}>
                  Присоединиться к группе
                </button>
                <small>
                  В этой версии: текстовые чаты в группах с администратором.
                </small>
              </section>
            ) : (
              <section className="conversation">
                <div className="conversation-head">
                  <span className="avatar">{g.name[0]}</span>
                  <div>
                    <h2>{g.name}</h2>
                    <small>
                      {Object.keys(g.member_profiles).length} участников ·
                      зашифрованная доставка
                    </small>
                  </div>
                </div>
                <div className="messages">
                  {g.messages.length === 0 && (
                    <p className="muted center">
                      Пока нет сообщений. Можно написать первым.
                    </p>
                  )}
                  {g.messages.map((m) => (
                    <article
                      className={
                        "bubble " +
                        (m.sender_bls_pubkey_hex === me ? "mine" : "")
                      }
                      key={m.message_id}
                    >
                      <strong>
                        {(() => {
                          const profile =
                            g.member_profiles[m.sender_bls_pubkey_hex];
                          const key = profile
                            ? hex(unb64(profile.sending_pubkey))
                            : "";
                          const named = client.nameFor(key);
                          return named ? (
                            <span title={named.name + "@" + NAMING_NS}>
                              {named.displayName}
                              <small className="bsn-source">
                                @{NAMING_NS} ·{" "}
                                {named.stellarAccount.slice(0, 6)}…
                                {named.stellarAccount.slice(-6)}
                                {m.sender_bls_pubkey_hex === me ? " · Вы" : ""}
                              </small>
                            </span>
                          ) : m.sender_bls_pubkey_hex === me ? (
                            "Вы"
                          ) : (
                            profile?.alias ||
                            "BLS " + m.sender_bls_pubkey_hex.slice(0, 8)
                          );
                        })()}
                      </strong>
                      <p>
                        {m.variant.body || "Вложение (пока не поддерживается)"}
                      </p>
                      <footer>
                        {new Date(m.sent_at_millis).toLocaleTimeString("ru", {
                          hour: "2-digit",
                          minute: "2-digit",
                        })}{" "}
                        {m.delivery === "sent" ? (
                          "· принято реле"
                        ) : m.delivery === "pending" ? (
                          "· отправляется"
                        ) : m.delivery === "failed" ? (
                          <button
                            disabled={busy}
                            onClick={() =>
                              run(() =>
                                client.send(
                                  g.group_id,
                                  m.variant.body,
                                  m.message_id,
                                ),
                              )
                            }
                          >
                            Повторить
                          </button>
                        ) : (
                          ""
                        )}
                      </footer>
                    </article>
                  ))}
                  <div ref={bottom} />
                </div>
                <form
                  className="composer"
                  onSubmit={(e) => {
                    e.preventDefault();
                    const value = draft;
                    void run(async () => {
                      await client.send(g.group_id, value);
                      setDraft("");
                    });
                  }}
                >
                  <textarea
                    aria-label="Сообщение"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    placeholder="Напишите сообщение…"
                    maxLength={16000}
                  />
                  <button className="primary" disabled={busy || !draft.trim()}>
                    Отправить ↑
                  </button>
                </form>
              </section>
            )}
          </div>
        ) : tab === "join" ? (
          <section className="page">
            <div className="eyebrow">ПО ПРИГЛАШЕНИЮ</div>
            <h1>Присоединиться к группе</h1>
            <p className="muted">
              Попросите администратора мобильного Onym поделиться ссылкой на
              группу.
            </p>
            <label>
              Ссылка приглашения
              <textarea
                value={link}
                onChange={(e) => setLink(e.target.value)}
                placeholder="https://onym.app/join?c=…"
                spellCheck={false}
              />
            </label>
            {previewError && (
              <p role="alert" className="alert error">
                {previewError}
              </p>
            )}
            {preview && (
              <div className="card">
                <h3>{preview.group_name || "Группа Onym"}</h3>
                {preview.rules && (
                  <>
                    <h4>Правила группы</h4>
                    <p className="pre">{preview.rules}</p>
                  </>
                )}
                <p className="muted small">
                  Отправляя запрос, вы передаёте администратору имя и публичные
                  ключи
                  {preview.rules
                    ? " и подписываете согласие с этими правилами"
                    : ""}
                  .
                </p>
              </div>
            )}
            <button
              className="primary"
              disabled={!preview || busy}
              onClick={() => run(() => client.join(link))}
            >
              {busy ? "Проверяем и отправляем…" : "Отправить запрос"}
            </button>
            <p className="fine">
              Сеть и контракт должны совпадать с настройками группы. Сейчас
              поддерживаются группы типа Tyranny. Создание групп и личных
              диалогов из браузера ещё не реализовано.
            </p>
          </section>
        ) : tab === "identity" ? (
          <section className="page">
            <div className="profile-hero">
              <span className="avatar big">{client.displayName[0]}</span>
              <div>
                <h1>{client.displayName}</h1>
                {client.nameFor(hex(client.identity.signingPublic)) && (
                  <small className="bsn-source">@{NAMING_NS}</small>
                )}
                <span className="pill">Идентичность Onym</span>
              </div>
            </div>
            {import.meta.env.BASE_URL !== "/preview/" && (
              <BSNName
                key={client.identity.id}
                client={client}
                run={run}
                busy={busy}
              />
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const n = new FormData(e.currentTarget).get("name") as string;
                void run(async () => {
                  client.state.name = n.trim() || client.state.name;
                  await client.save();
                  setNotice(
                    "Имя обновлено локально. Старые профили в группах не меняются автоматически.",
                  );
                });
              }}
            >
              <label>
                Локальное имя (если BSN не подключён)
                <input
                  name="name"
                  defaultValue={client.state.name}
                  maxLength={60}
                  required
                />
              </label>
              <button className="secondary" disabled={busy}>
                Сохранить имя
              </button>
            </form>
            <div className="card">
              <h3>Публичные ключи</h3>
              {[
                ["BLS — идентичность", hex(client.identity.blsPublic)],
                [
                  "Inbox — получение сообщений",
                  hex(client.identity.inboxPublic),
                ],
                ["Ed25519 — подпись", hex(client.identity.signingPublic)],
                ["Stellar-адрес", client.identity.stellarAccount],
              ].map(([label, value]) => (
                <div className="key-row" key={label}>
                  <label>
                    {label}
                    <code>{value}</code>
                  </label>
                  <button
                    className="secondary"
                    onClick={() =>
                      run(async () => {
                        await navigator.clipboard.writeText(value);
                        setNotice("Публичный ключ скопирован.");
                      })
                    }
                  >
                    Копировать
                  </button>
                </div>
              ))}
              <p className="fine">
                Stellar-адрес выведен из ключей Onym. Это не импорт вашего
                существующего кошелька.
              </p>
            </div>
            <div className="card">
              <h3>Восстановление и перенос</h3>
              <button className="text-button" onClick={lock}>
                Заблокировать хранилище
              </button>
              <p className="muted">
                Зашифрованный файл сохраняет ключи, настройки и переписку. Фраза
                восстанавливает только идентичность.
              </p>
              <div className="actions">
                <button className="secondary" onClick={exportBackup}>
                  Скачать зашифрованную копию
                </button>
                <button
                  className="text-button"
                  onClick={() => setShowPhrase(!showPhrase)}
                >
                  {showPhrase
                    ? "Скрыть фразу"
                    : "Показать фразу восстановления"}
                </button>
              </div>
              {showPhrase && (
                <p className="secret pre">{client.identity.phrase}</p>
              )}
            </div>
          </section>
        ) : (
          <section className="page">
            <h1>Ваши подключения</h1>
            <Services client={client} run={run} busy={busy} />
            <p className="muted">
              Используйте те же реле, сеть и контракт, что и участники вашей
              группы.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const data = new FormData(e.currentTarget);
                void run(async () => {
                  const settings = {
                    relays: (data.get("relays") as string)
                      .split(/\s+/)
                      .filter(Boolean)
                      .map((s) => secureUrl(s, "wss:")),
                    relayer:
                      data.get("relayer") === "/api/chain"
                        ? "/api/chain"
                        : secureUrl(data.get("relayer") as string, "https:"),
                    contract: (data.get("contract") as string).trim(),
                    network: data.get("network") as "testnet" | "public",
                  };
                  await client.settings(settings);
                  setNotice("Настройки сохранены, соединение обновлено.");
                });
              }}
            >
              <label>
                Nostr-реле · по одному адресу на строку
                <textarea
                  name="relays"
                  defaultValue={client.state.settings.relays.join("\n")}
                  required
                />
              </label>
              <label>
                HTTP-реле контрактов
                <input
                  name="relayer"
                  defaultValue={client.state.settings.relayer}
                  required
                />
              </label>
              <label>
                Сеть Stellar
                <select
                  name="network"
                  defaultValue={client.state.settings.network}
                >
                  <option value="testnet">Testnet</option>
                  <option value="public">Public</option>
                </select>
              </label>
              <label>
                Контракт Tyranny
                <input
                  name="contract"
                  defaultValue={client.state.settings.contract}
                  required
                  pattern="C[A-Z2-7]{55}"
                />
              </label>
              <button className="primary" disabled={busy}>
                Сохранить подключения
              </button>
            </form>
            <p className="fine">
              Проверка состояния групп доверяет выбранному HTTP-реле. Адрес
              /api/chain использует встроенный посредник только для чтения
              официального реле; сторонний сервер должен разрешать CORS. Ключи и
              незашифрованные сообщения ему не передаются.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
