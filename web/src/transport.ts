import { makeEvent, validEvent, type NostrEvent } from "./wire";
import { unb64 } from "./bytes";
export function secureUrl(raw: string, protocol: "https:" | "wss:") {
  const u = new URL(raw);
  if (u.protocol !== protocol || u.username || u.password || u.hash)
    throw Error("Нужен безопасный адрес " + protocol + "//");
  return u.toString();
}
export class InboxTransport {
  private sockets = new Map<string, WebSocket>();
  private stopped = false;
  private timers = new Set<ReturnType<typeof setTimeout>>();
  private seen = new Set<string>();
  private pending = new Map<
    string,
    {
      resolve: (n: number) => void;
      reject: (e: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  constructor(
    private inbox: string,
    private receive: (bytes: Uint8Array) => void,
    private status: (s: string) => void,
  ) {}
  connect(urls: string[]) {
    for (const raw of urls) {
      const url = secureUrl(raw, "wss:");
      this.attach(url);
    }
  }
  private attach(url: string) {
    if (this.stopped) return;
    const ws = new WebSocket(url);
    this.sockets.set(url, ws);
    ws.onopen = () => {
      if (this.stopped) {
        ws.close();
        return;
      }
      this.status("Подключено");
      ws.send(
        JSON.stringify([
          "REQ",
          "inbox",
          { kinds: [34113], "#d": ["sep-inbox:" + this.inbox], limit: 500 },
          { kinds: [34113, 24113], "#t": [this.inbox], limit: 500 },
        ]),
      );
    };
    ws.onmessage = (event) => {
      if (
        this.stopped ||
        typeof event.data !== "string" ||
        event.data.length > 4_000_000
      )
        return;
      try {
        const row = JSON.parse(event.data);
        if (row[0] === "OK" && row[2] === true) {
          const pending = this.pending.get(row[1]);
          if (pending) {
            clearTimeout(pending.timer);
            this.pending.delete(row[1]);
            pending.resolve(1);
          }
          return;
        }
        if (row[0] !== "EVENT") return;
        const e = row[2] as NostrEvent;
        if (!validEvent(e, this.inbox) || this.seen.has(e.id)) return;
        if (this.seen.size >= 5000)
          this.seen.delete(this.seen.values().next().value!);
        this.seen.add(e.id);
        this.receive(unb64(e.content));
      } catch {
        /* hostile relay input is ignored */
      }
    };
    ws.onerror = () => this.status("Ошибка соединения");
    ws.onclose = () => {
      if (this.stopped) return;
      this.status("Переподключение…");
      const timer = setTimeout(() => {
        this.timers.delete(timer);
        this.attach(url);
      }, 5000);
      this.timers.add(timer);
    };
  }
  async send(bytes: Uint8Array, inbox: string) {
    if (this.stopped) throw Error("Клиент заблокирован");
    const event = makeEvent(bytes, inbox),
      open = [...this.sockets.values()].filter(
        (s) => s.readyState === WebSocket.OPEN,
      );
    if (!open.length)
      throw Error("Нет соединения с реле. Проверьте настройки.");
    return new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(event.id);
        reject(Error("Реле не подтвердило приём. Можно повторить отправку."));
      }, 12000);
      this.pending.set(event.id, { resolve, reject, timer });
      for (const ws of open) ws.send(JSON.stringify(["EVENT", event]));
    });
  }
  close() {
    this.stopped = true;
    for (const t of this.timers) clearTimeout(t);
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(Error("Клиент заблокирован"));
    }
    this.pending.clear();
    for (const ws of this.sockets.values()) {
      ws.onclose = null;
      ws.close();
    }
    this.sockets.clear();
    this.seen.clear();
  }
}
export async function limitedJson(
  url: string,
  init: RequestInit = {},
  limit = 2_000_000,
) {
  const response = await fetch(
    url === "/api/chain" ? url : secureUrl(url, "https:"),
    {
      ...init,
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(15000),
    },
  );
  if (!response.ok) throw Error("Сервис ответил HTTP " + response.status);
  if (Number(response.headers.get("content-length")) > limit)
    throw Error("Ответ слишком большой");
  const reader = response.body!.getReader();
  let n = 0,
    out = "";
  const dec = new TextDecoder();
  try {
    while (true) {
      const r = await reader.read();
      if (r.done) break;
      n += r.value.length;
      if (n > limit) throw Error("Ответ слишком большой");
      out += dec.decode(r.value, { stream: true });
    }
    out += dec.decode();
    return JSON.parse(out) as unknown;
  } finally {
    await reader.cancel();
  }
}
