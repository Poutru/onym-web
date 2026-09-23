import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import {
  identityFromPhrase,
  inboxTag,
  wipeIdentity,
  type Identity,
} from "./identity";
import { leafHash, commitment } from "./poseidon";
import { b64, unb64, hex, utf8, concat, equal } from "./bytes";
import {
  parseInviteLink,
  offerSchema,
  seal,
  openEnvelope,
  inviteSchema,
  messageSchema,
  profileSchema,
  type Invitation,
} from "./wire";
import { InboxTransport, limitedJson } from "./transport";
import { stateSchema, type State, type Group, type Settings } from "./state";
import { encryptVault, writeVault } from "./vault";
import {
  acceptName,
  disavowName,
  namingManifest,
  resolveName,
  recordDigest,
  type NameRecord,
  NAMING_NS,
} from "./naming";
const chainSchema = z.object({
  epoch: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  commitment: z.string().refine((s) => {
    try {
      return unb64(s, 32).length === 32;
    } catch {
      return false;
    }
  }),
});
export async function chainRead(
  settings: Settings,
  groupId: string,
  history = false,
) {
  return limitedJson(settings.relayer, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contractID: settings.contract,
      contractType: "tyranny",
      network: settings.network,
      function: history ? "get_history" : "get_commitment",
      payload: history
        ? { group_id: groupId, max_entries: 64 }
        : { group_id: groupId },
    }),
  });
}
export async function verifyChain(
  settings: Settings,
  groupId: string,
  expected: string,
  epoch: number,
) {
  const current = chainSchema.parse(await chainRead(settings, groupId));
  if (current.epoch === epoch && current.commitment === expected) return;
  if (current.epoch > epoch) {
    const history = z
      .array(chainSchema)
      .max(64)
      .parse(await chainRead(settings, groupId, true));
    if (history.some((e) => e.epoch === epoch && e.commitment === expected))
      return;
  }
  throw Error("Состояние группы не подтверждено выбранным контрактом.");
}
export function verifyInvitation(
  inv: Invitation,
  identity: Identity,
  sender: string,
) {
  const myKey = hex(identity.blsPublic),
    me = inv.member_profiles[myKey],
    admin = inv.member_profiles[inv.admin_pubkey_hex];
  if (
    !me ||
    !admin ||
    hex(unb64(admin.sending_pubkey)) !== sender ||
    !equal(unb64(me.inbox_public_key), identity.inboxPublic) ||
    !equal(unb64(me.sending_pubkey), identity.signingPublic)
  )
    throw Error("Приглашение не соответствует ключам участников.");
  const members = [...inv.members].sort((a, b) =>
    hex(unb64(a.public_key_compressed)).localeCompare(
      hex(unb64(b.public_key_compressed)),
    ),
  );
  if (
    new Set(members.map((m) => m.public_key_compressed)).size !== members.length
  )
    throw Error("Повтор участника");
  const ownLeaf = members.find(
    (m) => hex(unb64(m.public_key_compressed)) === myKey,
  );
  if (
    !ownLeaf ||
    !equal(unb64(ownLeaf.leaf_hash), leafHash(identity.blsSecret))
  )
    throw Error("Мой ключ отсутствует в дереве группы");
  const calculated = commitment(
    members.map((m) => unb64(m.leaf_hash)),
    [5, 8, 11][inv.tier_raw],
    inv.epoch,
    unb64(inv.salt),
  );
  if (!equal(calculated, unb64(inv.commitment)))
    throw Error("Неверное обязательство состава группы");
}
export class Client {
  identity: Identity;
  names = new Map<string, { record: NameRecord; until: number }>();
  private resolvingNames = false;
  nameFor(signingKey: string) {
    const n = this.names.get(signingKey);
    return n && n.until > Date.now() ? n.record : undefined;
  }
  get displayName() {
    return (
      this.nameFor(hex(this.identity.signingPublic))?.displayName ||
      this.state.name
    );
  }
  get displayLabel() {
    return this.nameFor(hex(this.identity.signingPublic))
      ? this.displayName + " @" + NAMING_NS
      : this.state.name;
  }
  async refreshNames(groupId?: string) {
    if (!this.live || !this.state.naming?.enabled || this.resolvingNames)
      return;
    this.resolvingNames = true;
    try {
      const m = await namingManifest();
      const g = this.state.groups.find((g) => g.group_id === groupId);
      const keys = [
        hex(this.identity.signingPublic),
        ...Object.values(g?.member_profiles || {}).map((p) =>
          hex(unb64(p.sending_pubkey)),
        ),
      ];
      for (const key of [...new Set(keys)].slice(0, 20)) {
        if (!this.live || !this.state.naming?.enabled) break;
        try {
          const r = await resolveName("onym:key:" + key, m.policy);
          if (!this.live || !this.state.naming?.enabled) break;
          const active = r.records
            .filter((r) => r.status === "active")
            .sort((a, b) => b.record.sequence - a.record.sequence)[0];
          if (active)
            this.names.set(key, {
              record: active.record,
              until: Math.min(
                Date.parse(r.expiresAt),
                Date.parse(active.record.expiresAt),
                Date.parse(active.acceptance!.expiresAt),
              ),
            });
          else this.names.delete(key);
        } catch {
          this.names.delete(key);
        }
      }
    } catch {
      this.names.clear();
    } finally {
      this.resolvingNames = false;
      if (this.live) this.changed();
    }
  }
  async useName(record: NameRecord) {
    const r = await acceptName(record, this.identity);
    if (!this.live) return;
    this.state.naming = {
      enabled: true,
      account: record.stellarAccount,
      record: recordDigest(record),
    };
    this.names.set(hex(this.identity.signingPublic), {
      record,
      until: Date.parse(r.expiresAt),
    });
    await this.save();
  }
  async removeName() {
    if (this.state.naming?.record)
      await disavowName(this.state.naming.record, this.identity);
    if (!this.live) return;
    this.state.naming = {
      enabled: false,
      account: this.state.naming?.account || "",
    };
    this.names.clear();
    await this.save();
  }
  async toggleNaming(enabled: boolean) {
    this.state.naming = {
      ...this.state.naming,
      enabled,
      account: this.state.naming?.account || "",
    };
    this.names.clear();
    await this.save();
    if (enabled) await this.refreshNames();
  }

  live = true;
  transport?: InboxTransport;
  private saveQueue = Promise.resolve();
  private receiveQueue = Promise.resolve();
  private parked: { sender: string; payload: unknown }[] = [];
  constructor(
    public state: State,
    private key: CryptoKey | null,
    private salt: Uint8Array,
    private changed: () => void,
    private notice: (s: string) => void,
    private status: (s: string) => void,
  ) {
    this.identity = identityFromPhrase(state.phrase);
  }
  start() {
    this.transport = new InboxTransport(
      this.identity.inboxTag,
      (bytes) => {
        this.receiveQueue = this.receiveQueue
          .then(async () => {
            if (!this.live) return;
            const envelope = await openEnvelope(bytes, this.identity);
            if (this.live)
              await this.receive(envelope.sender, envelope.payload);
          })
          .catch(() => {
            /* unauthenticated input never affects UI */
          });
      },
      this.status,
    );
    this.transport.connect(this.state.settings.relays);
  }
  async save() {
    if (!this.live) throw Error("Хранилище заблокировано");
    stateSchema.parse(this.state);
    const snapshot = JSON.stringify(this.state);
    this.saveQueue = this.saveQueue
      .catch(() => {})
      .then(async () => {
        const envelope = await encryptVault(
          JSON.parse(snapshot),
          this.key!,
          this.salt,
        );
        await writeVault(envelope);
      });
    await this.saveQueue;
    if (this.live) this.changed();
  }
  async close() {
    this.live = false;
    this.transport?.close();
    this.parked = [];
    await this.saveQueue.catch(() => {});
    this.key = null;
    wipeIdentity(this.identity);
    this.state.phrase = "";
    this.state.groups = [];
    this.state.pending = [];
    this.state.offers = [];
    this.names.clear();
  }
  async join(link: string) {
    const cap = parseInviteLink(link);
    chainSchema.parse(await chainRead(this.state.settings, cap.group_id));
    if (!this.live) return;
    const rules = cap.rules?.trim();
    const payload = {
      joiner_inbox_pub: b64(this.identity.inboxPublic),
      joiner_bls_pub: b64(this.identity.blsPublic),
      joiner_leaf_hash: b64(leafHash(this.identity.blsSecret)),
      joiner_sending_pub: b64(this.identity.signingPublic),
      joiner_display_label: this.displayLabel,
      group_id: cap.group_id,
      ...(rules
        ? {
            rules_hash: b64(sha256(utf8(rules))),
            rules_signature: b64(
              ed25519.sign(
                concat(
                  utf8("onym-group-rules-v1"),
                  unb64(cap.group_id),
                  sha256(utf8(rules)),
                  this.identity.signingPublic,
                ),
                this.identity.signingSecret,
              ),
            ),
          }
        : {}),
    };
    const encrypted = await seal(payload, unb64(cap.intro_pub), this.identity);
    if (!this.live) return;
    const pending = {
      groupId: cap.group_id,
      name: cap.group_name || "Группа Onym",
      introKey: cap.intro_pub,
      createdAt: Date.now(),
    };
    this.state.pending = this.state.pending
      .filter((p) => p.groupId !== cap.group_id)
      .concat(pending);
    await this.save();
    await this.transport!.send(encrypted, inboxTag(unb64(cap.intro_pub)));
    if (this.live) {
      for (const offer of this.state.offers ?? [])
        if (
          offer.group_id === cap.group_id &&
          offer.intro_pub === cap.intro_pub
        )
          offer.status = "requested";
      await this.save();
      this.notice(
        "Запрос принят реле. Ожидаем одобрения администратора в Onym.",
      );
    }
  }
  async dismissOffer(groupId: string, sender: string) {
    if (!this.live) return;
    const offer = this.state.offers?.find(
      (o) => o.group_id === groupId && o.sender === sender,
    );
    if (offer) {
      offer.status = "dismissed";
      await this.save();
    }
  }
  private async receive(sender: string, payload: unknown) {
    if (!this.live) return;
    const offer = offerSchema.safeParse(payload);
    if (offer.success) {
      if (this.state.groups.some((g) => g.group_id === offer.data.group_id))
        return;
      const offers = (this.state.offers ??= []);
      if (
        offers.some(
          (o) => o.group_id === offer.data.group_id && o.sender === sender,
        ) ||
        offers.length >= 100
      )
        return;
      offers.push({
        ...offer.data,
        sender,
        receivedAt: Date.now(),
        status: "new",
      });
      await this.save();
      if (this.live)
        this.notice(
          "Получено приглашение в «" +
            (offer.data.group_name || "группу Onym") +
            "». Оно в списке переписки.",
        );
      return;
    }
    const invite = inviteSchema.safeParse(payload);
    if (invite.success) {
      const inv = invite.data;
      const old = this.state.groups.find((g) => g.group_id === inv.group_id);
      if (!old && !this.state.pending.some((p) => p.groupId === inv.group_id))
        return;
      if (old && (old.adminSigner !== sender || inv.epoch < old.epoch)) return;
      verifyInvitation(inv, this.identity, sender);
      await verifyChain(
        this.state.settings,
        inv.group_id,
        inv.commitment,
        inv.epoch,
      );
      if (!this.live) return;
      const group: Group = {
        ...inv,
        adminSigner: sender,
        verifiedAt: Date.now(),
        messages: old?.messages ?? [],
      };
      this.state.groups = this.state.groups
        .filter((g) => g.group_id !== inv.group_id)
        .concat(group);
      this.state.pending = this.state.pending.filter(
        (p) => p.groupId !== inv.group_id,
      );
      for (const offer of this.state.offers ?? [])
        if (offer.group_id === inv.group_id) offer.status = "joined";
      await this.save();
      this.notice("Вы присоединились к группе «" + inv.name + "».");
      const parked = this.parked.splice(0);
      for (const p of parked) await this.receive(p.sender, p.payload);
      return;
    }
    const msg = messageSchema.safeParse(payload);
    if (msg.success) {
      const m = msg.data,
        g = this.state.groups.find((g) => g.group_id === m.group_id),
        member = g?.member_profiles[m.sender_bls_pubkey_hex];
      if (!g || !member) {
        if (this.parked.length < 200) this.parked.push({ sender, payload });
        return;
      }
      if (
        hex(unb64(member.sending_pubkey)) !== sender ||
        g.messages.some((x) => x.message_id === m.message_id)
      )
        return;
      g.messages.push({ ...m, delivery: "received" });
      g.messages = g.messages
        .slice(-5000)
        .sort((a, b) => a.sent_at_millis - b.sent_at_millis);
      await this.save();
      return;
    }
    const announcement = z
      .object({
        version: z.literal(1),
        group_id: z.string(),
        epoch: z.number().int().nonnegative(),
        commitment: z.string(),
        new_member: z.object({
          bls_pub: z.string(),
          inbox_pub: z.string(),
          sending_pub: z.string(),
          alias: z.string().max(200),
        }),
      })
      .safeParse(payload);
    if (announcement.success) {
      const a = announcement.data,
        g = this.state.groups.find((g) => g.group_id === a.group_id);
      if (!g || g.adminSigner !== sender) return;
      const memberKey = hex(unb64(a.new_member.bls_pub, 48));
      if (g.member_profiles[memberKey]) return;
      const profile = profileSchema.parse({
        alias: a.new_member.alias,
        inbox_public_key: a.new_member.inbox_pub,
        sending_pubkey: a.new_member.sending_pub,
      });
      await verifyChain(this.state.settings, a.group_id, a.commitment, a.epoch);
      if (!this.live) return;
      g.member_profiles[memberKey] = profile;
      await this.save();
      const parked = this.parked.splice(0);
      for (const p of parked) await this.receive(p.sender, p.payload);
    }
  }
  async send(groupId: string, body: string, retryId?: string) {
    const g = this.state.groups.find((g) => g.group_id === groupId);
    if (!g || !this.live) throw Error("Нет активной группы");
    if (!body.trim() || utf8(body).length > 16000)
      throw Error("Сообщение должно содержать от 1 до 16000 байт");
    let message = retryId
      ? g.messages.find((m) => m.message_id === retryId)
      : undefined;
    if (!message) {
      message = {
        version: 1,
        message_id: crypto.randomUUID().toUpperCase(),
        group_id: groupId,
        sender_bls_pubkey_hex: hex(this.identity.blsPublic),
        sent_at_millis: Date.now(),
        variant: { kind: "tyranny", body },
        delivery: "pending",
      };
      g.messages.push(message);
    }
    message.delivery = "pending";
    await this.save();
    const { delivery: _, ...payload } = message;
    try {
      const recipients = Object.values(g.member_profiles).filter(
        (p) => !equal(unb64(p.inbox_public_key), this.identity.inboxPublic),
      );
      if (!recipients.length) throw Error("В группе нет получателей");
      for (const p of recipients) {
        if (!this.live) return;
        const bytes = await seal(
          payload,
          unb64(p.inbox_public_key),
          this.identity,
        );
        await this.transport!.send(bytes, inboxTag(unb64(p.inbox_public_key)));
      }
      if (this.live) {
        message.delivery = "sent";
        await this.save();
      }
    } catch (e) {
      if (this.live) {
        message.delivery = "failed";
        await this.save();
      }
      throw e;
    }
  }
  async settings(settings: Settings) {
    this.state.settings = settings;
    await this.save();
    this.transport?.close();
    this.start();
  }
}
