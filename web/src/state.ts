import { z } from "zod";
import { inviteSchema, messageSchema, offerSchema } from "./wire";
export const settingsSchema = z.object({
  relays: z.array(z.string().url()).min(1).max(5),
  relayer: z.union([z.literal("/api/chain"), z.string().url()]),
  contract: z.string().regex(/^C[A-Z2-7]{55}$/),
  network: z.enum(["testnet", "public"]),
});
export const groupSchema = inviteSchema.extend({
  adminSigner: z.string().regex(/^[a-f0-9]{64}$/),
  verifiedAt: z.number(),
  messages: z
    .array(
      messageSchema.extend({
        delivery: z.enum(["received", "sent", "failed", "pending"]),
      }),
    )
    .max(5000),
});
export const stateSchema = z.object({
  version: z.literal(1),
  phrase: z.string().max(300),
  name: z.string().min(1).max(60),
  settings: settingsSchema,
  groups: z.array(groupSchema).max(100),
  offers: z
    .array(
      offerSchema.extend({
        sender: z.string().regex(/^[a-f0-9]{64}$/),
        receivedAt: z.number(),
        status: z.enum(["new", "requested", "dismissed", "joined"]),
      }),
    )
    .max(100)
    .optional(),
  pending: z
    .array(
      z.object({
        groupId: z.string(),
        name: z.string(),
        introKey: z.string(),
        createdAt: z.number(),
      }),
    )
    .max(100),
});
export type State = z.infer<typeof stateSchema>;
export type Group = z.infer<typeof groupSchema>;
export type Settings = z.infer<typeof settingsSchema>;
export const defaultSettings: Settings = {
  relays: ["wss://nostr.onym.app"],
  relayer: "/api/chain",
  contract: "CAFX4A2KLOK7RE5QSPTDQ3UBCWOUSBPPFC2PU7M6ZP53GPGRCL67HNR3",
  network: "testnet",
};
