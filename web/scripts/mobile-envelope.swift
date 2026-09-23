// Independent CryptoKit fixture for the mobile Onym envelope format. Public test keys only.
import Foundation
import CryptoKit
let sender = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
let recipient = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32))
let ephemeral = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 11, count: 32))
let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient.publicKey)
let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data("sep-invitation-v1".utf8), sharedInfo: Data("aes-256-gcm".utf8), outputByteCount: 32)
let plaintext = Data("{\"body\":\"Привет из CryptoKit\"}".utf8)
let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: Data(repeating: 13, count: 12)))
let envelope: [String:Any] = ["version":1,"scheme":"x25519-aes-256-gcm-v1","ephemeral_public_key":ephemeral.publicKey.rawRepresentation.base64EncodedString(),"ephemeral_key_signature":try sender.signature(for:ephemeral.publicKey.rawRepresentation).base64EncodedString(),"sender_ed25519_public_key":sender.publicKey.rawRepresentation.base64EncodedString(),"nonce":Data(box.nonce).base64EncodedString(),"ciphertext":box.ciphertext.base64EncodedString(),"authentication_tag":box.tag.base64EncodedString()]
let out = try JSONSerialization.data(withJSONObject:envelope,options:[.sortedKeys])
print(String(data:out,encoding:.utf8)!)
