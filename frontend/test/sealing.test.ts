// @vitest-environment node
// Credentials sealed in the browser (lib/sealing.ts): the envelope is
// byte-for-byte what the server's code makes (sdk/testdata/trust-vectors.json,
// from backend/scripts/trust_vectors.py) - so the proxy opens it
// (proxy/internal/egress/sealed_test.go checks the same vectors in Go) - and a
// proxy's encryption key is used only with its own signing key's signature.

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { proxyKeyHolds, seal, x25519, type ProxyKey } from "@/lib/sealing";

const V = JSON.parse(readFileSync(path.resolve(__dirname, "../../sdk/testdata/trust-vectors.json"), "utf8"));
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const b64 = (b: Uint8Array | ArrayBuffer) => Buffer.from(b instanceof ArrayBuffer ? new Uint8Array(b) : b).toString("base64");

describe("X25519", () => {
  it("matches RFC 7748", () => {
    const k = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    const u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    expect(Buffer.from(x25519(k, u)).toString("hex")).toBe(
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  });
});

describe("sealing", () => {
  it("makes exactly the envelope the server's code makes", async () => {
    const c = V.sealed.find((x: { name: string }) => x.name === "made by the browser");
    const env = await seal(c.credential, c.encryption_key, c.context, unb64(c.ephemeral), unb64(c.nonce));
    expect(env).toEqual(c.envelope);
  });

  it("uses a proxy's encryption key only with its signing key's signature", async () => {
    const c = V.sealed[0];
    // the proxy's signing key from its seed (PKCS#8 for Ed25519)
    const pkcs8 = new Uint8Array([...hex("302e020100300506032b657004220420"), ...unb64(c.proxy_seed)]);
    const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", priv);
    const pub = b64(Buffer.from(jwk.x as string, "base64url"));
    const sig = b64(await crypto.subtle.sign({ name: "Ed25519" }, priv, new TextEncoder().encode(c.key_statement)));
    const fp = async (k: string) => "SHA256:" + b64(await crypto.subtle.digest("SHA-256", unb64(k))).replace(/=+$/, "");
    const key: ProxyKey = {
      proxy_id: 2, org_id: 1, name: "p", public_key: pub, key_fingerprint: await fp(pub),
      encryption_key: c.encryption_key, encryption_key_signature: sig, encryption_key_fingerprint: await fp(c.encryption_key),
    };
    expect(await proxyKeyHolds(key)).toBe(true);
    // a key the server swapped in, or a signature by another key, is refused
    const other = b64(crypto.getRandomValues(new Uint8Array(32)));
    expect(await proxyKeyHolds({ ...key, encryption_key: other, encryption_key_fingerprint: await fp(other) })).toBe(false);
    const stranger = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const forged = b64(await crypto.subtle.sign({ name: "Ed25519" }, stranger.privateKey, new TextEncoder().encode(c.key_statement)));
    expect(await proxyKeyHolds({ ...key, encryption_key_signature: forged })).toBe(false);
    expect(await proxyKeyHolds({ ...key, key_fingerprint: "SHA256:other" })).toBe(false);
  });
});
