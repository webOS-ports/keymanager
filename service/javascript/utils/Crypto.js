/* Keystore record encryption.
 *
 * Both key stores encrypt their records with the master key from
 * /var/palm/keystore/key. They used to do it with nodeCrypto.createCipher():
 *
 *     cipher = nodeCrypto.createCipher("AES-256-CBC", masterkey);
 *
 * That call was removed in node 22 (deprecated as DEP0106 since v10), so on a
 * current LuneOS every store() threw "nodeCrypto.createCipher is not a
 * function" and no credential could be saved at all.
 *
 * It was also poor even while it existed. createCipher derives the key and IV
 * from the password with EVP_BytesToKey: MD5, one iteration, no salt. That
 * makes the IV a function of the key, so the same plaintext always encrypts to
 * the same bytes, and CBC on its own is unauthenticated, so a modified record
 * decrypts to attacker-influenced garbage rather than being rejected.
 *
 * So records are now AES-256-GCM with a random IV each time and the tag stored
 * alongside, and the AES key is derived from the master key material with HKDF
 * rather than by hashing it once with MD5.
 *
 * Records written by the old scheme are still readable: decrypt() recognises
 * them by the absence of the magic below and reproduces EVP_BytesToKey itself,
 * since the API that used to do it is gone. Anything re-written after that is
 * stored in the new format, so a device migrates as it is used.
 */
/*jslint node: true, nomen: true */
/*global nodeCrypto */

var KeymanagerCrypto = (function () {
    "use strict";

    // "KM1\0". Chosen so it cannot collide with a legacy record: those are raw
    // AES-CBC ciphertext, a multiple of 16 bytes with no structure, and the
    // chance of one opening with these four bytes is 2^-32 - see isLegacy().
    var MAGIC = Buffer.from([0x4B, 0x4D, 0x31, 0x00]);
    var IV_BYTES = 12;      // GCM standard nonce length
    var TAG_BYTES = 16;
    var ALGORITHM = "aes-256-gcm";
    var HKDF_INFO = "keymanager keystore v1";

    /* Passphrase-encrypted export - see exportKeystore/importKeystore.
     *
     * A keystore record is encrypted with the device master key, which by
     * design does not survive a webOS Doctor and does not exist on another
     * handset. That is exactly why restoring a backup never brought passwords
     * back on legacy webOS: the ciphertext travelled and the key did not.
     *
     * An export therefore re-encrypts under something the *user* carries: a
     * passphrase they type at backup time and again at restore time. scrypt
     * because the input is a human passphrase and needs to be expensive to
     * guess - measured at ~340ms on a mindphone (armv7), which is a fair price
     * once per backup.
     */
    var EXPORT_VERSION = 1;
    var SCRYPT_N = 16384;
    var SCRYPT_R = 8;
    var SCRYPT_P = 1;
    var SALT_BYTES = 16;

    /**
     * A 32-byte AES key from the master key material, via HKDF-SHA256.
     *
     * The master key is 256 bytes of randomBytes - good material, wrong length.
     * HKDF is the right tool for that.
     *
     * Written out with createHmac rather than calling nodeCrypto.hkdfSync,
     * deliberately. hkdfSync only arrived in node 15, and branching on whether
     * it exists would mean the derivation - and therefore every stored record -
     * depended on which runtime happened to write it. A device that wrote its
     * store on one node and read it on another would find its keys
     * undecryptable. HMAC-SHA256 is available on every runtime this has ever
     * run on, so doing the two steps by hand keeps one answer everywhere.
     *
     * RFC 5869 with an all-zero salt and a single output block, which is all a
     * 32-byte key needs.
     */
    function deriveKey(masterkey) {
        var material = Buffer.isBuffer(masterkey) ? masterkey : Buffer.from(String(masterkey));
        var prk = nodeCrypto.createHmac("sha256", Buffer.alloc(32)).update(material).digest();

        return nodeCrypto.createHmac("sha256", prk)
            .update(Buffer.concat([Buffer.from(HKDF_INFO, "utf8"), Buffer.from([1])]))
            .digest();
    }

    /**
     * EVP_BytesToKey(MD5, count=1, no salt) - what createCipher used to do
     * internally, reimplemented because the API that did it no longer exists.
     * Only ever used to read records written before this change.
     */
    function legacyKeyAndIv(password, keyBytes, ivBytes) {
        var material = Buffer.isBuffer(password) ? password : Buffer.from(String(password));
        var out = Buffer.alloc(0);
        var block = Buffer.alloc(0);

        while (out.length < keyBytes + ivBytes) {
            block = nodeCrypto.createHash("md5").update(Buffer.concat([block, material])).digest();
            out = Buffer.concat([out, block]);
        }

        return {
            key: out.subarray(0, keyBytes),
            iv: out.subarray(keyBytes, keyBytes + ivBytes)
        };
    }

    function isLegacy(blob) {
        return !(Buffer.isBuffer(blob) && blob.length >= MAGIC.length &&
                blob.subarray(0, MAGIC.length).equals(MAGIC));
    }

    return {
        MAGIC: MAGIC,
        deriveKey: deriveKey,
        legacyKeyAndIv: legacyKeyAndIv,
        isLegacy: isLegacy,

        /**
         * Buffer in, self-describing Buffer out:
         *   MAGIC(4) | iv(12) | tag(16) | ciphertext
         * Throws rather than returning something unusable.
         */
        encrypt: function (masterkey, plaintext) {
            var key = deriveKey(masterkey);
            var iv = nodeCrypto.randomBytes(IV_BYTES);
            var cipher = nodeCrypto.createCipheriv(ALGORITHM, key, iv);
            var body = Buffer.concat([cipher.update(plaintext), cipher.final()]);

            return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), body]);
        },

        /**
         * A short, stable fingerprint of some key material.
         *
         * A wrapped key carries one so import can work out which of the
         * caller's keys unwraps it. The legacy service did the same - see
         * CWrappedKey::hashKey - which is why its import method takes only the
         * wrapped blob and no wrapping key name.
         */
        keyFingerprint: function (material) {
            var buf = Buffer.isBuffer(material) ? material : Buffer.from(String(material));
            return nodeCrypto.createHash("sha256").update(buf).digest().subarray(0, 16).toString("base64");
        },

        /**
         * Wrap one key's material with another key's material.
         *
         * This is what the legacy export/import pair did: a key is handed out
         * encrypted under a second key that both sides already share, rather
         * than under a passphrase. The original used AES-128-CBC via
         * CWrappedKey::wrap; this uses the same AEAD as everything else here.
         * The wire format is not byte-compatible with a webOS 3.0.5 device -
         * reproducing CWrappedKey::encode was not worth it for a format that
         * has no reader left - but the method contract is.
         */
        wrapKey: function (wrappingMaterial, plaintext) {
            var key = deriveKey(wrappingMaterial);
            var iv = nodeCrypto.randomBytes(IV_BYTES);
            var cipher = nodeCrypto.createCipheriv(ALGORITHM, key, iv);
            var body = Buffer.concat([cipher.update(plaintext), cipher.final()]);

            return {
                version: EXPORT_VERSION,
                cipher: ALGORITHM,
                wrappingKey: KeymanagerCrypto.keyFingerprint(wrappingMaterial),
                iv: iv.toString("base64"),
                tag: cipher.getAuthTag().toString("base64"),
                ciphertext: body.toString("base64")
            };
        },

        unwrapKey: function (wrappingMaterial, envelope) {
            if (!envelope || typeof envelope !== "object") {
                throw new Error("Malformed wrapped key: not an object");
            }
            if (envelope.version !== EXPORT_VERSION) {
                throw new Error("Unsupported wrapped key version: " + envelope.version);
            }

            var key = deriveKey(wrappingMaterial);
            var decipher = nodeCrypto.createDecipheriv(envelope.cipher || ALGORITHM, key,
                Buffer.from(envelope.iv, "base64"));

            decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
            return Buffer.concat([
                decipher.update(Buffer.from(envelope.ciphertext, "base64")),
                decipher.final()
            ]);
        },

        /**
         * Re-encrypt a buffer under a user passphrase, for a backup that has to
         * be readable on a different device.
         *
         * Returns a plain object rather than a buffer: it has to carry the KDF
         * parameters, and pinning them into a binary layout would mean a format
         * bump the first time they need raising. Every field is base64 so the
         * whole thing survives JSON and the Luna bus.
         */
        encryptWithPassphrase: function (passphrase, plaintext) {
            if (typeof passphrase !== "string" || passphrase.length === 0) {
                throw new Error("A passphrase is required to export the keystore");
            }

            var salt = nodeCrypto.randomBytes(SALT_BYTES);
            var key = nodeCrypto.scryptSync(passphrase, salt, 32,
                { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
            var iv = nodeCrypto.randomBytes(IV_BYTES);
            var cipher = nodeCrypto.createCipheriv(ALGORITHM, key, iv);
            var body = Buffer.concat([cipher.update(plaintext), cipher.final()]);

            return {
                version: EXPORT_VERSION,
                kdf: "scrypt",
                kdfParams: { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
                cipher: ALGORITHM,
                salt: salt.toString("base64"),
                iv: iv.toString("base64"),
                tag: cipher.getAuthTag().toString("base64"),
                ciphertext: body.toString("base64")
            };
        },

        /**
         * The inverse. A wrong passphrase and a tampered export both fail here
         * the same way - the GCM tag does not verify - which is the behaviour
         * we want: neither should ever yield plausible-looking output.
         */
        decryptWithPassphrase: function (passphrase, envelope) {
            if (typeof passphrase !== "string" || passphrase.length === 0) {
                throw new Error("A passphrase is required to import the keystore");
            }
            if (!envelope || typeof envelope !== "object") {
                throw new Error("Malformed export: not an object");
            }
            if (envelope.version !== EXPORT_VERSION) {
                throw new Error("Unsupported export version: " + envelope.version);
            }
            if (envelope.kdf !== "scrypt") {
                throw new Error("Unsupported key derivation: " + envelope.kdf);
            }

            var params = envelope.kdfParams || {};
            var key = nodeCrypto.scryptSync(passphrase, Buffer.from(envelope.salt, "base64"), 32,
                { N: params.N || SCRYPT_N, r: params.r || SCRYPT_R, p: params.p || SCRYPT_P });
            var decipher = nodeCrypto.createDecipheriv(envelope.cipher || ALGORITHM, key,
                Buffer.from(envelope.iv, "base64"));

            decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
            return Buffer.concat([
                decipher.update(Buffer.from(envelope.ciphertext, "base64")),
                decipher.final()
            ]);
        },

        /**
         * The inverse, transparently handling both formats.
         *
         * A new-format record whose ciphertext or tag has been altered throws:
         * that is the entire point of moving to an AEAD, so it must not be
         * softened into returning empty data.
         */
        decrypt: function (masterkey, blob) {
            var derived, legacy, decipher, iv, tag, body;

            if (!Buffer.isBuffer(blob)) {
                blob = Buffer.from(blob);
            }

            if (isLegacy(blob)) {
                legacy = legacyKeyAndIv(masterkey, 32, 16);
                decipher = nodeCrypto.createDecipheriv("aes-256-cbc", legacy.key, legacy.iv);
                return Buffer.concat([decipher.update(blob), decipher.final()]);
            }

            if (blob.length < MAGIC.length + IV_BYTES + TAG_BYTES) {
                throw new Error("Keystore record is too short to be valid");
            }

            iv = blob.subarray(MAGIC.length, MAGIC.length + IV_BYTES);
            tag = blob.subarray(MAGIC.length + IV_BYTES, MAGIC.length + IV_BYTES + TAG_BYTES);
            body = blob.subarray(MAGIC.length + IV_BYTES + TAG_BYTES);

            derived = deriveKey(masterkey);
            decipher = nodeCrypto.createDecipheriv(ALGORITHM, derived, iv);
            decipher.setAuthTag(tag);
            return Buffer.concat([decipher.update(body), decipher.final()]);
        }
    };
}());
