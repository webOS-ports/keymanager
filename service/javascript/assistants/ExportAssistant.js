/* export: hand one key out, wrapped with another key.
 *
 * This was a stub throwing "Not yet implemented.". The contract below is the
 * one the original webOS 3.0.5 keymanager binary implemented, recovered from a
 * decompile of /usr/bin/keymanager (build 86, 1.0-48.1) rather than guessed:
 *
 *     KeyServiceHandler::Export @ 0x00011c28
 *       getRequired(keyname)
 *       getappId(...)
 *       getRequired("wrappingkeyname")
 *       fetchKeyId(appId, keyname)  /  fetchKeyId(appId, wrappingkeyname)
 *       -> both must exist            ("unknown key")
 *       -> and must differ            ("same keys")
 *       exportWrappedKey(keyId, wrapKeyId)
 *       reply { returnValue: true, wrappedkey: "..." }
 *
 * So: a key is handed out encrypted under a *second key both sides already
 * share*, not under a passphrase. Both are looked up under the caller's own
 * appId, so an app can only ever wrap its own key with its own key.
 *
 * Not byte-compatible with a 3.0.5 device: the original wrapped with
 * AES-128-CBC through CWrappedKey::encode, and this uses the same AEAD as the
 * rest of the service. The method contract is what matters here - there is no
 * 3.0.5 device left to exchange wrapped keys with.
 *
 * The passphrase-based whole-store backup lives in exportKeystore, which is a
 * different job with a different access group.
 */
/*jslint node: true */
/*global getAppId, KeyStore, KeymanagerCrypto */

var ExportAssistant = function () {
    "use strict";
};

ExportAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, appId, target, wrappingMaterial, plaintext;

    if (!args.keyname) {
        throw {errorCode: -1, message: "Need keyname parameter"};
    }
    if (!args.wrappingkeyname) {
        throw {errorCode: -1, message: "Need wrappingkeyname parameter"};
    }
    if (args.keyname === args.wrappingkeyname) {
        // "same keys" in the original. Wrapping a key with itself protects
        // nothing: anyone who can unwrap it already has it.
        throw {errorCode: -1, message: "same keys"};
    }

    appId = getAppId(this.controller);
    if (!appId) {
        throw {errorCode: -1, message: "Could not determine appId."};
    }

    target = KeyStore.keyMaterial(appId, args.keyname);
    wrappingMaterial = KeyStore.keyMaterial(appId, args.wrappingkeyname);

    if (!target || !wrappingMaterial) {
        outerfuture.exception = {errorCode: -1, message: "unknown key"};
        return outerfuture;
    }

    // keyInfo reports a noexport flag; honour it. A key stored as
    // non-exportable must not leave through the method named "export".
    plaintext = KeyStore.exportKey(appId, args.keyname);
    plaintext.then(this, function keyCB(f) {
        var result = f.result, key;

        if (!result || result.returnValue !== true) {
            outerfuture.exception = {
                errorCode: -1,
                message: (result && result.message) || "unknown key"
            };
            return;
        }

        key = result.key;
        if (key.noexport === true) {
            outerfuture.exception = {errorCode: -1, message: "key is not exportable"};
            return;
        }

        try {
            outerfuture.result = {
                returnValue: true,
                wrappedkey: KeymanagerCrypto.wrapKey(wrappingMaterial,
                    Buffer.from(JSON.stringify(key), "utf-8"))
            };
        } catch (e) {
            outerfuture.exception = {errorCode: -1, message: e.message};
        }
    });

    return outerfuture;
};
