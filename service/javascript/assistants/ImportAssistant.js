/* import: put back a key produced by export.
 *
 * Contract recovered from the 3.0.5 binary alongside Export - see the note
 * there:
 *
 *     KeyServiceHandler::Import @ 0x00013c38
 *       getappId(...)
 *       getRequired("wrappedkey")
 *       InBackup(...)   -> refuse while a backup is running
 *       addWrappingKey(...)
 *       importWrappedKey(wrappedkey)
 *       keyInfo(keyId)
 *       reply { returnValue: true, keyname: "..." }
 *
 * Note what is *not* there: no wrapping key name. The wrapped blob identifies
 * its own wrapping key - the original hashed it in CWrappedKey::hashKey - so
 * import finds the right one among the caller's keys itself. This does the
 * same, matching on the fingerprint wrapKey records.
 *
 * The key lands in the caller's own appId, which is the appId the original
 * looked up before doing anything else.
 */
/*jslint node: true */
/*global getAppId, KeyStore, KeymanagerCrypto */

var ImportAssistant = function () {
    "use strict";
};

ImportAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, appId, wrapping, plaintext, key, future;

    if (!args.wrappedkey || typeof args.wrappedkey !== "object") {
        throw {errorCode: -1, message: "Need wrappedkey parameter"};
    }

    appId = getAppId(this.controller);
    if (!appId) {
        throw {errorCode: -1, message: "Could not determine appId."};
    }

    wrapping = KeyStore.findKeyByFingerprint(appId, args.wrappedkey.wrappingKey);
    if (!wrapping) {
        // The original's "wrapping key missing".
        outerfuture.exception = {errorCode: -1, message: "wrapping key missing"};
        return outerfuture;
    }

    try {
        plaintext = KeymanagerCrypto.unwrapKey(wrapping.material, args.wrappedkey);
    } catch (e) {
        outerfuture.exception = {
            errorCode: -1,
            message: "Could not unwrap the key - wrong wrapping key, or the export is damaged."
        };
        return outerfuture;
    }

    try {
        key = JSON.parse(plaintext.toString("utf-8"));
    } catch (e2) {
        outerfuture.exception = {errorCode: -1, message: "Wrapped key unwrapped but does not parse."};
        return outerfuture;
    }

    // Not in the original, which had no such parameter: an explicit keyname
    // lets a key be brought in under a new name, and overwrite lets it replace
    // one that is already there. Both default to the conservative behaviour.
    if (args.keyname) {
        key.keyname = args.keyname;
    }

    future = KeyStore.importKey(appId, key, args.overwrite === true);

    future.then(this, function importCB() {
        var result = future.result;

        if (!result || result.returnValue !== true) {
            outerfuture.exception = {
                errorCode: -1,
                message: (result && result.message) || "Could not import key."
            };
            return;
        }

        outerfuture.result = { returnValue: true, keyname: key.keyname };
    });

    return outerfuture;
};
