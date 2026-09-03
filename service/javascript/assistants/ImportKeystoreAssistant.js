/* importKeystore: put an exportKeystore result back.
 *
 * Each record is re-encrypted under *this* device's master key as it is stored,
 * which is what makes an export portable: the passphrase carries it across, the
 * device key takes over once it lands.
 *
 * Existing keys are left alone unless overwrite is set. Restoring onto a device
 * that already has credentials should not quietly replace a working password
 * with an older one out of a backup.
 *
 * A wrong passphrase and a tampered export fail identically here - the GCM tag
 * does not verify - and both are reported as a failure rather than as an empty
 * import, so the caller can tell the user to try the passphrase again instead
 * of silently restoring nothing.
 *
 * Access: keymanager-service.backup, not the general operation group. See
 * ExportKeystoreAssistant.
 */
/*jslint node: true */
/*global KeyStore, KeymanagerCrypto, log */

var ImportKeystoreAssistant = function () {
    "use strict";
};

ImportKeystoreAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, plaintext, keys, future;

    if (typeof args.passphrase !== "string" || args.passphrase.length === 0) {
        throw {errorCode: -1, message: "Need passphrase parameter"};
    }
    if (!args.keystore || typeof args.keystore !== "object") {
        throw {errorCode: -1, message: "Need keystore parameter"};
    }

    try {
        plaintext = KeymanagerCrypto.decryptWithPassphrase(args.passphrase, args.keystore);
    } catch (e) {
        // Deliberately not distinguishing "wrong passphrase" from "damaged
        // export": with an AEAD they are the same event, and guessing between
        // them for the user's benefit would mean claiming to know which.
        outerfuture.exception = {
            errorCode: -1,
            message: "Could not decrypt the export - wrong passphrase, or the export is damaged."
        };
        return outerfuture;
    }

    try {
        keys = JSON.parse(plaintext.toString("utf-8"));
    } catch (e2) {
        outerfuture.exception = {errorCode: -1, message: "Export decrypted but does not parse."};
        return outerfuture;
    }

    future = KeyStore.importAll(keys, args.overwrite === true);

    future.then(this, function importCB() {
        var result = future.result;

        if (!result || result.returnValue !== true) {
            outerfuture.exception = {
                errorCode: -1,
                message: (result && result.message) || "Could not import the keystore."
            };
            return;
        }

        log("Imported " + result.imported + " key(s), skipped " + result.skipped +
            ", failed " + result.failed.length + ".");

        outerfuture.result = {
            returnValue: true,
            imported: result.imported,
            skipped: result.skipped,
            failed: result.failed
        };
    });

    return outerfuture;
};
