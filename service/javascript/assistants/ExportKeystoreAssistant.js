/* exportKeystore: hand the whole keystore over, encrypted under a passphrase.
 *
 * This exists so a backup can restore passwords. Keystore records are encrypted
 * with a device master key that does not survive a webOS Doctor and does not
 * exist on another handset, so a backup of the raw store restores to nothing
 * usable - which is precisely why legacy webOS always made you re-enter every
 * password after a restore.
 *
 * The passphrase is the user's, supplied at backup time and again at restore
 * time, so the only thing that has to travel between devices is something they
 * carry in their head.
 *
 * The reply carries the export inline rather than writing it to a path the
 * caller names. It is a few kilobytes, and taking a path here would mean this
 * service - running as root - writing wherever a caller asked.
 *
 * A key stored with noexport is left out: the flag says the key must not leave
 * the device, and a backup is a copy leaving for another one. It is reported in
 * `excluded` rather than quietly skipped.
 *
 * ACCESS
 * ------
 * This returns every credential on the device in one call, so unlike the rest
 * of the API it is NOT in keymanager-service.operation, which many callers
 * hold. It sits in keymanager-service.backup, granted to the backup service
 * alone. Anything else asking for it is refused by the hub before it reaches
 * this file.
 */
/*jslint node: true */
/*global KeyStore, KeymanagerCrypto, log */

var ExportKeystoreAssistant = function () {
    "use strict";
};

ExportKeystoreAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, future;

    if (typeof args.passphrase !== "string" || args.passphrase.length === 0) {
        throw {errorCode: -1, message: "Need passphrase parameter"};
    }

    future = KeyStore.exportAll();

    future.then(this, function exportCB() {
        var result = future.result, envelope;

        if (!result || result.returnValue !== true) {
            outerfuture.exception = {
                errorCode: -1,
                message: (result && result.message) || "Could not read the keystore."
            };
            return;
        }

        try {
            envelope = KeymanagerCrypto.encryptWithPassphrase(
                args.passphrase,
                Buffer.from(JSON.stringify(result.keys), "utf-8")
            );
        } catch (e) {
            outerfuture.exception = {errorCode: -1, message: e.message};
            return;
        }

        log("Exported " + result.count + " key(s), " + result.failed.length +
            " unreadable, " + result.excluded.length + " excluded by noexport.");

        outerfuture.result = {
            returnValue: true,
            count: result.count,
            // Both named so the caller can record what did not make it rather
            // than discovering the gap at restore time - and so the two reasons
            // stay distinguishable: `unreadable` is a damaged record, `excluded`
            // is a key the owner marked as one that must not leave the device.
            unreadable: result.failed,
            excluded: result.excluded,
            keystore: envelope
        };
    });

    return outerfuture;
};
