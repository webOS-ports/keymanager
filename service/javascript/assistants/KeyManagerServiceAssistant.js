/* ServiceAssistant
* This assistant is called before anything within the service.
* It sets up the keystore decipher.
*/
/*jslint node: true */
/*global log, debug, fs, crypto, Future, KeyStore */

var keystoreFolder = "/var/palm/keystore/";
var keyFile = keystoreFolder + "key";
var keyStoreFile = keystoreFolder + "store.db";

var KeyManagerServiceAssistant = function () {
    "use strict";
};

KeyManagerServiceAssistant.prototype.setup = function () {
    "use strict";
    var future = new Future(), masterkey;

    fs.exists(keystoreFolder, function existsCB(exists) {
        if (!exists) {
            fs.mkdir(keystoreFolder, function (err) {
                if (err) {
                    future.exception = {errorCode: -1, message: JSON.stringify(err)};
                } else {
                    future.result = { returnValue: true };
                }
            });
        } else {
            future.result = { returnValue: true };
        }
    });

    future.then(this, function dirCheckCB() {
        var result = future.result;
        if (result.returnValue) {
            future.nest(KeyStore.loadKey()); //let's try anyway.
        } else {
            future.result = result;
        }
    });

    future.then(this, function haveCiphersCB() {
        var result = future.result;
        if (result.returnValue) {
            future.nest(KeyStore.loadDatabase(keyStoreFile));
        } else {
            future.result = result;
        }
    });

    return future;
};
