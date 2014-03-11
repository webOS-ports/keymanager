/* ServiceAssistant
* This assistant is called before anything within the service.
* It sets up the keystore decipher.
*/
/*jslint node: true */
/*global log, debug, fs, crypto, Future, KeyStore */

var keystoreFolder = "/var/palm/keystore/";
var keyFile = keystoreFolder + "key";
var keyStoreFile = keystoreFolder + "store.json";

var KeyManagerServiceAssistant = function () {
    "use strict";
};

KeyManagerServiceAssistant.prototype.setup = function () {
    "use strict";
    var future = new Future(), masterkey;

    fs.exists(keystoreFolder, function existsCB(exists) {
        if (!exists) {
            fs.mkdirSync(keystoreFolder);
        }
        future.result = { returnValue: true };
    });

    future.then(this, function dirCheckCB() {
        var result = future.result;
        future.nest(KeyStore.loadKey()); //let's try anyway.
    });

    future.then(this, function haveCiphersCB() {
        var result = future.result;
        future.nest(KeyStore.loadDatabase(keyStoreFile));
    });

    return future;
};