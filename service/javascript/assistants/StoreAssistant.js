/*jslint node: true */
/*global log, KeyStore, getAppId */

var StoreAssistant = function () {
    "use strict";
};

StoreAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, key = {}, appId;

    if (!args.keyname) {
        throw {errorCode: -1, message: "Need keyname parameter"};
    } else {
        key.keyname = args.keyname;
    }

    if (!args.keydata) {
        throw {errorCode: -1, message: "Need keydata parameter"};
    } else {
        key.keydata = args.keydata;
    }

    if (!args.type || (args.type !== "AES" &&
                       args.type !== "DES" &&
                       args.type !== "3DES" &&
                       args.type !== "HMACSHA1" &&
                       args.type !== "BLOB" &&
                       args.type !== "ASCIIBLOB")) {
        throw {errorCode: -1, message: "Need valid type parameter"};
    } else {
        key.type = args.type;
    }

    key.nohide = args.nohide;

    if (args.backup || args.cloud) {
        log("WARNING: backup and cloud backup not supported!");
    }

    appId = getAppId(this.controller);
    if (!appId) {
        throw {errorCode: -1, message: "Could not determine appId."};
    }

    KeyStore.putKey(appId, key).then(this, function putCB(future) {
        var result = future.result;
        if (result.returnValue === true) {
            outerfuture.result = result;
        } else {
            outerfuture.exception = result;
        }
    });
};
