/*jslint node: true */
/*global log, KeyStore, getAppId */

/* Validate contact username/password */
var StoreAssistant = function () {
    "use strict";
};

StoreAssistant.prototype.run = function (outerfuture) {
    "use strict";
	var args = this.controller.args, key = {}, appId;

    if (!args.keyname) {
        outerfuture.result = {returnValue: false, errorText: "Need keyname parameter"};
        return outerfuture;
    } else {
        key.keyname = args.keyname;
    }

    if (!args.keydata) {
        outerfuture.result = {returnValue: false, errorText: "Need keydata parameter"};
        return outerfuture;
    } else {
        key.keydata = args.keydata;
    }

    if (!args.type || (args.type !== "AES" &&
                       args.type !== "DES" &&
                       args.type !== "3DES" &&
                       args.type !== "HMACSHA1" &&
                       args.type !== "BLOB" &&
                       args.type !== "ASCIIBLOB")) {
        outerfuture.result = {returnValue: false, errorText: "Need valid type parameter"};
        return outerfuture;
    } else {
        key.type = args.type;
    }

    key.nohide = args.nohide;

    if (args.backup || args.cloud) {
        log("WARNING: backup and cloud backup not supported!");
    }

    appId = getAppId(this.controller);
    if (!appId) {
        outerfuture.result = {returnValue: false, errorText: "Could not determine appId."};
        return outerfuture;
    }

    KeyStore.putKey(appId, key).then(this, function putCB(future) {
        var result = future.result;
        outerfuture.result = result;
    });
};
