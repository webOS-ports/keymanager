/*jslint node: true */
/*global getAppId, KeyStore, crypto, log */

/* Validate contact username/password */
var GenerateAssistant = function () {
    "use strict";
};

GenerateAssistant.prototype.run = function (outerfuture) {
    "use strict";
	var args = this.controller.args, appId, key = {}, future;

    appId = getAppId(this.controller);
    if (!appId) {
        outerfuture.result = { returnValue: false, errorText: "Could not determine appId."};
        return outerfuture;
    }

    if (!args.keyname) {
        outerfuture.result = {returnValue: false, errorText: "Need keyname parameter"};
        return outerfuture;
    } else {
        key.keyname = args.keyname;
    }

    if (!args.type || (args.type !== "AES" &&
                       args.type !== "DES" &&
                       args.type !== "3DES" &&
                       args.type !== "HMACSHA1")) {
        outerfuture.result = {returnValue: false, errorText: "Need valid type parameter"};
        return outerfuture;
    } else {
        key.type = args.type;
    }

    if (!args.size) {
        outerfuture.result = {returnValue: false, errorText: "Need valid size parameter"};
        return outerfuture;
    } else if ((key.type === "DES" || key.type === "3DES") && args.size !== 24) {
        outerfuture.result = {returnValue: false, errorText: "Need valid size parameter, (3)DES can only be 24 byte."};
        return outerfuture;
    } else if (key.type === "AES" && args.size !== 16 && args.size !== 24 && args.size !== 32) {
        outerfuture.result = {returnValue: false, errorText: "Need valid size parameter, AES can only be 16, 24 or 32 byte."};
        return outerfuture;
    } else {
        key.size = args.size;
    }

    key.nohide = args.nohide;

    future = KeyStore.getKeyRawByName(appId, key.keyname);

    future.then(this, function getKeyCB() {
        var result = future.result;
        if (result.returnValue === true) {
            outerfuture.result = { returnValue: false, errorText: "Key already exists."};
        } else {
            crypto.randomBytes(key.size, function radomCB(ex, buf) {
                if (ex) {
                    log("Could not create random key:", ex);
                    outerfuture.result = { returnValue: false, errorText: "Could not create random key: " + JSON.stringify(ex) };
                } else {
                    key.keydata = buf.toString("base64");
                    outerfuture.nest(KeyStore.putKey(appId, key));
                }
            });
        }
    });
};
