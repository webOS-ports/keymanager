/*jslint node: true */
/*global KeyStore, Future, getAppId */

/* Validate contact username/password */
var KeyInfoAssistant = function () {
    "use strict";
};

KeyInfoAssistant.prototype.run = function (outerfuture) {
    "use strict";
	var args = this.controller.args, future, appId;

    appId = getAppId(this.controller);
    if (!appId) {
        outerfuture.result = {returnValue: false, errorText: "Could not determine appId."};
        return outerfuture;
    }

    future = KeyStore.getKeyRawByName(appId, args.keyname);

    future.then(this, function getKeyCB() {
        var result = future.result;
        if (result.returnValue === true) {
            delete result.key.keydata;
            result.key.returnValue = true;
            outerfuture.result = result.key;
        } else {
            outerfuture.result = result;
        }
    });
};
