/*jslint node: true */
/*global KeyStore, Future, getAppId */

var KeyInfoAssistant = function () {
    "use strict";
};

KeyInfoAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, future, appId;

    appId = getAppId(this.controller);
    if (!appId) {
        throw {errorCode: -1, errorText: "Could not determine appId."};
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
