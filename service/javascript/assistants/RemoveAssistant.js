/*jslint node: true */
/*global KeyStore, getAppId */

var RemoveAssistant = function () {
    "use strict";
};

RemoveAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, appId;

    if (!args.keyname) {
        throw {errorCode: -1, errorText: "Need keyname parameter."};
    }

    appId = getAppId(this.controller);
    if (!appId) {
        throw {errorCode: -1, errorText: "Could not determine appId."};
    }

    outerfuture.result = KeyStore.deleteKey(appId, args.keyname);
    return outerfuture;
};
