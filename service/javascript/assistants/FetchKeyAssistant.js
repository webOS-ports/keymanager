/*jslint node: true */
/*global getAppId, KeyStore */

var FetchKeyAssistant = function () {
    "use strict";
};

FetchKeyAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, future, appId;

    appId = getAppId(this.controller);
    if (!appId) {
        throw { erroCode: -1, message: "Could not determine appId."};
    }

    KeyStore.getKeyDecryptedByName(appId, args.keyname).then(function getCB(f) {
        var result = f.result;
        if (result.returnValue === true) {
            outerfuture.result = result;
        } else {
            outerfuture.exception = result;
        }
    });

    return outerfuture;
};
