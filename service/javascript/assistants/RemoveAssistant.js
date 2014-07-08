/*jslint node: true */
/*global KeyStore, getAppId */

var RemoveAssistant = function () {
    "use strict";
};

RemoveAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, appId;

    if (!args.keyname) {
        throw {errorCode: -1, message: "Need keyname parameter."};
    }

    appId = getAppId(this.controller);
    if (!appId) {
        throw {errorCode: -1, message: "Could not determine appId."};
    }

    KeyStore.deleteKey(appId, args.keyname).then(function delCB(f) {
        var result = f.result;
        if (result.returnValue === true) {
            debug("Remove success: ", args.keyname);
            outerfuture.result = result;
        } else {
            debug("Remove failure: ", args.keyname, " result: ", JSON.stringify(result));
            outerfuture.exception = result;
        }
    });
    return outerfuture;
};
