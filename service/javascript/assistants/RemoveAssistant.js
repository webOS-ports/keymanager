/*jslint node: true */
/*global KeyStore, getAppId */

/* Validate contact username/password */
var RemoveAssistant = function () {
    "use strict";
};

RemoveAssistant.prototype.run = function (outerfuture) {
    "use strict";
	var args = this.controller.args, appId;

    if (!args.keyname) {
        outerfuture.result = {returnValue: false, errorText: "Need keyname parameter."};
        return outerfuture;
    }

    appId = getAppId(this.controller);
    if (!appId) {
        outerfuture.result = {returnValue: false, errorText: "Could not determine appId."};
        return outerfuture;
    }

    outerfuture.result = KeyStore.deleteKey(appId, args.keyname);
    return outerfuture;
};
