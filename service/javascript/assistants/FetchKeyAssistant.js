/*jslint node: true */
/*global getAppId, KeyStore */

/* Validate contact username/password */
var FetchKeyAssistant = function () {
    "use strict";
};

FetchKeyAssistant.prototype.run = function (outerfuture) {
    "use strict";
	var args = this.controller.args, future, appId;

    appId = getAppId(this.controller);
    if (!appId) {
        outerfuture.result = {returnValue: false, errorText: "Could not determine appId."};
        return outerfuture;
    }

    outerfuture.nest(KeyStore.getKeyDecryptedByName(appId, args.keyname));

    return outerfuture;
};
