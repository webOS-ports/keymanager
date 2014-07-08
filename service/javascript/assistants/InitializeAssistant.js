/*jslint node: true */
/*global log */

var InitializeAssistant = function () {
    "use strict";
};

InitializeAssistant.prototype.run = function (outerfuture) {
    "use strict";

    var args = this.controller.args;

    log("WARNING: initialize was called with arguments " + JSON.stringify(args));

    outerfuture.exception = {errorCode: -1, errorText: "Not yet implemented." };
    return outerfuture;
};
