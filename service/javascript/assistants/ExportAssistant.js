/*jslint node: true */
/*global  */

var ExportAssistant = function () {
    "use strict";
};

ExportAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args;

    outerfuture.exception = {errorCode: -1, message: "Not yet implemented." };
    return outerfuture;
};
