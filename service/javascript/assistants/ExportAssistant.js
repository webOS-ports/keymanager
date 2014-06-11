/*jslint node: true */
/*global  */

var ExportAssistant = function () {
    "use strict";
};

ExportAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args;

    outerfuture.result = {returnValue: false, errorText: "Not yet implemented." };
    return outerfuture;
};
