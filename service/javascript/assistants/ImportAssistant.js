/*jslint node: true */
/*global  */

var ImportAssistant = function () {
    "use strict";
};

ImportAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args;

    outerfuture.result = {returnValue: false, errorText: "Not yet implemented." };
    return outerfuture;
};
