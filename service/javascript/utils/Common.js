/*global debug */

function getAppId(controller) {
    "use strict";
    var appId = controller.message.applicationID().split(" ")[0];
    if (!appId) {
        appId = controller.message.senderServiceName();
    }

    debug("AppId ", appId, " from ", controller.message.applicationID(), " && ", controller.message.senderServiceName());

    return appId;
}
