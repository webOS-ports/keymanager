/*jslint node: true */

var pathToFoundations = "./";

global.fs = require("fs"); //required for own node modules and current vCard converter.
global.crypto = require("crypto");

global.Queue = require(pathToFoundations + "queue.js").Queue;
global.Future = require(pathToFoundations + "future.js").Future;
global.Assert = require(pathToFoundations + "assert.js").Assert;

global.keyFile = "key.json";
global.keyStoreFile = "test.sqlite";

global.log = console.log;
global.debug = console.log;

var KeyStore = require("./service/javascript/utils/KeyStoreSQLite.js");

var future = KeyStore.loadDatabase();

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-loadDatabase: ", result);

    future.nest(KeyStore.loadKey());
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-loadKey: ", result);

    future.nest(KeyStore.putKey("org.webosports.test", {
        keyname: "testkey",
        type: "AES",
        size: 32,
        nohide: true,
        keydata: new Buffer("1222345678901234567890123456789032").toString("base64")
    }));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-putkey: ", result);

    future.nest(KeyStore.deleteKey("org.webosports.test", "testkey"));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-delkey: ", result);

    future.nest(KeyStore.putKey("org.webosports.test", {
        keyname: "testkey",
        type: "AES",
        size: 32,
        nohide: true,
        keydata: new Buffer("1222345678901234567890123456789032").toString("base64")
    }));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-putkey2: ", result);

    future.nest(KeyStore.getKeyRawByName("org.webosports.test", "testkey"));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-getRawByName: ", result);
    console.log("type: ", typeof result.key.keydata);
    console.log("class: ", result.key.keydata instanceof Buffer);

    future.nest(KeyStore.getKeyDecryptedByName("org.webosports.test", "testkey"));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-getDecryptedByName: ", result);

    future.nest(KeyStore.deleteKey("org.webosports.test", "testBlob"));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-deleteblob: ", result);

    var data = {
        blub: "schlubbelb blub.",
        data: 123124123541234,
        object: {
            schlupp: "1232"
        }
    };

    future.nest(KeyStore.putKey("org.webosports.test", {
        keyname: "testBlob",
        type: "BLOB",
        nohide: true,
        keydata: new Buffer(JSON.stringify(data)).toString("base64")
    }));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-putkey3: ", result);

    future.nest(KeyStore.getKeyRawByName("org.webosports.test", "testBlob"));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-getRawByName2: ", result);
    console.log("type: ", typeof result.key.keydata);
    console.log("class: ", result.key.keydata instanceof Buffer);

    future.nest(KeyStore.getKeyDecryptedByName("org.webosports.test", "testBlob"));
});

future.then(function () {
    "use strict";
    var result = future.result;
    console.log("Result-getDecryptedByName2: ", result);

    console.log("Blob: ", new Buffer(result.keydata, "base64").toString("utf8"));
});
