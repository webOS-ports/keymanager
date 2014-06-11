global.Queue = require('/home/koenigs/Private/Download/webOS/queue.js').Queue;
global.Future = require('/home/koenigs/Private/Download/webOS/future.js').Future;
global.Assert = require('/home/koenigs/Private/Download/webOS/assert.js').Assert;

global.keyStoreFile = "/tmp/test.sqlite";

global.log = console.log;
global.debug = console.log;

var KeyStore = require('/home/koenigs/Private/Download/webOS/keymanager/service/javascript/utils/KeyStoreSQLite.js');

var future = KeyStore.loadDatabase();

future.then(function () {
    var result = future.result;
    console.log("Result: ", result);
});
