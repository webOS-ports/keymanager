/*jslint node: true, nomen: true */
/*global Future, log, debug, fs, keyStoreFile, keyFile */

var crypto = require("crypto");
var sqlite3 = require("sqlite3").verbose();


var KeyStore = (function () {
    "use strict";
    var database,
        masterkey = "";

    function saveDB() {
        fs.writeFile(keyStoreFile, JSON.stringify(database), function writeCB(err) {
            if (err) {
                log("Could not write keydb file:", err);
            } else {
                log("Keydb saved.");
            }
        });
    }

    function _crypt(decrypt, inData) {
        var future = new Future(), cipher, data = new Buffer("");
        if (decrypt) {
            cipher = crypto.createDecipher("AES-256-CBC", masterkey);
        } else {
            cipher = crypto.createCipher("AES-256-CBC", masterkey);
        }

        cipher.on("data", function dataCB(chunk) {
            debug("Got chunk: ", chunk, " with length ", chunk.length);
            data = Buffer.concat([data, chunk]);
        });

        cipher.on("end", function endCB() {
            //done reading.
            debug("End reading, have ", data.length, " bytes of data.");
            future.result = { returnValue: true, data: data };
        });

        debug("Writing ", inData.length, " bytes of data.");
        cipher.write(inData);
        cipher.end(); //should trigger end cb.

        return future;
    }

    function decrypt(data) {
        return _crypt(true, data);
    }

    function encrypt(data) {
        return _crypt(false, data);
    }

    return {
        copyKey: function (dest, from) {
            var props = Object.getOwnPropertyNames(from);
            debug("Own property names: ", props);
            props.forEach(function (name) {
                if (!dest[name]) {
                    if (Buffer.isBuffer(from[name])) {
                        dest[name] = new Buffer(from[name].length);
                        from[name].copy(dest[name]);
                    } else if (typeof from[name] === "object") {
                        dest[name] = KeyStore.copyKey({}, from[name]);
                    } else {
                        dest[name] = from[name];
                    }
                }
            });
            return dest;
        },

        getKeyRawByName: function (appid, keyname) {
            var future = new Future(),
                appStore,
                key;

            appStore = database[appid];
            debug("Got appstore: ", appStore);

            if (appStore && appStore[keyname]) {
                key = KeyStore.copyKey({}, appStore[keyname]);
                debug("Got key: ", key);
                future.result = {
                    key: key,
                    returnValue: true
                };
            } else {
                debug("No key found.");
                future.result = { returnValue: false, errorText: "Key not found" };
            }

            return future;
        },

        getKeyDecryptedByName: function (appid, keyname) {
            var future = KeyStore.getKeyRawByName(appid, keyname);

            future.then(this, function rawCB() {
                var result = future.result, cData, key;
                debug("Got raw result:", result);
                if (result.returnValue === true) {
                    key = result.key;
                    if (key.nohide) {
                        cData = new Buffer(key.keydata); //we store keydata as buffer array.
                        debug("ciphered: ", cData.toString("utf-8"));
                        decrypt(cData).then(this, function decryptCB(f2) {
                            var r2 = f2.result;
                            if (r2.returnValue === true) {
                                if (key.type === "ASCIIBLOB") {
                                    key.keydata = r2.data.toString("utf-8");
                                } else {
                                    key.keydata = r2.data.toString("base64");
                                }
                                debug("deciphered: ", key.keydata);
                                key.returnValue = true;
                                future.result = key;
                            }
                        });
                    } else {
                        //nohide is false, delete keydata.
                        delete result.key.keydata;
                        result.key.returnValue = true;
                        future.result = result.key;
                    }
                } else {
                    future.result = {returnValue: false, errorText: result.errorText};
                }
            });

            return future;
        },

        putKey: function (appid, key) {
            var future = new Future(), appstore, cData, dData;

            if (!appid || !key || !key.keyname) {
                future.result = { returnValue: false, errorText: "Need appid, key and keyname."};
                return future;
            }

            appstore = database[appid];
            if (!appstore) {
                appstore = {};
                database[appid] = appstore;
            }
            debug("Got appstore:", appstore);

            if (appstore[key.keyname]) {
                future.result = { returnValue: false, errorText: "Key already exists."};
                return future;
            }

            if (key.type === "ASCIIBLOB") {
                cData = new Buffer(key.keydata, "utf-8");
            } else {
                cData = new Buffer(key.keydata, "base64");
            }
            future.nest(encrypt(cData));

            future.then(this, function cryptCB() {
                var result = future.result;
                if (result.returnValue === true) {
                    debug("Unciphered: ", cData.toString("utf-8"));
                    debug("Ciphered: ", result.data.toString("utf-8"));
                    key.keydata = result.data; //we store the raw buffer

                    appstore[key.keyname] = key;
                    saveDB();

                    future.result = {returnValue: true};
                } else {
                    log("Could not encrypt.");
                    future.result = {returnValue: false, errorTest: "Could not encrypt key."};
                }
            });

            return future;
        },

        deleteKey: function (appid, keyname) {
            var appstore = database[appid];

            if (appstore) {
                if (appstore[keyname]) {
                    delete appstore[keyname];
                    saveDB();
                    return { returnValue: true };
                } else {
                    return {returnValue: false, errorText: "Key not found."};
                }
            } else {
                return {returnValue: false, errorText: "Key not found."};
            }
        },

        loadDatabase: function () {
            var future = new Future();

            database = new sqlite3.Database(keyStoreFile);

            database.on("error", function (err) {
                log("Error opening database: ", err);
                future.result = { retrunValue: false, error: err };
            });

            database.on("open", function () {
                future.result = { returnValue: true };
            });

            future.then(function openCB() {
                var result = future.result;
                if (result.returnValue) {
                    //check if table already exists:
                    database.all("SELECT name FROM sqlite_master WHERE type='table'", function checkTableCB(err, rows) {
                        if (err) {
                            future.result = { returnValue: false, error: err };
                        } else {
                            debug("Got rows from check if table is there: ", rows);
                            //decide how to go on, if table is there, finish, if not, create tables.
                            future.result = { returnValue: true, createTable: rows.length === 0 };
                        }
                    });
                } else {
                    future.result = result;
                }
            });

            //create table, if not present:
            future.then(function checkTableCB() {
                var result = future.result;
                if (result.returnValue && result.createTable) {
                    database.run("CREATE TABLE keytableconfig(id INTEGER PRIMARY KEY,data BLOB,dataLength INTEGER,iv BLOB,ivLength INTEGER);");

                    database.run("CREATE TABLE keytable(id INTEGER PRIMARY KEY,ownerID TEXT,keyID TEXT,data BLOB,keysize INTEGER,type INTEGER,scope INTEGER, hash BLOB);", function (err) {
                        future.result = {returnValue: !err, error: err};
                    });
                } else {
                    future.result = result;
                }
            });

            return future;
        },

        loadKey: function () {
            var future = new Future();
            fs.readFile(keyFile, function fileReadCB(err, data) {
                if (err) {
                    //generate random key:
                    debug("No file. Generating random key. Error was:", err);
                    crypto.randomBytes(256, function radomCB(ex, buf) {
                        if (ex) {
                            log("Could not create random key:", ex);
                            future.result = { returnValue: false };
                        } else {
                            masterkey = buf;
                            future.result = {returnValue: true};
                            fs.writeFile(keyFile, masterkey, function writeCB(err) {
                                if (err) {
                                    log("Could not write key file:", err);
                                } else {
                                    log("Keyfile saved.");
                                }
                            });
                        }
                    });
                } else {
                    debug("Read key with length " + data.length + " from file.");
                    masterkey = data;
                    future.result = {returnValue: true};
                }
            });
            return future;
        }
    };
}());

module.exports = KeyStore;
