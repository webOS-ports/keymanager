/*jslint node: true, nomen: true */
/*global Future, log, debug, fs, keyStoreFile, keyFile, crypto */

var KeyStore = (function () {
    "use strict";
    var database = {},
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
                if (!Buffer.isBuffer(key.keydata)) {
                    debug("Have to create buffer from keydata.");
                    key.keydata = new Buffer(key.keydata.data);
                }
                future.result = {
                    key: key,
                    returnValue: true
                };
            } else {
                debug("No key found.");
                future.result = { returnValue: false, message: "Key not found" };
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
                    future.result = {returnValue: false, message: result.message};
                }
            });

            return future;
        },

        putKey: function (appid, key) {
            var future = new Future(), appstore, cData, dData;

            if (!appid || !key || !key.keyname) {
                future.result = { returnValue: false, message: "Need appid, key and keyname."};
                return future;
            }

            appstore = database[appid];
            if (!appstore) {
                appstore = {};
                database[appid] = appstore;
            }
            debug("Got appstore:", appstore);

            if (appstore[key.keyname]) {
                future.result = { returnValue: false, message: "Key already exists."};
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
            var appstore = database[appid], future = new Future();

            if (appstore) {
                if (appstore[keyname]) {
                    delete appstore[keyname];
                    saveDB();
                    future.result = {returnValue: true};
                } else {
                    future.result = {returnValue: false, message: "Key not found."};
                }
            } else {
                future.result = {returnValue: false, message: "Key not found."};
            }

            return future;
        },

        loadDatabase: function () {
            var future = new Future();
            fs.exists(keyStoreFile, function existsCB(exists) {
                if (exists) {
                    fs.readFile(keyStoreFile, function fileReadCB(err, data) {
                        if (err) {
                            log("Could not read store file. Error: ", err);
                        } else {
                            try {
                                database = JSON.parse(data.toString("utf-8"));
                                debug("Read keystore from disk.");
                            } catch (e) {
                                log("Could not read keystore from file: " + e.stack);
                                log("Creating fresh keystore, expect issues.");
                                database = {};
                            }
                            future.result = { returnValue: true };
                        }
                    });
                } else {
                    //initialize fresh db.
                    debug("No keystore file, creating new store.");
                    database = {};
                    future.result = { returnValue: false };
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
