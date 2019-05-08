/*jslint node: true, nomen: true */
/*global Future, log, debug, fs, keyStoreFile, keyFile */

var crypto = require("crypto");
var sqlite3 = require("sqlite3").verbose();


var KeyStore = (function () {
    "use strict";
    var database,
        masterkey = "",
        typesToString = { 1: "AES", 2: "DES", 3: "3DES", 4: "HMACSHA1", 5: "BLOB", 6: "ASCIIBLOB" },
        stringToType = { AES: 1, DES: 2, "3DES": 3, HMACSHA1: 4, BLOB: 5, ASCIIBLOB: 6};

    function _crypt(decrypt, inData) {
        var future = new Future(), cipher, data = new Buffer.from("");
        if (decrypt) {
            cipher = crypto.createDecipher("AES-256-CBC", masterkey);
        } else {
            cipher = crypto.createCipher("AES-256-CBC", masterkey);
        }

        cipher.on("data", function dataCB(chunk) {
            //debug("Got chunk: ", chunk, " with length ", chunk.length);
            data = Buffer.concat([data, chunk]);
        });

        cipher.on("end", function endCB() {
            //done reading.
            //debug("End reading, have ", data.length, " bytes of data.");
            future.result = { returnValue: true, data: data };
        });

        //debug("Writing ", inData.length, " bytes of data.");
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
        //be careful: does not care for nohide! => can oppose (encrypted) key.
        getKeyRawByName: function (appid, keyname) {
            var future = new Future();
            if (!appid || !keyname) {
                future.result = { returnValue: false, errorCode: -1, message: "Need appid and keyname."};
                return future;
            }

            database.get("SELECT * FROM keytable WHERE ownerID IS $ownerID AND keyID IS $keyID", {
                $ownerID: appid,
                $keyID: keyname
            }, function getCB(err, row) {
                if (err) {
                    future.result = { returnValue: false, errorCode: -1, message: JSON.stringify(err)};
                } else if (!row) {
                    future.result = { returnValue: false, errorCode: -1, message: "Key not found."};
                } else {
                    //maybe check hash here to prevent changes in DB?

                    future.result = {
                        returnValue: true,
                        key: {
                            keyname: row.keyID,
                            keydata: row.data,
                            size: parseInt(row.keysize, 10),
                            type: typesToString[row.type],
                            nohide: row.scope > 0
                        }
                    };
                }
            });

            return future;
        },

        getKeyDecryptedByName: function (appid, keyname) {
            var future = KeyStore.getKeyRawByName(appid, keyname);

            future.then(this, function rawCB() {
                var result = future.result, cData, key;
                //debug("Got raw result:", result);
                if (result.returnValue === true) {
                    key = result.key;
                    if (key.nohide) {
                        cData = key.keydata; //we store keydata as buffer array.
                        //debug("ciphered: ", cData.toString("utf-8"));
                        decrypt(cData).then(this, function decryptCB(f2) {
                            var r2 = f2.result;
                            if (r2.returnValue === true) {
                                if (key.type === "ASCIIBLOB") {
                                    key.keydata = r2.data.toString("utf-8");
                                } else {
                                    key.keydata = r2.data.toString("base64");
                                }
                                //debug("deciphered: ", key.keydata);
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
                    future.result = result;
                }
            });

            return future;
        },

        putKey: function (appid, key) {
            var future = new Future(), cData;

            if (!appid || !key || !key.keyname) {
                future.result = { returnValue: false, errorCode: -1, message: "Need appid, key and keyname."};
                return future;
            }

            //get from database
            database.get("SELECT keyID FROM keytable WHERE ownerID IS $ownerID AND keyID IS $keyID", {
                $ownerID: appid,
                $keyID: key.keyname
            }, function getCB(err, row) {
                if (err) {
                    future.result = { returnValue: false, errorCode: -1, message: JSON.stringify(err) };
                } else if (!row) {
                    if (key.type === "ASCIIBLOB") {
                        cData = new Buffer.from(key.keydata, "utf-8");
                        if (!key.size) {
                            key.size = key.keydata.length;
                        }
                    } else {
                        cData = new Buffer.from(key.keydata, "base64");
                        if (!key.size) {
                            key.size = cData.toString("base64").length;
                        }
                    }
                    future.nest(encrypt(cData));
                } else {
                    future.result = { returnValue: false, errorCode: -1, message: "Key already exists."};
                }
            });

            future.then(function checkKeyExistsCB() {
                var result = future.result, hash;
                if (result.returnValue) {
                    hash = crypto.createHash("md5");
                    hash.update(appid);
                    hash.update(key.keyname);
                    hash.update(result.data);
                    hash.update(String(key.size || 0));
                    hash.update(key.type);
                    hash.update(key.nohide ? "1" : "0");

                    database.run("INSERT INTO keytable (ownerID, keyID, data, keysize, type, scope, hash) VALUES ($ownerID, $keyID, $data, $keysize, $type, $scope, $hash)", {
                        $ownerID: appid,
                        $keyID: key.keyname,
                        $data: result.data,
                        $keysize: key.size,
                        $type: stringToType[key.type],
                        $scope: key.nohide ? 1 : 0,
                        $hash: hash.digest("base64")
                    }, function putCB(err) {
                        if (err) {
                            future.result = { returnValue: false, errorCode: -1, message: JSON.stringify(err) };
                        } else {
                            future.result = {returnValue: true};
                        }
                    });
                } else {
                    future.result = result;
                }
            });

            return future;
        },

        deleteKey: function (appid, keyname) {
            var future = new Future();
            if (!appid || !keyname) {
                future.result = { returnValue: false, errorCode: -1, message: "Need appid and keyname."};
                return future;
            }

            database.run("DELETE FROM keytable WHERE ownerID IS $ownerID AND keyID IS $keyID", {
                $ownerID: appid,
                $keyID: keyname
            }, function deleteCB(err) {
                if (err) {
                    future.result = { returnValue: false, errorCode: -1, message: JSON.stringify(err) };
                } else {
                    future.result = {returnValue: true};
                }
            });

            return future;
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
                            future.result = { returnValue: false, errorCode: -1, message: JSON.stringify(err) };
                        } else {
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
                    // legacy has additional db of type:
                    // database.run("CREATE TABLE keytableconfig(id INTEGER PRIMARY KEY,data BLOB,dataLength INTEGER,iv BLOB,ivLength INTEGER);");
                    // I don't have any clue what that could be useful for... really... I had a look, on my device it only has
                    // one entry and I can't see what it is referenced by. It MAY be the master key. But I'm not sure.

                    database.run("CREATE TABLE keytable(id INTEGER PRIMARY KEY,ownerID TEXT,keyID TEXT,data BLOB,keysize INTEGER,type INTEGER,scope INTEGER, hash BLOB);", function (err) {
                        if (err) {
                            future.result = { returnValue: false, errorCode: -1, message: JSON.stringify(err) };
                        } else {
                            future.result = {returnValue: true};
                        }
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
                            future.result = { returnValue: false, errorCode: -1, message: JSON.stringify(ex) };
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

if (typeof module !== "undefined") { //allow to "require" this file.
    module.exports = KeyStore;
}
