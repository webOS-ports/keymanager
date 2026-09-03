/*jslint node: true, nomen: true */
/*global Future, log, debug, fs, keyStoreFile, keyFile, nodeCrypto, KeymanagerCrypto */

var KeyStore = (function () {
    "use strict";
    var database = {},
        masterkey = "",
        saving = false,
        savePending = false;

    /* Write the store atomically, and never two at once.
     *
     * This used to be a bare fs.writeFile onto keyStoreFile. Two of those
     * overlapping - which is all it takes, since every putKey and deleteKey
     * calls this and none of them wait - each truncate and then write at their
     * own pace, so the shorter one can finish inside the longer one and leave
     * its tail behind. The result is a store.db that no longer parses, and
     * loadDatabase() answers that by starting a fresh empty database: every
     * stored credential silently gone. Reproduced by the suite, which stores a
     * handful of keys in quick succession and then reads the file back.
     *
     * So: serialise, write to a temp file, rename into place. rename is atomic
     * within a filesystem, so a reader sees either the old store or the new one
     * and never a half-written one.
     *
     * 0600 on create, and chmod too - writeFile only applies mode when it
     * creates the file, so a store written before this change would keep its
     * old bits.
     */
    function saveDB() {
        if (saving) {
            savePending = true;     // coalesce: one more save after this one
            return;
        }
        saving = true;

        var tmpFile = keyStoreFile + ".tmp";
        var snapshot = JSON.stringify(database);

        function done() {
            saving = false;
            if (savePending) {
                savePending = false;
                saveDB();
            }
        }

        fs.writeFile(tmpFile, snapshot, {mode: 384}, function writeCB(err) {
            if (err) {
                log("Could not write keydb file:", err);
                return done();
            }
            fs.chmod(tmpFile, 384, function chmodCB(chmodErr) {
                if (chmodErr) {
                    log("Could not tighten permissions on the keydb file:", chmodErr);
                }
                fs.rename(tmpFile, keyStoreFile, function renameCB(renameErr) {
                    if (renameErr) {
                        log("Could not put the keydb file in place:", renameErr);
                    } else {
                        log("Keydb saved.");
                    }
                    done();
                });
            });
        });
    }

    /* Was a streamed createCipher/createDecipher. Two things changed:
     *
     * The cipher itself - see utils/Crypto.js. createCipher no longer exists on
     * node 22, and what it did was not worth reproducing.
     *
     * And the shape: update()/final() rather than the "data"/"end" events. The
     * old version only ever set future.result on "end", so any failure left the
     * future unresolved and the caller hanging until its command timed out -
     * the same silent-hang failure mode that took out account creation when
     * randomBytes went missing. A future that always settles, one way or the
     * other, is worth more here than streaming a few hundred bytes.
     */
    function _crypt(decrypt, inData) {
        var future = new Future(), data;

        try {
            debug("Crypting ", inData.length, " bytes of data.");
            if (decrypt) {
                data = KeymanagerCrypto.decrypt(masterkey, inData);
            } else {
                data = KeymanagerCrypto.encrypt(masterkey, inData);
            }
            debug("Have ", data.length, " bytes of data.");
            future.result = { returnValue: true, data: data };
        } catch (e) {
            log("Could not " + (decrypt ? "decrypt" : "encrypt") + " keystore record:", e.message);
            future.result = { returnValue: false, message: e.message };
        }

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
                        dest[name] = new Buffer.alloc(from[name].length);
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
                    key.keydata = new Buffer.from(key.keydata.data);
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
                        cData = new Buffer.from(key.keydata); //we store keydata as buffer array.
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
                            } else {
                                // Previously left unset, which hung the caller.
                                // A record that will not decrypt is now an
                                // answer, not a stall - and with an AEAD it is
                                // also how tampering surfaces.
                                future.result = {
                                    returnValue: false,
                                    message: r2.message || "Could not decrypt key."
                                };
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
                cData = new Buffer.from(key.keydata, "utf-8");
            } else {
                cData = new Buffer.from(key.keydata, "base64");
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

        /**
         * Every key in the store, decrypted, for a passphrase-encrypted export.
         *
         * Decrypted on purpose. Records are encrypted with this device's master
         * key, and that key does not survive a Doctor and does not exist on
         * another handset - shipping the ciphertext would reproduce exactly the
         * legacy behaviour where a restore brought accounts back without their
         * passwords. The caller re-encrypts this under the user's passphrase
         * immediately; see Crypto.encryptWithPassphrase.
         *
         * nohide is carried through but not honoured here: it controls whether
         * a *reader* gets the key material back, and an export has to contain
         * it either way or restoring the key would restore an empty shell.
         */
        exportAll: function () {
            var future = new Future();
            var out = {};
            var count = 0;
            var failed = [];
            var appid, keyname, appStore, record, plain;

            try {
                for (appid in database) {
                    if (database.hasOwnProperty(appid)) {
                        appStore = database[appid];
                        for (keyname in appStore) {
                            if (appStore.hasOwnProperty(keyname)) {
                                record = appStore[keyname];
                                try {
                                    plain = KeymanagerCrypto.decrypt(masterkey,
                                        Buffer.isBuffer(record.keydata)
                                            ? record.keydata
                                            : Buffer.from(record.keydata.data));
                                } catch (e) {
                                    // One unreadable record must not cost the
                                    // user every other credential they have.
                                    log("Cannot export " + appid + "/" + keyname + ":", e.message);
                                    failed.push(appid + "/" + keyname);
                                    continue;
                                }
                                if (!out[appid]) {
                                    out[appid] = {};
                                }
                                out[appid][keyname] = {
                                    keyname: keyname,
                                    type: record.type,
                                    size: record.size,
                                    nohide: record.nohide,
                                    keydata: (record.type === "ASCIIBLOB")
                                        ? plain.toString("utf-8")
                                        : plain.toString("base64")
                                };
                                count += 1;
                            }
                        }
                    }
                }
            } catch (err) {
                future.result = { returnValue: false, message: err.message };
                return future;
            }

            future.result = { returnValue: true, keys: out, count: count, failed: failed };
            return future;
        },

        /**
         * The other half: put an export back, re-encrypting each record under
         * *this* device's master key as it goes.
         *
         * Existing keys are left alone unless overwrite is set. Restoring onto
         * a device that already has credentials should not quietly replace a
         * working password with an older one from a backup.
         */
        importAll: function (keys, overwrite) {
            var future = new Future();
            var pending = [];
            var imported = 0;
            var skipped = 0;
            var failed = [];
            var appid, keyname;

            if (!keys || typeof keys !== "object") {
                future.result = { returnValue: false, message: "No keys to import." };
                return future;
            }

            for (appid in keys) {
                if (keys.hasOwnProperty(appid)) {
                    for (keyname in keys[appid]) {
                        if (keys[appid].hasOwnProperty(keyname)) {
                            pending.push({ appid: appid, key: keys[appid][keyname] });
                        }
                    }
                }
            }

            function next() {
                if (pending.length === 0) {
                    future.result = {
                        returnValue: true,
                        imported: imported,
                        skipped: skipped,
                        failed: failed
                    };
                    return;
                }

                var entry = pending.shift();
                var appStore = database[entry.appid];
                var exists = appStore && appStore[entry.key.keyname];

                if (exists && !overwrite) {
                    skipped += 1;
                    return next();
                }
                if (exists) {
                    delete appStore[entry.key.keyname];
                }

                // A fresh object each time: putKey stores what it is given and
                // replaces keydata with the ciphertext, so handing it the
                // caller's object would mutate the export in place.
                var inner = KeyStore.putKey(entry.appid, {
                    keyname: entry.key.keyname,
                    type: entry.key.type,
                    size: entry.key.size,
                    nohide: entry.key.nohide,
                    keydata: entry.key.keydata
                });

                inner.then(this, function putCB(f) {
                    var result;
                    try {
                        result = f.result;
                    } catch (e) {
                        result = { returnValue: false, message: e.message };
                    }
                    if (result && result.returnValue === true) {
                        imported += 1;
                    } else {
                        failed.push(entry.appid + "/" + entry.key.keyname);
                    }
                    next();
                });
            }

            next();
            return future;
        },

        loadDatabase: function () {
            var future = new Future();
            fs.access(keyStoreFile, function existsCB(error) {
                if (!error) {
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
                    nodeCrypto.randomBytes(256, function radomCB(ex, buf) {
                        if (ex) {
                            log("Could not create random key:", ex);
                            future.result = { returnValue: false };
                        } else {
                            masterkey = buf;
                            future.result = {returnValue: true};
                            fs.writeFile(keyFile, masterkey, {mode: 384}, function writeCB(err) {
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
                    // Existing devices shipped this file as 0644, sitting next
                    // to the data it protects. Tighten it in passing; there is
                    // no point encrypting a store with a key anyone can read.
                    fs.chmod(keyFile, 384, function chmodCB(chmodErr) {
                        if (chmodErr) {
                            log("Could not tighten permissions on the key file:", chmodErr);
                        }
                    });
                    future.result = {returnValue: true};
                }
            });
            return future;
        }
    };
}());
