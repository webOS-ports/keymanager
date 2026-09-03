/*jslint node: true */
/*global getAppId, KeyStore, KeymanagerCrypto, nodeCrypto, debug */

var CryptAssistant = function () {
    "use strict";
};

CryptAssistant.prototype.run = function (outerfuture) {
    "use strict";
    var args = this.controller.args, future, appId;

    appId = getAppId(this.controller);
    if (!appId) {
        throw {errorCode: -1, message: "Could not determine appId."};
    }

    if (!args.keyname) {
        throw {errorCode: -1, message: "Need keyname parameter"};
    }

    if (args.mode !== "CBC" && args.mode !== "CFB" && args.mode !== "ECB" &&
                    args.mode !== "none") {
        //just set CBC mode here, legacy does the same.
        args.mode = "CBC";
    }

    future = KeyStore.getKeyDecryptedByName(appId, args.keyname);

    future.then(this, function keyCB() {
        var result = future.result, algorithm, cipher, buffer, keydata, iv, info, derived,
            resData = new Buffer.from("");
        if (result.returnValue === true) {
            if (args.algorithm !== result.type) {
                outerfuture.exception = {errorCode: -1, message: "Stored key algorithm and parameter differ."};
            }

            keydata = new Buffer.from(result.keydata, "base64");
            debug("Keydata: ", keydata, " with length", keydata.length);
            algorithm = result.type + "-" + keydata.length * 8;
            if (args.mode !== "none") {
                algorithm += "-" + args.mode;
            }
            try {
                if (args.iv) {
                    iv = new Buffer.from(args.iv, "base64");
                    if (args.decrypt) {
                        debug(algorithm, " for decryption with iv.");
                        cipher = nodeCrypto.createDecipheriv(algorithm, keydata, iv);
                    } else {
                        debug(algorithm, " for encryption with iv.");
                        cipher = nodeCrypto.createCipheriv(algorithm, keydata, iv);
                    }
                } else {
                    /* No iv given. This used to be createCipher/createDecipher,
                     * which derived key and iv from `keydata` with
                     * EVP_BytesToKey(MD5, 1 iteration, no salt) - and which node
                     * 22 removed, so this branch threw for every caller.
                     *
                     * Reproduced rather than replaced: callers have data
                     * encrypted under exactly this derivation, and a "better"
                     * one here would silently fail to decrypt it. Callers who
                     * want something sound should pass an iv, which takes the
                     * branch above. See utils/Crypto.js.
                     */
                    info = nodeCrypto.getCipherInfo(algorithm);
                    if (!info) {
                        throw new Error("Unknown algorithm: " + algorithm);
                    }
                    derived = KeymanagerCrypto.legacyKeyAndIv(keydata, info.keyLength, info.ivLength || 0);
                    if (args.decrypt) {
                        debug(algorithm, " for decryption, key and iv derived from the key.");
                        cipher = nodeCrypto.createDecipheriv(algorithm, derived.key, derived.iv);
                    } else {
                        debug(algorithm, " for encryption, key and iv derived from the key.");
                        cipher = nodeCrypto.createCipheriv(algorithm, derived.key, derived.iv);
                    }
                }

                if (args.pad === "none") {
                    debug("Deaktivating padding.");
                    cipher.setAutoPadding(false);
                }

                cipher.on("data", function dataCB(chunk) {
                    debug("Got chunk with length ", chunk.length);
                    resData = Buffer.concat([resData, chunk]);
                });

                cipher.on("end", function endCB() {
                    debug("Read " + resData.length + " data.");
                    outerfuture.result = {
                        returnValue: true,
                        data: resData.toString("base64")
                    };
                });

                buffer = new Buffer.from(args.data, "base64");
                debug("Writing " + buffer.length + " bytes of data.");
                cipher.write(buffer);
                cipher.end();
            } catch (e) {
                outerfuture.exception = {errorCode: -1, message: e.message};
            }
        } else {
            outerfuture.exception = {errorCode: -1, message: result.message};
        }
    });

    return outerfuture;
};
