/* keymanager test suite.
 *
 *   node test/run-tests.js
 *
 * Loads the real service sources into a vm sandbox (see harness.js) rather than
 * testing a copy of them, and keeps every file it writes in a temp directory -
 * nothing here touches /var/palm/keystore.
 *
 * The interesting cases are the ones the old code got wrong: a record that will
 * not decrypt must be an answer rather than a hang, a tampered record must be
 * rejected rather than decrypted into garbage, and records written before the
 * cipher change must still be readable.
 */
/*jslint node: true */

var assert = require("assert");
var child_process = require("child_process");
var crypto = require("crypto");
var fs = require("fs");
var path = require("path");
var vm = require("vm");

var harness = require("./harness.js");

var passed = 0;
var failed = 0;
var skipped = 0;
var ROOTS = [];

function section(name) {
    "use strict";
    console.log("\n" + name);
}

function check(label, condition, detail) {
    "use strict";
    if (condition) {
        passed += 1;
        console.log("  PASS  " + label);
    } else {
        failed += 1;
        console.log("  FAIL  " + label + (detail ? "  (" + detail + ")" : ""));
    }
}

function skip(label, why) {
    "use strict";
    skipped += 1;
    console.log("  SKIP  " + label + (why ? "  (" + why + ")" : ""));
}

function throws(fn) {
    "use strict";
    try {
        fn();
        return null;
    } catch (e) {
        return e;
    }
}

function newContext(options) {
    "use strict";
    options = options || {};
    if (!options.root) {
        options.root = harness.mkdtemp("keymanager-test-");
    }
    ROOTS.push(options.root);
    options.quiet = options.quiet !== false;
    return harness.loadService(options);
}

/** Resolve a future, but never wait forever - a hang is a test failure. */
function settle(future, ms) {
    "use strict";
    return Promise.race([
        harness.settle(future),
        new Promise(function (resolve) {
            setTimeout(function () { resolve("__TIMEOUT__"); }, ms || 2000);
        })
    ]);
}

function mode(file) {
    "use strict";
    return fs.statSync(file).mode & 511;   // 0777
}

async function main() {
    "use strict";

    /* ------------------------------------------------ Crypto: round trip */
    section("Crypto: record format");

    var ctx = newContext();
    var C = ctx.KeymanagerCrypto;
    var master = crypto.randomBytes(256);
    var plain = Buffer.from("correct horse battery staple", "utf8");

    var blob = C.encrypt(master, plain);
    check("encrypt/decrypt round-trips",
        C.decrypt(master, blob).equals(plain));
    check("the record carries the KM1 magic",
        blob.subarray(0, 4).equals(C.MAGIC), blob.subarray(0, 4).toString("hex"));
    check("a new record is not mistaken for a legacy one", C.isLegacy(blob) === false);

    var blob2 = C.encrypt(master, plain);
    check("the same plaintext encrypts differently each time (random IV)",
        !blob.equals(blob2));
    check("...and both still decrypt to the same plaintext",
        C.decrypt(master, blob2).equals(plain));

    check("an empty plaintext round-trips",
        C.decrypt(master, C.encrypt(master, Buffer.alloc(0))).length === 0);

    var big = crypto.randomBytes(200000);
    check("a 200KB record round-trips", C.decrypt(master, C.encrypt(master, big)).equals(big));

    /* ------------------------------------------------ Crypto: tampering */
    section("Crypto: a tampered record is rejected, not decrypted");

    var tampered = Buffer.from(blob);
    tampered[tampered.length - 1] ^= 0x01;
    check("a flipped ciphertext byte throws", throws(function () {
        C.decrypt(master, tampered);
    }) !== null);

    var badTag = Buffer.from(blob);
    badTag[4 + 12] ^= 0x01;             // first byte of the auth tag
    check("a flipped auth-tag byte throws", throws(function () {
        C.decrypt(master, badTag);
    }) !== null);

    var badIv = Buffer.from(blob);
    badIv[4] ^= 0x01;                   // first byte of the IV
    check("a flipped IV byte throws", throws(function () {
        C.decrypt(master, badIv);
    }) !== null);

    check("a truncated record throws rather than reading out of bounds",
        throws(function () { C.decrypt(master, blob.subarray(0, 20)); }) !== null);

    check("the wrong master key throws",
        throws(function () { C.decrypt(crypto.randomBytes(256), blob); }) !== null);

    /* ------------------------------------------------ Crypto: derivation */
    section("Crypto: key derivation");

    var derived = C.deriveKey(master);
    check("deriveKey returns 32 bytes", derived.length === 32, String(derived.length));
    check("deriveKey is deterministic", C.deriveKey(master).equals(derived));
    check("a different master key derives a different AES key",
        !C.deriveKey(crypto.randomBytes(256)).equals(derived));

    // The reason deriveKey is written out with createHmac instead of calling
    // hkdfSync: the answer must not depend on what the runtime happens to
    // offer, or a store written on one node is unreadable on another.
    var maskedCrypto = Object.create(crypto);
    maskedCrypto.hkdfSync = undefined;
    var maskedCtx = newContext({ nodeCrypto: maskedCrypto });
    check("a runtime without hkdfSync derives the same key",
        maskedCtx.KeymanagerCrypto.deriveKey(master).equals(derived));
    check("...so a record written there is readable here",
        C.decrypt(master, maskedCtx.KeymanagerCrypto.encrypt(master, plain)).equals(plain));

    /* ------------------------------------------------ Crypto: legacy read */
    section("Crypto: records written by the old createCipher scheme");

    // Independent oracle. `openssl enc -md md5 -nosalt` is exactly the
    // EVP_BytesToKey(MD5, 1 iteration, no salt) derivation createCipher used,
    // so if our reimplementation agrees with the openssl binary it agrees with
    // what actually wrote the records on existing devices.
    var opensslAvailable = true;
    try {
        child_process.execFileSync("openssl", ["version"], { stdio: "ignore" });
    } catch (ignored) {
        opensslAvailable = false;
    }

    if (opensslAvailable) {
        var asciiMaster = "a-master-key-that-openssl-can-take-on-argv";
        var legacyPlain = Buffer.from("legacy secret value", "utf8");
        var legacyBlob = child_process.execFileSync("openssl",
            ["enc", "-aes-256-cbc", "-md", "md5", "-nosalt", "-pass", "pass:" + asciiMaster],
            { input: legacyPlain, stdio: ["pipe", "pipe", "ignore"] });

        check("openssl-produced legacy record decrypts",
            C.decrypt(asciiMaster, legacyBlob).equals(legacyPlain),
            C.decrypt(asciiMaster, legacyBlob).toString("utf8"));
        check("legacy records are recognised as legacy", C.isLegacy(legacyBlob) === true);

        var kv = C.legacyKeyAndIv(asciiMaster, 32, 16);
        check("legacyKeyAndIv agrees with openssl on key and IV lengths",
            kv.key.length === 32 && kv.iv.length === 16);
    } else {
        skip("openssl-produced legacy record decrypts", "openssl binary not found");
        skip("legacy records are recognised as legacy", "openssl binary not found");
        skip("legacyKeyAndIv agrees with openssl on key and IV lengths", "openssl binary not found");
    }

    /* ------------------------------------------------ KeyStore: round trip */
    section("KeyStore: storing and reading keys");

    var storeCtx = newContext();
    await settle(storeCtx.KeyStore.loadKey());
    await settle(storeCtx.KeyStore.loadDatabase());

    var ascii = await settle(storeCtx.KeyStore.putKey("org.webosports.test", {
        keyname: "asciikey", type: "ASCIIBLOB", nohide: true, keydata: "hunter2"
    }));
    check("putKey accepts an ASCIIBLOB", ascii && ascii.returnValue === true, JSON.stringify(ascii));

    var readBack = await settle(storeCtx.KeyStore.getKeyDecryptedByName("org.webosports.test", "asciikey"));
    check("an ASCIIBLOB reads back unchanged",
        readBack && readBack.returnValue === true && readBack.keydata === "hunter2",
        JSON.stringify(readBack));

    var aesData = crypto.randomBytes(32).toString("base64");
    await settle(storeCtx.KeyStore.putKey("org.webosports.test", {
        keyname: "aeskey", type: "AES", size: 32, nohide: true, keydata: aesData
    }));
    var aesBack = await settle(storeCtx.KeyStore.getKeyDecryptedByName("org.webosports.test", "aeskey"));
    check("a base64 AES key reads back unchanged",
        aesBack && aesBack.returnValue === true && aesBack.keydata === aesData,
        JSON.stringify(aesBack && aesBack.keydata));

    var dup = await settle(storeCtx.KeyStore.putKey("org.webosports.test", {
        keyname: "asciikey", type: "ASCIIBLOB", nohide: true, keydata: "again"
    }));
    check("a duplicate keyname is refused", dup && dup.returnValue === false, JSON.stringify(dup));

    var missing = await settle(storeCtx.KeyStore.getKeyDecryptedByName("org.webosports.test", "nosuchkey"));
    check("an unknown keyname reports not found", missing && missing.returnValue === false);

    var other = await settle(storeCtx.KeyStore.getKeyDecryptedByName("org.webosports.other", "asciikey"));
    check("another appid cannot read the key", other && other.returnValue === false);

    var del = await settle(storeCtx.KeyStore.deleteKey("org.webosports.test", "aeskey"));
    check("deleteKey removes a key", del && del.returnValue === true);
    var afterDel = await settle(storeCtx.KeyStore.getKeyDecryptedByName("org.webosports.test", "aeskey"));
    check("...and it is gone afterwards", afterDel && afterDel.returnValue === false);

    /* ------------------------------------------------ KeyStore: on disk */
    section("KeyStore: what lands on disk");

    var storeFile = path.join(storeCtx.__root, "store.db");
    var keyFile = path.join(storeCtx.__root, "key");

    // saveDB is fire-and-forget; give the write a moment to land.
    await new Promise(function (r) { setTimeout(r, 200); });

    check("the master key file exists", fs.existsSync(keyFile));
    check("the master key is 0600, not world-readable",
        mode(keyFile) === 384, "0" + mode(keyFile).toString(8));
    check("the store file is 0600",
        mode(storeFile) === 384, "0" + mode(storeFile).toString(8));

    // Parsed defensively: if the store is corrupt this must report a failure
    // here rather than take the whole run down with a JSON.parse stack.
    var onDisk = null;
    var onDiskErr = throws(function () {
        onDisk = JSON.parse(fs.readFileSync(storeFile, "utf8"));
    });
    check("the store file is valid JSON", onDiskErr === null, onDiskErr && onDiskErr.message);

    var storedRecord = onDisk &&
        Buffer.from(onDisk["org.webosports.test"].asciikey.keydata.data);
    check("the stored record is in the new format",
        storedRecord !== null && !C.isLegacy(storedRecord));
    check("the plaintext is not sitting in the store file",
        fs.readFileSync(storeFile, "utf8").indexOf("hunter2") === -1);

    /* ------------------------------------------------ KeyStore: concurrency */
    section("KeyStore: rapid writes do not corrupt the store");

    // Every putKey/deleteKey calls saveDB and none of them wait. With a bare
    // fs.writeFile, two overlapping writes each truncate and then race, so the
    // shorter one can finish inside the longer one and leave its tail behind -
    // and a store.db that will not parse is thrown away by loadDatabase(),
    // taking every credential with it. This is what caught that.
    var raceCtx = newContext();
    await settle(raceCtx.KeyStore.loadKey());
    await settle(raceCtx.KeyStore.loadDatabase());

    var i;
    var writes = [];
    for (i = 0; i < 25; i += 1) {
        // Deliberately not awaited one at a time: the point is to overlap them.
        writes.push(settle(raceCtx.KeyStore.putKey("org.webosports.test", {
            keyname: "k" + i,
            type: "ASCIIBLOB",
            nohide: true,
            // Varying length, so an interleaved write leaves a detectable tail.
            keydata: new Array(i * 40 + 5).join("x")
        })));
    }
    await Promise.all(writes);
    await new Promise(function (r) { setTimeout(r, 500); });

    var racePath = path.join(raceCtx.__root, "store.db");
    var raceParsed = null;
    var raceErr = throws(function () {
        raceParsed = JSON.parse(fs.readFileSync(racePath, "utf8"));
    });
    check("the store still parses after 25 overlapping writes",
        raceErr === null, raceErr && raceErr.message);
    check("...and holds every key that was stored",
        raceParsed !== null &&
            Object.keys(raceParsed["org.webosports.test"] || {}).length === 25,
        raceParsed && String(Object.keys(raceParsed["org.webosports.test"] || {}).length));
    check("no temp file is left behind", !fs.existsSync(racePath + ".tmp"));

    var raceReadCtx = newContext({ root: raceCtx.__root });
    await settle(raceReadCtx.KeyStore.loadKey());
    await settle(raceReadCtx.KeyStore.loadDatabase());
    var raceRead = await settle(raceReadCtx.KeyStore.getKeyDecryptedByName("org.webosports.test", "k24"));
    check("...and the last one still decrypts after a reload",
        raceRead !== "__TIMEOUT__" && raceRead.returnValue === true &&
            raceRead.keydata === new Array(24 * 40 + 5).join("x"),
        JSON.stringify(raceRead && raceRead.returnValue));

    /* ------------------------------------------------ KeyStore: tightening */
    section("KeyStore: an existing world-readable key file is tightened");

    var loose = harness.mkdtemp("keymanager-test-");
    ROOTS.push(loose);
    fs.writeFileSync(path.join(loose, "key"), crypto.randomBytes(256), { mode: 420 });  // 0644
    fs.chmodSync(path.join(loose, "key"), 420);
    check("fixture starts out 0644", mode(path.join(loose, "key")) === 420);

    var looseCtx = newContext({ root: loose });
    await settle(looseCtx.KeyStore.loadKey());
    await new Promise(function (r) { setTimeout(r, 200); });
    check("loadKey tightens it to 0600",
        mode(path.join(loose, "key")) === 384, "0" + mode(path.join(loose, "key")).toString(8));

    /* ------------------------------------------------ KeyStore: failure */
    section("KeyStore: a record that will not decrypt answers instead of hanging");

    // The old _crypt only ever set future.result from the cipher's "end" event,
    // so a failure left the future unresolved and the caller blocked until its
    // command timed out. That is the shape of bug that took out account
    // creation once already, so it is worth a test of its own.
    var corruptCtx = newContext();
    await settle(corruptCtx.KeyStore.loadKey());
    await settle(corruptCtx.KeyStore.loadDatabase());
    await settle(corruptCtx.KeyStore.putKey("org.webosports.test", {
        keyname: "victim", type: "ASCIIBLOB", nohide: true, keydata: "secret"
    }));
    // saveDB is fire-and-forget; let it land before reading the file back.
    await new Promise(function (r) { setTimeout(r, 200); });

    var victimPath = path.join(corruptCtx.__root, "store.db");
    var victimStore = JSON.parse(fs.readFileSync(victimPath, "utf8"));
    var victimBytes = victimStore["org.webosports.test"].victim.keydata.data;
    victimBytes[victimBytes.length - 1] ^= 0xFF;     // damage the ciphertext
    fs.writeFileSync(victimPath, JSON.stringify(victimStore));

    var reloadCtx = newContext({ root: corruptCtx.__root });
    await settle(reloadCtx.KeyStore.loadKey());
    await settle(reloadCtx.KeyStore.loadDatabase());
    var corruptResult = await settle(reloadCtx.KeyStore.getKeyDecryptedByName("org.webosports.test", "victim"));
    check("a corrupted record settles rather than hanging",
        corruptResult !== "__TIMEOUT__", "future never resolved");
    check("...and reports failure rather than returning garbage",
        corruptResult !== "__TIMEOUT__" && corruptResult.returnValue === false,
        JSON.stringify(corruptResult));

    /* ------------------------------------------------ KeyStore: migration */
    section("KeyStore: a store written by the old scheme still opens");

    var legacyCtx = newContext();
    await settle(legacyCtx.KeyStore.loadKey());
    // loadKey resolves as soon as it has the key in memory; the write to disk
    // is fire-and-forget behind it, so the file is not necessarily there yet.
    await new Promise(function (r) { setTimeout(r, 300); });
    var legacyMaster = fs.readFileSync(path.join(legacyCtx.__root, "key"));
    var legacyKv = legacyCtx.KeymanagerCrypto.legacyKeyAndIv(legacyMaster, 32, 16);
    var legacyCipher = crypto.createCipheriv("aes-256-cbc", legacyKv.key, legacyKv.iv);
    var legacyRecord = Buffer.concat([
        legacyCipher.update(Buffer.from("old-format-secret", "utf8")),
        legacyCipher.final()
    ]);

    fs.writeFileSync(path.join(legacyCtx.__root, "store.db"), JSON.stringify({
        "org.webosports.test": {
            oldkey: {
                keyname: "oldkey", type: "ASCIIBLOB", nohide: true,
                keydata: { type: "Buffer", data: Array.prototype.slice.call(legacyRecord) }
            }
        }
    }));

    var migrateCtx = newContext({ root: legacyCtx.__root });
    await settle(migrateCtx.KeyStore.loadKey());
    await settle(migrateCtx.KeyStore.loadDatabase());
    var legacyRead = await settle(migrateCtx.KeyStore.getKeyDecryptedByName("org.webosports.test", "oldkey"));
    check("a legacy record decrypts",
        legacyRead !== "__TIMEOUT__" && legacyRead.returnValue === true &&
            legacyRead.keydata === "old-format-secret",
        JSON.stringify(legacyRead && legacyRead.keydata));

    await settle(migrateCtx.KeyStore.deleteKey("org.webosports.test", "oldkey"));
    await settle(migrateCtx.KeyStore.putKey("org.webosports.test", {
        keyname: "oldkey", type: "ASCIIBLOB", nohide: true, keydata: "old-format-secret"
    }));
    await new Promise(function (r) { setTimeout(r, 200); });
    var migrated = JSON.parse(fs.readFileSync(path.join(migrateCtx.__root, "store.db"), "utf8"));
    check("rewriting it stores the new format",
        !C.isLegacy(Buffer.from(migrated["org.webosports.test"].oldkey.keydata.data)));

    /* ------------------------------------------------ CryptAssistant */
    section("CryptAssistant: the no-iv path works again");

    var cryptCtx = newContext({
        sources: [
            "javascript/utils/Common.js",
            "javascript/utils/Crypto.js",
            "javascript/utils/KeyStore.js",
            "javascript/assistants/CryptAssistant.js"
        ]
    });
    await settle(cryptCtx.KeyStore.loadKey());
    await settle(cryptCtx.KeyStore.loadDatabase());

    var appKey = crypto.randomBytes(32).toString("base64");
    await settle(cryptCtx.KeyStore.putKey("org.webosports.test", {
        keyname: "cryptkey", type: "AES", size: 32, nohide: true, keydata: appKey
    }));

    function runCrypt(args) {
        var outer = new harness.Future();
        var assistant = new cryptCtx.CryptAssistant();
        assistant.controller = {
            args: args,
            message: {
                applicationID: function () { return "org.webosports.test"; },
                senderServiceName: function () { return "org.webosports.test"; }
            }
        };
        assistant.run(outer);
        return settle(outer);
    }

    var secret = Buffer.from("sixteen bytes ok", "utf8").toString("base64");
    var enc = await runCrypt({ keyname: "cryptkey", algorithm: "AES", data: secret });
    check("encrypting without an iv no longer throws",
        enc !== "__TIMEOUT__" && enc && enc.returnValue === true, JSON.stringify(enc));

    if (enc && enc.returnValue === true) {
        var dec = await runCrypt({
            keyname: "cryptkey", algorithm: "AES", decrypt: true, data: enc.data
        });
        check("...and decrypting returns the original plaintext",
            dec !== "__TIMEOUT__" && dec && dec.returnValue === true && dec.data === secret,
            JSON.stringify(dec && dec.data));
    } else {
        skip("...and decrypting returns the original plaintext", "encryption failed");
    }

    var ivB64 = crypto.randomBytes(16).toString("base64");
    var encIv = await runCrypt({
        keyname: "cryptkey", algorithm: "AES", iv: ivB64, data: secret
    });
    check("the explicit-iv path still works",
        encIv !== "__TIMEOUT__" && encIv && encIv.returnValue === true, JSON.stringify(encIv));

    /* ------------------------------------------------ keystore export */
    section("Export/import: a backup that can restore passwords");

    var BACKUP_SOURCES = [
        "javascript/utils/Common.js",
        "javascript/utils/Crypto.js",
        "javascript/utils/KeyStore.js",
        "javascript/assistants/ExportKeystoreAssistant.js",
        "javascript/assistants/ImportKeystoreAssistant.js"
    ];

    function runAssistant(context, Name, args) {
        var outer = new harness.Future();
        var assistant = new context[Name]();
        assistant.controller = {
            args: args,
            message: {
                applicationID: function () { return "com.palm.app.backup.service"; },
                senderServiceName: function () { return "com.palm.app.backup.service"; }
            }
        };
        // An assistant reports a bad request by throwing and a failed operation
        // by setting outerfuture.exception. Both are outcomes a test wants to
        // assert on, so neither should escape as an unhandled rejection.
        try {
            assistant.run(outer);
        } catch (thrown) {
            return Promise.resolve({ __threw: thrown, returnValue: false });
        }
        return settle(outer, 20000).catch(function (failed) {
            return { __failed: failed, returnValue: false };
        });
    }

    // "Device A": a store with a couple of credentials in it.
    var devA = newContext({ sources: BACKUP_SOURCES });
    await settle(devA.KeyStore.loadKey());
    await settle(devA.KeyStore.loadDatabase());
    await settle(devA.KeyStore.putKey("com.palm.palmprofile", {
        keyname: "password", type: "ASCIIBLOB", nohide: true, keydata: "s3cr3t-mail-pw"
    }));
    await settle(devA.KeyStore.putKey("org.webosports.cdav", {
        keyname: "password", type: "ASCIIBLOB", nohide: true, keydata: "another-password"
    }));
    // nohide:false - readers get no key material back, but an export must still
    // carry it or the restored key would be an empty shell.
    await settle(devA.KeyStore.putKey("com.palm.palmprofile", {
        keyname: "hidden", type: "AES", size: 32, nohide: false,
        keydata: Buffer.from("0123456789abcdef0123456789abcdef").toString("base64")
    }));

    var PASSPHRASE = "correct horse battery staple";
    var exported = await runAssistant(devA, "ExportKeystoreAssistant", { passphrase: PASSPHRASE });
    check("exportKeystore succeeds",
        exported !== "__TIMEOUT__" && exported && exported.returnValue === true,
        JSON.stringify(exported && (exported.__threw || exported.errorText || exported)));
    check("...and reports every key it exported",
        exported && exported.count === 3, exported && String(exported.count));

    var envelope = exported && exported.keystore;
    check("the export is scrypt + aes-256-gcm with its parameters recorded",
        envelope && envelope.kdf === "scrypt" && envelope.cipher === "aes-256-gcm" &&
            envelope.kdfParams && envelope.kdfParams.N > 0);
    check("no password appears in clear anywhere in the export",
        JSON.stringify(envelope).indexOf("s3cr3t-mail-pw") === -1 &&
            Buffer.from(envelope.ciphertext, "base64").indexOf("s3cr3t-mail-pw") === -1);

    var missingPass = await runAssistant(devA, "ExportKeystoreAssistant", {});
    check("exporting without a passphrase is refused", missingPass && missingPass.__threw);

    /* ---- the point of the exercise: another device, another master key ---- */
    section("Export/import: onto a different device");

    var devB = newContext({ sources: BACKUP_SOURCES });
    await settle(devB.KeyStore.loadKey());
    await settle(devB.KeyStore.loadDatabase());
    await new Promise(function (r) { setTimeout(r, 300); });

    var keyA = fs.readFileSync(path.join(devA.__root, "key"));
    var keyB = fs.readFileSync(path.join(devB.__root, "key"));
    check("the two devices really do have different master keys", !keyA.equals(keyB));

    var importedB = await runAssistant(devB, "ImportKeystoreAssistant",
        { passphrase: PASSPHRASE, keystore: envelope });
    check("importKeystore succeeds on the other device",
        importedB !== "__TIMEOUT__" && importedB && importedB.returnValue === true,
        JSON.stringify(importedB && (importedB.__threw || importedB)));
    check("...importing all three keys",
        importedB && importedB.imported === 3 && importedB.failed.length === 0,
        JSON.stringify(importedB));

    var restored = await settle(devB.KeyStore.getKeyDecryptedByName("com.palm.palmprofile", "password"));
    check("a password restored onto the other device decrypts there",
        restored !== "__TIMEOUT__" && restored.returnValue === true &&
            restored.keydata === "s3cr3t-mail-pw",
        JSON.stringify(restored && restored.keydata));

    var restoredCdav = await settle(devB.KeyStore.getKeyDecryptedByName("org.webosports.cdav", "password"));
    check("...and so does one belonging to a different appid",
        restoredCdav !== "__TIMEOUT__" && restoredCdav.returnValue === true &&
            restoredCdav.keydata === "another-password");

    // Re-encrypted under device B's key, not carried over as device A's bytes.
    await new Promise(function (r) { setTimeout(r, 300); });
    var bStore = JSON.parse(fs.readFileSync(path.join(devB.__root, "store.db"), "utf8"));
    var bRecord = Buffer.from(bStore["com.palm.palmprofile"].password.keydata.data);
    check("the restored record is re-encrypted under this device's key",
        !C.isLegacy(bRecord) &&
            throws(function () { devA.KeymanagerCrypto.decrypt(keyA, bRecord); }) !== null);

    /* ---- failure modes ---- */
    section("Export/import: wrong passphrase and tampering");

    var devC = newContext({ sources: BACKUP_SOURCES });
    await settle(devC.KeyStore.loadKey());
    await settle(devC.KeyStore.loadDatabase());

    var wrongPass = await runAssistant(devC, "ImportKeystoreAssistant",
        { passphrase: "not the passphrase", keystore: envelope });
    check("a wrong passphrase is rejected",
        wrongPass !== "__TIMEOUT__" && wrongPass && wrongPass.returnValue !== true &&
            wrongPass.__failed !== undefined,
        JSON.stringify(wrongPass));

    var mangled = JSON.parse(JSON.stringify(envelope));
    var ctBytes = Buffer.from(mangled.ciphertext, "base64");
    ctBytes[0] ^= 0xFF;
    mangled.ciphertext = ctBytes.toString("base64");
    var tamperedImport = await runAssistant(devC, "ImportKeystoreAssistant",
        { passphrase: PASSPHRASE, keystore: mangled });
    check("a tampered export is rejected",
        tamperedImport !== "__TIMEOUT__" && tamperedImport &&
            tamperedImport.returnValue !== true);

    var emptyAfterFailures = await settle(devC.KeyStore.getKeyDecryptedByName("com.palm.palmprofile", "password"));
    check("nothing was imported by either failed attempt",
        emptyAfterFailures !== "__TIMEOUT__" && emptyAfterFailures.returnValue === false);

    var wrongVersion = JSON.parse(JSON.stringify(envelope));
    wrongVersion.version = 99;
    var versionFail = await runAssistant(devC, "ImportKeystoreAssistant",
        { passphrase: PASSPHRASE, keystore: wrongVersion });
    check("an export from a future version is refused, not guessed at",
        versionFail !== "__TIMEOUT__" && versionFail && versionFail.returnValue !== true);

    /* ---- restoring over existing credentials ---- */
    section("Export/import: restoring onto a device that already has keys");

    var devD = newContext({ sources: BACKUP_SOURCES });
    await settle(devD.KeyStore.loadKey());
    await settle(devD.KeyStore.loadDatabase());
    await settle(devD.KeyStore.putKey("com.palm.palmprofile", {
        keyname: "password", type: "ASCIIBLOB", nohide: true, keydata: "the-current-password"
    }));

    var noOverwrite = await runAssistant(devD, "ImportKeystoreAssistant",
        { passphrase: PASSPHRASE, keystore: envelope });
    check("an existing key is skipped by default",
        noOverwrite && noOverwrite.returnValue === true && noOverwrite.skipped === 1 &&
            noOverwrite.imported === 2,
        JSON.stringify(noOverwrite));

    var kept = await settle(devD.KeyStore.getKeyDecryptedByName("com.palm.palmprofile", "password"));
    check("...and the working password is left alone",
        kept.returnValue === true && kept.keydata === "the-current-password",
        JSON.stringify(kept && kept.keydata));

    var overwritten = await runAssistant(devD, "ImportKeystoreAssistant",
        { passphrase: PASSPHRASE, keystore: envelope, overwrite: true });
    check("overwrite:true replaces it", overwritten && overwritten.imported === 3,
        JSON.stringify(overwritten));
    var replaced = await settle(devD.KeyStore.getKeyDecryptedByName("com.palm.palmprofile", "password"));
    check("...with the one from the backup",
        replaced.returnValue === true && replaced.keydata === "s3cr3t-mail-pw",
        JSON.stringify(replaced && replaced.keydata));

    /* ---- empty store ---- */
    var devE = newContext({ sources: BACKUP_SOURCES });
    await settle(devE.KeyStore.loadKey());
    await settle(devE.KeyStore.loadDatabase());
    var emptyExport = await runAssistant(devE, "ExportKeystoreAssistant", { passphrase: PASSPHRASE });
    check("an empty keystore exports without complaint",
        emptyExport && emptyExport.returnValue === true && emptyExport.count === 0,
        JSON.stringify(emptyExport && emptyExport.count));

    /* ------------------------------------------------ summary */
    console.log("\n" + passed + " passed, " + failed + " failed, " + skipped + " skipped");
    ROOTS.forEach(harness.rmrf);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch(function (err) {
    "use strict";
    console.error("\nHarness error:", (err && err.stack) || err);
    ROOTS.forEach(harness.rmrf);
    process.exit(1);
});
