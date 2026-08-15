/*jslint sloppy: true */
/*global IMPORTS, console, require:true, process */
console.error("Starting to load libraries");

//... Load the Foundations library and create
//... short-hand references to some of its components.
var Foundations = IMPORTS.foundations;

var DB = Foundations.Data.DB;
var Future = Foundations.Control.Future;

//now add some node.js imports:
if (typeof require === "undefined") {
    require = IMPORTS.require;
}
var fs = require("fs"); //required for own node modules and current vCard converter.

// Deliberately NOT called "crypto". Node 19 and later define globalThis.crypto as a
// getter-only accessor holding the WebCrypto Crypto object, whose interface is
// getRandomValues/randomUUID/subtle and which has no randomBytes(), createCipher() or
// createHash(). A top-level "var crypto = require('crypto')" in this sandbox assigns to
// that accessor and, because the property has no setter and we run sloppy mode, the
// assignment is silently discarded: every source file kept seeing WebCrypto.
//
// The visible effect was that KeyStore.loadKey() threw
//     TypeError: crypto.randomBytes is not a function
// which the uncaughtException handler at the bottom of this file swallowed, so
// loadKey()'s future was never resolved, KeyManagerServiceAssistant.setup() never
// completed, and MojoService never dispatched a single command. Every keymanager method
// then blocked until its caller gave up, which took out account creation:
// com.palm.service.accounts/createAccount hit its 20s commandTimeout inside
// Utils.saveCredentials(), leaving accounts stored in db8 with no credentials.
//
// This only bit on a fresh system. Once /var/palm/keystore/key exists loadKey() reads it
// and never reaches randomBytes(), which is why an already-provisioned device was fine.
var nodeCrypto = IMPORTS.require("crypto");
if (!nodeCrypto || typeof nodeCrypto.randomBytes !== "function") {
    nodeCrypto = require("crypto");
}

console.error("--------->Loaded Libraries OK1");

var dummy = function () {};

var printObj = function (obj, depth) {
    var key, msg = "{";
    if (depth < 5) {
        for (key in obj) {
            if (obj.hasOwnProperty(key)) {
                try {
                    msg += " " + key + ": " + JSON.stringify(obj[key]) + ",";
                } catch (e) {
                    msg += " " + key + ": " + printObj(obj[key], depth + 1) + ",";
                }
            }
        }
        msg[msg.length - 1] = "}";
    } else {
        msg = "...";
    }
    return msg;
};

var logBase = function () {
    var i, pos, datum, argsArr = Array.prototype.slice.call(arguments, 0),
        data;

    for (i = 0; i < argsArr.length; i += 1) {
        if (typeof argsArr[i] !== "string") {
            try {
                argsArr[i] = JSON.stringify(argsArr[i]);
            } catch (e) {
                argsArr[i] = printObj(argsArr[i], 0);
            }
        }
    }

    data = argsArr.join(" ");

    // I want ALL my logs!
    data = data.split("\n");
    for (i = 0; i < data.length; i += 1) {
        datum = data[i];
        if (datum.length < 500) {
            console.error(datum);
        } else {
            // Do our own wrapping
            for (pos = 0; pos < datum.length; pos += 500) {
                console.error(datum.slice(pos, pos + 500));
            }
        }
    }
};

var log = logBase;

/* Simple debug function to print out to console error, error because other stuff does not show up in sys logs.. */
var debug = logBase;

process.on("uncaughtException", function (e) {
    log("Uncaught error: " + e.stack);
    //throw e;
});
