/* Loads the keymanager service sources off device.
 *
 * On device these files are concatenated into one sandbox by jsservicelauncher,
 * with Foundations, `fs`, `nodeCrypto` and the keystore paths supplied as
 * globals. Nothing is a CommonJS module, so they cannot simply be require()d.
 * A vm context reproduces that arrangement closely enough to exercise the real
 * code rather than a copy of it.
 *
 * The two knobs a test needs are the keystore paths (pointed at a temp
 * directory) and `nodeCrypto`, which can be masked to check the fallbacks for a
 * runtime that lacks hkdfSync.
 */
/*jslint node: true */

var fs = require("fs");
var os = require("os");
var path = require("path");
var vm = require("vm");

var SERVICE_DIR = path.join(__dirname, "..", "service");
var Future = require("./future.js").Future;

function mkdtemp(prefix) {
    "use strict";
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function rmrf(target) {
    "use strict";
    try {
        fs.rmSync(target, { recursive: true, force: true });
    } catch (ignored) {
        // best effort - a leftover temp dir is not worth failing a run over
    }
}

/**
 * options:
 *   root        directory to keep key/store in (created if absent)
 *   sources     source paths to load, relative to service/. Defaults to the
 *               crypto + in-memory store, which is what sources.json loads.
 *   nodeCrypto  stand in a different crypto module (see the hkdf fallback test)
 *   quiet       silence the service's log()/debug()
 */
function loadService(options) {
    "use strict";
    options = options || {};

    var root = options.root || mkdtemp("keymanager-test-");
    if (!fs.existsSync(root)) {
        fs.mkdirSync(root, { recursive: true });
    }

    var sandbox = {
        Future: Future,
        fs: fs,
        nodeCrypto: options.nodeCrypto || require("crypto"),
        Buffer: Buffer,
        console: console,
        require: require,
        process: process,
        setTimeout: setTimeout,

        // Normally set by KeyManagerServiceAssistant.js, which we do not load:
        // it hardcodes /var/palm/keystore and would have the suite writing to
        // the real one.
        keystoreFolder: root + path.sep,
        keyFile: path.join(root, "key"),
        keyStoreFile: path.join(root, "store.db"),

        log: options.quiet ? function () { return; } : console.log,
        debug: function () { return; }
    };
    sandbox.global = sandbox;

    var context = vm.createContext(sandbox);

    var sources = options.sources || [
        "javascript/utils/Common.js",
        "javascript/utils/Crypto.js",
        "javascript/utils/KeyStore.js"
    ];

    sources.forEach(function (relative) {
        var file = path.join(SERVICE_DIR, relative);
        var code = fs.readFileSync(file, "utf8");
        try {
            vm.runInContext(code, context, { filename: relative });
        } catch (err) {
            throw new Error("Failed loading " + relative + ": " + err.message);
        }
    });

    context.__root = root;
    return context;
}

/** Runs a Future to completion, resolving with its value or rejecting. */
function settle(future) {
    "use strict";
    return new Promise(function (resolve, reject) {
        future.then(function (f) {
            try {
                resolve(f.result);
            } catch (e) {
                reject(e);
            }
        });
    });
}

module.exports = {
    loadService: loadService,
    settle: settle,
    mkdtemp: mkdtemp,
    rmrf: rmrf,
    Future: Future,
    SERVICE_DIR: SERVICE_DIR
};
