/* A stand-in for Foundations' Future, enough to run the service off device.
 *
 * The real one comes from the mojoservice/foundations frameworks, which only
 * exist on a webOS image. The service uses a small and well-defined slice of
 * it, so reproducing that slice is what makes the store testable on a build
 * machine at all:
 *
 *   new Future()          unresolved
 *   new Future(value)     resolved
 *   future.result = v     resolve, and run any waiting then() callbacks
 *   future.result         the value - throws if an exception was set instead
 *   future.exception = e  resolve with a failure
 *   future.then(cb)       run cb(future) once resolved; cb may set result again
 *   future.then(scope,cb) same, with an explicit `this`
 *   future.nest(inner)    wait for inner, then adopt its result or exception
 *
 * The one subtlety worth stating: a then() callback resolves the future again
 * for the next callback in the chain, so a resolution is consumed by exactly
 * one callback. Setting `result` from inside a callback therefore re-arms the
 * chain rather than re-running it, which is what the service's
 * future.then(...).then(...) sequences rely on.
 */
/*jslint node: true */

function Future(initialValue) {
    "use strict";
    this._callbacks = [];
    this._hasValue = false;
    this._dispatching = false;
    this._value = undefined;
    this._exception = undefined;

    if (arguments.length > 0) {
        this.result = initialValue;
    }
}

Object.defineProperty(Future.prototype, "result", {
    get: function () {
        "use strict";
        if (this._exception !== undefined) {
            throw this._exception;
        }
        return this._value;
    },
    set: function (value) {
        "use strict";
        this._value = value;
        this._exception = undefined;
        this._hasValue = true;
        this._dispatch();
    }
});

Object.defineProperty(Future.prototype, "exception", {
    get: function () {
        "use strict";
        return this._exception;
    },
    set: function (err) {
        "use strict";
        this._exception = err;
        this._value = undefined;
        this._hasValue = true;
        this._dispatch();
    }
});

Future.prototype.then = function (scope, callback) {
    "use strict";
    if (typeof scope === "function") {
        callback = scope;
        scope = null;
    }
    this._callbacks.push({ scope: scope, callback: callback });
    this._dispatch();
    return this;
};

Future.prototype.nest = function (inner) {
    "use strict";
    var self = this;

    // Un-resolve: we are now waiting on `inner`, whatever we held before.
    this._hasValue = false;

    inner.then(function () {
        try {
            self.result = inner.result;
        } catch (e) {
            self.exception = e;
        }
    });

    return this;
};

Future.prototype._dispatch = function () {
    "use strict";
    var entry;

    // Re-entrancy guard: a callback that resolves this future again must not
    // recurse into the loop below - it just re-arms it.
    if (this._dispatching) {
        return;
    }
    this._dispatching = true;

    try {
        while (this._hasValue && this._callbacks.length > 0) {
            entry = this._callbacks.shift();
            this._hasValue = false;
            try {
                entry.callback.call(entry.scope || this, this);
            } catch (e) {
                this.exception = e;
            }
        }
    } finally {
        this._dispatching = false;
    }
};

module.exports = { Future: Future };
