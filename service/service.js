// Copyright (c) 2014 Achim Königs, 2026 Herman van Hazendonk
// SPDX-License-Identifier: Apache-2.0

'use strict';

/*
	com.palm.keymanager: keeps keys and credentials for apps and services,
	encrypted under the device's master key in /var/palm/keystore.

	The launcher (run-js-service -> jsservicelauncher's bootstrap-node.js)
	requires this directory, as it has a package.json, and calls run().
	Nothing starts on require, so a test can start() it on a stand-in bus.
	The methods are in lib/commands.js, the store in lib/keystore.js and its
	encryption in lib/crypto.js.
*/

const {createBus} = require('./lib/bus');
const {createKeyStore} = require('./lib/keystore');
const {createCommands, createTable, SERVICE, NAMES} = require('./lib/commands');
const {DEFAULT_TIMEOUT_S} = require('./lib/mojo');

const NAME = SERVICE;
// services.json's activityTimeout: mojoservice quit after 30 s with no command running.
const IDLE_MS = 30000;

/*
	start({palmbus, ...}): the service on that bus. keystoreDir is where the
	key and store.db are (/var/palm/keystore/); timeoutS is the command
	timeout (mojoservice's 60 s).
*/
async function start({palmbus, exit, idleMs = IDLE_MS, log = console, keystoreDir, timeoutS = DEFAULT_TIMEOUT_S} = {}) {
	const bus = createBus({palmbus, name: NAME, exit, idleMs, log});
	const keyStore = createKeyStore({dir: keystoreDir, log});
	// The methods answer from the start; a call that comes in while the store loads waits.
	const ready = keyStore.load();
	const commands = createCommands({keyStore, log});
	bus.serve(createTable({commands, ready, log, timeoutS, subscribe: bus.subscribe}));
	const state = await ready;
	log.log(NAME + ': ' + (state === 'ok' ? 'up' : 'set-up did not finish: ' + state.stuck) + ' (' + NAMES.length +
		' methods, node ' + process.version + ')');
	return {bus, keyStore, commands, state};
}

let running = null;
function run() {
	if (running) {
		return running;
	}
	process.title = NAME;
	// palmbus is the launcher's: it is there on the device and nowhere else.
	running = start({palmbus: require('palmbus')});
	running.catch(e => {
		console.error(NAME + ': failed to start: ' + ((e && e.stack) || e));
		process.exit(1);
	});
	return running;
}

module.exports = {start, run, NAME};

if (require.main === module) {
	run();
}
