// Copyright (c) 2026 Herman van Hazendonk
// SPDX-License-Identifier: GPL-3.0-or-later

'use strict';

/*
	The service on a stand-in bus (palmbus.js) with its keystore in a fresh
	directory under os.tmpdir() (set TMPDIR to put it elsewhere), never
	/var/palm/keystore. Every log line is kept, to look for key material in.
*/

const fs = require('fs');
const os = require('os');
const path = require('path');
const {createPalmbus} = require('./palmbus');

const SERVICE = path.join(__dirname, '..', 'service');
const NAME = 'com.palm.keymanager';
const APP = {appId: 'org.webosports.test 4242'};

function tempDir() {
	return fs.mkdtempSync(path.join(os.tmpdir(), 'keymanager-test-'));
}

/*
	boot({dir, timeoutS, fresh}): dir is the keystore directory (a new one
	inside a temp directory by default, not yet made, as on a new device).
*/
async function boot({dir, timeoutS = 2, wait = true} = {}) {
	const root = dir ? null : tempDir();
	const keystoreDir = dir || path.join(root, 'keystore');
	const logs = [];
	const sink = (...a) => logs.push(a.join(' '));
	const log = {log: sink, error: sink, warn: sink, info: sink};
	const calls = [];
	const pb = createPalmbus(async (uri, args) => {
		calls.push({uri, args});
		return {returnValue: true};
	});
	const {start} = require(path.join(SERVICE, 'service'));
	const started = start({palmbus: pb, idleMs: 0, log, keystoreDir, timeoutS, exit() {}});
	const service = wait ? await started : null;

	async function settle() {
		if (service) {
			await service.keyStore.idle();
		}
		await new Promise(r => setTimeout(r, 5));
	}

	// -> the parsed reply, or 'NO REPLY' when none came in waitMs.
	async function ask(method, params, caller = APP, waitMs = (timeoutS + 2) * 1000) {
		let timer;
		const reply = await Promise.race([pb.request(NAME, method, params || {}, caller),
			new Promise(r => {
				timer = setTimeout(() => r('"NO REPLY"'), waitMs);
			})]);
		clearTimeout(timer);
		await settle();
		return JSON.parse(reply);
	}

	function stop() {
		if (service) {
			service.bus.stop();
		}
	}

	return {ask, settle, stop, logs, calls, dir: keystoreDir, root, service, started, pb,
		storeFile: path.join(keystoreDir, 'store.db'), keyFile: path.join(keystoreDir, 'key'),
		cleanup() {
			stop();
			if (root) {
				fs.rmSync(root, {recursive: true, force: true});
			}
		}};
}

module.exports = {boot, tempDir, SERVICE, NAME, APP};
