// Copyright (c) 2026 Herman van Hazendonk
// SPDX-License-Identifier: Apache-2.0

'use strict';

/*
	The old service's bugs (README.md, K1-K8), one test each; every one of
	them fails on the rewrite as it first was, which answered as the old
	service did.
*/

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {boot, tempDir} = require('./boot');

// An exportKeystore envelope around any JSON text, as a backup made elsewhere could be.
function envelope(passphrase, text) {
	const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
	const key = crypto.scryptSync(passphrase, salt, 32, {N: 16384, r: 8, p: 1});
	const c = crypto.createCipheriv('aes-256-gcm', key, iv);
	const body = Buffer.concat([c.update(Buffer.from(text, 'utf-8')), c.final()]);
	return {version: 1, kdf: 'scrypt', kdfParams: {N: 16384, r: 8, p: 1}, cipher: 'aes-256-gcm',
		salt: salt.toString('base64'), iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'),
		ciphertext: body.toString('base64')};
}

test('K1: keys and apps named after what every object has are ordinary keys and apps', async () => {
	const km = await boot();
	try {
		for (const name of ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf']) {
			assert.deepStrictEqual(await km.ask('store', {keyname: name, keydata: 'v-' + name, type: 'ASCIIBLOB', nohide: true}),
				{returnValue: true}, name);
			assert.strictEqual((await km.ask('fetchKey', {keyname: name})).keydata, 'v-' + name);
			assert.strictEqual((await km.ask('keyInfo', {keyname: name})).returnValue, true);
		}
		assert.strictEqual((await km.ask('keyInfo', {keyname: 'isPrototypeOf'})).errorText,
			'MojoService: no errorCode supplied Key not found');
		const text = '{"__proto__": {"polluted": {"keyname": "polluted", "type": "ASCIIBLOB", "keydata": "p-1", "nohide": true}},' +
			' "hasOwnProperty": {"k": {"keyname": "k", "type": "ASCIIBLOB", "keydata": "p-2", "nohide": true}}}';
		const r = await km.ask('importKeystore', {passphrase: 'pp', keystore: envelope('pp', text)});
		assert.deepStrictEqual(r, {returnValue: true, imported: 2, skipped: 0, failed: [],
			namespaces: ['__proto__', 'hasOwnProperty']});
		assert.strictEqual(({}).polluted, undefined);
		const ex = await km.ask('exportKeystore', {passphrase: 'pp'});
		assert.strictEqual(ex.count, 7);
		assert.strictEqual((await km.ask('fetchKey', {keyname: 'polluted'}, {appId: '__proto__'})).keydata, 'p-1');
	} finally {
		km.cleanup();
	}
});

test('K2: a key stored with null or an array in it reads back as it was stored', async () => {
	const km = await boot();
	try {
		await km.ask('store', {keyname: 'n', keydata: 'null-case', type: 'ASCIIBLOB', nohide: null});
		await km.ask('store', {keyname: 'a', keydata: 'array-case', type: 'ASCIIBLOB', nohide: [1, 2]});
		assert.deepStrictEqual(await km.ask('keyInfo', {keyname: 'n'}),
			{keyname: 'n', type: 'ASCIIBLOB', nohide: null, noexport: false, returnValue: true});
		assert.deepStrictEqual(await km.ask('fetchKey', {keyname: 'a'}),
			{keyname: 'a', keydata: 'array-case', type: 'ASCIIBLOB', nohide: [1, 2], noexport: false, returnValue: true});
		// And after a restart, from what is on disk.
		km.stop();
		const again = await boot({dir: km.dir});
		assert.deepStrictEqual((await again.ask('keyInfo', {keyname: 'n'})).nohide, null);
		again.stop();
	} finally {
		km.cleanup();
	}
});

test('K3: generate with a size randomBytes will not take answers at once', async () => {
	const km = await boot({timeoutS: 3});
	try {
		for (const size of ['16', -1, 2 ** 32]) {
			const t0 = Date.now();
			assert.deepStrictEqual(await km.ask('generate', {keyname: 'h', type: 'HMACSHA1', size}),
				{errorText: 'Need valid size parameter', errorCode: -1, exception: '[object Object]', returnValue: false},
				JSON.stringify(size));
			assert.ok(Date.now() - t0 < 1000);
		}
		assert.deepStrictEqual(await km.ask('generate', {keyname: 'h', type: 'HMACSHA1', size: 20}), {returnValue: true});
	} finally {
		km.cleanup();
	}
});

test('K4: crypt with a key that is not nohide answers at once', async () => {
	const km = await boot({timeoutS: 3});
	try {
		await km.ask('store', {keyname: 'hid', keydata: crypto.randomBytes(16).toString('base64'), type: 'AES'});
		const t0 = Date.now();
		assert.deepStrictEqual(await km.ask('crypt', {keyname: 'hid', algorithm: 'AES', data: 'AAAA'}),
			{errorText: 'Key cannot be used: it was not stored with nohide.', errorCode: -1, exception: '[object Object]',
				returnValue: false});
		assert.ok(Date.now() - t0 < 1000);
		// A wrong algorithm is still the answer it was.
		assert.strictEqual((await km.ask('crypt', {keyname: 'hid', algorithm: 'DES', data: 'AAAA'})).errorText,
			'Stored key algorithm and parameter differ.');
	} finally {
		km.cleanup();
	}
});

test('K5: crypt whose cipher fails at its end answers at once', async () => {
	const km = await boot({timeoutS: 3});
	try {
		// A fixed key, so the decrypt below fails its padding check every time.
		const keydata = crypto.createHash('sha256').update('k5-fixture').digest().subarray(0, 16).toString('base64');
		await km.ask('store', {keyname: 'a', keydata, type: 'AES', nohide: true});
		for (const [params, errorText] of [
			[{pad: 'none', data: 'AAAA'}, 'error:1C80006B:Provider routines::wrong final block length'],
			[{decrypt: true, data: Buffer.alloc(16).toString('base64')}, 'error:1C800064:Provider routines::bad decrypt']]) {
			const t0 = Date.now();
			assert.deepStrictEqual(await km.ask('crypt', Object.assign({keyname: 'a', algorithm: 'AES', mode: 'cbc'}, params)),
				{errorText, errorCode: -1, exception: '[object Object]', returnValue: false});
			assert.ok(Date.now() - t0 < 1000);
		}
		// A wrong algorithm is still the answer it was, and a good call still works.
		assert.strictEqual((await km.ask('crypt', {keyname: 'a', algorithm: 'DES', mode: 'cbc', pad: 'none', data: 'AAAA'})).errorText,
			'Stored key algorithm and parameter differ.');
		assert.strictEqual((await km.ask('crypt', {keyname: 'a', algorithm: 'AES', mode: 'cbc', data: 'AAAA'})).returnValue, true);
	} finally {
		km.cleanup();
	}
});

test('K6: a keystore that will not load answers every call with why, and writes nothing', async () => {
	const root = tempDir();
	try {
		// store.db that is a directory; a keystore directory under a file, which mkdir cannot make.
		const unreadable = path.join(root, 'a');
		fs.mkdirSync(path.join(unreadable, 'store.db'), {recursive: true});
		fs.writeFileSync(path.join(root, 'file'), '');
		for (const [dir, errorText] of [
			[unreadable, 'Keystore not available: store.db could not be read (EISDIR)'],
			[path.join(root, 'file', 'keystore'), 'Keystore not available: the keystore directory could not be made (ENOTDIR)']]) {
			const km = await boot({dir, timeoutS: 3});
			try {
				const before = fs.existsSync(dir) ? fs.readdirSync(dir).sort() : null;
				for (const [m, p] of [['keyInfo', {keyname: 'x'}], ['store', {keyname: 'x', keydata: 'AAAA', type: 'AES'}],
					['initialize', {}]]) {
					const t0 = Date.now();
					assert.deepStrictEqual(await km.ask(m, p),
						{errorText, errorCode: -1, exception: '[object Object]', returnValue: false}, m);
					assert.ok(Date.now() - t0 < 1000);
				}
				assert.deepStrictEqual(fs.existsSync(dir) ? fs.readdirSync(dir).sort() : null, before);
				assert.ok(fs.statSync(path.join(unreadable, 'store.db')).isDirectory());
			} finally {
				km.cleanup();
			}
		}
	} finally {
		fs.rmSync(root, {recursive: true, force: true});
	}
});

test('K7: importKeystore goes on past an entry it cannot import, and names it as failed', async () => {
	const km = await boot({timeoutS: 3});
	try {
		const good = name => ({keyname: name, type: 'ASCIIBLOB', keydata: 'fixture-' + name, nohide: true});
		for (const [keys, failed] of [
			[{'org.webosports.test': {bad: null, g1: good('g1')}}, ['org.webosports.test/bad']],
			[{'org.webosports.test': {g1: good('g1'), bad: null, g2: good('g2')}}, ['org.webosports.test/bad']],
			[{'org.webosports.test': {g1: good('g1'), num: {keyname: 'num', type: 'AES', keydata: 5}, g2: good('g2')}},
				['org.webosports.test/num']]]) {
			const t0 = Date.now();
			const r = await km.ask('importKeystore', {passphrase: 'pp-fixture', keystore: envelope('pp-fixture', JSON.stringify(keys))});
			assert.ok(Date.now() - t0 < 1500);
			const names = Object.keys(keys['org.webosports.test']).filter(n => n.startsWith('g'));
			assert.deepStrictEqual(r, {returnValue: true, imported: names.length, skipped: 0, failed,
				namespaces: ['org.webosports.test']});
			for (const n of names) {
				assert.strictEqual((await km.ask('fetchKey', {keyname: n})).keydata, 'fixture-' + n);
				assert.deepStrictEqual(await km.ask('remove', {keyname: n}), {returnValue: true});
			}
			assert.strictEqual((await km.ask('keyInfo', {keyname: 'num'})).returnValue, false);
		}
		// What the caller sent as keydata is not in the log.
		assert.ok(!km.logs.some(l => /fixture-|Received type number/.test(l)));
	} finally {
		km.cleanup();
	}
});
