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
const {boot} = require('./boot');

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
