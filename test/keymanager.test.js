// Copyright (c) 2026 Herman van Hazendonk
// SPDX-License-Identifier: Apache-2.0

'use strict';

/*
	The methods over the stand-in bus, on a keystore in a temp directory.
	Run: node --test test/ (or test/run.sh, which adds the static checks).
*/

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');
const {boot, tempDir, APP} = require('./boot');
const C = require('../service/lib/crypto');

const OTHER = {appId: 'org.webosports.other'};

// What mojoservice answered for an error with no errorCode of its own.
function noCode(text) {
	return {errorText: 'MojoService: no errorCode supplied ' + text, errorCode: -9999, exception: '[object Object]',
		returnValue: false};
}
function minusOne(text) {
	return {errorText: text, errorCode: -1, exception: '[object Object]', returnValue: false};
}

function onDisk(km) {
	return JSON.parse(fs.readFileSync(km.storeFile, 'utf-8'));
}

const mode = file => fs.statSync(file).mode & 0o777;

test('a fresh device: the directory, a 0600 master key of 256 bytes, no store until a key is stored', async () => {
	const km = await boot();
	try {
		// The key is written after the set-up has read it into memory.
		await km.settle();
		assert.strictEqual(fs.statSync(km.keyFile).size, 256);
		assert.strictEqual(mode(km.keyFile), 0o600);
		assert.strictEqual(fs.existsSync(km.storeFile), false);
		assert.deepStrictEqual(await km.ask('store', {keyname: 'pw', keydata: 'hunter2-test', type: 'ASCIIBLOB', nohide: true}),
			{returnValue: true});
		assert.strictEqual(mode(km.storeFile), 0o600);
	} finally {
		km.cleanup();
	}
});

test('store, fetchKey, keyInfo, remove: the replies the old service gave', async () => {
	const km = await boot();
	try {
		const aes = crypto.randomBytes(16).toString('base64');
		assert.deepStrictEqual(await km.ask('store', {keyname: 'aes', keydata: aes, type: 'AES', nohide: true}),
			{returnValue: true});
		assert.deepStrictEqual(await km.ask('fetchKey', {keyname: 'aes'}),
			{keyname: 'aes', keydata: aes, type: 'AES', nohide: true, noexport: false, returnValue: true});
		assert.deepStrictEqual(await km.ask('keyInfo', {keyname: 'aes'}),
			{keyname: 'aes', type: 'AES', nohide: true, noexport: false, returnValue: true});
		// Another app does not see it.
		assert.deepStrictEqual(await km.ask('fetchKey', {keyname: 'aes'}, OTHER), noCode('Key not found'));
		assert.deepStrictEqual(await km.ask('store', {keyname: 'aes', keydata: aes, type: 'AES'}), noCode('Key already exists.'));
		// Not nohide: fetchKey leaves the key out.
		await km.ask('store', {keyname: 'hid', keydata: aes, type: 'BLOB'});
		assert.deepStrictEqual(await km.ask('fetchKey', {keyname: 'hid'}),
			{keyname: 'hid', type: 'BLOB', noexport: false, returnValue: true});
		assert.deepStrictEqual(await km.ask('remove', {keyname: 'aes'}), {returnValue: true});
		assert.deepStrictEqual(await km.ask('remove', {keyname: 'aes'}), noCode('Key not found.'));
		assert.deepStrictEqual(await km.ask('remove', {}), minusOne('Need keyname parameter.'));
		assert.deepStrictEqual(await km.ask('store', {keyname: 'x', type: 'AES'}), minusOne('Need keydata parameter'));
		assert.deepStrictEqual(await km.ask('store', {keyname: 'x', keydata: 'a', type: 'RSA'}), minusOne('Need valid type parameter'));
		// InitializeAssistant.js was never in sources.json: mojoservice had no assistant to run.
		assert.deepStrictEqual(await km.ask('initialize', {}),
			{returnValue: false, errorCode: -9999, errorText: 'MojoService: no errorCode supplied '});
	} finally {
		km.cleanup();
	}
});

test('the caller: the app id without its pid, else the service name; fetchKey said "erroCode"', async () => {
	const km = await boot();
	try {
		await km.ask('store', {keyname: 'k', keydata: 'one-test', type: 'ASCIIBLOB', nohide: true}, {appId: 'org.example.app 99'});
		assert.strictEqual((await km.ask('fetchKey', {keyname: 'k'}, {appId: 'org.example.app'})).keydata, 'one-test');
		await km.ask('store', {keyname: 'k', keydata: 'two-test', type: 'ASCIIBLOB', nohide: true}, {service: 'org.example.svc'});
		assert.strictEqual((await km.ask('fetchKey', {keyname: 'k'}, {appId: '', service: 'org.example.svc'})).keydata,
			'two-test');
		assert.deepStrictEqual(await km.ask('keyInfo', {keyname: 'k'}, {}), minusOne('Could not determine appId.'));
		assert.deepStrictEqual(await km.ask('fetchKey', {keyname: 'k'}, {}), noCode('Could not determine appId.'));
	} finally {
		km.cleanup();
	}
});

test('a payload that is not JSON: the error mojoservice made of it; null is {}', async () => {
	const km = await boot();
	try {
		assert.deepStrictEqual(await km.ask('keyInfo', {__raw: '{bad'}),
			{returnValue: false, errorCode: -9999, errorText: 'MojoService: no errorCode supplied '});
		assert.deepStrictEqual(await km.ask('store', {__raw: 'null'}), minusOne('Need keyname parameter'));
	} finally {
		km.cleanup();
	}
});

test('store.db: the old format, which the old service reads back', async () => {
	const km = await boot();
	try {
		await km.ask('store', {keyname: 'pw', keydata: 'secret-pw-test', type: 'ASCIIBLOB', nohide: true, noexport: true});
		await km.ask('generate', {keyname: 'gen', type: 'AES', size: 32, nohide: true});
		const db = onDisk(km);
		const rec = db[APP.appId.split(' ')[0]];
		assert.deepStrictEqual(Object.keys(rec.pw), ['keyname', 'keydata', 'type', 'nohide', 'noexport']);
		assert.deepStrictEqual(Object.keys(rec.gen), ['keyname', 'type', 'size', 'nohide', 'keydata']);
		assert.strictEqual(rec.pw.keydata.type, 'Buffer');
		const blob = Buffer.from(rec.pw.keydata.data);
		assert.deepStrictEqual(blob.subarray(0, 4), Buffer.from([0x4B, 0x4D, 0x31, 0x00]));
		// The harness's own HKDF + GCM, not the service's, opens it.
		const master = fs.readFileSync(km.keyFile);
		const prk = crypto.createHmac('sha256', Buffer.alloc(32)).update(master).digest();
		const key = crypto.createHmac('sha256', prk).update(Buffer.from('keymanager keystore v1\u0001')).digest();
		const d = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(4, 16));
		d.setAuthTag(blob.subarray(16, 32));
		assert.strictEqual(Buffer.concat([d.update(blob.subarray(32)), d.final()]).toString(), 'secret-pw-test');
		assert.strictEqual(fs.readFileSync(km.storeFile, 'utf-8').indexOf('secret-pw-test'), -1);
	} finally {
		km.cleanup();
	}
});

test('a store written by the old createCipher scheme opens, checked against openssl', async t => {
	const root = tempDir();
	try {
		const dir = path.join(root, 'keystore');
		fs.mkdirSync(dir);
		const master = 'a-master-key-that-openssl-can-take-on-argv';
		fs.writeFileSync(path.join(dir, 'key'), master, {mode: 0o644});
		let blob;
		try {
			blob = childProcess.execFileSync('openssl', ['enc', '-aes-256-cbc', '-md', 'md5', '-nosalt', '-pass', 'pass:' + master],
				{input: Buffer.from('legacy secret value'), stdio: ['pipe', 'pipe', 'ignore']});
		} catch (e) {
			t.skip('no openssl binary');
			return;
		}
		fs.writeFileSync(path.join(dir, 'store.db'), JSON.stringify({'org.webosports.test': {
			old: {keyname: 'old', type: 'ASCIIBLOB', nohide: true, keydata: {type: 'Buffer', data: Array.from(blob)}}}}));
		const km = await boot({dir});
		try {
			assert.strictEqual((await km.ask('fetchKey', {keyname: 'old'})).keydata, 'legacy secret value');
			// The 0644 key file is tightened.
			assert.strictEqual(mode(path.join(dir, 'key')), 0o600);
		} finally {
			km.stop();
		}
	} finally {
		fs.rmSync(root, {recursive: true, force: true});
	}
});

test('a tampered record does not decrypt, and says so', async () => {
	const km = await boot();
	try {
		await km.ask('store', {keyname: 'v', keydata: 'victim-test', type: 'ASCIIBLOB', nohide: true});
		km.stop();
		const db = onDisk(km);
		db['org.webosports.test'].v.keydata.data[40] ^= 0xff;
		fs.writeFileSync(km.storeFile, JSON.stringify(db));
		const again = await boot({dir: km.dir});
		const r = await again.ask('fetchKey', {keyname: 'v'});
		again.stop();
		assert.strictEqual(r.returnValue, false);
		assert.strictEqual(r.errorCode, -9999);
	} finally {
		km.cleanup();
	}
});

test('25 stores at once: the store still parses and holds them all', async () => {
	const km = await boot();
	try {
		const replies = await Promise.all(Array.from({length: 25}, (x, i) =>
			km.ask('store', {keyname: 'k' + i, keydata: 'v' + i + '-test', type: 'ASCIIBLOB', nohide: true})));
		assert.ok(replies.every(r => r.returnValue === true));
		await km.settle();
		assert.strictEqual(Object.keys(onDisk(km)['org.webosports.test']).length, 25);
		assert.strictEqual(fs.existsSync(km.storeFile + '.tmp'), false);
	} finally {
		km.cleanup();
	}
});

test('generate: the size rules, and an existing name', async () => {
	const km = await boot();
	try {
		assert.deepStrictEqual(await km.ask('generate', {keyname: 'g', type: 'AES', size: 16, nohide: true}), {returnValue: true});
		assert.strictEqual(Buffer.from((await km.ask('fetchKey', {keyname: 'g'})).keydata, 'base64').length, 16);
		assert.deepStrictEqual(await km.ask('generate', {keyname: 'g', type: 'AES', size: 16}), minusOne('Key already exists.'));
		assert.deepStrictEqual(await km.ask('generate', {keyname: 'h', type: 'DES', size: 16}),
			minusOne('Need valid size parameter, (3)DES can only be 24 byte.'));
		assert.deepStrictEqual(await km.ask('generate', {keyname: 'h', type: 'AES', size: 20}),
			minusOne('Need valid size parameter, AES can only be 16, 24 or 32 byte.'));
		assert.deepStrictEqual(await km.ask('generate', {keyname: 'h', type: 'BLOB', size: 20}),
			minusOne('Need valid type parameter'));
	} finally {
		km.cleanup();
	}
});

test('crypt: with an iv, without one (key and iv from the key), and back', async () => {
	const km = await boot();
	try {
		const key = crypto.randomBytes(16);
		await km.ask('store', {keyname: 'c', keydata: key.toString('base64'), type: 'AES', nohide: true});
		const data = Buffer.from('some plaintext to encrypt').toString('base64');
		const iv = crypto.randomBytes(16);
		const enc = await km.ask('crypt', {keyname: 'c', algorithm: 'AES', mode: 'CBC', iv: iv.toString('base64'), data});
		const c = crypto.createCipheriv('aes-128-cbc', key, iv);
		assert.strictEqual(enc.data, Buffer.concat([c.update(Buffer.from(data, 'base64')), c.final()]).toString('base64'));
		const dec = await km.ask('crypt', {keyname: 'c', algorithm: 'AES', iv: iv.toString('base64'), data: enc.data,
			decrypt: true});
		assert.strictEqual(dec.data, data);
		const noIv = await km.ask('crypt', {keyname: 'c', algorithm: 'AES', data});
		const back = await km.ask('crypt', {keyname: 'c', algorithm: 'AES', data: noIv.data, decrypt: true});
		assert.strictEqual(back.data, data);
		assert.deepStrictEqual(await km.ask('crypt', {keyname: 'c', data}), minusOne('Stored key algorithm and parameter differ.'));
		assert.deepStrictEqual(await km.ask('crypt', {keyname: 'c', algorithm: 'AES', mode: 'none', data}),
			minusOne('Unknown algorithm: AES-128'));
	} finally {
		km.cleanup();
	}
});

test('a command that never finished: 504 after the command timeout, as mojoservice answered', async () => {
	const km = await boot({timeoutS: 1});
	try {
		await km.ask('store', {keyname: 'c', keydata: crypto.randomBytes(16).toString('base64'), type: 'AES', nohide: true});
		// A block that is not whole, with no padding: the cipher fails at its end, and the old service never answered.
		const r = await km.ask('crypt', {keyname: 'c', algorithm: 'AES', iv: crypto.randomBytes(16).toString('base64'),
			data: Buffer.alloc(5).toString('base64'), decrypt: true});
		assert.strictEqual(r.errorCode, 504);
		assert.strictEqual(r.errorText, 'commandTimeout in com.palm.keymanager/crypt');
	} finally {
		km.cleanup();
	}
});

test('export and import: a key wrapped with another, put back on another device', async () => {
	const a = await boot();
	const b = await boot();
	try {
		const wrap = crypto.randomBytes(32).toString('base64');
		for (const km of [a, b]) {
			await km.ask('store', {keyname: 'wrap', keydata: wrap, type: 'AES', nohide: true});
		}
		await a.ask('store', {keyname: 'pw', keydata: 'wrapped-secret-test', type: 'ASCIIBLOB', nohide: true});
		const ex = await a.ask('export', {keyname: 'pw', wrappingkeyname: 'wrap'});
		assert.strictEqual(ex.returnValue, true);
		assert.strictEqual(JSON.stringify(ex).indexOf('wrapped-secret-test'), -1);
		assert.deepStrictEqual(await b.ask('import', {wrappedkey: ex.wrappedkey}), {returnValue: true, keyname: 'pw'});
		assert.strictEqual((await b.ask('fetchKey', {keyname: 'pw'})).keydata, 'wrapped-secret-test');
		assert.deepStrictEqual(await b.ask('import', {wrappedkey: ex.wrappedkey}), minusOne('Key already exists.'));
		assert.deepStrictEqual(await b.ask('import', {wrappedkey: ex.wrappedkey}, OTHER), minusOne('wrapping key missing'));
		assert.deepStrictEqual(await a.ask('export', {keyname: 'pw', wrappingkeyname: 'pw'}), minusOne('same keys'));
		assert.deepStrictEqual(await a.ask('export', {keyname: 'pw', wrappingkeyname: 'nope'}), minusOne('unknown key'));
		await a.ask('store', {keyname: 'nx', keydata: 'noexport-test', type: 'ASCIIBLOB', nohide: true, noexport: true});
		assert.deepStrictEqual(await a.ask('export', {keyname: 'nx', wrappingkeyname: 'wrap'}),
			minusOne('key is not exportable'));
	} finally {
		a.cleanup();
		b.cleanup();
	}
});

test('exportKeystore and importKeystore: every key, under a passphrase, onto another device', async () => {
	const a = await boot();
	const b = await boot();
	try {
		await a.ask('store', {keyname: 'pw', keydata: 'backup-secret-test', type: 'ASCIIBLOB', nohide: true});
		await a.ask('store', {keyname: 'tok', keydata: 'other-app-secret', type: 'ASCIIBLOB', nohide: true}, OTHER);
		await a.ask('store', {keyname: 'nx', keydata: 'stays-here-test', type: 'ASCIIBLOB', nohide: true, noexport: true});
		const ex = await a.ask('exportKeystore', {passphrase: 'correct horse'});
		assert.deepStrictEqual([ex.returnValue, ex.count, ex.unreadable, ex.excluded],
			[true, 2, [], ['org.webosports.test/nx']]);
		assert.strictEqual(JSON.stringify(ex).indexOf('secret'), -1);
		assert.deepStrictEqual(await b.ask('importKeystore', {passphrase: 'wrong', keystore: ex.keystore}),
			minusOne('Could not decrypt the export - wrong passphrase, or the export is damaged.'));
		assert.deepStrictEqual(await b.ask('importKeystore', {passphrase: 'correct horse', keystore: ex.keystore}),
			{returnValue: true, imported: 2, skipped: 0, failed: [], namespaces: ['org.webosports.other', 'org.webosports.test']});
		assert.strictEqual((await b.ask('fetchKey', {keyname: 'tok'}, OTHER)).keydata, 'other-app-secret');
		assert.deepStrictEqual(await b.ask('importKeystore', {passphrase: 'correct horse', keystore: ex.keystore}),
			{returnValue: true, imported: 0, skipped: 2, failed: [], namespaces: []});
		assert.deepStrictEqual(await a.ask('exportKeystore', {}), minusOne('Need passphrase parameter'));
	} finally {
		a.cleanup();
		b.cleanup();
	}
});

test('no key material in the log (PR #16)', async () => {
	const km = await boot();
	try {
		const ascii = 'GEZDGNBVGY3TQOJQ-log-test';
		const aes = crypto.randomBytes(16);
		await km.ask('store', {keyname: 'otp', keydata: ascii, type: 'ASCIIBLOB', nohide: true});
		await km.ask('store', {keyname: 'aes', keydata: aes.toString('base64'), type: 'AES', nohide: true});
		await km.ask('fetchKey', {keyname: 'otp'});
		await km.ask('fetchKey', {keyname: 'aes'});
		await km.ask('crypt', {keyname: 'aes', algorithm: 'AES', data: 'AAAA'});
		await km.ask('initialize', {keydata: ascii});
		await km.ask('store', {__raw: '{"keyname": "x", "keydata": "' + ascii + '", '});
		// Node's own messages quote what they were given.
		await km.ask('store', {keyname: 'n', keydata: 987654321123, type: 'AES'});
		const ex = await km.ask('exportKeystore', {passphrase: 'pass-phrase-test'});
		await km.ask('importKeystore', {passphrase: 'pass-phrase-test', keystore: ex.keystore});
		const text = km.logs.join('\n');
		assert.ok(km.logs.length > 0);
		for (const s of [ascii, aes.toString('base64'), aes.toString('hex'), 'pass-phrase-test', '987654321123']) {
			assert.strictEqual(text.indexOf(s), -1, 'found in the log: a ' + s.length + '-character secret');
		}
	} finally {
		km.cleanup();
	}
});

test('crypto.js: records round-trip, carry the magic, differ each time, and fail when tampered with', () => {
	const master = crypto.randomBytes(256);
	const plain = Buffer.from('round trip');
	const one = C.encrypt(master, plain), two = C.encrypt(master, plain);
	assert.ok(C.decrypt(master, one).equals(plain));
	assert.ok(!one.equals(two));
	assert.strictEqual(C.isLegacy(one), false);
	for (const at of [5, 20, one.length - 1]) {
		const bad = Buffer.from(one);
		bad[at] ^= 1;
		assert.throws(() => C.decrypt(master, bad));
	}
	assert.throws(() => C.decrypt(master, one.subarray(0, 20)));
	assert.throws(() => C.decrypt(crypto.randomBytes(256), one));
});
