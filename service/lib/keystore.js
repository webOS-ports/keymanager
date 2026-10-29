// Copyright (c) 2014 Achim Königs, 2026 Herman van Hazendonk
// SPDX-License-Identifier: Apache-2.0

'use strict';

/*
	The key store: javascript/utils/KeyStore.js and the set-up of
	KeyManagerServiceAssistant.js, without Foundations' futures.

	/var/palm/keystore/key is the master key (256 random bytes) and
	store.db is JSON: {appId: {keyname: record}}, a record being what the
	method that wrote it was given (keyname, type, size, nohide, noexport,
	in the order it set them) with keydata the encrypted bytes, as
	JSON.stringify writes a Buffer: {"type":"Buffer","data":[...]}. That
	format, and what crypto.js does to the bytes, is unchanged, so a device
	keeps its keys across the update, and the old service reads what this
	one writes.

	Everything here but the file reads and writes is synchronous, as it was
	under the futures: they were all already settled when they were handed
	back. What the futures did decide is where an exception ends up, and
	the methods keep that (commands.js): a throw straight out of a method
	is the command's error, one inside a .then callback was caught by the
	future and the command never answered. importAll() is the only method
	here with code in such a callback; it returns HANG for a throw there.

	Never log key material here, or anything a caller sent as a key (PR #16).
*/

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const KeymanagerCrypto = require('./crypto');

const HANG = Symbol('no reply');
const MODE = 384; // 0600

function createKeyStore({dir = '/var/palm/keystore/', log = console} = {}) {
	// The old paths were string concatenations onto a folder ending in "/".
	const keystoreFolder = dir.endsWith('/') ? dir : dir + '/';
	const keyFile = path.join(keystoreFolder, 'key');
	const keyStoreFile = path.join(keystoreFolder, 'store.db');
	const say = (...args) => log.log(args.map(a => typeof a === 'string' ? a : String(a && a.message || a)).join(' '));

	let database = {};
	let masterkey = '';
	let saving = false;
	let savePending = false;
	// Writes in flight, so a test or the A/B can wait for the disk to settle.
	let writes = 0;
	let idleWaiters = [];
	function writeStart() {
		writes++;
	}
	function writeEnd() {
		writes--;
		if (writes === 0) {
			const w = idleWaiters;
			idleWaiters = [];
			w.forEach(f => f());
		}
	}

	/* Write the store atomically, and never two at once: a temp file, then
	   rename; a save asked for while one runs is done once after it. */
	function saveDB() {
		if (saving) {
			savePending = true;
			return;
		}
		saving = true;
		writeStart();

		const tmpFile = keyStoreFile + '.tmp';
		const snapshot = JSON.stringify(database);

		function done() {
			saving = false;
			if (savePending) {
				savePending = false;
				saveDB();
			}
			writeEnd();
		}

		fs.writeFile(tmpFile, snapshot, {mode: MODE}, function writeCB(err) {
			if (err) {
				say('Could not write keydb file:', err);
				done();
				return;
			}
			fs.chmod(tmpFile, MODE, function chmodCB(chmodErr) {
				if (chmodErr) {
					say('Could not tighten permissions on the keydb file:', chmodErr);
				}
				fs.rename(tmpFile, keyStoreFile, function renameCB(renameErr) {
					if (renameErr) {
						say('Could not put the keydb file in place:', renameErr);
					} else {
						say('Keydb saved.');
					}
					done();
				});
			});
		});
	}

	// -> {returnValue: true, data} or {returnValue: false, message}, never a throw.
	function crypt(decrypt, inData) {
		try {
			const data = decrypt ? KeymanagerCrypto.decrypt(masterkey, inData) : KeymanagerCrypto.encrypt(masterkey, inData);
			return {returnValue: true, data};
		} catch (e) {
			say('Could not ' + (decrypt ? 'decrypt' : 'encrypt') + ' keystore record:', e.message);
			return {returnValue: false, message: e.message};
		}
	}

	// One record's plaintext, as an export wants it: ASCIIBLOB as utf-8, the rest base64.
	function exportRecord(keyname, record) {
		const blob = Buffer.isBuffer(record.keydata) ? record.keydata : Buffer.from(record.keydata.data);
		const plain = KeymanagerCrypto.decrypt(masterkey, blob);
		return {
			keyname: keyname,
			type: record.type,
			size: record.size,
			nohide: record.nohide,
			noexport: record.noexport,
			keydata: (record.type === 'ASCIIBLOB') ? plain.toString('utf-8') : plain.toString('base64')
		};
	}

	const store = {
		HANG,

		/* A deep copy, as the old one made it: own property names, a Buffer
		   copied, any other object (an array too, and null, which throws)
		   copied the same way. */
		copyKey(dest, from) {
			const props = Object.getOwnPropertyNames(from);
			props.forEach(function (name) {
				if (!dest[name]) {
					if (Buffer.isBuffer(from[name])) {
						dest[name] = Buffer.alloc(from[name].length);
						from[name].copy(dest[name]);
					} else if (typeof from[name] === 'object') {
						dest[name] = store.copyKey({}, from[name]);
					} else {
						dest[name] = from[name];
					}
				}
			});
			return dest;
		},

		getKeyRawByName(appid, keyname) {
			const appStore = database[appid];
			if (appStore && appStore[keyname]) {
				const key = store.copyKey({}, appStore[keyname]);
				if (!Buffer.isBuffer(key.keydata)) {
					key.keydata = Buffer.from(key.keydata.data);
				}
				return {key, returnValue: true};
			}
			return {returnValue: false, message: 'Key not found'};
		},

		getKeyDecryptedByName(appid, keyname) {
			const result = store.getKeyRawByName(appid, keyname);
			if (result.returnValue !== true) {
				return {returnValue: false, message: result.message};
			}
			const key = result.key;
			if (key.nohide) {
				const r2 = crypt(true, Buffer.from(key.keydata));
				if (r2.returnValue !== true) {
					return {returnValue: false, message: r2.message || 'Could not decrypt key.'};
				}
				key.keydata = key.type === 'ASCIIBLOB' ? r2.data.toString('utf-8') : r2.data.toString('base64');
				key.returnValue = true;
				return key;
			}
			delete key.keydata;
			key.returnValue = true;
			return key;
		},

		// May throw (keydata Buffer.from cannot take), after making the app's store.
		putKey(appid, key) {
			if (!appid || !key || !key.keyname) {
				return {returnValue: false, message: 'Need appid, key and keyname.'};
			}
			let appstore = database[appid];
			if (!appstore) {
				appstore = {};
				database[appid] = appstore;
			}
			if (appstore[key.keyname]) {
				return {returnValue: false, message: 'Key already exists.'};
			}
			const cData = key.type === 'ASCIIBLOB' ? Buffer.from(key.keydata, 'utf-8') : Buffer.from(key.keydata, 'base64');
			const result = crypt(false, cData);
			if (result.returnValue !== true) {
				say('Could not encrypt.');
				return {returnValue: false, errorTest: 'Could not encrypt key.'};
			}
			key.keydata = result.data;
			appstore[key.keyname] = key;
			saveDB();
			return {returnValue: true};
		},

		deleteKey(appid, keyname) {
			const appstore = database[appid];
			if (appstore && appstore[keyname]) {
				delete appstore[keyname];
				saveDB();
				return {returnValue: true};
			}
			return {returnValue: false, message: 'Key not found.'};
		},

		// One key, decrypted, from the caller's own app.
		exportKey(appid, keyname) {
			const appStore = database[appid];
			if (!appStore || !appStore[keyname]) {
				return {returnValue: false, message: 'Key not found'};
			}
			try {
				return {returnValue: true, key: exportRecord(keyname, appStore[keyname])};
			} catch (e) {
				return {returnValue: false, message: e.message};
			}
		},

		// A key's plaintext bytes, for wrapping; null when missing or unreadable.
		keyMaterial(appid, keyname) {
			const appStore = database[appid];
			if (!appStore || !appStore[keyname]) {
				return null;
			}
			try {
				return KeymanagerCrypto.decrypt(masterkey,
					Buffer.isBuffer(appStore[keyname].keydata) ? appStore[keyname].keydata :
						Buffer.from(appStore[keyname].keydata.data));
			} catch (e) {
				say('Cannot read ' + appid + '/' + keyname + ':', e.message);
				return null;
			}
		},

		// Which of this app's keys has the fingerprint, if any.
		findKeyByFingerprint(appid, fingerprint) {
			const appStore = database[appid];
			if (!appStore) {
				return null;
			}
			for (const keyname in appStore) {
				if (appStore.hasOwnProperty(keyname)) {
					const material = store.keyMaterial(appid, keyname);
					if (material && KeymanagerCrypto.keyFingerprint(material) === fingerprint) {
						return {keyname, material};
					}
				}
			}
			return null;
		},

		importKey(appid, key, overwrite) {
			if (!appid || !key || !key.keyname) {
				return {returnValue: false, message: 'Need appid and a key with a keyname.'};
			}
			const appStore = database[appid];
			if (appStore && appStore[key.keyname]) {
				if (!overwrite) {
					return {returnValue: false, message: 'Key already exists.'};
				}
				delete appStore[key.keyname];
			}
			return store.putKey(appid, {
				keyname: key.keyname,
				type: key.type,
				size: key.size,
				nohide: key.nohide,
				noexport: key.noexport,
				keydata: key.keydata
			});
		},

		// Every exportable key, decrypted, for exportKeystore to encrypt under a passphrase.
		exportAll() {
			const out = {};
			let count = 0;
			const failed = [];
			const excluded = [];
			try {
				for (const appid in database) {
					if (database.hasOwnProperty(appid)) {
						const appStore = database[appid];
						for (const keyname in appStore) {
							if (appStore.hasOwnProperty(keyname)) {
								const record = appStore[keyname];
								if (record.noexport === true) {
									excluded.push(appid + '/' + keyname);
									continue;
								}
								let plain;
								try {
									plain = exportRecord(keyname, record);
								} catch (e) {
									say('Cannot export ' + appid + '/' + keyname + ':', e.message);
									failed.push(appid + '/' + keyname);
									continue;
								}
								if (!out[appid]) {
									out[appid] = {};
								}
								out[appid][keyname] = plain;
								count += 1;
							}
						}
					}
				}
			} catch (err) {
				return {returnValue: false, message: err.message};
			}
			return {returnValue: true, keys: out, count, failed, excluded};
		},

		/* An export put back, each key under this device's master key; one
		   already there is skipped unless overwrite. The old code went from
		   key to key in the .then of the one before: once the first key was
		   stored, a throw ended the import with no answer (HANG). */
		importAll(keys, overwrite) {
			const pending = [];
			let imported = 0;
			let skipped = 0;
			const failed = [];
			const namespaces = {};
			let inThen = false;

			if (!keys || typeof keys !== 'object') {
				return {returnValue: false, message: 'No keys to import.'};
			}
			for (const appid in keys) {
				if (keys.hasOwnProperty(appid)) {
					for (const keyname in keys[appid]) {
						if (keys[appid].hasOwnProperty(keyname)) {
							pending.push({appid, key: keys[appid][keyname]});
						}
					}
				}
			}

			for (const entry of pending) {
				try {
					const appStore = database[entry.appid];
					const exists = appStore && appStore[entry.key.keyname];
					if (exists && !overwrite) {
						skipped += 1;
						continue;
					}
					if (exists) {
						delete appStore[entry.key.keyname];
					}
					const result = store.putKey(entry.appid, {
						keyname: entry.key.keyname,
						type: entry.key.type,
						size: entry.key.size,
						nohide: entry.key.nohide,
						noexport: entry.key.noexport,
						keydata: entry.key.keydata
					});
					inThen = true;
					if (result && result.returnValue === true) {
						imported += 1;
						namespaces[entry.appid] = (namespaces[entry.appid] || 0) + 1;
					} else {
						failed.push(entry.appid + '/' + entry.key.keyname);
					}
				} catch (e) {
					if (!inThen) {
						throw e;
					}
					say('importKeystore stopped: ' + (e && e.name));
					return HANG;
				}
			}

			const written = Object.keys(namespaces).sort();
			if (written.length > 0) {
				say('Import wrote to ' + written.length + ' namespace(s): ' +
					written.map(name => name + ' (' + namespaces[name] + ')').join(', '));
			}
			return {returnValue: true, imported, skipped, failed, namespaces: written};
		},

		/* The set-up the service assistant did before any command ran:
		   -> 'ok', or 'stuck' when it never finished (mkdir failed, or the
		   store could not be read), and no command ever ran. */
		load() {
			return new Promise(resolve => {
				fs.access(keystoreFolder, function existsCB(error) {
					if (!error) {
						resolve(true);
						return;
					}
					fs.mkdir(keystoreFolder, function (err) {
						resolve(!err);
					});
				});
			}).then(dirOk => {
				if (!dirOk) {
					return 'stuck';
				}
				return store.loadKey().then(r => r.returnValue ? store.loadDatabase().then(() => 'ok') : 'ok');
			});
		},

		// -> {returnValue: true} once the database is in memory; never settles when the file will not read.
		loadDatabase() {
			return new Promise(resolve => {
				fs.access(keyStoreFile, function existsCB(error) {
					if (error) {
						database = {};
						resolve({returnValue: false});
						return;
					}
					fs.readFile(keyStoreFile, function fileReadCB(err, data) {
						if (err) {
							say('Could not read store file. Error: ', err);
							return;
						}
						try {
							database = JSON.parse(data.toString('utf-8'));
						} catch (e) {
							say('Could not read keystore from file: ' + e.name);
							say('Creating fresh keystore, expect issues.');
							database = {};
						}
						resolve({returnValue: true});
					});
				});
			});
		},

		loadKey() {
			return new Promise(resolve => {
				fs.readFile(keyFile, function fileReadCB(err, data) {
					if (err) {
						nodeCrypto.randomBytes(256, function randomCB(ex, buf) {
							if (ex) {
								say('Could not create random key:', ex);
								resolve({returnValue: false});
								return;
							}
							masterkey = buf;
							resolve({returnValue: true});
							writeStart();
							fs.writeFile(keyFile, masterkey, {mode: MODE}, function writeCB(werr) {
								say(werr ? 'Could not write key file: ' + werr.message : 'Keyfile saved.');
								writeEnd();
							});
						});
						return;
					}
					masterkey = data;
					// Existing devices had this file 0644: tighten it in passing.
					writeStart();
					fs.chmod(keyFile, MODE, function chmodCB(chmodErr) {
						if (chmodErr) {
							say('Could not tighten permissions on the key file:', chmodErr);
						}
						writeEnd();
					});
					resolve({returnValue: true});
				});
			});
		},

		// Resolves when no write is in flight (tests, the A/B).
		idle() {
			return writes === 0 ? Promise.resolve() : new Promise(r => idleWaiters.push(r));
		}
	};
	return store;
}

module.exports = {createKeyStore, HANG};
