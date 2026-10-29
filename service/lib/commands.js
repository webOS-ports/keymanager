// Copyright (c) 2014 Achim Königs, 2026 Herman van Hazendonk
// SPDX-License-Identifier: Apache-2.0

'use strict';

/*
	The eleven methods, from javascript/assistants/*Assistant.js, answering
	as they did on mojoservice (mojo.js). Each runs as its run() did:

	- what the run threw, or set as its future's exception, is the error
	  reply: {errorText: <its message>, errorCode, exception, returnValue:
	  false}, with -9999 and "MojoService: no errorCode supplied " when it
	  had no errorCode. Most of them threw {errorCode: -1, message}, and
	  several passed on a KeyStore result ({returnValue: false, message})
	  as it was, which has no errorCode;
	- a throw inside a future's .then callback was caught by the future
	  and the command never answered: mojoservice answered 504 after its
	  60 s command timeout. never() is that;
	- the order of the checks, and so which error a bad call gets, is the
	  old order.

	Nothing that is or may be key material is logged: not keydata, not a
	passphrase, not a wrapped key, not the payload (PR #16).
*/

const nodeCrypto = require('crypto');
const KeymanagerCrypto = require('./crypto');
const {method} = require('./mojo');
const {HANG} = require('./keystore');

const SERVICE = 'com.palm.keymanager';
// mojoservice's answer when it could not make a command's assistant, and for a payload it could
// not parse: the Error it made, with returnValue, errorCode and errorText added and no text.
const NO_ASSISTANT = () => ({returnValue: false, errorCode: -9999, errorText: 'MojoService: no errorCode supplied '});
const NAMES = ['initialize', 'crypt', 'export', 'exportKeystore', 'importKeystore', 'fetchKey', 'generate', 'import',
	'keyInfo', 'remove', 'store'];

// The old runs threw plain objects ({errorCode, message}), and mojoservice
// answered with what they had: "exception" is "[object Object]" for them.
function raise(value) {
	throw value;
}

const never = () => new Promise(() => {});

/* Common.js's getAppId: the app id the hub gives (a WAM app's comes as
   "<appid> <pid>"), else the calling service's name. A message whose
   applicationID() is not a string throws here, as it did. */
function getAppId(msg) {
	let appId = msg.applicationID().split(' ')[0];
	if (!appId) {
		appId = msg.senderServiceName();
	}
	return appId;
}

function needAppId(ctx, errorKey) {
	const appId = getAppId(ctx.msg);
	if (!appId) {
		// fetchKey's said "erroCode", so it went out with -9999.
		raise({[errorKey || 'errorCode']: -1, message: 'Could not determine appId.'});
	}
	return appId;
}

function createCommands({keyStore: ks, log = console}) {
	const say = text => log.log(SERVICE + ': ' + text);

	const commands = {
		crypt(args, ctx) {
			const appId = needAppId(ctx);
			if (!args.keyname) {
				raise({errorCode: -1, message: 'Need keyname parameter'});
			}
			let mode = args.mode;
			if (mode !== 'CBC' && mode !== 'CFB' && mode !== 'ECB' && mode !== 'none') {
				mode = 'CBC';
			}
			const result = ks.getKeyDecryptedByName(appId, args.keyname);
			if (result.returnValue !== true) {
				raise({errorCode: -1, message: result.message});
			}
			/* From here the old code ran in a .then callback. A wrong algorithm
			   set the error and went on; that error is the answer unless a later
			   one in the try below replaced it. A throw outside that try (a key
			   that is not nohide has no keydata), and a cipher that fails at its
			   end (that was an 'error' event no one listened to), left no answer
			   but that one. */
			const mismatch = args.algorithm !== result.type ?
				{errorCode: -1, message: 'Stored key algorithm and parameter differ.'} : null;
			const orHang = () => mismatch ? raise(mismatch) : never();
			let keydata;
			try {
				keydata = Buffer.from(result.keydata, 'base64');
			} catch (e) {
				return orHang();
			}
			let algorithm = result.type + '-' + keydata.length * 8;
			if (mode !== 'none') {
				algorithm += '-' + mode;
			}
			let cipher, head;
			try {
				if (args.iv) {
					const iv = Buffer.from(args.iv, 'base64');
					cipher = args.decrypt ? nodeCrypto.createDecipheriv(algorithm, keydata, iv) :
						nodeCrypto.createCipheriv(algorithm, keydata, iv);
				} else {
					// No iv: key and iv from the key, as createCipher did (EVP_BytesToKey).
					const info = nodeCrypto.getCipherInfo(algorithm);
					if (!info) {
						throw new Error('Unknown algorithm: ' + algorithm);
					}
					const derived = KeymanagerCrypto.legacyKeyAndIv(keydata, info.keyLength, info.ivLength || 0);
					cipher = args.decrypt ? nodeCrypto.createDecipheriv(algorithm, derived.key, derived.iv) :
						nodeCrypto.createCipheriv(algorithm, derived.key, derived.iv);
				}
				if (args.pad === 'none') {
					cipher.setAutoPadding(false);
				}
				head = cipher.update(Buffer.from(args.data, 'base64'));
			} catch (e) {
				raise({errorCode: -1, message: e.message});
			}
			let tail;
			try {
				tail = cipher.final();
			} catch (e) {
				return orHang();
			}
			if (mismatch) {
				raise(mismatch);
			}
			return {returnValue: true, data: Buffer.concat([head, tail]).toString('base64')};
		},

		export(args, ctx) {
			if (!args.keyname) {
				raise({errorCode: -1, message: 'Need keyname parameter'});
			}
			if (!args.wrappingkeyname) {
				raise({errorCode: -1, message: 'Need wrappingkeyname parameter'});
			}
			if (args.keyname === args.wrappingkeyname) {
				raise({errorCode: -1, message: 'same keys'});
			}
			const appId = needAppId(ctx);
			const target = ks.keyMaterial(appId, args.keyname);
			const wrappingMaterial = ks.keyMaterial(appId, args.wrappingkeyname);
			if (!target || !wrappingMaterial) {
				raise({errorCode: -1, message: 'unknown key'});
			}
			const result = ks.exportKey(appId, args.keyname);
			if (!result || result.returnValue !== true) {
				raise({errorCode: -1, message: (result && result.message) || 'unknown key'});
			}
			const key = result.key;
			if (key.noexport === true) {
				raise({errorCode: -1, message: 'key is not exportable'});
			}
			try {
				return {
					returnValue: true,
					wrappedkey: KeymanagerCrypto.wrapKey(wrappingMaterial, Buffer.from(JSON.stringify(key), 'utf-8'))
				};
			} catch (e) {
				return raise({errorCode: -1, message: e.message});
			}
		},

		exportKeystore(args) {
			if (typeof args.passphrase !== 'string' || args.passphrase.length === 0) {
				raise({errorCode: -1, message: 'Need passphrase parameter'});
			}
			const result = ks.exportAll();
			if (!result || result.returnValue !== true) {
				raise({errorCode: -1, message: (result && result.message) || 'Could not read the keystore.'});
			}
			let envelope;
			try {
				envelope = KeymanagerCrypto.encryptWithPassphrase(args.passphrase,
					Buffer.from(JSON.stringify(result.keys), 'utf-8'));
			} catch (e) {
				raise({errorCode: -1, message: e.message});
			}
			say('Exported ' + result.count + ' key(s), ' + result.failed.length + ' unreadable, ' +
				result.excluded.length + ' excluded by noexport.');
			return {
				returnValue: true,
				count: result.count,
				unreadable: result.failed,
				excluded: result.excluded,
				keystore: envelope
			};
		},

		importKeystore(args) {
			if (typeof args.passphrase !== 'string' || args.passphrase.length === 0) {
				raise({errorCode: -1, message: 'Need passphrase parameter'});
			}
			if (!args.keystore || typeof args.keystore !== 'object') {
				raise({errorCode: -1, message: 'Need keystore parameter'});
			}
			let plaintext, keys;
			try {
				plaintext = KeymanagerCrypto.decryptWithPassphrase(args.passphrase, args.keystore);
			} catch (e) {
				raise({errorCode: -1, message: 'Could not decrypt the export - wrong passphrase, or the export is damaged.'});
			}
			try {
				keys = JSON.parse(plaintext.toString('utf-8'));
			} catch (e2) {
				raise({errorCode: -1, message: 'Export decrypted but does not parse.'});
			}
			const result = ks.importAll(keys, args.overwrite === true);
			if (result === HANG) {
				return never();
			}
			if (!result || result.returnValue !== true) {
				raise({errorCode: -1, message: (result && result.message) || 'Could not import the keystore.'});
			}
			say('Imported ' + result.imported + ' key(s), skipped ' + result.skipped + ', failed ' +
				result.failed.length + '.');
			return {
				returnValue: true,
				imported: result.imported,
				skipped: result.skipped,
				failed: result.failed,
				namespaces: result.namespaces
			};
		},

		fetchKey(args, ctx) {
			const appId = needAppId(ctx, 'erroCode');
			const result = ks.getKeyDecryptedByName(appId, args.keyname);
			if (result.returnValue === true) {
				return result;
			}
			return raise(result);
		},

		generate(args, ctx) {
			const key = {};
			const appId = needAppId(ctx);
			if (!args.keyname) {
				raise({errorCode: -1, message: 'Need keyname parameter'});
			}
			key.keyname = args.keyname;
			if (!args.type || (args.type !== 'AES' && args.type !== 'DES' && args.type !== '3DES' &&
				args.type !== 'HMACSHA1')) {
				raise({errorCode: -1, message: 'Need valid type parameter'});
			}
			key.type = args.type;
			if (!args.size) {
				raise({errorCode: -1, message: 'Need valid size parameter'});
			} else if ((key.type === 'DES' || key.type === '3DES') && args.size !== 24) {
				raise({errorCode: -1, message: 'Need valid size parameter, (3)DES can only be 24 byte.'});
			} else if (key.type === 'AES' && args.size !== 16 && args.size !== 24 && args.size !== 32) {
				raise({errorCode: -1, message: 'Need valid size parameter, AES can only be 16, 24 or 32 byte.'});
			}
			key.size = args.size;
			key.nohide = args.nohide;

			if (ks.getKeyRawByName(appId, key.keyname).returnValue === true) {
				raise({errorCode: -1, message: 'Key already exists.'});
			}
			return new Promise((resolve, reject) => {
				try {
					nodeCrypto.randomBytes(key.size, function randomCB(ex, buf) {
						if (ex) {
							say('Could not create random key: ' + ex.name);
							reject({errorCode: -1, message: 'Could not create random key: ' + JSON.stringify(ex)});
							return;
						}
						key.keydata = buf.toString('base64');
						let result;
						try {
							result = ks.putKey(appId, key);
						} catch (e) {
							// The old service's uncaughtException handler took this one: no answer.
							say('generate: ' + e.name);
							return;
						}
						if (result.returnValue === true) {
							resolve(result);
						} else {
							reject(result);
						}
					});
				} catch (e) {
					// K3: a size randomBytes will not take ("16", -1, 2^32: HMACSHA1 has no
					// size rule). The old code threw this in a .then and never answered.
					reject({errorCode: -1, message: 'Need valid size parameter'});
				}
			});
		},

		import(args, ctx) {
			if (!args.wrappedkey || typeof args.wrappedkey !== 'object') {
				raise({errorCode: -1, message: 'Need wrappedkey parameter'});
			}
			const appId = needAppId(ctx);
			const wrapping = ks.findKeyByFingerprint(appId, args.wrappedkey.wrappingKey);
			if (!wrapping) {
				raise({errorCode: -1, message: 'wrapping key missing'});
			}
			let plaintext, key;
			try {
				plaintext = KeymanagerCrypto.unwrapKey(wrapping.material, args.wrappedkey);
			} catch (e) {
				raise({errorCode: -1, message: 'Could not unwrap the key - wrong wrapping key, or the export is damaged.'});
			}
			try {
				key = JSON.parse(plaintext.toString('utf-8'));
			} catch (e2) {
				raise({errorCode: -1, message: 'Wrapped key unwrapped but does not parse.'});
			}
			if (args.keyname) {
				key.keyname = args.keyname;
			}
			const result = ks.importKey(appId, key, args.overwrite === true);
			if (!result || result.returnValue !== true) {
				raise({errorCode: -1, message: (result && result.message) || 'Could not import key.'});
			}
			return {returnValue: true, keyname: key.keyname};
		},

		keyInfo(args, ctx) {
			const appId = needAppId(ctx);
			const result = ks.getKeyRawByName(appId, args.keyname);
			if (result.returnValue === true) {
				delete result.key.keydata;
				result.key.returnValue = true;
				return result.key;
			}
			return raise(result);
		},

		remove(args, ctx) {
			if (!args.keyname) {
				raise({errorCode: -1, message: 'Need keyname parameter.'});
			}
			const appId = needAppId(ctx);
			const result = ks.deleteKey(appId, args.keyname);
			if (result.returnValue === true) {
				return result;
			}
			return raise(result);
		},

		store(args, ctx) {
			const key = {};
			if (!args.keyname) {
				raise({errorCode: -1, message: 'Need keyname parameter'});
			}
			key.keyname = args.keyname;
			if (!args.keydata) {
				raise({errorCode: -1, message: 'Need keydata parameter'});
			}
			key.keydata = args.keydata;
			if (!args.type || (args.type !== 'AES' && args.type !== 'DES' && args.type !== '3DES' &&
				args.type !== 'HMACSHA1' && args.type !== 'BLOB' && args.type !== 'ASCIIBLOB')) {
				raise({errorCode: -1, message: 'Need valid type parameter'});
			}
			key.type = args.type;
			key.nohide = args.nohide;
			key.noexport = args.noexport === true;
			if (args.backup || args.cloud) {
				say('WARNING: backup and cloud backup not supported!');
			}
			const appId = needAppId(ctx);
			const result = ks.putKey(appId, key);
			if (result.returnValue === true) {
				return result;
			}
			return raise(result);
		}
	};
	return commands;
}

/* What the log says of a failed command: its kind and code, and a message
   only when it is one of ours. Node's own messages quote what they were
   given ("Received type number (...)", a JSON parse error's text), and what
   a caller gives this service may be a key. */
function describe(e) {
	if (e && typeof e === 'object' && !(e instanceof Error)) {
		return 'errorCode ' + e.errorCode + ': ' + e.message;
	}
	return (e && e.name) || typeof e;
}

/*
	The bus table: each method as mojoservice ran it. The payload is parsed
	here, as mojoservice did: one that is not JSON is answered with the
	error object it made of it, which has no text; a falsy one is {}.
	initialize has no command: InitializeAssistant.js was never in
	sources.json, so mojoservice could not make its assistant, and answered
	every call so (NO_ASSISTANT); the run that would have said "Not yet
	implemented." never ran.
	ready resolves to 'ok', or to 'stuck' when the set-up never finished:
	mojoservice then never ran a command, and nothing answered.
*/
function createTable({commands, ready, log = console, timeoutS, subscribe}) {
	const table = {};
	for (const name of NAMES) {
		const m = method(SERVICE, name, (args, ctx) => commands[name](args, ctx), {timeoutS, log, subscribe, describe});
		table[name] = {
			raw: true,
			rawPayload: true,
			// mojoservice's own timeout answers (mojo.js); the bus's must not come first.
			timeoutMs: 2147483647,
			handler: async (text, ctx) => {
				if ((await ready) === 'stuck') {
					return never();
				}
				let args;
				try {
					args = JSON.parse(text);
				} catch (e) {
					return NO_ASSISTANT();
				}
				if (!commands[name]) {
					return NO_ASSISTANT();
				}
				return m.handler(args || {}, ctx);
			}
		};
	}
	return table;
}

module.exports = {createCommands, createTable, getAppId, describe, SERVICE, NAMES};
