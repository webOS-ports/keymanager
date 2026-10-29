keymanager
==========

Summary
=======
Keymanager implementation for webOS ports

Description
===========
com.palm.keymanager keeps keys and credentials for apps and services (the
accounts service stores every account's password and tokens in it),
encrypted under the device's master key in `/var/palm/keystore`:

| | |
|---|---|
| `key` | the master key: 256 random bytes, 0600 |
| `store.db` | JSON, `{appId: {keyname: record}}`; a record's `keydata` is the encrypted key as JSON writes a Buffer (`{"type":"Buffer","data":[...]}`), 0600 |

A record is AES-256-GCM under a key HKDF derives from the master key
(`"KM1\0" | iv | tag | ciphertext`); records written before that (AES-256-CBC
by way of createCipher) are still read. An app only ever sees its own keys:
the namespace is the caller's app id, or else its service name.

The methods: `store`, `generate`, `fetchKey` (the key itself only for a key
stored `nohide`), `keyInfo`, `remove`, `crypt` (encrypt or decrypt with a
stored key), `export`/`import` (one key, wrapped with another key both sides
have), and, for the backup service only (ACG group
`keymanager-service.backup`), `exportKeystore`/`importKeystore` (every key,
under a passphrase). `initialize` answers an error with no text and errorCode
-9999: its assistant was never in the old `sources.json`, so mojoservice had
nothing to run for it.

The service
===========
Plain Node 22, for the launcher's plain-node path (`run-js-service` requires
`/usr/palm/services/com.palm.keymanager`, which has a `package.json`, and
calls `run()`). It used to run on mojoservice and Foundations.

| | |
|---|---|
| `service/service.js` | start-up: the bus, the keystore, the methods |
| `service/lib/commands.js` | the 11 methods, answering as the old service did (`lib/mojo.js`) |
| `service/lib/keystore.js` | `key` and `store.db`: reading, writing, the records |
| `service/lib/crypto.js` | what is done to the bytes (the old `Crypto.js`, unchanged) |
| `service/lib/bus.js`, `lib/mojo.js`, `lib/errors.js` | the bus and mojoservice's replies, from the contacts linker (app-services PR #29) |

The first version answers every call as the old service did, its bugs
included, and leaves the same bytes on disk. That was checked by an A/B
test: the old service, run unchanged on the host from the VM's frameworks,
and this one, on the same generated calls from keystores of every kind
(fresh, pre-GCM records, damaged records, an unparseable or unreadable
store), each side's random bytes from the same seed, comparing every reply
and the bytes of `key` and `store.db` after every call; and with the two
taking turns on one keystore, so that each reads what the other wrote. The
bugs were then mended one commit at a time, each with its own test; the
code, tests and commits refer to them by these numbers:

- K1: a key name or app id that is the name of something every JavaScript
  object has (`toString`, `constructor`, `hasOwnProperty`, `__proto__`, ...)
  was taken for a key that is there: `store` said "Key already exists.",
  `keyInfo` and `fetchKey` failed with a TypeError, and an `importKeystore`
  naming such an app wrote into the prototype every object in the service
  shares. A key or app called `hasOwnProperty` that an import brought in
  broke `exportKeystore` and `import` from then on.
- K2: a key stored with a property that is `null` (`nohide: null`) could not
  be read again: `keyInfo`, `fetchKey`, `crypt` and `generate` of that name
  failed with "Cannot convert undefined or null to object". An array came
  back as an object with a `length`.
- K3: `generate` with a size `randomBytes` will not take (`"16"`, `-1`,
  `2^32`, for HMACSHA1, which has no size rule) never answered: 504 after
  60 s.
- K4: `crypt` with a key that is not `nohide` never answered (504), unless
  the algorithm given was not the key's.
- K5: `crypt` whose cipher failed at its end (a wrong key or iv when
  decrypting, data that is not whole blocks with `pad: "none"`) never
  answered (504).
- K6: with a `store.db` that cannot be read (a directory, an I/O error), or
  a keystore directory that cannot be made, the service never answered
  anything, not even after the command timeout.
- K7: `importKeystore` stopped without an answer (504) at an entry that is
  not an object, or whose keydata is not a string; the keys before it
  stayed imported. When it was the first entry, its error was the answer,
  and nothing was imported.
- K8: `fetchKey` without an app id answered errorCode -9999: its error said
  `erroCode`.

These things deliberately differ from the old service:

- No activity is made for each call. mojoservice made one for every command
  and ran the command once activitymanager had answered; the service now
  stays up while a call is being answered instead (and quits after 30 s
  idle, the old `activityTimeout`). A call that brings an `$activity` still
  has it adopted or monitored (`lib/mojo.js`).
- mojoservice's `__info`, `__quit` and `__gc` are now the bus's `info` and
  `quit`, as in the linker; none of them is in an ACG group.
- The log says less. The old service logged the stack of every error, and
  Node's messages quote what they were given: `store` with a number as
  keydata put that number in the journal ("Received type number (...)"),
  and a payload that did not parse put the start of it there. Now a failure
  is logged by its kind and code. Key material was already kept out
  of the log (PR #16); a test keeps it out.
- An error reply's `exception` is a stack from this service's files where
  it was one from the old one's; for the `{errorCode, message}` errors the
  old code threw it is `"[object Object]"`, as before.
- `importKeystore` goes through the keys in a loop; the old one recursed
  once for each key, and would have run out of stack on a very large import.

Tests
=====

    test/run.sh

The unit tests (`node --test test/*.test.js`) run the service on a stand-in
bus (`test/palmbus.js`) with its keystore in a temp directory (`TMPDIR`),
never `/var/palm/keystore`; then jshint (set `JSHINT` if it is not on the
path) and a parse of every module. The pre-GCM records are checked against
the `openssl` binary where there is one.


# Copyright and License Information

All content, including all source code files and documentation files in this repository are: 

Copyright (c) 2014 Achim Königs <garfonso@tratschtante.de>

All content, including all source code files and documentation files in this repository are: Licensed under the Apache License, Version 2.0 (the "License"); you may not use this content except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
