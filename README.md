keymanager
==========

Summary
=======
Keymanager implementation for webOS ports

Description
===========
Backward compatible implementation of the keymanager service which is
done as node.js service. For more API details please see the Open webOS
project documentation site.


Tests
=====

    node test/run-tests.js

Runs off device: the suite loads the real service sources into a vm sandbox
(`test/harness.js`) with a stand-in for Foundations' Future (`test/future.js`),
and keeps everything it writes in a temp directory - it never touches
/var/palm/keystore.

Worth knowing what it covers, because these are the cases that have actually
gone wrong: records must survive a round trip, a tampered record must be
rejected rather than decrypted into garbage, a record that will not decrypt must
answer rather than hang, overlapping writes must not corrupt the store, and
records written by the pre-GCM scheme must still be readable. The legacy case is
checked against the `openssl` binary where it is available, so the
reimplementation of that old key derivation is verified against something other
than itself.


# Copyright and License Information

All content, including all source code files and documentation files in this repository are: 

Copyright (c) 2014 Achim Königs <garfonso@tratschtante.de>

All content, including all source code files and documentation files in this repository are: Licensed under the Apache License, Version 2.0 (the "License"); you may not use this content except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
