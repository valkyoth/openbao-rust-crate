# Disposable Rekey Test Recipient

`rekey-test-public.b64` is only the public `TestPubKey1` from OpenBao tag
v2.7.0, commit `ca305a02daa68b203325daa1b25c18d7a252d4b3`,
`internal/helper/pgpkeys/test_keys.go` (Copyright (c) HashiCorp, Inc.;
SPDX-License-Identifier: MPL-2.0).

Its corresponding private key is public upstream test material. Never use this
recipient for real credentials. The raw-backup fixture uses it only inside a
disposable isolated server and never stores or prints generated shares.
No private key is included here and backup decryption is not claimed.
