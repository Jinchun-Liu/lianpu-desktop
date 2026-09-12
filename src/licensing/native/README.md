# Windows TPM 2.0 device helper

This component is authored for this repository using Windows APIs. It uses only the **Microsoft Platform Crypto Provider**, requires a TPM 2.0 response from TBS, and rejects a provider that does not report hardware protection or also reports software implementation. It does not attest the physical provenance of a TPM to a remote verifier: a managed virtual TPM may satisfy Windows' TPM 2.0 and platform-provider checks. There is no software-key fallback.

## Build and distribution

Build on Windows x64 with the .NET Framework compiler supplied by Windows:

```powershell
& .\src\licensing\native\build.ps1
```

The fixed output is `src/licensing/native/bin/Lianpu.Device.exe`. The helper uses the installed .NET Framework 4.x runtime and Windows `tbs.dll` / `ncrypt.dll` from System32; the end user does not install Python, Node, an SDK, or a compiler. The build does not download dependencies. It prints the exact executable SHA-256 so the main process can pin it in the application integrity manifest. Rebuilding changes the executable hash; regenerate the manifest and perform validation against that exact binary before packaging. Authenticode publisher signing is a separate release step.

The package owner places only the production executable at `resources/licensing/Lianpu.Device.exe`, outside ASAR, and verifies its hash against the manifest inside ASAR before each invocation. Native source, build scripts, test code and test executables are not shipped to customers. Normal install, update, and uninstall must not delete the fixed CNG key or licensing directory.

## Protocol version 1

Launch with shell execution disabled, `windowsHide: true`, redirected standard input/output/error, an appropriate bounded timeout, and exactly one of these arguments:

| Command | Behavior |
| --- | --- |
| `status` | Reads TPM version, hardware provider, the fixed project key, its DACL, and fixed directory permissions. Creates no key, directory or probe file. |
| `prepare` | Prepares this project's machine directory, idempotently creates the fixed machine key if absent, and checks or supplements required permissions for both new and existing keys. Reopens the exact key and verifies persisted permissions plus unchanged public identity. Never replaces a key or overrides explicit deny rules. May require an administrator; the helper itself never requests elevation. |
| `sign` | Opens the fixed existing key, checks its key policy and DACL, and signs a challenge. Does not create a key or directory. |

`sign` standard input is the unpadded canonical base64url encoding of the **original challenge bytes**, not a digest and not a JSON wrapper. One final LF or CRLF is permitted; other whitespace, padding, non-canonical encodings, empty input and input over 16 KiB decoded are rejected. The helper hashes the original bytes with SHA-256 once, signs that digest, verifies the result with CNG, and returns a 64-byte IEEE P1363 `r || s` signature as unpadded base64url. The remote verifier must use the same original bytes and SHA-256 with P1363 encoding.

Every invocation emits exactly one JSON object to standard output. All responses contain `version:1`, `ok`, `state`, `testMode`, `tpm:{present,version}`, and `storage:{path,exists,prepared}`. `storage.prepared` checks the required directory ACL grants and inheritance without writing a test file; it is not a promise that a later file write succeeds. The client must handle an atomic license-save failure.

A successful ready response also contains:

```json
{
  "ok": true,
  "state": "ready",
  "key": {
    "prepared": true,
    "provider": "Microsoft Platform Crypto Provider",
    "machineKey": true,
    "hardwareBacked": true,
    "exportable": false,
    "algorithm": "ECDSA_P256",
    "created": false,
    "implementationFlags": 1
  },
  "publicKeySpki": "<base64url of DER SubjectPublicKeyInfo>",
  "deviceId": "<lowercase SHA-256 hex of the same DER bytes>"
}
```

The example's `implementationFlags` is illustrative; the actual hardware provider may set additional non-software bits. A `sign` response adds `signature`, `signatureFormat:"ieee-p1363"`, and `hashAlgorithm:"SHA-256"`. Public-key DER uses `id-ecPublicKey`, `prime256v1`, and the uncompressed 65-byte point. `status` reports `ok:true,state:"not_prepared",key.prepared:false` only when Windows confirms that the fixed key is absent; access denial is never reported as absence.

Failures contain `ok:false`, `state`, `code`, `message`, and where available `operation` and hexadecimal `nativeCode`. States include `needs_admin`, `no_tpm`, `tpm_not_2`, `not_prepared`, `tpm_not_ready`, `unsupported`, `invalid_request`, and `error`. Exit status is 0 for `ok:true`, 20 for `needs_admin`, and 1 for other failures. Read the JSON even when the child exits nonzero. Do not activate on a helper failure. Error text must not be treated as a request to silently elevate, reset the TPM, or substitute a software key.

## Fixed resources and permissions

Production has the compile-time CNG name `Lianpu.Desktop.Licensing.DeviceKey.v1` and directory `%ProgramData%\Lianpu\Licensing\v1`. There are no command-line or environment overrides for these names. The helper never enumerates any other key. Native private-key export, import, delete, overwrite, TPM provisioning and TPM clearing are not exposed or called.

New keys are `ECDSA_P256`, use `NCRYPT_MACHINE_KEY_FLAG`, have `Export Policy = 0` and signing-only `Key Usage`. New and existing keys must first pass the same export, machine scope, length, usage, and public-key type checks; an unexpected existing key is rejected without changing it. After finalization, their common preparation path checks the DACL and supplements missing SYSTEM/Administrators full control and BUILTIN\Users generic read/use. The fixed key is closed and reopened even if its ACL was already complete; persisted permissions and unchanged SPKI are checked before preparation succeeds. A setter success alone is insufficient.

The security descriptor update uses `DACL_SECURITY_INFORMATION | NCRYPT_PERSIST_FLAG` on the persisted key; it does not use `NCRYPT_PERSIST_ONLY_FLAG`. Existing safe rules, including the creating owner's rights, are retained. Explicit deny rules, unsupported ACE forms, absent/unusable DACLs, or overbroad grants outside the accepted policy cause an accurate failure rather than silently overwriting administrator policy. `status` and `sign` also check the DACL without writing: missing required permissions return `KEY_PERMISSIONS_REQUIRED`; incompatible rules return `KEY_ACL_POLICY_CONFLICT`. Failed persistence readback returns `KEY_PERMISSIONS_NOT_PERSISTED`; changed identity returns `KEY_IDENTITY_CHANGED`. These errors do not delete or replace the key.

An administrator's one-time preparation is expected on systems that restrict machine keys. Its exit status does not prove the original ordinary Windows user can use the key: the caller must re-query and verify a fresh signature without elevation. Actual cross-user and reinstall persistence remain separate hardware/deployment acceptance boundaries.

The version directory grants SYSTEM and Administrators full control and BUILTIN\Users modification for the signed license and its atomic temporary replacement. A compliant ACL is read and left unchanged, avoiding an unnecessary `WRITE_DAC` requirement. Missing safe grants are supplemented and read back; inherited-only grants do not count as permission on the directory itself. Explicit deny or conflicting rules stop preparation. Only that final directory ACL is considered; unrelated ProgramData ACLs are untouched. Existing reparse points in the fixed path are rejected. Because ordinary users can write license files, trust must come from server signatures and a fresh device-key proof, not from the directory being writable only by an administrator. Business archives, local passwords, user-bound safeStorage tokens and SQLite data are separate from this machine directory.

The JavaScript bootstrap classifies elevation interruption/timeouts as **unconfirmed**, not success or cancellation. Only a Windows cancellation result of 1223 is called cancellation; launch and other process failures remain distinct. There is no internal retry. Every successful preparation branch validates the full native contract, directory readiness and a fresh signature as the original caller. Failed/killed signing processes are rejected even if stdout contains a plausible signature. Public device diagnostics preserve the preparation category and safe native error code/operation; no cloud activation is inferred from TPM readiness.

## Rebuild after the 2026-09-11 preparation diagnosis

The previous exact package `0.5.0-4a5acb7af78c` invoked the production preparation API once and remained `needs_admin`; its hardware binding was not verified. Its preserved report is `evidence/license-device-package-0.5.0-4a5acb7af78c/2026-09-11T11-10-24-608Z/report.json`. The public result did not distinguish cancellation, timeout or post-elevation access failure, and must not be described as evidence that the user cancelled.

The old binary SHA-256 `bb696bb1b40d875bae93531badbf037b95178b3af1aa701c641f3e6871e234c4` was copied to the ignored `work/native-history/` directory and verified before rebuilding. The repaired native source SHA-256 is `d7dfef63d8571cb4cb91c1b1ebcf8e768bfd6af16bcfcd502533a169eeb1e149`; the rebuilt production executable SHA-256 is `66120c459baf4baea3defd6f1dd88c5e544a3b8357e1a420a3eafefd848b520a`, also pinned in `src/licensing/native-integrity.json`. Rebuilding again may change this executable hash; never silently reuse evidence for another binary.

Source-level process-substitute and pure ACL tests have passed. This rebuild does not itself prove real hardware preparation. Only read-only status and commands rejected before hardware access are permitted in the current verification; no valid `prepare`, UAC, key creation/deletion or Windows permission change is performed. A newly built exact customer package still needs a separately started, single user-controlled Windows preparation and independent signing acceptance. Rebuild evidence is recorded in `evidence/licensing-native-rebuild.json`.

The key belongs to the machine CNG store, independent of the application installation directory and Windows-user business profile. This supports normal software reinstalls when that store is preserved. It does not promise survival after TPM reset, OS reinstallation, motherboard replacement, VM changes, disk-image restoration, or removal of the platform-provider backing files. Those are licensing recovery/transfer boundaries, not silent key recreation or permission fallbacks.

## Isolated hardware validation

```powershell
& .\src\licensing\native\build.ps1 -IsolatedTest
node --test .\tests\licensing-client-tpm.test.cjs
node .\tests\licensing-client-tpm-native.cjs
```

The isolated build has the compile-time name `Lianpu.Desktop.Licensing.IsolatedTest.DeviceKey.v1.20260911`, directory `%ProgramData%\Lianpu\LicensingIsolatedTest\v1`, and `testMode:true`. Its executable and JSON evidence are under `tests/work/licensing-client-tpm/`. No argument can make the isolated helper use the production key, or make the production helper use a test key. Never ship the isolated executable. The acceptance runner performs production `status` only; preparation and signing are isolated. It stops when Windows denies access or the hardware does not meet requirements. A blocked hardware run is not a passed signing test.

The hypothesis, decision value, stop rule, source and binary hashes, actual responses, and unverified boundaries are recorded in `tests/work/licensing-client-tpm/verification.json`. On a usable TPM the test verifies the native signature independently with Node/OpenSSL, rejects a changed challenge and checks unchanged identity after restarting the helper and repeating preparation. This is process persistence, not a claim of product reinstall, Windows-user switching, or clean-machine installer acceptance. The isolated test key is retained if created; no deletion command is present.

## Official API references

- [Tbsi_GetDeviceInfo](https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_getdeviceinfo) and [TPM_DEVICE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tpm_device_info): the native TPM version query.
- [NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey) and [NCryptOpenKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenkey): fixed persisted machine keys, without overwrite.
- [Key storage property identifiers](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers) and [NCryptSetProperty](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty): implementation type, export policy, key usage and security descriptor.
- [NCryptExportKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey) and [BCRYPT_ECCKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob): public point export and coordinate encoding.
- [NCryptSignHash](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash) and [NCryptVerifySignature](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptverifysignature): hashing and native signature verification.
