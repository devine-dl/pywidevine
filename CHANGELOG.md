# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2023-11-21

- Supported Serve API: `v1.4.3` or newer

### Added

- Ability to specify output filename by specifying a full path or a relative file name in CLI command `create-device`.
- Add the staging privacy certificate (`staging.google.com`) to `Cdm.staging_privacy_cert`.
  - Similar to `common_privacy_cert` which would be used on Google's production license server,
  - Though this one is used on Google's staging license server (a production-ready testing server).

### Changed

- Raise an error if a file already exists at the output path in CLI command `create-device`.
- Use std-lib xml instead of lxml to reduce dependencies and support ARM (#35).
- Lessen restriction on Python version to any Python version `>=3.7`, but `<4.0`.
  - I was hoping to do `^3.7`, but some dependencies also require `<4.0` therefore I cannot, for now.
- Move Key ID parsing to static `PSSH.parse_key_ids()` method.
- The `shaka-packager` subprocess call's return code is now returned from `Cdm.decrypt()`.
- The flags variable of a `Device` now defaults to a dict, even if not set.
- Heavily improve initializing of protobuf objects, improving readability, typing, and linting quite a bit.
- Renamed Device's `_Types` enum class to `DeviceTypes`.

### Removed

- Removed `Device.Types` class variable alias to `_Types` enum class as a static linter cannot recognize a class
  variable as a type. Instead, the actual `_Types` (now named `DeviceTypes`) enum should be imported and used instead.

### Fixed

- Ensure output directory exists before creating new `.wvd` files in CLI command `create-device`.
- Ignore empty Key ID values in v4.0.0.0 PlayReadyHeaders.
- Remove `Cdm.system_id` class variable as it conflicted with the `cdm.system_id` class instance variable of the same
  name. It's also generally not needed. The same data can be gotten via `Cdm.uuid.bytes`.
- Casting of `type_` when passed a non-int value in `Cdm.get_license_challenge()`.
- Pass a PSSH object in `test` CLI command instead of a string.
- Lower-case and setup `__all__` correctly, add missing `__all__` in some of the modules.
  - For the longest time I thought it was `__ALL__` and an iterable of objects/variables.
  - However, its actually `__all__` and explicitly a list of Strings...

### New Contributors

- [mediaminister](https://github.com/mediaminister)

## [1.6.0] - 2023-02-03

- Supported Serve API: `v1.4.3` or newer

### Added

- Support Python 3.11.
- New CLI command `export-device` to export WVD files back as files. I.e., a private key and client ID blob file.

## [1.5.3] - 2022-12-27

- Supported Serve API: `v1.4.3` or newer

### Added

- New utility `load_xml()` to parse XML data with lxml ignoring Namespaces.
- PSSH class now have `__str__` and `__repr__` methods to print the object in more Human-friendly ways.
  - `str(pssh)` is now identical to `pssh.dumps()`.
  - `repr(pssh)` or just `pssh` in some cases will result in a nice overview of the PSSHs contents.
- New `to_playready()` method to convert Widevine PSSH Data to PlayReady PSSH Data. Please note that the
  Checksums for AES-CTR and COCKTAIL KIDs cannot be calculated as the Content Encryption Key would be needed.

### Changed

- The System ID must now be explicitly specified when creating a new PSSH box in `PSSH.new()`.
  - This allows you to now create PlayReady PSSH boxes.
- The `playready_to_widevine()` method has been renamed to just `to_widevine()`.

### Fixed

- Correct capitalization of the `key_IDs` field when making the new box in `PSSH.new()`.
- Correct the value type of `key_IDs` value when creating a new box in `PSSH.new()`.
- Ensure Key IDs are list of UUIDs instead of bytes in `PSSH.new()`.
- Create v0 PSSH boxes by only setting the `key_IDs` field when the version is set to `1` in `PSSH.new()`.
- Fix loading of PlayReadyHeaders (and PlayReadyObjects) as PSSH boxes. It would previously load it under the
  Widevine SystemID breaking all PlayReady-specific code after construction.
- Parse Key IDs within PlayReadyHeaders by using the new `load_xml()` utility to ignore namespaces so that `xpath` can
  correctly locate any and all KID tags.
- Support parsing PlayReadyObjects with more than one PlayReadyHeader (more than one record).
## [1.5.2] - 2022-10-11

- Supported Serve API: `v1.4.3` or newer

### Fixed

- Fixed license signature calculation for newer Widevine Server licenses on OEM Crypto v16.0.0 or newer.
  The `oemcrypto_core_message` data needed to be part of the HMAC ingest if available.

## [1.5.1] - 2022-10-23

- Supported Serve API: `v1.4.3` or newer

### Added

- Support for big-int Key IDs in `PSSH`. All integer values are converted to a UUID and are loaded big-endian.
- Import path shortcuts in the `__init__.py` package constructor to all the user classes.
  - Now you can do e.g., `from pywidevine import PSSH` instead of `from pywidevine.pssh import PSSH`.
  - You can still do it the full direct way if you want.
- Parsing check to the raw DrmCertificate in `Cdm.set_service_certificate()`.

### Changed

- Service Certificates are now stored in the session as a `SignedDrmCertificate`.
  - This is to keep the signature with the Certificate, without wrapping it in a SignedMessage unnecessarily.
- Reduced the maximum concurrent Cdm sessions from 50 to 16 as it seems to be a more common limit on more up-to-date
  devices and versions of OEMCrypto. This also helps encourage people to close their sessions when they are no longer
  required.

### Fixed

- Acquisition of the Certificate's provider_id in `Cdm.set_service_certificate()` in some edge cases, but also when you
  try to remove the certificate by setting it to `None`.
- When exporting a PSSH object it will now do so in the same version it was initially loaded or created in. Previously
  it would always dump as a v1 PSSH box due to a cascading check in pymp4. It now also honors the currently set version
  in the case it gets overridden.
- Improved reliability of computing License Signatures by verifying the signature against the original raw License
  message instead of the re-serialized version of the message.
  - Some license messages when parsed would be slightly different when re-serialized against my protobuf, therefore the
    computed signature would have always mismatched.

## [1.5.0] - 2022-09-24

- Supported Serve API: `v1.4.3` or newer

### Changed

- Updated `protobuf` dependency to `v4.x` branch with recompiled proto-buffers, specifically `v4.21.6`.

## [1.4.4] - 2022-09-24

- Supported Serve API: `v1.4.3` or newer

### Security

- Updated `protobuf` dependency to `3.19.5` due to the Security Advisory [GHSA-8gq9-2x98-w8hf].

  [GHSA-8gq9-2x98-w8hf]: <https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-8gq9-2x98-w8hf>

## [1.4.3] - 2022-09-10

- Supported Serve API: `v1.4.3` or newer

### Added

- Serve's `/get_license_challenge` endpoint can now disable privacy mode per-request, even if a service certificate is
  set, as long as privacy mode is not enforced in the Serve API config.
- New Cdm method `get_service_certificate()` to get the currently set service certificate of a Session.

### Changed

- All f-string formatting in log statements have been replaced with logging formatting to save performance when that
  log wouldn't have been printed.
- The Serve APIs `/open` endpoint's function has been renamed from `open()` to `open_()` to prevent shadowing the
  built-in `open`.

### Security

- Updated `lxml` dependency to `>=4.9.1` due to the Security Advisory [GHSA-wrxv-2j5q-m38w].

  [GHSA-wrxv-2j5q-m38w]: <https://github.com/advisories/GHSA-wrxv-2j5q-m38w>

### Removed

- The Protocol image has been removed from the README as it is too broad to Browser scenarios and some stuff on it
  is too broad. If the viewer is really interested they can Google it to get a much better view into the Protocol.

## [1.4.2] - 2022-09-05

- Supported Serve API: `v1.4.0` to `v1.4.2`

### Changed

- Sessions in `Cdm.open()` are now initialized with a unique session number.
- Android Cdm Devices now use a Request ID formula similar to OEMCrypto library when generating a Challenge.
  This formula has yet to be fully confirmed and ironed out, but it is closer than the Chrome Cdm formula.
- `Device` no longer throws `ValueError` exceptions on `DecodeErrors` if it fails to parse the provided Client ID, or
  it's VMP data if any. It will now re-raise `DecodeError`.

### Fixed

- Parsed Proto Messages now go through an elaborate yet efficient verification, it must parse and serialize back to it's
  received form, byte-for-byte, or it will be rejected.
  - This prevents protobuf from parsing a message that could be a different message depending on the starting bytes.
  - It was possible to bypass some minor checks by providing specially crafted messages that parsed as other messages.
    However, I haven't noticed any way where this would lead to a vulnerability or anything bad. It mostly just lead to
    Serve API crashes or just rejected messages down the chain as they wouldn't have the right data within them.

## [1.4.1] - 2022-08-17

- Supported Serve API: `v1.4.0` to `v1.4.2`

### Changed

- Rework `PSSH.overwrite_key_ids()` as an instance method now named `PSSH.set_key_ids()`.
- Rework `PSSH.get_key_ids()` as a property method named `PSSH.key_ids`. This allows swift access to all the Key IDs of
  the current PSSH object data.
- Rework `PSSH.from_playready_pssh()` as an instance method now named `PSSH.playready_to_widevine()` that now converts
  the current instances values directly. This allows you to more easily instance as any PSSH, then convert after wards
  and only if wanted and when needed.

## [1.4.0] - 2022-08-06

- Supported Serve API: `v1.4.0` to `v1.4.2`

### Added

- New PSSH boxes can now be manually crafted with `PSSH.new()`.
  - The box can be crafted from arbitrary init_data and/or key_ids.
  - If only key_ids is supplied a new Widevine CENC Header will be created and the key IDs will be put into it.
  - This allows you to make compliant v0 or v1 boxes with as little data as just a Key ID.
- PSSH boxes can now be exported as MP4 Box objects using pymp4 with `PSSH.dump()`.
- PSSH boxes can now also be exported as Base64 strings with `PSSH.dumps()`.
- License Keys can now be obtained from a Cdm session with a parsed license using `Cdm.get_keys()`.
  - This is the alternative to manually accessing the keys from the `Cdm._sessions` object.
  - It is also available on the Serve API through the new `/get_keys` endpoint.

### Changed

- `PSSH.get_as_box()` has been merged into the PSSH constructor, simplifying usage of the PSSH class.
- `PSSH.from_playready_pssh()` is now a class method and returns as a PSSH object.
- Only PSSH objects are now accepted by `Cdm.get_license_challenge()`.
  - You can no longer provide it anything else, that includes base64 or bytes form.
  - You should first parse or make a new PSSH with the PSSH class, and then pass that object.
  - This is to simplify typing and repetition across the codebase.
- Serve's `/challenge` endpoint has been changed to `/get_license_challenge`, and `/keys` to `/parse_license`.
  - This is to be consistent with the method names of the underlying Cdm class.
- Serve now passes the license type value as-is (as a string) instead of parsing it to an integer.
- Serve now passes the key type value as-is (as a string) instead of parsing it to an integer.
- Serve no longer returns license keys in the response of the `/parse_license` endpoint.
  - Once parsed, the `/get_keys` endpoint should be used to retrieve keys.
- Privatized the `Cdm._sessions` class instance variable even more to `Cdm.__sessions`.
  - If you still need something from it, while not advised, you can call it via `cdm._Cdm__sessions`.

### Removed

- `PSSH.from_key_ids()` has been removed entirely, you should now use `PSSH.new(key_ids=...)` instead.
- Unnecessary parsing of the license message received by RemoteCdm is now skipped. Parsing should be done by the Serve
  API as it will be able to actually decrypt and verify the message.
- All uses of a local `Session` object has been removed from `RemoteCdm`. The session is now fully controlled by the
  remote API and de-synchronization by external alteration or unexpected exceptions is no longer a possibility.

### Fixed

- Correct the WidevinePsshData proto field name from `key_id` to `key_ids` in the PSSH class.
- Handle `DecodeError` and `SignatureMismatch` exceptions in the Serve `/set_service_certificate` endpoint.
- Handle `InvalidInitData` and `InvalidLicenseType` exceptions in the Serve `/get_license_challenge` endpoint.
- Handle various exceptions in the Serve `/parse_license` endpoint.
- Handle various client-side runtime errors in `RemoteCdm` with improved error handling.

## [1.3.1] - 2022-08-04

- Supported Serve API: `v1.3.0` to `v1.3.1`

### Added

- String value support to the `device_type` parameter in `Cdm`s constructor.

### Changed

- Serve no longer requires `force_privacy_mode` to be defined in the config file. It now assumes a default of false.
- Serve now uses `pywidevine serve ...` instead of the full project url in the Server header.
- `RemoteCdm`s Server version check is now case-insensitive.

### Fixed

- `RemoteCdm`s Server version check now ignores other Server/Proxy names prepended or appended to the Server header.
  - For example, if reverse-proxied through Caddy it may have prepended "Caddy" to the Server header.

## [1.3.0] - 2022-08-04

- Supported Serve API: `v1.3.0` to `v1.3.1`

### Added

- New Client for using the Serve API; `RemoteCdm` class. It has an identical interface as the original `Cdm` class.
  - However, the constructor is different. Instead of passing a Widevine device object, you need to pass information
    about the API like its host (including port if not on a reverse-proxy), and info about the device like its name and
    security level.
  - Other than that, once the RemoteCdm object is created, you use it exactly the same. Magic!
  - Any time there's a change or fix to `Cdm` in this update or any in the future, will also be done to RemoteCdm.
- New Serve endpoint `/set_service_certificate` as an improved way of setting (or unsetting) the service certificate.

### Changed

- `Cdm`s constructor now uses more direct values, so you don't have to use the Device class or `.wvd` files.
  - To continue using `.wvd` files you must now use `Cdm.from_device()` instead.
- You can now unset the Service certificate by providing `None` to `Cdm.set_service_certificate().

### Removed

- Serve's `/challenge` endpoint no longer accepts a `service_certificate` item in the JSON payload.
  - Instead, use the new `/set_service_certificate` endpoint before calling `/challenge`.
  - You do not need to set it every time. Once per session is enough unless you now want to use a different certificate.

## [1.2.1] - 2022-08-02

### Added

- Support `SignedDrmCertificate` and `SignedMessages` messages in `Cdm.encrypt_client_id()`. This is mainly as a
  convenience for any scripts wanting to encrypt their Client ID with a service certificate manually.
- All License Keys from Serve's `/keys` endpoint can now be received by providing `ALL` as the key type.
  - This adds support for systems needing more than two types of keys from the license, e.g., Netflix MSL.
  - For faster response times it is best to still ask for only `CONTENT` keys if that's all you need.
- Serve now has a `/close` endpoint to close a session. All clients should close the session once they are finished
  with it or the user will eventually hit a limit of 50 sessions per user and the server will hog memory til it
  restarts.
- Serve now verifies that all Devices in config actually exist before starting the server.
- Serve now responds with a `Server` header denoting that pywidevine serve is being used, and it's version.
  - This allows Clients to selectively support APIs based on version; verify the API as being supported.

### Changed

- Lessened version pin on `lxml` from `^4.9.1` to `>=4.8.0` to support projects using pycaption.
- Service Certificate is now saved in the session as a `SignedMessage` with a `SignedDrmCertificate` instead of the raw
  `DrmCertificate`. The `SignedMessage` is unsigned as the `SignedDrmCertificate` within it, is signed. This is so
  anything inheriting or using the Cdm (e.g., `serve`) can verify the certificate down the chain and keep it signed.
- Serve now constructs one Cdm object for each user+device combination so one user cannot fill or overuse the CDM
  session limit.
- All of Serve's endpoints now have a `/{device}` prefix. E.g., instead of `/challenge/STREAMING`, it's now
  `/device_name/challenge/STREAMING`. This is to support the previous change.

### Fixed

- Handle server crash when the session limit is reached in Serve's `/open` endpoint by returning a 400 error.
- Serve now correctly updates (or rather now makes a new Cdm object) if a user switches from one Device to another.
  - Previously it would reuse an existing Cdm object, but would forget to switch device if they changed.
  - Note: It does still leave the previous Cdm with the older Device in memory.
- Handle IOError when parsing bytes as MP4 Box to allow arbitrary data to be made as new boxes in `PSSH.get_as_box()`.

## [1.2.0] - 2022-07-30

### Added

- New CLI command `serve` that hosts a CDM API that can be externally accessed with authentication. This can be used to
  access and/or share your CDM without exposing your Widevine device private key, or even it's identity by enforcing
  Privacy Mode.
  - Requires installing with the `serve` extras, i.e., `pip install pywidevine[serve]`.
  - The default host of `127.0.0.1` blocks access outside your network, even if port-forwarded. Use
    `-h 0.0.0.0` to allow remote access.
  - Setup requires the use of a config file for configuring the CDM and authentication. An example config file named
    `serve.example.yml` in the project root folder has verbose documentation on available options.
- Batch migration of WVD files by passing a folder as the path to the CLI command `migrate`.
- Strict mode to `PSSH.get_as_box()` to raise an Exception if passed data is not already a box, as it has been improved
  to create a new box if not detected as a box already.

### Changed

- Elevated the Development Status Classifier from 4 (Beta) to 5 (Production/Stable).
- License messages passed to `Cdm.parse_license()` are now rejected if they are not of `LICENSE` type.
- Service Certificates passed to `Cdm.set_service_certificate()` are now verified. This patches a trivial "exploit"
  that allows an attacker to recover the plaintext Client ID from a license under Privacy Mode. See
  <https://gist.github.com/rlaphoenix/74acabdd7269a21845e18b621c5860ef>.
- Data passed to `PSSH.get_as_box()` now supports arbitrary and box data automatically as it tries to detect if it is a
  valid box, otherwise makes a new box.
- Renamed the `Cdm` constructor's parameter `pssh` to `init_data`, as that's what the Cdm actually wants and uses,
  whereas a `PSSH` is an `mp4` atom (aka box) containing `init_data` (a Widevine CENC Header). The full PSSH is never
  kept nor ever used. It still accepts PSSH box data.
- Service Certificate's Provider ID is now returned by `Cdm.set_service_certificate()` instead of the passed
  certificate, of which they would already have.
- The Cdm class now works more closely to the official CDM model. Instead of using one Cdm object per-request having to
  provide device information each time,
  - You now initialize the Cdm with the Widevine device you wish to use and then open sessions with `Cdm.open()`.
  - You will receive a session ID that are then passed to other methods of the same Cdm object.
  - The PSSH/init_data that used to be passed to the constructor is now passed to `Cdm.get_license_challenge()`.
  - This allows initializing one Cdm object with up to 50 sessions open at the same time.
    Session limits seem to fluctuate between libraries and devices. 50 seems like a permissive value.
  - Once you are finished with DRM operations, discard all session (and key) data by calling `Cdm.close(session_id)`.
- License Keys are no longer returned by `Cdm.parse_license()` and now must be obtained directly from `cdm._sessions`.
  - For example, `for key in cdm._sessions[session_id].keys: print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")`.
  - This is to detach the action of parsing a license as just for getting keys, as it isn't. It can be and should be
    used for a lot more data like security requirements like HDCP, expiration, and more.
  - It is also to detour users from directly using the keys over the `Cdm.decrypt()` method.
- Various std-lib exceptions have been replaced with custom exceptions under `pywidevine.exceptions`.
- License responses can now only be parsed once by `Cdm.parse_license()`. Any further attempts will raise an
  `InvalidContext` exception.
  - This is as license context data is cleared once used to reduce data lingering in memory, otherwise the more license
    requests you make without closing the session, the more and more memory is taken up.
  - Open multiple sessions in the same Cdm object if you need to request and parse multiple licenses on the same device.

### Removed

- Direct `DrmCertificate`s are no longer supported by `Cdm.set_service_certificate()` as they have no signature.
  See the 3rd Change above. Provide either a `SignedDrmCertificate` or a `SignedMessage` containing a
  `SignedDrmCertificate`. A `SignedMessage` containing a `DrmCertificate` will also be rejected.
- `PSSH.from_init_data()`, use `PSSH.get_as_box()`.
- `raw` parameter of `Cdm` constructor, as well as CLI commands as it is now handled upstream by the `PSSH` creation.

### Fixed

- Detection of Widevine CENC Header data encoded as bytes in `PSSH.get_as_box()`.
- Custom ValueError on missing contexts instead of the generic KeyError in `Cdm.parse_license()`.
- Typing of `type_` parameter in `Cdm.get_license_challenge()`.
- Value of `type_` parameter if is a string in `Cdm.get_license_challenge()`.

## [1.1.1] - 2022-07-22

### Fixed

- The `-v/--vmp` parameter of the `test` CLI command is now optional.

## [1.1.0] - 2022-07-21

### Added

- WVD (Widevine Device file) Version 2 bringing reduced file sizes by up to 30%~.
- New CLI command `create-device` to create `.wvd` files (Widevine Device files) from RSA PEM/DER Private Keys and
  Client ID blobs. You can also provide VMP (FileHashes) data which will be merged into the Client ID blob.
- New CLI command `migrate` that uses `Device.migrate()` and `dump()` to migrate older v1 Widevine Device files to v2.
- New `Device` method `migrate()` to load an older Widevine Device file format. It is recommended to then use the
  `dumps()` method to save it as a new v2 Widevine Device file, which can then be loaded normally.
- Support `SignedDrmCertificate` and `DrmCertificate` messages in `Cdm.set_service_certificate()`. Services can provide
  the certificate as a `SignedMessage`, `SignedDrmCertificate`, or a `DrmCertificate`. Only `SignedMessage` and
  `SignedDrmCertificate` are signed.
- Privacy Mode can now be used in the `test` CLI command with the `-p/--privacy` flag.

### Changed

- Moved all `.wvd` Widevine Device file structures from `Device` to a `_Structures` class in `device.py`. The
  `_Structures` class can be imported and used directly, or via `Device.structures`.
- Moved the majority of Widevine Device file migration code from the CLI command `migrate` to `Device.migrate()`. The
  CLI command `migrate` now internally uses `Device.migrate()`.
- Set Service Certificates are now stored as `DrmCertificate`s instead of a `SignedMessage` as the signature and other
  data in the message is unused and unneeded.

### Removed

- Unused Widevine Device file flag `send_key_control_nonce` from v1 and v2 Structures as it was only used before initial
  release, and isn't a necessary nor useful flag.

### Fixed

- Correct the type argument name from `type` to `type_` in `Device.dump()`.

### Security

- Even though support for more kinds of Service Certificate Signatures were added, they are still unverified as the
  signing public key is Unknown.

## [1.0.1] - 2022-07-21

### Changed

- Moved the License Type parameter from the `Cdm` constructor to it's `get_license_challenge()` method.
- Every License request now uses a unique random value instead of the CDM Session ID.
- Only the Context Data of License requests are now stored in the Session instead of the full message.
- Session ID formula now uses a random 16-byte value for both Chrome and Android provisions.

### Removed

- Unused and unnecessary `Cdm.raw` class instance variable.

### Fixed

- Re-raise DecodeErrors instead of a new ValueError on DecodeErrors in `Cdm.set_service_certificate()`.
- Creating a new License request no longer overwrites the context data of the previous challenge.

## [1.0.0] - 2022-07-20

Initial Release.

### Security

- Service Certificate Signatures are unverified as the signing public key is Unknown.

[1.6.0]: https://github.com/devine-dl/pywidevine/releases/tag/v1.6.0
[1.5.3]: https://github.com/devine-dl/pywidevine/releases/tag/v1.5.3
[1.5.2]: https://github.com/devine-dl/pywidevine/releases/tag/v1.5.2
[1.5.1]: https://github.com/devine-dl/pywidevine/releases/tag/v1.5.1
[1.5.0]: https://github.com/devine-dl/pywidevine/releases/tag/v1.5.0
[1.4.4]: https://github.com/devine-dl/pywidevine/releases/tag/v1.4.4
[1.4.3]: https://github.com/devine-dl/pywidevine/releases/tag/v1.4.3
[1.4.2]: https://github.com/devine-dl/pywidevine/releases/tag/v1.4.2
[1.4.1]: https://github.com/devine-dl/pywidevine/releases/tag/v1.4.1
[1.4.0]: https://github.com/devine-dl/pywidevine/releases/tag/v1.4.0
[1.3.1]: https://github.com/devine-dl/pywidevine/releases/tag/v1.3.1
[1.3.0]: https://github.com/devine-dl/pywidevine/releases/tag/v1.3.0
[1.2.1]: https://github.com/devine-dl/pywidevine/releases/tag/v1.2.1
[1.2.0]: https://github.com/devine-dl/pywidevine/releases/tag/v1.2.0
[1.1.1]: https://github.com/devine-dl/pywidevine/releases/tag/v1.1.1
[1.1.0]: https://github.com/devine-dl/pywidevine/releases/tag/v1.1.0
[1.0.1]: https://github.com/devine-dl/pywidevine/releases/tag/v1.0.1
[1.0.0]: https://github.com/devine-dl/pywidevine/releases/tag/v1.0.0
