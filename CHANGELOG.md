# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.3] - 2022-12-27

### Added

- Added a new utility `load_xml()` to parse XML data with lxml ignoring Namespaces.
- PSSH class now has a `__str__` and `__repr__` representation to print the object in more Human-friendly and
  useful ways. `str(pssh)` is now identical to `pssh.dumps()` and `repr(pssh)` or just `pssh` in some cases will
  result in a nice overview of the PSSHs contents.
- Added new `to_playready()` method to convert Widevine PSSH Data to PlayReady PSSH Data. Please note that the
  Checksums for AES-CTR and COCKTAIL KIDs cannot be calculated as the Content Encryption Key would be needed.

### Changed

- You must now explicitly specify the System ID to use when creating a new PSSH box.
  This allows you to now create PlayReady PSSH boxes.
- The `playready_to_widevine()` method has been renamed to just `to_widevine()`.

### Fixed

- Fix the capitalization of the `key_IDs` field, and it's value when creating a new PSSH box.
- Fix the ability to create v0 PSSH boxes by only setting the `key_IDs` field when the version is set to `1`.
- Fix parsing of Key IDs within PlayReadyHeaders by using the new `load_xml()` utility to ignore namespaces so
  that `xpath` can correctly locate any and all KID tags.
- Fix loading of PlayReadyHeaders (and PlayReadyObjects) as PSSH boxes. It would previously load it under the
  Widevine SystemID breaking all PlayReady-specific code after construction.
- Fix support for loading PlayReadyObjects with more than one PlayReadyHeader (more than one record).

## [1.5.2] - 2022-10-11

### Fixed

- Fixed license signature calculation for newer Widevine Server licenses on OEM Crypto v16.0.0 or newer.
  The `oemcrypto_core_message` data needed to be part of the HMAC ingest if available.

## [1.5.1] - 2022-10-23

### Added

- Added import path shortcuts in the `__init__.py` package constructor to all the user classes. Now you can do e.g.,
  `from pywidevine import PSSH` instead of `from pywidevine.pssh import PSSH`. You can still do it both ways.
- Improved error handling and sanitization checks when parsing some Service Certificates in `set_service_certificate()`.

### Changed

- Maximum concurrent Cdm sessions are now set to 16 as it seems tto be a more common limit on more up-to-date CDMs,
  including Android's OEMCrypto Library. This also helps encourage people to close their sessions when they are no
  longer required.
- Service Certificates are now stored in the session as a `SignedDrmCertificate`. This is to keep the signature with
  the stored Certificate for use by the user if necessary. It also reduces code repetition relating to the usage of the
  signature.

### Fixed

- Improved reliability of computing License Signatures. Some license messages when parsed would be slightly different
  when re-serialized with `SerializeToString()`, therefore the computed signature would have always mismatched.
- Added support for Key IDs that are integer values. Effectively all values are now considered to be a UUID as 16 bytes
  (in hex or bytes) or an integer value with support for up to 16 bytes. All integer values are converted to a UUID and
  are loaded big-endian.
- Fixed acquisition of the Certificate's provider_id within `set_service_certificate()` in some edge cases, but also
  when you try to remove the certificate by setting it to `None`.
- PSSH now dumps in the same version the PSSH was loaded or created in. Previously it would always dump as a v1 PSSH
  box due to a cascading check in pymp4. It now also honors the currently set version in the case it gets overridden.

## [1.5.0] - 2022-09-24

With just one change this brings along a reduced dependency tree, smoother experience across different platforms, and
speed improvements (especially on larger input messages).

### Changed

- Updated protobuf dependency to v4.x branch with recompiled proto-buffers. They now also have python stub files.

## [1.4.4] - 2022-09-24

### Security

- Updated `protobuf` dependency to v3.19.5 due to the Security Advisory [GHSA-8gq9-2x98-w8hf].

  [GHSA-8gq9-2x98-w8hf]: <https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-8gq9-2x98-w8hf>

## [1.4.3] - 2022-09-10

RemoteCdm minimum supported Serve API version is now v1.4.3.

### Added

- Cdm now has a `get_service_certificate()` endpoint to get the currently set service certificate of a Session.
  RemoteCdm and Serve also has support for these endpoints.

### Changed

- Added installation instructions, troubleshooting steps, a minimal example, and a list of features to the README.
- The minimum version for lxml has been upped to >=4.9.1. This is due to some vulnerabilities present in all older
  versions.
- All f-string formatting in log statements have been replaced with logging formatting to improve performance when
  logging is disabled.

### Removed

- The Protocol image has been removed from the README as it is too broad to Browser scenarios and some stuff on it
  is too broad. If the viewer is really interested they can Google it to get a much better view into the Protocol.

### Fixed

- Serve's get_license_challenge can now disable privacy mode even if a service certificate is set, as long as privacy
  mode is not enforced in settings.

## [1.4.2] - 2022-09-05

### Changed

- Device's constructor no longer throws `ValueError` exceptions if it fails to parse the provided Client ID or it's
  VMP data if any. It will now raise a `DecodeError`.

### Fixed

- Android Cdm Devices now use a Request ID formula similar to OEMCrypto library when generating a Challenge.
  This formula has yet to be fully confirmed and ironed out, but it is better than the Chrome Cdm formula.
- Various Proto Message Parsing now has full verification and expects the parsed response to be the same length
  as the serialized input, or it will throw an error. For example, this prevents vague errors to happen when you
  provide a bad License to `Cdm.parse_license`. It also prevents possibilities of it going past various other checks
  depending on the first few bytes provided.

## [1.4.1] - 2022-08-17

Small patch release for some fixes to the PSSH classes recent face-lift.

### Changed

- `PSSH.overwrite_key_ids` static method is now an instance method named `set_key_ids` and works on the current
  instance instead of making and returning a new one.
- `PSSH.get_key_ids` static method is now a property method named `key_ids`. This allows swift access to all the
  Key IDs of the current access.
- `PSSH.from_playready_pssh` class method is now an instance method named `playready_to_widevine` and now converts
  the current instances values directly. This allows you to more easily instance as any PSSH, then convert afterwards.

## [1.4.0] - 2022-08-06

This release is a face-lift for the PSSH class with a moderate amount of Cdm and Serve interface changes.  
You will likely need to make a moderate amount of changes in your client code, please study the changelog.

Please note that while it was always privatized as `_sessions`, accessing the Session directly for any purpose was
never recommended or supported. With v1.4.0, there will be drastic problems if you continue to do so. One of the
few reasons to do that was to get the license keys which is no longer required with CDMs new `get_keys()` method.

RemoteCdm minimum supported Serve API version is now v1.4.0.

### Added

- The PSSH class now has a `new()` method to craft a new PSSH box. The box can be crafted from arbitrary init_data
  and/or key_ids. If only key_ids is supplied a new Widevine Cenc Header will be created and the key IDs will be put
  into it. This allows you to make compliant v0 or v1 boxes with as little data as just a Key ID.
- The PSSH class now has `dump()` and `dumps()` methods to serialize the data as binary or base64 respectively. It will
  be serialized as a pymp4 PSSH box, ready to be used in an MP4 file.
- Cdm now has a method `get_keys()` to get the keys of the loaded license. This is the alternative to manually
  accessing the keys by navigating the `_sessions` class instance variable.
- Serve API now also has a `/get_keys` endpoint to call the `get_keys()` method of the underlying Cdm session.

### Changed

- Cdm and RemoteCdm now expect a PSSH object as the `init_data` param for `get_license_challenge`. You can no longer
  provide it anything else, that includes base64 or bytes form. It must be a PSSH object.
- Serve no longer returns license keys in the response of the `/keys` endpoint.
- Serve has changed the endpoint `/challenge` to `/get_license_challenge` and `/keys` to `/parse_license`. This is to
  be consistent with the method names of the underlying Cdm class.
- The PSSH class has been reworked from being a static helper class to a proper PSSH class.
- PSSH.from_playready_pssh is now a class method and returns as a PSSH object.

### Removed

- PSSH.get_as_box has been removed and merged into the PSSH constructor.
- PSSH.from_key_ids has been removed entirely, you should now use `PSSH.new(key_ids=...)` instead.
- All uses of a local Session() object has been removed from RemoteCdm. The session is now fully controlled by the
  remote API and de-synchronization by external alteration or unexpected exceptions is no longer a possibility.

### Fixed

- Various uses of the `key_ids` field of WidevinePsshData proto has been fixed in the PSSH class.
- Fixed a few Serve API crashes in edge cases with improved error handling on Cdm method calls.

## [1.3.1] - 2022-08-04

### Added

- Cdm and RemoteCdm can now be supplied a string value for `device_type` for scenarios where providing it as a string
  is more convenient (e.g., from Config files).

### Fixed

- The `force_privacy_mode` key no longer needs to be defined at all in the configuration file. This was previously
  crashing serve APIs if it wasn't set before starting.
- RemoteCdm's Server version check will no longer fail under certain serving conditions e.g., Caddy prepending `Caddy`
  to the Server header value. It also fixes case sensitivity and removed the full url from the header.

## [1.3.0] - 2022-08-04

### Added

- New RemoteCdm class to be used as Client code for the `serve` Remote CDM API server. The RemoteCdm should be used
  entirely separately from the normal Cdm class. All serve APIs must update to v1.3.0 to be compatible. The RemoteCdm
  verifies the server version to ensure compatibility. Changes to the serve API schema will be immediately reflected in
  the RemoteCdm code in the future.
- Implemented `/set_service_certificate` endpoint in serve schema as an improved way of setting the service certificate
  than passing it to `/challenge`.
- You can now unset the service certificate by providing an empty service certificate value (or None or null). This
  includes support for doing so even in serve API and the new RemoteCdm.

### Changed

- The Construction of the Cdm object has changed. You can now initialize it with more direct values if you don't want
  to use the Device class or don't want to use `.wvd` files. To use Device classes, you must now use the
  `Cdm.from_device()` class method.
- The ability to pass the certificate to `/challenge` has been removed. Please use the new `/set_service_certificate`
  endpoint before calling `/challenge`. You do not need to set it every time. Once per session is enough unless you
  now want to use a different certificate.

## [1.2.1] - 2022-08-02

This release is primarily a maintenance release for `serve` functionality but some Cdm fixes are also present.

### Added

- You can now return all License Keys from Serve's `/keys` endpoint by supplying `ALL` as the key type.
  This adds support for Exchange Systems like Netflix's WidevineExchange MSL scheme. I recommend using `ALL` unless
  you only want `CONTENT` keys and will not be using any other type of keys including `SIGNING` and `OPERATOR_SESSION`.
- Serve now has a `/close` endpoint to close a session. The Cdm has a limit of 50 sessions per user.
- Serve now responds with a `Server` header denoting that pywidevine serve is being used, also specifying the version.
  This allows Clients to selectively support APIs based on version, and also verify the API as being supported at all.
- Serve now verifies that all Devices in config actually exist before letting you start serving.

### Changed

- Downgraded lxml to >=4.8.0 to support projects using pycaption, which is likely considering the project's topic.
- All of Serve's endpoints now have a `/{device}` prefix. E.g., instead of `/challenge/STREAMING`, it's now
  `/device_name/challenge/STREAMING`. This is to support a multi-device per-user Cdm setup, see Fixed below regarding
  Serve's Cdm objects.

### Fixed

- Fixed support for Raw PSSH values, e.g., Netflix's WidevineExchange MSL Scheme arbitrary init_data value.
- The Service Certificate is now saved to the Session in full SignedMessage form instead of just the underlying
  DrmCertificate. This is so any class inheriting the Cdm (e.g., for Remote capabilities) can sufficiently use
  and supply the service certificate while being signed.
- Serve's /open endpoint will now return a 400 error if there's too many sessions opened.
- Serve's Cdm objects with Device initialized are now stored per-user and device name. This fixes the issue where the
  entire user base has only 50 sessions available to be used. Effectively rate limiting to only 50 users at a time.
  Since /close endpoint was not implemented yet, there was no way to even close effectively meaning only 50 uses could
  be done.

## [1.2.0] - 2022-07-30

### Added

- New CLI command `serve` to serve local WVD devices and CDM sessions remotely as a JSON API.
- The CLI command `migrate` can now accept a folder path to batch migrate WVD files.
- The Cdm now uses custom exceptions where the use case is justified. All custom exceptions are under a parent custom
  exception to allow catching of any Pywidevine exception.

### Changed

- The Cdm has been reworked as a session-based Cdm. You now initialize the Cdm with just the device you wish to use,
  and now you open sessions with `Cdm.open()` to get a session ID. For usage example see `license` CLI command in
  `main.py`.
- The Cdm no longer requires you to specify `raw` bool parameter. It now supports arbitrary and valid Widevine Cenc
 Header Data without needing to explicitly specify which it is.
- The Cdm `pssh` param has been renamed as `init_data`. Doc-strings have been changed to prioritize explanation of it
  referring to Widevine Cenc Header rather than PSSH Boxes. This is to show that the Cdm more-so wants Init Data than
  a PSSH box. The full PSSH is never kept nor ever used, only it's init data is. It still supports PSSH box data.
- Cdm `set_service_certificate()` now returns the provider ID string rather than the underlying (and now verified)
  DrmCertificate. This is because the DrmCertificate is not likely useful and would still be possible to obtain in full
  but quick access to the Provider ID may be more useful.
- License responses can now be only be parsed once by `Cdm.parse_license()`. Any further attempts will raise an
  InvalidContext exception. This is because context data is now cleared for it's respective License Request once it's
  parsed to reduce data lingering in memory.
- Trove Classifier for Development Status is now 5 (Production/Stable).

### Removed

- You can no longer provide a direct `DrmCertificate` to `Cdm.set_service_certificate()` for security reasons.
  You must provide either a `SignedDrmCertificate` or a `SignedMessage` containing a `SignedDrmCertificate`.
- PSSH `from_init_data()` has been removed. It was unused and is unnecessary with improvements to `get_as_box()`.

### Fixed

- Cdm `set_service_certificate()` now verifies the signature of the provided Certificate. This patches a trivial
  exploit/workaround that allows an attacker to recover the plaintext Client ID from an encrypted Client ID.
- Cdm `parse_license()` now verifies the input message type as a `LICENSE` message.
- Cdm `parse_license()` now clears context for the License Request once it's License Response message has been parsed.
  This reduces data lingering in the `context` dictionary when it may only be needed once.
- The Context Availability error handler in Cdm `parse_license()` has been fixed.
- Typing of `type_` param of `Cdm.get_license_challenge()` has been fixed.

## [1.1.1] - 2022-07-22

### Fixed

- The --vmp argument of the create-device command is now optional.

## [1.1.0] - 2022-07-21

### Added

- Added support for setting a Service Certificate in SignedDrmCertificate form as well as raw DrmCertificate form.
  However, It's unlikely for the service to provide the certificate in raw DrmCertificate form without a signature.
- Added a CLI command `create-device` to create Widevine Device (`.wvd`) files from RSA PEM/DER Private Keys and
  Client ID blobs. You can also provide VMP (FileHashes) data which will be merged into the Client ID blob.
- Added a CLI command `migrate` that uses `Device.migrate()` and `dump()` to migrate older v1 Widevine Device files
  to v2.
- Added the v1 Structure of Widevine Devices for migration use.
- Added `Device.migrate()` class method that effectively loads older format WVD data. You can then use `dumps()` to
  get back the WVD data in the latest supported format.
- Added ability to use Privacy mode on the test command.

### Changed

- Set Service Certificates are now stored as the raw underlying DrmCertificate as the signature data is unused by
  the CDM.
- Moved all Widevine Device structures under a Structures class.
- I removed the `send_key_control_nonce` flag from all Structures even though it was technically used.
  This is because the flag was never used as of this project, and I do not want to take up the flag slot.

### Fixed

- Devices `dump()` function now uses the correct `type_` parameter when building the struct.
- Fixed release date year of v1.0.0 and v1.0.1 in the changelog.

## [1.0.1] - 2022-07-21

### Added

- More information to the PyPI meta information, e.g., classifiers, readme, some URLs.

### Changed

- Moved the License Type parameter from the Cdm constructor to `get_license_challenge()`.
- The Session ID is no longer used as the Request ID which could help with blocks or replay checks due
  to it being the same Session ID for each request. It's now a random 16 byte value each time.
- Only the Context Data of each license request is now stored instead of the full message.

### Removed

- Removed unnecessary and unused `raw` Cdm class instance variable.

### Fixed

- CDMs `set_service_certificate()` now correctly raises a DecodeError on Decode Error instead of a ValueError.
- Context Data will now always match to their corresponding License Responses. This fixes an issue where creating
  a second challenge would overwrite the context data of the first challenge. Parsing the first challenge after
  would result in either a key decrypt error, or garbage key data.

## [1.0.0] - 2022-07-20

Initial Release.

[1.5.3]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.5.3
[1.5.2]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.5.2
[1.5.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.5.1
[1.5.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.5.0
[1.4.4]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.4.4
[1.4.3]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.4.3
[1.4.2]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.4.2
[1.4.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.4.1
[1.4.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.4.0
[1.3.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.3.1
[1.3.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.3.0
[1.2.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.2.1
[1.2.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.2.0
[1.1.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.1.1
[1.1.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.1.0
[1.0.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.1
[1.0.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.0
