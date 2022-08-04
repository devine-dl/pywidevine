# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.3.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.3.1
[1.3.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.3.0
[1.2.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.2.1
[1.2.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.2.0
[1.1.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.1.1
[1.1.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.1.0
[1.0.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.1
[1.0.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.0
