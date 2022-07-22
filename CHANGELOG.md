# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.1.1
[1.1.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.1.0
[1.0.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.1
[1.0.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.0
