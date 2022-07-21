# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

- Cdm's `set_service_certificate()` now correctly raises a DecodeError on Decode Error instead of a ValueError.
- Context Data will now always match to their corresponding License Responses. This fixes an issue where creating
  a second challenge would overwrite the context data of the first challenge. Parsing the first challenge after
  would result in either a key decrypt error, or garbage key data.

## [1.0.0] - 2022-07-20

Initial Release.

[1.0.1]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.1
[1.0.0]: https://github.com/rlaphoenix/pywidevine/releases/tag/v1.0.0
