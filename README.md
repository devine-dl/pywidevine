<p align="center">
    <img src="docs/images/widevine_icon_24.png"> <a href="https://github.com/devine-dl/pywidevine">pywidevine</a>
    <br/>
    <sup><em>Python Widevine CDM implementation</em></sup>
</p>

<p align="center">
    <a href="https://github.com/devine-dl/pywidevine/blob/master/LICENSE">
        <img src="https://img.shields.io/:license-GPL%203.0-blue.svg" alt="License">
    </a>
    <a href="https://pypi.org/project/pywidevine">
        <img src="https://img.shields.io/badge/python-3.9%2B-informational" alt="Python version">
    </a>
    <a href="https://github.com/astral-sh/uv">
        <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Onyx-Nostalgia/uv/refs/heads/fix/logo-badge/assets/badge/v0.json" alt="Manager: uv">
    </a>
    <a href="https://github.com/astral-sh/ruff">
        <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Linter: Ruff">
    </a>
    <a href="https://github.com/devine-dl/pywidevine/actions/workflows/ci.yml">
        <img src="https://github.com/devine-dl/pywidevine/actions/workflows/ci.yml/badge.svg" alt="Build status">
    </a>
</p>

## Features

- 🚀 Seamless Installation via [pip](#installation)
- 🛡️ Robust Security with message signature verification
- 🙈 Privacy Mode with Service Certificates
- 🌐 Servable CDM API Server and Client with Authentication
- 📦 Custom provision serialization format (WVD v2)
- 🧰 Create, parse, or convert PSSH headers with ease
- 🗃️ User-friendly YAML configuration
- ❤️ Forever FOSS!

## Installation

### With pip

> Since *pip* is pre-installed with Python, it is the most straight forward way to install pywidevine.

Simply run `pip install pywidevine` and it will be ready to use from the CLI or within scripts in a minute.

### With uv

> This is recommended for those who wish to install from the source code, are working on changes in the source code, or
just simply prefer it's many handy features.

Go to to the official website and [get uv installed](https://docs.astral.sh/uv/getting-started/installation/). Download
or clone this repository, go inside it, and run `uv run pywidevine --version`. To run scripts, like a `license.py` that
is importing pywidevine, do `uv run license.py`. Effectively, put `uv run` before calling whatever is using pywidevine.
For other ways to run pywidevine with uv, see [Running commands](https://docs.astral.sh/uv/guides/projects/#running-commands).

## Usage

There are two ways to use pywidevine, through scripts, or the CLI (command-line interface).
Most people would be using it through scripts due to complexities working with license server APIs.

### Scripts

The following is a minimal example of using pywidevine in a script to get a License for Bitmovin's Art of Motion Demo.
This demo can be found on [Bitmovin's DRM Stream Test demo page](https://bitmovin.com/demos/drm/).

```py
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

import requests

# prepare pssh (usually inside the MPD/M3U8, an API response, the player page, or inside the pssh mp4 box)
pssh = PSSH("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa"
            "7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==")

# load device from a WVD file (your provision)
device = Device.load("C:/Path/To/A/Provision.wvd")

# load cdm (creating a CDM instance using that device)
cdm = Cdm.from_device(device)

# open cdm session (note that any one device should have a practical limit to amount of sessions open at any one time)
session_id = cdm.open()

# get license challenge (generate a license request message, signed using the device with the pssh)
challenge = cdm.get_license_challenge(session_id, pssh)

# send license challenge to bitmovin's license server (which has no auth and asks simply for the license challenge as-is)
# another license server may require authentication and ask for it as JSON or form data instead
# you may also be required to use privacy mode, where you use their service certificate when creating the challenge
licence = requests.post("https://cwip-shaka-proxy.appspot.com/no_auth", data=challenge)
licence.raise_for_status()

# parse the license response message received from the license server API
cdm.parse_license(session_id, licence.content)

# print keys
for key in cdm.get_keys(session_id):
    print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")

# finished, close the session, disposing of all keys and other related data
cdm.close(session_id)
```

There are other features not shown in this small example like:

- Privacy Mode
- Setting Service Certificates
- Remote CDMs and Serving
- Choosing a License Type
- Creating WVD files
- and much more!

> [!TIP]
> For examples, take a look at the methods available in the [Cdm class](/pywidevine/cdm.py) and read their doc-strings
> for further information.

### Command-line Interface

The CLI can be useful to do simple license calls, migrate WVD files, and test provisions.
Take a look at `pywidevine --help` to see a list of commands available.

```plain
Usage: pywidevine [OPTIONS] COMMAND [ARGS]...

  pywidevine—Python Widevine CDM implementation.

Options:
  -v, --version  Print version information.
  -d, --debug    Enable DEBUG level logs.
  --help         Show this message and exit.

Commands:
  create-device  Create a Widevine Device (.wvd) file from an RSA Private...
  export-device  Export a Widevine Device (.wvd) file to an RSA Private...
  license        Make a License Request for PSSH to SERVER using DEVICE.
  migrate        Upgrade from earlier versions of the Widevine Device...
  serve          Serve your local CDM and Widevine Devices Remotely.
  test           Test the CDM code by getting Content Keys for Bitmovin's...
```

Every command has further help information, simply type `pywidevine <command> --help`.
For example, `pywidevine test --help`:

```plain
Usage: pywidevine test [OPTIONS] DEVICE

  Test the CDM code by getting Content Keys for Bitmovin's Art of Motion
  example. https://bitmovin.com/demos/drm
  https://bitmovin-a.akamaihd.net/content/art-of-motion_drm/mpds/11331.mpd

  The device argument is a Path to a Widevine Device (.wvd) file which
  contains the device private key among other required information.

Options:
  -p, --privacy  Use Privacy Mode, off by default.
  --help         Show this message and exit.
```

## Disclaimer

1. This project requires a valid Google-provisioned Private Key and Client Identification blob which are not
   provided by this project.
2. Public test provisions are available and provided by Google to use for testing projects such as this one.
3. License Servers have the ability to block requests from any provision, and are likely already blocking test
   provisions on production endpoints.
4. This project does not condone piracy or any action against the terms of the DRM systems.
5. All efforts in this project have been the result of Reverse-Engineering, Publicly available research, and Trial
   & Error.

## Key and Output Security

*Licenses, Content Keys, and Decrypted Data is not secure in this CDM implementation.*

The Content Decryption Module is meant to do all downloading, decrypting, and decoding of content, not just license
acquisition. This Python implementation only does License Acquisition within the CDM.

The section of which a 'Decrypt Frame' call is made would be more of a 'Decrypt File' in this implementation. Just
returning the original file in plain text defeats the point of the DRM. Even if 'Decrypt File' was somehow secure, the
Content Keys used to decrypt the files are already exposed to the caller anyway, allowing them to manually decrypt.

An attack on a 'Decrypt Frame' system would be analogous to doing an HDMI capture or similar attack. This is because it
would require re-encoding the video by splicing each individual frame with the right frame-rate, syncing to audio, and
more.

While a 'Decrypt Video' system would be analogous to downloading a Video and passing it through a script. Not much of
an attack if at all. The only protection against a system like this would be monitoring the provision and acquisitions
of licenses and prevent them. This can be done by revoking the device provision, or the user or their authorization to
the service.

There isn't any immediate way to secure either Key or Decrypted information within a Python environment that is not
Hardware backed. Even if obfuscation or some other form of Security by Obscurity was used, this is a Software-based
Content Protection Module (in Python no less) with no hardware backed security. It would be incredibly trivial to break
any sort of protection against retrieving the original video data.

Though, it's not impossible. Google's Chrome Browser CDM is a simple library extension file programmed in C++ that has
been improving its security using math and obscurity for years. It's getting harder and harder to break with its latest
versions only being beaten by Brute-force style methods. However, they have a huge team of very skilled workers, and
making a CDM in C++ has immediate security benefits and a lot of methods to obscure and obfuscate the code.

## Contributors

<a href="https://github.com/rlaphoenix"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/17136956?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt=""/></a>
<a href="https://github.com/mediaminister"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/45148099?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt=""/></a>
<a href="https://github.com/sr0lle"><img src="https://images.weserv.nl/?url=avatars.githubusercontent.com/u/111277375?v=4&h=25&w=25&fit=cover&mask=circle&maxage=7d" alt=""/></a>

## Licensing

This software is licensed under the terms of [GNU General Public License, Version 3.0](LICENSE).  
You can find a copy of the license in the LICENSE file in the root folder.

- Widevine Icon &copy; Google.
- Props to the awesome community for their shared research and insight into the Widevine Protocol and Key Derivation.

* * *

© rlaphoenix 2022-2025
