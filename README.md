<p align="center">
    <img src="docs/images/widevine_icon_24.png"> <a href="https://github.com/devine-dl/pywidevine">pywidevine</a>
    <br/>
    <sup><em>Python Widevine CDM implementation</em></sup>
</p>

<p align="center">
    <a href="https://github.com/devine-dl/pywidevine/actions/workflows/ci.yml">
        <img src="https://github.com/devine-dl/pywidevine/actions/workflows/ci.yml/badge.svg" alt="Build status">
    </a>
    <a href="https://pypi.org/project/pywidevine">
        <img src="https://img.shields.io/badge/python-3.8%2B-informational" alt="Python version">
    </a>
    <a href="https://deepsource.io/gh/devine-dl/pywidevine">
        <img src="https://deepsource.io/gh/devine-dl/pywidevine.svg/?label=active+issues" alt="DeepSource">
    </a>
</p>
<p align="center">
    <a href="https://github.com/astral-sh/ruff">
        <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Linter: Ruff">
    </a>
    <a href="https://python-poetry.org">
        <img src="https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json" alt="Dependency management: Poetry">
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

```shell
$ pip install pywidevine
```

> **Note**
If pip gives you a warning about a path not being in your PATH environment variable then promptly add that path then
close all open command prompt/terminal windows, or `pywidevine` CLI won't work as it will not be found.

Voilà 🎉 — You now have the `pywidevine` package installed!  
You can now import pywidevine in scripts ([see below](#usage)).  
A command-line interface is also available, try `pywidevine --help`.

## Usage

The following is a minimal example of using pywidevine in a script to get a License for Bitmovin's
Art of Motion Demo.

```py
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

import requests

# prepare pssh
pssh = PSSH("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa"
            "7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==")

# load device
device = Device.load("C:/Path/To/A/Provision.wvd")

# load cdm
cdm = Cdm.from_device(device)

# open cdm session
session_id = cdm.open()

# get license challenge
challenge = cdm.get_license_challenge(session_id, pssh)

# send license challenge (assuming a generic license server SDK with no API front)
licence = requests.post("https://...", data=challenge)
licence.raise_for_status()

# parse license challenge
cdm.parse_license(session_id, licence.content)

# print keys
for key in cdm.get_keys(session_id):
    print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")

# close session, disposes of session data
cdm.close(session_id)
```

> **Note**
> There are various features not shown in this specific example like:
>
> - Privacy Mode
> - Setting Service Certificates
> - Remote CDMs and Serving
> - Choosing a License Type to request
> - Creating WVD files
> - and much more!
>
> Take a look at the methods available in the [Cdm class](/pywidevine/cdm.py) and their doc-strings for
> further information. For more examples see the [CLI functions](/pywidevine/main.py) which uses a lot
> of previously mentioned features.

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

© rlaphoenix 2022-2023
