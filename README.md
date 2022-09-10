<p align="center">
    <img src="docs/images/widevine_icon_24.png"> <a href="https://github.com/rlaphoenix/pywidevine">pywidevine</a>
    <br/>
    <sup><em>Python Widevine CDM implementation.</em></sup>
</p>

<p align="center">
    <a href="https://github.com/rlaphoenix/pywidevine/actions/workflows/ci.yml">
        <img src="https://github.com/rlaphoenix/pywidevine/actions/workflows/ci.yml/badge.svg" alt="Build status">
    </a>
    <a href="https://pypi.org/project/pywidevine">
        <img src="https://img.shields.io/badge/python-3.7%2B-informational" alt="Python version">
    </a>
    <a href="https://deepsource.io/gh/rlaphoenix/pywidevine">
        <img src="https://deepsource.io/gh/rlaphoenix/pywidevine.svg/?label=active+issues" alt="DeepSource">
    </a>
</p>

## Features

- 🛡️ Security-first approach; All user input has Signatures verified
- 👥 Remotely accessible Server/Client CDM code
- 📦 Supports parsing and serialization of WVD (v2) provisions
- 🛠️ Class for creation, parsing, and conversion of PSSH data
- 🧩 Plug-and-play installation via PIP/PyPI
- 🗃️ YAML configuration files
- ❤️ Forever FOSS!

## Installation

*Note: Requires [Python] 3.7.0 or newer with PIP installed.*

```shell
$ pip install pywidevine
```

You now have the `pywidevine` package installed and a `pywidevine` executable is now available.
Check it out with `pywidevine --help` - Voilà 🎉!

### From Source Code

The following steps are instructions on download, preparing, and running the code under a Poetry environment.
You can skip steps 3-5 with a simple `pip install .` call instead, but you miss out on a wide array of benefits.

1. `git clone https://github.com/rlaphoenix/pywidevine`
2. `cd pywidevine`
3. (optional) `poetry config virtualenvs.in-project true` 
4. `poetry install`
5. `poetry run pywidevine --help`

As seen in Step 5, running the `pywidevine` executable is somewhat different to a normal PIP installation.
See [Poetry's Docs] on various ways of making calls under the virtual-environment.

  [Python]: <https://python.org>
  [Poetry]: <https://python-poetry.org>
  [Poetry's Docs]: <https://python-poetry.org/docs/basic-usage/#using-your-virtual-environment>

## Usage

The following is a minimal example of using pywidevine in a script. It gets a License for Bitmovin's
Art of Motion Demo. There's various stuff not shown in this specific example like:

- Privacy Mode
- Setting Service Certificates
- Remote CDMs and Serving
- Choosing a License Type to request
- Creating WVD files
- and much more!

Just take a look around the Cdm code to see what stuff does. Everything is documented quite well.
There's also various functions in `main.py` that showcases a lot of features.

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

## Troubleshooting

### Executable `pywidevine` was not found

Make sure the Python installation's Scripts directory is added to your Path Environment Variable.

If this happened under a Poetry environment, make sure you use the appropriate Poetry-specific way of calling
the executable. You may make this executable available globally by adding the .venv's Scripts folder to your
Path Environment Variable.

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

## Credit

- Widevine Icon &copy; Google.
- The awesome community for their shared research and insight into the Widevine Protocol and Key Derivation.

## License

[GNU General Public License, Version 3.0](LICENSE)
