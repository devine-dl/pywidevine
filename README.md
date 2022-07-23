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

## Disclaimer

1. This project requires a valid Google-provisioned Private Key and Client Identification blob which are not
   provided by this project.
2. Public test provisions are available and provided by Google to use for testing projects such as this one.
3. License Servers have the ability to block requests from any provision, and are likely already blocking test
   provisions on production endpoints.
4. This project does not condone piracy or any action against the terms of the DRM systems.
5. All efforts in this project have been the result of Reverse-Engineering, Publicly available research, and Trial
   & Error.

## Protocol

![widevine-overview](docs/images/widevine_overview.svg)

### Web Server

This may be an API/Server in front of a License Server. For example, Netflix's Custom MSL-based API front.
This is evident by their custom Service Certificate which would only be needed if they had to read the License.

### Net, Media Stack and MediaKeySession

These generally refer to the Encrypted Media Extensions API on Browsers.

Under the assumption of the Android Widevine ecosystem, you can think of `Net` as the Application Code, `Media Stack`
as the OEM Crypto Library, and `MediaKeySession` as a Session. The orange wrapper titled `Browser` is effectively the
Application as a whole, while `Platform` (in Green at the bottom) would be the OS or Other libraries.

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

- Widevine Icons &copy; Google.
- Protocol Overview &copy; https://www.w3.org/TR/encrypted-media -- slightly modified to fit the page better.
- The awesome community for their shared research and insight into the Widevine Protocol and Key Derivation.

## License

[GNU General Public License, Version 3.0](LICENSE)
