import base64
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Union, Optional
from uuid import UUID

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, HMAC, SHA256, CMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util import Padding
from construct import Container
from google.protobuf.message import DecodeError

from pywidevine.utils import get_binary_path
from pywidevine.license_protocol_pb2 import LicenseType, SignedMessage, LicenseRequest, ProtocolVersion, \
    SignedDrmCertificate, DrmCertificate, EncryptedClientIdentification, ClientIdentification, License
from pywidevine.device import Device
from pywidevine.key import Key
from pywidevine.pssh import PSSH


class Cdm:
    system_id = b"\xed\xef\x8b\xa9\x79\xd6\x4a\xce\xa3\xc8\x27\xdc\xd5\x1d\x21\xed"
    uuid = UUID(bytes=system_id)
    urn = f"urn:uuid:{uuid}"
    key_format = urn
    service_certificate_challenge = b"\x08\x04"
    common_privacy_cert = ("CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8y"
                           "zdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHl"
                           "eB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/TH"
                           "hv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7c4kcHCCaA1vZ8bYLErF8xNEkKdO7Dev"
                           "Sy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuN"
                           "HMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M"
                           "4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9"
                           "qm9Nta/gr52u/DLpP3lnSq8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5"
                           "+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkP"
                           "j89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq4"
                           "7gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ=")

    NUM_OF_SESSIONS = 0
    MAX_NUM_OF_SESSIONS = 50  # most common limit

    def __init__(self, device: Device, pssh: Union[Container, bytes, str], raw: bool = False):
        """
        Open a Widevine Content Decryption Module (CDM) session.

        Parameters:
            device: Widevine Device containing the Client ID, Device Private Key, and
                more device-specific information.
            pssh: Protection System Specific Header Box or Init Data. This should be a
                compliant mp4 pssh box, or just the init data (Widevine Cenc Header).
            raw: This should be set to True if the PSSH data provided is arbitrary data.
                E.g., a PSSH Box where the init data is not a Widevine Cenc Header, or
                is simply arbitrary data.

        Devices have a limit on how many sessions can be open and active concurrently.
        The limit is different for each device and security level, most commonly 50.
        This limit is handled by the OEM Crypto API. Multiple sessions can be open at
        a time and sessions should be closed when no longer needed.
        """
        if not device:
            raise ValueError("A Widevine Device must be provided.")
        if not pssh:
            raise ValueError("A PSSH Box must be provided.")

        if self.NUM_OF_SESSIONS >= self.MAX_NUM_OF_SESSIONS:
            raise ValueError(
                f"Too many Sessions open {self.NUM_OF_SESSIONS}/{self.MAX_NUM_OF_SESSIONS}. "
                f"Close some Sessions to be able to open more."
            )

        self.NUM_OF_SESSIONS += 1

        self.device = device
        self.init_data = pssh

        if not raw:
            # we only want the init_data of the pssh box
            self.init_data = PSSH.get_as_box(pssh).init_data

        self.session_id = get_random_bytes(16)
        self.service_certificate: Optional[SignedMessage] = None
        self.context: dict[bytes, tuple[bytes, bytes]] = {}

    def set_service_certificate(self, certificate: Union[bytes, str]) -> SignedMessage:
        """
        Set a Service Privacy Certificate for Privacy Mode. (optional but recommended)

        Parameters:
            certificate: Signed Message in Base64 or Bytes form obtained from the Service.
                Some services have their own, but most use the common privacy cert,
                (common_privacy_cert).

        Returns the parsed Signed Message if successful, otherwise raises a DecodeError.

        The Service Certificate is used to encrypt Client IDs in Licenses. This is also
        known as Privacy Mode and may be required for some services or for some devices.
        Chrome CDM requires it as of the enforcement of VMP (Verified Media Path).
        """
        if isinstance(certificate, str):
            certificate = base64.b64decode(certificate)  # assuming base64

        signed_message = SignedMessage()
        try:
            signed_message.ParseFromString(certificate)
        except DecodeError as e:
            raise DecodeError(f"Could not parse certificate as a Signed Message: {e}")

        self.service_certificate = signed_message
        return signed_message

    def get_license_challenge(self, type_: LicenseType = LicenseType.STREAMING, privacy_mode: bool = True) -> bytes:
        """
        Get a License Challenge to send to a License Server.

        Parameters:
            type_: Type of License you wish to exchange, often `STREAMING`.
                The `OFFLINE` Licenses are for Offline licensing of Downloaded content.
            privacy_mode: Encrypt the Client ID using the Privacy Certificate. If the
                privacy certificate is not set yet, this does nothing.

        Returns a SignedMessage containing a LicenseRequest message. It's signed with
        the Private Key of the device provision.
        """
        request_id = get_random_bytes(16)

        license_request = LicenseRequest()
        license_request.type = LicenseRequest.RequestType.Value("NEW")
        license_request.request_time = int(time.time())
        license_request.protocol_version = ProtocolVersion.Value("VERSION_2_1")
        license_request.key_control_nonce = random.randrange(1, 2 ** 31)

        license_request.content_id.widevine_pssh_data.pssh_data.append(self.init_data)
        license_request.content_id.widevine_pssh_data.license_type = type_
        license_request.content_id.widevine_pssh_data.request_id = request_id

        if self.service_certificate and privacy_mode:
            # encrypt the client id for privacy mode
            license_request.encrypted_client_id.CopyFrom(self.encrypt_client_id(
                client_id=self.device.client_id,
                service_certificate=self.service_certificate
            ))
        else:
            license_request.client_id.CopyFrom(self.device.client_id)

        license_message = SignedMessage()
        license_message.type = SignedMessage.MessageType.Value("LICENSE_REQUEST")
        license_message.msg = license_request.SerializeToString()

        license_message.signature = pss. \
            new(self.device.private_key). \
            sign(SHA1.new(license_message.msg))

        self.context[request_id] = self.derive_context(license_message.msg)

        return license_message.SerializeToString()

    def parse_license(self, license_message: Union[bytes, str]) -> list[Key]:
        if not license_message:
            raise ValueError("Cannot parse an empty license_message as a SignedMessage")

        if isinstance(license_message, str):
            license_message = base64.b64decode(license_message)
        if isinstance(license_message, bytes):
            signed_message = SignedMessage()
            try:
                signed_message.ParseFromString(license_message)
            except DecodeError:
                raise ValueError("Failed to parse license_message as a SignedMessage")
            license_message = signed_message
        if not isinstance(license_message, SignedMessage):
            raise ValueError(f"Expecting license_response to be a SignedMessage, got {license_message!r}")

        licence = License()
        licence.ParseFromString(license_message.msg)

        context = self.context[licence.id.request_id]
        if not context:
            raise ValueError("Cannot parse a license message without first making a license request")

        session_key = PKCS1_OAEP. \
            new(self.device.private_key). \
            decrypt(license_message.session_key)

        enc_key, mac_key_server, mac_key_client = self.derive_keys(*context, session_key)

        license_signature = HMAC. \
            new(mac_key_server, digestmod=SHA256). \
            update(licence.SerializeToString()). \
            digest()

        if license_message.signature != license_signature:
            raise ValueError("The License Signature doesn't match the Signature listed in the Message")

        return [
            Key.from_key_container(key, enc_key)
            for key in licence.key
        ]

    @staticmethod
    def decrypt(content_keys: dict[UUID, str], input_: Path, output: Path, temp: Optional[Path] = None):
        """
        Decrypt a Widevine-encrypted file using Shaka-packager.
        Shaka-packager is much more stable than mp4decrypt.

        Raises:
            EnvironmentError if the Shaka Packager executable could not be found.
            ValueError if the track has not yet been downloaded.
            SubprocessError if Shaka Packager returned a non-zero exit code.
        """
        if not content_keys:
            raise ValueError("Cannot decrypt without any Content Keys")
        if not input_:
            raise ValueError("Cannot decrypt nothing, specify an input path")
        if not output:
            raise ValueError("Cannot decrypt nowhere, specify an output path")

        platform = {"win32": "win", "darwin": "osx"}.get(sys.platform, sys.platform)
        executable = get_binary_path("shaka-packager", f"packager-{platform}", f"packager-{platform}-x64")
        if not executable:
            raise EnvironmentError("Shaka Packager executable not found but is required")

        args = [
            f"input={input_},stream=0,output={output}",
            "--enable_raw_key_decryption", "--keys",
            ",".join([
                *[
                    "label={}:key_id={}:key={}".format(i, kid.hex, key.lower())
                    for i, (kid, key) in enumerate(content_keys.items())
                ],
                *[
                    # Apple TV+ needs this as their files do not use the KID supplied in the manifest
                    "label={}:key_id={}:key={}".format(i, "00" * 16, key.lower())
                    for i, (kid, key) in enumerate(content_keys.items(), len(content_keys))
                ]
            ]),
        ]

        if temp:
            temp.mkdir(parents=True, exist_ok=True)
            args.extend(["--temp_dir", temp])

        try:
            subprocess.check_call([executable, *args])
        except subprocess.CalledProcessError as e:
            raise subprocess.SubprocessError(f"Failed to Decrypt! Shaka Packager Error: {e}")

    @staticmethod
    def encrypt_client_id(
        client_id: ClientIdentification,
        service_certificate: Union[SignedMessage, SignedDrmCertificate, DrmCertificate],
        key: bytes = None,
        iv: bytes = None
    ) -> EncryptedClientIdentification:
        """Encrypt the Client ID with the Service's Privacy Certificate."""
        privacy_key = key or get_random_bytes(16)
        privacy_iv = iv or get_random_bytes(16)

        if isinstance(service_certificate, SignedMessage):
            signed_service_certificate = SignedDrmCertificate()
            signed_service_certificate.ParseFromString(service_certificate.msg)
            service_certificate = signed_service_certificate

        if isinstance(service_certificate, SignedDrmCertificate):
            service_service_drm_certificate = DrmCertificate()
            service_service_drm_certificate.ParseFromString(service_certificate.drm_certificate)
            service_certificate = service_service_drm_certificate

        if not isinstance(service_certificate, DrmCertificate):
            raise ValueError(f"Service Certificate is in an unexpected type {service_certificate!r}")

        enc_client_id = EncryptedClientIdentification()
        enc_client_id.provider_id = service_certificate.provider_id
        enc_client_id.service_certificate_serial_number = service_certificate.serial_number

        enc_client_id.encrypted_client_id = AES. \
            new(privacy_key, AES.MODE_CBC, privacy_iv). \
            encrypt(Padding.pad(client_id.SerializeToString(), 16))

        enc_client_id.encrypted_privacy_key = PKCS1_OAEP. \
            new(RSA.importKey(service_certificate.public_key)). \
            encrypt(privacy_key)
        enc_client_id.encrypted_client_id_iv = privacy_iv

        return enc_client_id

    @staticmethod
    def derive_context(message: bytes) -> tuple[bytes, bytes]:
        """Returns 2 Context Data used for computing the AES Encryption and HMAC Keys."""

        def _get_enc_context(msg: bytes) -> bytes:
            label = b"ENCRYPTION"
            key_size = 16 * 8  # 128-bit
            return label + b"\x00" + msg + key_size.to_bytes(4, "big")

        def _get_mac_context(msg: bytes) -> bytes:
            label = b"AUTHENTICATION"
            key_size = 32 * 8 * 2  # 512-bit
            return label + b"\x00" + msg + key_size.to_bytes(4, "big")

        return _get_enc_context(message), _get_mac_context(message)

    @staticmethod
    def derive_keys(enc_context: bytes, mac_context: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Returns 3 keys derived from the input message.
        Key can either be a pre-provision device aes key, provision key, or a session key.

        For provisioning:
        - enc: aes key used for unwrapping RSA key out of response
        - mac_key_server: hmac-sha256 key used for verifying provisioning response
        - mac_key_client: hmac-sha256 key used for signing provisioning request

        When used with a session key:
        - enc: decrypting content and other keys
        - mac_key_server: verifying response
        - mac_key_client: renewals

        With key as pre-provision device key, it can be used to provision and get an
        RSA device key and token/cert with key as session key (OAEP wrapped with the
        post-provision RSA device key), it can be used to decrypt content and signing
        keys and verify licenses.
        """

        def _derive(session_key: bytes, context: bytes, counter: int) -> bytes:
            return CMAC.new(session_key, ciphermod=AES). \
                update(counter.to_bytes(1, "big") + context). \
                digest()

        enc_key = _derive(key, enc_context, 1)
        mac_key_server = _derive(key, mac_context, 1)
        mac_key_server += _derive(key, mac_context, 2)
        mac_key_client = _derive(key, mac_context, 3)
        mac_key_client += _derive(key, mac_context, 4)

        return enc_key, mac_key_server, mac_key_client


__ALL__ = (Cdm,)
