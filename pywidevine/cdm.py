from __future__ import annotations

import base64
import binascii
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Union, Container, Optional
from uuid import UUID

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, HMAC, SHA256, CMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util import Padding
from google.protobuf.message import DecodeError

from pywidevine.device import Device
from pywidevine.exceptions import TooManySessions, InvalidSession, InvalidLicenseType, SignatureMismatch, \
    InvalidInitData, InvalidLicenseMessage, NoKeysLoaded, InvalidContext
from pywidevine.key import Key
from pywidevine.license_protocol_pb2 import DrmCertificate, SignedMessage, SignedDrmCertificate, LicenseType, \
    LicenseRequest, ProtocolVersion, ClientIdentification, EncryptedClientIdentification, License
from pywidevine.pssh import PSSH
from pywidevine.session import Session
from pywidevine.utils import get_binary_path


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
    root_signed_cert = SignedDrmCertificate()
    root_signed_cert.ParseFromString(base64.b64decode(
        "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZy"
        "f7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfM"
        "qIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx"
        "+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg1"
        "7B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSC"
        "UNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0a"
        "y5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZV"
        "dA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2F"
        "RXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7"
        "evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
    ))
    root_cert = DrmCertificate()
    root_cert.ParseFromString(root_signed_cert.drm_certificate)

    MAX_NUM_OF_SESSIONS = 50  # most common limit

    def __init__(
        self,
        device_type: Device.Types,
        system_id: int,
        security_level: int,
        client_id: ClientIdentification,
        rsa_key: RSA.RsaKey
    ):
        """Initialize a Widevine Content Decryption Module (CDM)."""
        if not device_type:
            raise ValueError("Device Type must be provided")
        if not isinstance(device_type, Device.Types):
            raise TypeError(f"Expected device_type to be a {Device.Types!r} not {device_type!r}")

        if not system_id:
            raise ValueError("System ID must be provided")
        if not isinstance(system_id, int):
            raise TypeError(f"Expected system_id to be a {int} not {system_id!r}")

        if not security_level:
            raise ValueError("Security Level must be provided")
        if not isinstance(security_level, int):
            raise TypeError(f"Expected security_level to be a {int} not {security_level!r}")

        if not client_id:
            raise ValueError("Client ID must be provided")
        if not isinstance(client_id, ClientIdentification):
            raise TypeError(f"Expected client_id to be a {ClientIdentification} not {client_id!r}")

        if not rsa_key:
            raise ValueError("RSA Key must be provided")
        if not isinstance(rsa_key, RSA.RsaKey):
            raise TypeError(f"Expected rsa_key to be a {RSA.RsaKey} not {rsa_key!r}")

        self.device_type = device_type
        self.system_id = system_id
        self.security_level = security_level
        self.__client_id = client_id

        self.__signer = pss.new(rsa_key)
        self.__decrypter = PKCS1_OAEP.new(rsa_key)

        self._sessions: dict[bytes, Session] = {}

    @classmethod
    def from_device(cls, device: Device) -> Cdm:
        """Initialize a Widevine CDM from a Widevine Device (.wvd) file."""
        return cls(
            device_type=device.type,
            system_id=device.system_id,
            security_level=device.security_level,
            client_id=device.client_id,
            rsa_key=device.private_key
        )

    def open(self) -> bytes:
        """
        Open a Widevine Content Decryption Module (CDM) session.

        Raises:
            TooManySessions: If the session cannot be opened as limit has been reached.
        """
        if len(self._sessions) > self.MAX_NUM_OF_SESSIONS:
            raise TooManySessions(f"Too many Sessions open ({self.MAX_NUM_OF_SESSIONS}).")

        session = Session()
        self._sessions[session.id] = session

        return session.id

    def close(self, session_id: bytes) -> None:
        """
        Close a Widevine Content Decryption Module (CDM) session.

        Parameters:
            session_id: Session identifier.

        Raises:
            InvalidSession: If the Session identifier is invalid.
        """
        session = self._sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")
        del self._sessions[session_id]

    def set_service_certificate(self, session_id: bytes, certificate: Optional[Union[bytes, str]]) -> str:
        """
        Set a Service Privacy Certificate for Privacy Mode. (optional but recommended)

        The Service Certificate is used to encrypt Client IDs in Licenses. This is also
        known as Privacy Mode and may be required for some services or for some devices.
        Chrome CDM requires it as of the enforcement of VMP (Verified Media Path).

        We reject direct DrmCertificates as they do not have signature verification and
        cannot be verified. You must provide a SignedDrmCertificate or a SignedMessage
        containing a SignedDrmCertificate.

        Parameters:
            session_id: Session identifier.
            certificate: SignedDrmCertificate (or SignedMessage containing one) in Base64
                or Bytes form obtained from the Service. Some services have their own,
                but most use the common privacy cert, (common_privacy_cert). If None, it
                will remove the current certificate.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            DecodeError: If the certificate could not be parsed as a SignedDrmCertificate
                nor a SignedMessage containing a SignedDrmCertificate.
            SignatureMismatch: If the Signature of the SignedDrmCertificate does not
                match the underlying DrmCertificate.

        Returns the Service Provider ID of the verified DrmCertificate if successful.
        If certificate is None, it will return the now unset certificate's Provider ID.
        """
        session = self._sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if certificate is None:
            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(session.service_certificate.drm_certificate)
            session.service_certificate = None
            return drm_certificate.provider_id

        if isinstance(certificate, str):
            try:
                certificate = base64.b64decode(certificate)  # assuming base64
            except binascii.Error:
                raise DecodeError("Could not decode certificate string as Base64, expected bytes.")
        elif not isinstance(certificate, bytes):
            raise DecodeError(f"Expecting Certificate to be bytes, not {certificate!r}")

        signed_message = SignedMessage()
        signed_drm_certificate = SignedDrmCertificate()

        try:
            signed_message.ParseFromString(certificate)
            if signed_message.SerializeToString() == certificate:
                signed_drm_certificate.ParseFromString(signed_message.msg)
            else:
                signed_drm_certificate.ParseFromString(certificate)
                if signed_drm_certificate.SerializeToString() != certificate:
                    raise DecodeError()
                # Craft a SignedMessage as it's stored as a SignedMessage
                signed_message.Clear()
                signed_message.msg = signed_drm_certificate.SerializeToString()
                # we don't need to sign this message, this is normal
        except DecodeError:
            # could be a direct unsigned DrmCertificate, but reject those anyway
            raise DecodeError("Could not parse certificate as a SignedDrmCertificate")

        try:
            pss. \
                new(RSA.import_key(self.root_cert.public_key)). \
                verify(
                    msg_hash=SHA1.new(signed_drm_certificate.drm_certificate),
                    signature=signed_drm_certificate.signature
                )
        except (ValueError, TypeError):
            raise SignatureMismatch("Signature Mismatch on SignedDrmCertificate, rejecting certificate")
        else:
            session.service_certificate = signed_message
            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)
            return drm_certificate.provider_id

    def get_license_challenge(
        self,
        session_id: bytes,
        init_data: Union[Container, bytes, str],
        type_: Union[int, str] = LicenseType.STREAMING,
        privacy_mode: bool = True
    ) -> bytes:
        """
        Get a License Request (Challenge) to send to a License Server.

        Parameters:
            session_id: Session identifier.
            init_data: Widevine Cenc Header (Init Data) or a Protection System Specific
                Header Box to take the init data from.
            type_: Type of License you wish to exchange, often `STREAMING`. The `OFFLINE`
                Licenses are for Offline licensing of Downloaded content.
            privacy_mode: Encrypt the Client ID using the Privacy Certificate. If the
                privacy certificate is not set yet, this does nothing.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            InvalidInitData: If the Init Data (or PSSH box) provided is invalid.
            InvalidLicenseType: If the type_ parameter value is not a License Type. It
                must be a LicenseType enum, or a string/int representing the enum's keys
                or values.

        Returns a SignedMessage containing a LicenseRequest message. It's signed with
        the Private Key of the device provision.
        """
        session = self._sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if not init_data:
            raise InvalidInitData("The init_data must not be empty.")
        try:
            init_data = PSSH.get_as_box(init_data).init_data
        except (ValueError, binascii.Error, DecodeError) as e:
            raise InvalidInitData(str(e))

        try:
            if isinstance(type_, int):
                LicenseType.Name(int(type_))
            elif isinstance(type_, str):
                type_ = LicenseType.Value(type_)
            elif not isinstance(type_, LicenseType):
                raise InvalidLicenseType()
        except ValueError:
            raise InvalidLicenseType(f"License Type {type_!r} is invalid")

        request_id = get_random_bytes(16)

        license_request = LicenseRequest()
        license_request.type = LicenseRequest.RequestType.Value("NEW")
        license_request.request_time = int(time.time())
        license_request.protocol_version = ProtocolVersion.Value("VERSION_2_1")
        license_request.key_control_nonce = random.randrange(1, 2 ** 31)

        license_request.content_id.widevine_pssh_data.pssh_data.append(init_data)
        license_request.content_id.widevine_pssh_data.license_type = type_
        license_request.content_id.widevine_pssh_data.request_id = request_id

        if session.service_certificate and privacy_mode:
            # encrypt the client id for privacy mode
            license_request.encrypted_client_id.CopyFrom(self.encrypt_client_id(
                client_id=self.__client_id,
                service_certificate=session.service_certificate
            ))
        else:
            license_request.client_id.CopyFrom(self.__client_id)

        license_message = SignedMessage()
        license_message.type = SignedMessage.MessageType.LICENSE_REQUEST
        license_message.msg = license_request.SerializeToString()
        license_message.signature = self.__signer.sign(SHA1.new(license_message.msg))

        session.context[request_id] = self.derive_context(license_message.msg)

        return license_message.SerializeToString()

    def parse_license(self, session_id: bytes, license_message: Union[SignedMessage, bytes, str]) -> None:
        """
        Load Keys from a License Message from a License Server Response.

        License Messages can only be loaded a single time. An InvalidContext error will
        be raised if you attempt to parse a License Message more than once.

        Parameters:
            session_id: Session identifier.
            license_message: A SignedMessage containing a License message.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            InvalidLicenseMessage: The License message could not be decoded as a Signed
                Message or License message.
            InvalidContext: If the Session has no Context Data. This is likely to happen
                if the License Challenge was not made by this CDM instance, or was not
                by this CDM at all. It could also happen if the Session is closed after
                calling parse_license but not before it got the context data.
            SignatureMismatch: If the Signature of the License SignedMessage does not
                match the underlying License.
        """
        session = self._sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if not license_message:
            raise InvalidLicenseMessage("Cannot parse an empty license_message")

        if isinstance(license_message, str):
            try:
                license_message = base64.b64decode(license_message)
            except (binascii.Error, binascii.Incomplete) as e:
                raise InvalidLicenseMessage(f"Could not decode license_message as Base64, {e}")

        if isinstance(license_message, bytes):
            signed_message = SignedMessage()
            try:
                signed_message.ParseFromString(license_message)
            except DecodeError as e:
                raise InvalidLicenseMessage(f"Could not parse license_message as a SignedMessage, {e}")
            license_message = signed_message

        if not isinstance(license_message, SignedMessage):
            raise InvalidLicenseMessage(f"Expecting license_response to be a SignedMessage, got {license_message!r}")

        if license_message.type != SignedMessage.MessageType.LICENSE:
            raise InvalidLicenseMessage(
                f"Expecting a LICENSE message, not a "
                f"'{SignedMessage.MessageType.Name(license_message.type)}' message."
            )

        licence = License()
        licence.ParseFromString(license_message.msg)

        context = session.context.get(licence.id.request_id)
        if not context:
            raise InvalidContext("Cannot parse a license message without first making a license request")

        enc_key, mac_key_server, _ = self.derive_keys(
            *context,
            key=self.__decrypter.decrypt(license_message.session_key)
        )

        computed_signature = HMAC. \
            new(mac_key_server, digestmod=SHA256). \
            update(licence.SerializeToString()). \
            digest()

        if license_message.signature != computed_signature:
            raise SignatureMismatch("Signature Mismatch on License Message, rejecting license")

        session.keys = [
            Key.from_key_container(key, enc_key)
            for key in licence.key
        ]

        del session.context[licence.id.request_id]

    def decrypt(
        self,
        session_id: bytes,
        input_file: Union[Path, str],
        output_file: Union[Path, str],
        temp_dir: Optional[Union[Path, str]] = None,
        exists_ok: bool = False
    ):
        """
        Decrypt a Widevine-encrypted file using Shaka-packager.
        Shaka-packager is much more stable than mp4decrypt.

        Parameters:
            session_id: Session identifier.
            input_file: File to be decrypted with Session's currently loaded keys.
            output_file: Location to save decrypted file.
            temp_dir: Directory to store temporary data while decrypting.
            exists_ok: Allow overwriting the output_file if it exists.

        Raises:
            ValueError: If the input or output paths have not been supplied or are
                invalid.
            FileNotFoundError: If the input file path does not exist.
            FileExistsError: If the output file path already exists. Ignored if exists_ok
                is set to True.
            NoKeysLoaded: No License was parsed for this Session, No Keys available.
            EnvironmentError: If the shaka-packager executable could not be found.
            subprocess.CalledProcessError: If the shaka-packager call returned a non-zero
                exit code.
        """
        if not input_file:
            raise ValueError("Cannot decrypt nothing, specify an input path")
        if not output_file:
            raise ValueError("Cannot decrypt nowhere, specify an output path")

        if not isinstance(input_file, (Path, str)):
            raise ValueError(f"Expecting input_file to be a Path or str, got {input_file!r}")
        if not isinstance(output_file, (Path, str)):
            raise ValueError(f"Expecting output_file to be a Path or str, got {output_file!r}")
        if not isinstance(temp_dir, (Path, str)) and temp_dir is not None:
            raise ValueError(f"Expecting temp_dir to be a Path or str, got {temp_dir!r}")

        input_file = Path(input_file)
        output_file = Path(output_file)
        if temp_dir:
            temp_dir = Path(temp_dir)

        if not input_file.is_file():
            raise FileNotFoundError(f"Input file does not exist, {input_file}")
        if output_file.is_file() and not exists_ok:
            raise FileExistsError(f"Output file already exists, {output_file}")

        session = self._sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if not session.keys:
            raise NoKeysLoaded("No Keys are loaded yet, cannot decrypt")

        platform = {"win32": "win", "darwin": "osx"}.get(sys.platform, sys.platform)
        executable = get_binary_path("shaka-packager", f"packager-{platform}", f"packager-{platform}-x64")
        if not executable:
            raise EnvironmentError("Shaka Packager executable not found but is required")

        args = [
            f"input={input_file},stream=0,output={output_file}",
            "--enable_raw_key_decryption",
            "--keys", ",".join([
                label
                for i, key in enumerate(session.keys)
                for label in [
                    f"label=1_{i}:key_id={key.kid.hex}:key={key.key.hex()}",
                    # some services need the KID blanked, e.g., Apple TV+
                    f"label=2_{i}:key_id={'0' * 32}:key={key.key.hex()}"
                ]
                if key.type == "CONTENT"
            ])
        ]

        if temp_dir:
            temp_dir.mkdir(parents=True, exist_ok=True)
            args.extend(["--temp_dir", temp_dir])

        subprocess.check_call([executable, *args])

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
            signed_drm_certificate = SignedDrmCertificate()
            signed_drm_certificate.ParseFromString(service_certificate.msg)
            service_certificate = signed_drm_certificate
        if isinstance(service_certificate, SignedDrmCertificate):
            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(service_certificate.drm_certificate)
            service_certificate = drm_certificate
        if not isinstance(service_certificate, DrmCertificate):
            raise ValueError(f"Expecting Service Certificate to be a DrmCertificate, not {service_certificate!r}")

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
            return CMAC. \
                new(session_key, ciphermod=AES). \
                update(counter.to_bytes(1, "big") + context). \
                digest()

        enc_key = _derive(key, enc_context, 1)
        mac_key_server = _derive(key, mac_context, 1)
        mac_key_server += _derive(key, mac_context, 2)
        mac_key_client = _derive(key, mac_context, 3)
        mac_key_client += _derive(key, mac_context, 4)

        return enc_key, mac_key_server, mac_key_client


__ALL__ = (Cdm,)
