from __future__ import annotations

import base64
import binascii
import re
from typing import Union, Optional

import requests
from Crypto.PublicKey import RSA
from construct import Container
from google.protobuf.message import DecodeError
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.exceptions import InvalidSession, InvalidInitData, InvalidLicenseType, TooManySessions, \
    InvalidLicenseMessage, DeviceMismatch
from pywidevine.key import Key

from pywidevine.license_protocol_pb2 import LicenseType, SignedMessage, License, ClientIdentification
from pywidevine.pssh import PSSH
from pywidevine.session import Session


class RemoteCdm(Cdm):
    """Remote Accessible CDM using pywidevine's serve schema."""

    def __init__(
        self,
        device_type: Union[Device.Types, str],
        system_id: int,
        security_level: int,
        host: str,
        secret: str,
        device_name: str
    ):
        """Initialize a Widevine Content Decryption Module (CDM)."""
        if not device_type:
            raise ValueError("Device Type must be provided")
        if isinstance(device_type, str):
            device_type = Device.Types[device_type]
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

        if not host:
            raise ValueError("API Host must be provided")
        if not isinstance(host, str):
            raise TypeError(f"Expected host to be a {str} not {host!r}")

        if not secret:
            raise ValueError("API Secret must be provided")
        if not isinstance(secret, str):
            raise TypeError(f"Expected secret to be a {str} not {secret!r}")

        if not device_name:
            raise ValueError("API Device name must be provided")
        if not isinstance(device_name, str):
            raise TypeError(f"Expected device_name to be a {str} not {device_name!r}")

        self.device_type = device_type
        self.system_id = system_id
        self.security_level = security_level
        self.host = host
        self.device_name = device_name

        # spoof client_id and rsa_key just so we can construct via super call
        super().__init__(device_type, system_id, security_level, ClientIdentification(), RSA.generate(2048))

        self.__session = requests.Session()
        self.__session.headers.update({
            "X-Secret-Key": secret
        })

        r = requests.head(self.host)
        if r.status_code != 200:
            raise ValueError(f"Could not test Remote API version [{r.status_code}]")
        server = r.headers.get("Server")
        if not server or "pywidevine serve" not in server.lower():
            raise ValueError(f"This Remote CDM API does not seem to be a pywidevine serve API ({server}).")
        server_version = re.search(r"pywidevine serve v([\d.]+)", server, re.IGNORECASE)
        if not server_version:
            raise ValueError(f"The pywidevine server API is not stating the version correctly, cannot continue.")
        server_version = server_version.group(1)
        if server_version < "1.3.0":
            raise ValueError(f"This pywidevine serve API version ({server_version}) is not supported.")

    @classmethod
    def from_device(cls, device: Device) -> RemoteCdm:
        raise NotImplementedError("You cannot load a RemoteCdm from a local Device file.")

    def open(self) -> bytes:
        if len(self._sessions) > self.MAX_NUM_OF_SESSIONS:
            raise TooManySessions(f"Too many Sessions open ({self.MAX_NUM_OF_SESSIONS}).")

        r = self.__session.get(f"{self.host}/{self.device_name}/open")
        if r.status_code != 200:
            raise ValueError(f"Cannot Open CDM Session, {r.text} [{r.status_code}]")
        r = r.json()["data"]

        session = Session()
        session.id = bytes.fromhex(r["session_id"])
        self._sessions[session.id] = session

        if int(r["device"]["system_id"]) != self.system_id:
            raise DeviceMismatch("The System ID specified does not match the one specified in the API response.")

        if int(r["device"]["security_level"]) != self.security_level:
            raise DeviceMismatch("The Security Level specified does not match the one specified in the API response.")

        return session.id

    def close(self, session_id: bytes) -> None:
        r = self.__session.get(f"{self.host}/{self.device_name}/close/{session_id.hex()}")
        if r.status_code != 200:
            raise ValueError(f"Cannot Close CDM Session, {r.text} [{r.status_code}]")
        del self._sessions[session_id]

    def set_service_certificate(self, session_id: bytes, certificate: Optional[Union[bytes, str]]) -> str:
        session = self._sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id!r} is invalid.")

        if certificate is None:
            certificate_b64 = None
        elif isinstance(certificate, str):
            certificate_b64 = certificate  # assuming base64
        elif isinstance(certificate, bytes):
            certificate_b64 = base64.b64encode(certificate).decode()
        else:
            raise DecodeError(f"Expecting Certificate to be base64 or bytes, not {certificate!r}")

        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/set_service_certificate",
            json={
                "session_id": session_id.hex(),
                "certificate": certificate_b64
            }
        )
        if r.status_code != 200:
            raise ValueError(f"Cannot Set CDMs Service Certificate, {r.text} [{r.status_code}]")
        r = r.json()["data"]

        return r["provider_id"]

    def get_license_challenge(
        self,
        session_id: bytes,
        init_data: Union[Container, bytes, str],
        type_: Union[int, str] = LicenseType.STREAMING,
        privacy_mode: bool = True
    ) -> bytes:
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
                type_ = LicenseType.Name(int(type_))
            elif isinstance(type_, str):
                type_ = LicenseType.Name(LicenseType.Value(type_))
            elif isinstance(type_, LicenseType):
                type_ = LicenseType.Name(type_)
            else:
                raise InvalidLicenseType()
        except ValueError:
            raise InvalidLicenseType(f"License Type {type_!r} is invalid")

        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/challenge/{type_}",
            json={
                "session_id": session_id.hex(),
                "init_data": base64.b64encode(init_data).decode()
            }
        )
        if r.status_code != 200:
            raise ValueError(f"Cannot get Challenge, {r.text} [{r.status_code}]")
        r = r.json()["data"]

        try:
            license_message = SignedMessage()
            license_message.ParseFromString(base64.b64decode(r["challenge_b64"]))
        except DecodeError as e:
            raise InvalidLicenseMessage(f"Failed to parse license request, {e}")

        return license_message.SerializeToString()

    def parse_license(self, session_id: bytes, license_message: Union[SignedMessage, bytes, str]) -> None:
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

        r = self.__session.post(
            url=f"{self.host}/{self.device_name}/keys/ALL",
            json={
                "session_id": session_id.hex(),
                "license_message": base64.b64encode(license_message.SerializeToString()).decode()
            }
        )
        if r.status_code != 200:
            raise ValueError(f"Cannot parse License, {r.text} [{r.status_code}]")
        r = r.json()["data"]

        session.keys = [
            Key(
                type_=key["type"],
                kid=Key.kid_to_uuid(bytes.fromhex(key["key_id"])),
                key=bytes.fromhex(key["key"]),
                permissions=key["permissions"]
            )
            for key in r["keys"]
        ]


__ALL__ = (RemoteCdm,)
