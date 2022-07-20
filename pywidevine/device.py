from __future__ import annotations

import base64
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

from construct import BitStruct, Bytes, Const
from construct import Enum as CEnum
from construct import Flag, Int8ub, Int16ub
from construct import Optional as COptional
from construct import Padded, Padding, Struct, this
from Crypto.PublicKey import RSA
from google.protobuf.message import DecodeError

from pywidevine.license_protocol_pb2 import ClientIdentification, FileHashes, SignedDrmCertificate, DrmCertificate


class _Types(Enum):
    CHROME = 1
    ANDROID = 2


class Device:
    # needed so bin_format can enumerate the types
    Types = _Types

    bin_format = Struct(
        "signature" / Const(b"WVD"),
        "version" / Const(Int8ub, 2),
        "type_" / CEnum(
            Int8ub,
            **{t.name: t.value for t in _Types}
        ),
        "security_level" / Int8ub,
        "flags" / Padded(1, COptional(BitStruct(
            Padding(7),
            "send_key_control_nonce" / Flag  # deprecated, do not use
        ))),
        "private_key_len" / Int16ub,
        "private_key" / Bytes(this.private_key_len),
        "client_id_len" / Int16ub,
        "client_id" / Bytes(this.client_id_len)
    )

    # == Bin Format Revisions == #
    # Version 2: Removed vmp and vmp_len as it should already be within the Client ID
    # Version 1: Removed system_id as it can be retrieved from the Client ID's DRM Certificate

    def __init__(
        self,
        *_: Any,
        type_: Types,
        security_level: int,
        flags: Optional[dict],
        private_key: Optional[bytes],
        client_id: Optional[bytes],
        **__: Any
    ):
        """
        This is the device key data that is needed for the CDM (Content Decryption Module).

        Parameters:
            type_: Device Type
            security_level: Security level from 1 (the highest ranking) to 3 (the lowest ranking)
            flags: Extra flags
            private_key: Device Private Key
            client_id: Device Client Identification Blob
        """
        # *_,*__ is to ignore unwanted args, like signature and version from the struct

        if not client_id:
            raise ValueError("Client ID is required, the WVD does not contain one or is malformed.")
        if not private_key:
            raise ValueError("Private Key is required, the WVD does not contain one or is malformed.")

        self.type = self.Types[type_] if isinstance(type_, str) else type_
        self.security_level = security_level
        self.flags = flags
        self.private_key = RSA.importKey(private_key)
        self.client_id = ClientIdentification()
        try:
            self.client_id.ParseFromString(client_id)
        except DecodeError:
            raise ValueError("Failed to parse client_id as a ClientIdentification")

        self.vmp = FileHashes()
        if self.client_id.vmp_data:
            try:
                self.vmp.ParseFromString(self.client_id.vmp_data)
            except DecodeError:
                raise ValueError("Failed to parse Client ID's VMP data as a FileHashes")

        signed_drm_certificate = SignedDrmCertificate()
        signed_drm_certificate.ParseFromString(self.client_id.token)
        drm_certificate = DrmCertificate()
        drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)
        self.system_id = drm_certificate.system_id

    def __repr__(self) -> str:
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join([f"{k}={repr(v)}" for k, v in self.__dict__.items()])
        )

    @classmethod
    def loads(cls, data: Union[bytes, str]) -> Device:
        if isinstance(data, str):
            data = base64.b64decode(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Expecting Bytes or Base64 input, got {data!r}")
        return cls(**cls.bin_format.parse(data))

    @classmethod
    def load(cls, path: Union[Path, str]) -> Device:
        if not isinstance(path, (Path, str)):
            raise ValueError(f"Expecting Path object or path string, got {path!r}")
        with Path(path).open(mode="rb") as f:
            return cls(**cls.bin_format.parse_stream(f))

    def dumps(self) -> bytes:
        private_key = self.private_key.export_key("DER") if self.private_key else None
        return self.bin_format.build(dict(
            version=2,
            type=self.type.value,
            security_level=self.security_level,
            flags=self.flags,
            private_key_len=len(private_key) if private_key else 0,
            private_key=private_key,
            client_id_len=len(self.client_id.SerializeToString()) if self.client_id else 0,
            client_id=self.client_id.SerializeToString() if self.client_id else None
        ))

    def dump(self, path: Union[Path, str]) -> None:
        if not isinstance(path, (Path, str)):
            raise ValueError(f"Expecting Path object or path string, got {path!r}")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.dumps())


__ALL__ = (Device,)
