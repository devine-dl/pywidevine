from __future__ import annotations

import base64
import binascii
import string
from typing import Union, Optional
from uuid import UUID

import construct
from construct import Container
from google.protobuf.message import DecodeError
from lxml import etree
from pymp4.parser import Box

from pywidevine.license_protocol_pb2 import WidevinePsshData


class PSSH:
    """PSSH-related utilities. Somewhat Widevine-biased."""

    class SystemId:
        Widevine = UUID(bytes=b"\xed\xef\x8b\xa9\x79\xd6\x4a\xce\xa3\xc8\x27\xdc\xd5\x1d\x21\xed")
        PlayReady = UUID(bytes=b"\x9a\x04\xf0\x79\x98\x40\x42\x86\xab\x92\xe6\x5b\xe0\x88\x5f\x95")

    def __init__(self, data: Union[Container, str, bytes], strict: bool = False):
        """
        Load a PSSH box or Widevine Cenc Header data as a new v0 PSSH box.

        [Strict mode (strict=True)]

        Supports the following forms of input data in either Base64 or Bytes form:
        - Full PSSH mp4 boxes (as defined by pymp4 Box).
        - Full Widevine Cenc Headers (as defined by WidevinePsshData proto).

        [Lenient mode (strict=False, default)]

        If the data is not supported in Strict mode, and is assumed not to be corrupt or
        parsed incorrectly, the License Server likely accepts a custom init_data value
        during a License Request call. This is uncommon behavior but not out of realm of
        possibilities. For example, Netflix does this with it's MSL WidevineExchange
        scheme.

        Lenient mode will craft a new v0 PSSH box with the init_data field set to
        the provided data as-is. The data will first be base64 decoded. This behavior
        may not work in your scenario and if that's the case please manually craft
        your own PSSH box with the init_data field to be used in License Requests.

        Raises:
            ValueError: If the data is empty.
            TypeError: If the data is an unexpected type.
            binascii.Error: If the data could not be decoded as Base64 if provided as a
                string.
            DecodeError: If the data could not be parsed as a PSSH mp4 box nor a Widevine
                Cenc Header and strict mode is enabled.
        """
        if not data:
            raise ValueError("Data must not be empty.")

        if isinstance(data, Container):
            box = data
        else:
            if isinstance(data, str):
                try:
                    data = base64.b64decode(data)
                except (binascii.Error, binascii.Incomplete) as e:
                    raise binascii.Error(f"Could not decode data as Base64, {e}")

            if not isinstance(data, bytes):
                raise TypeError(f"Expected data to be a {Container}, bytes, or base64, not {data!r}")

            try:
                box = Box.parse(data)
            except (IOError, construct.ConstructError):  # not a box
                try:
                    cenc_header = WidevinePsshData()
                    cenc_header.ParseFromString(data)
                    cenc_header = cenc_header.SerializeToString()
                    if cenc_header != data:  # not actually a WidevinePsshData
                        raise DecodeError()
                except DecodeError:  # not a widevine cenc header
                    if strict:
                        raise DecodeError(f"Could not parse data as a {Container} nor a {WidevinePsshData}.")
                    # Data is not a Widevine Cenc Header, it's something custom.
                    # The license server likely has something custom to parse it.
                    # See doc-string about Lenient mode for more information.
                    cenc_header = data

                box = Box.parse(Box.build(dict(
                    type=b"pssh",
                    version=0,
                    flags=0,
                    system_ID=PSSH.SystemId.Widevine,
                    init_data=cenc_header
                )))

        self.version = box.version
        self.flags = box.flags
        self.system_id = box.system_ID
        self.key_ids = box.key_IDs
        self.init_data = box.init_data

    @classmethod
    def new(
        cls,
        key_ids: Optional[list[Union[UUID, str, bytes]]] = None,
        init_data: Optional[Union[WidevinePsshData, str, bytes]] = None,
        version: int = 0,
        flags: int = 0
    ) -> PSSH:
        """Craft a new version 0 or 1 PSSH Box."""
        if key_ids is not None:
            if not isinstance(key_ids, list):
                raise TypeError(f"Expected key_ids to be a list not {key_ids!r}")

        if init_data is not None:
            if not isinstance(init_data, (WidevinePsshData, str, bytes)):
                raise TypeError(f"Expected init_data to be a {WidevinePsshData}, base64, or bytes, not {init_data!r}")

        if not isinstance(version, int):
            raise TypeError(f"Expected version to be an int not {version!r}")
        if version not in (0, 1):
            raise ValueError(f"Invalid version, must be either 0 or 1, not {version}.")

        if not isinstance(flags, int):
            raise TypeError(f"Expected flags to be an int not {flags!r}")
        if flags < 0:
            raise ValueError(f"Invalid flags, cannot be less than 0.")

        if version == 0 and key_ids is not None and init_data is not None:
            # v0 boxes use only init_data in the pssh field, but we can use the key_ids within the init_data
            raise ValueError("Version 0 PSSH boxes must use only init_data, not init_data and key_ids.")
        elif version == 1:
            # TODO: I cannot tell if they need either init_data or key_ids exclusively, or both is fine
            #       So for now I will just make sure at least one is supplied
            if init_data is None and key_ids is None:
                raise ValueError("Version 1 PSSH boxes must use either init_data or key_ids but neither were provided")

        if key_ids is not None:
            # ensure key_ids are bytes, supports hex, base64, and bytes
            key_ids = [
                (
                    x.bytes if isinstance(x, UUID) else
                    bytes.fromhex(x) if all(c in string.hexdigits for c in x) else
                    base64.b64decode(x) if isinstance(x, str) else
                    x
                )
                for x in key_ids
            ]
            if not all(isinstance(x, bytes) for x in key_ids):
                not_bytes = [x for x in key_ids if not isinstance(x, bytes)]
                raise TypeError(
                    "Expected all of key_ids to be a UUID, hex, base64, or bytes, but one or more are not, "
                    f"{not_bytes!r}"
                )

        if init_data is not None:
            if isinstance(init_data, WidevinePsshData):
                init_data = init_data.SerializeToString()
            elif isinstance(init_data, str):
                if all(c in string.hexdigits for c in init_data):
                    init_data = bytes.fromhex(init_data)
                else:
                    init_data = base64.b64decode(init_data)
            elif not isinstance(init_data, bytes):
                raise TypeError(
                    f"Expecting init_data to be {WidevinePsshData}, hex, base64, or bytes, not {init_data!r}"
                )

        box = Box.parse(Box.build(dict(
            type=b"pssh",
            version=version,
            flags=flags,
            system_ID=PSSH.SystemId.Widevine,
            key_ids=[key_ids, b""][key_ids is None],
            init_data=[init_data, b""][init_data is None]
        )))

        if key_ids and version == 0:
            PSSH.overwrite_key_ids(box, [UUID(bytes=x) for x in key_ids])

        return cls(box)

    @classmethod
    def from_playready_pssh(cls, box: Container) -> PSSH:
        """
        Convert a PlayReady PSSH Box to a Widevine PSSH Box.

        Note: The resulting Widevine PSSH will likely not be usable for Licensing. This
        is because there is some data for a Widevine Cenc Header that is missing from a
        PlayReady PSSH Box.

        This converted PSSH will only be useful for it's Key IDs, so realistically only
        for matching Key IDs with a Track. As a fallback.
        """
        if box.type != b"pssh":
            raise ValueError(f"Box must be a PSSH box, not {box.type}")
        if box.system_ID != PSSH.SystemId.PlayReady:
            raise ValueError(f"This is not a PlayReady PSSH Box, {box.system_ID}")

        key_ids = PSSH.get_key_ids(box)

        cenc_header = WidevinePsshData()
        cenc_header.algorithm = 1  # 0=Clear, 1=AES-CTR

        for key_id in key_ids:
            cenc_header.key_ids.append(key_id.bytes)
        if box.version == 1:
            # ensure both cenc header and box has same Key IDs
            # v1 uses both this and within init data for basically no reason
            box.key_IDs = key_ids

        box.init_data = cenc_header.SerializeToString()
        box.system_ID = PSSH.SystemId.Widevine

        return cls(box)

    def dump(self) -> bytes:
        """Export the PSSH object as a full PSSH box in bytes form."""
        return Box.build(dict(
            type=b"pssh",
            version=self.version,
            flags=self.flags,
            system_ID=self.system_id,
            key_IDs=self.key_ids,
            init_data=self.init_data
        ))

    def dumps(self) -> str:
        """Export the PSSH object as a full PSSH box in base64 form."""
        return base64.b64encode(self.dump()).decode()

    @staticmethod
    def get_key_ids(box: Container) -> list[UUID]:
        """
        Get Key IDs from a PSSH Box from within the Box or Init Data where possible.

        Supports:
        - Version 1 Boxes
        - Widevine Headers
        - PlayReady Headers (4.0.0.0->4.3.0.0)
        """
        if box.version == 1 and box.key_IDs:
            return box.key_IDs

        if box.system_ID == PSSH.SystemId.Widevine:
            init = WidevinePsshData()
            init.ParseFromString(box.init_data)
            return [
                # the key_ids value may or may not be hex underlying
                UUID(bytes=key_id) if len(key_id) == 16 else UUID(hex=key_id.decode())
                for key_id in init.key_ids
            ]

        if box.system_ID == PSSH.SystemId.PlayReady:
            xml_string = box.init_data.decode("utf-16-le")
            # some of these init data has garbage(?) in front of it
            xml_string = xml_string[xml_string.index("<"):]
            xml = etree.fromstring(xml_string)
            header_version = xml.attrib["version"]
            if header_version == "4.0.0.0":
                key_ids = xml.xpath("DATA/KID/text()")
            elif header_version == "4.1.0.0":
                key_ids = xml.xpath("DATA/PROTECTINFO/KID/@VALUE")
            elif header_version in ("4.2.0.0", "4.3.0.0"):
                key_ids = xml.xpath("DATA/PROTECTINFO/KIDS/KID/@VALUE")
            else:
                raise ValueError(f"Unsupported PlayReady header version {header_version}")
            return [
                UUID(bytes=base64.b64decode(key_id))
                for key_id in key_ids
            ]

        raise ValueError(f"Unsupported Box {box!r}")

    @staticmethod
    def overwrite_key_ids(box: Container, key_ids: list[UUID]) -> Container:
        """Overwrite all Key IDs in PSSH box with the specified Key IDs."""
        if box.system_ID != PSSH.SystemId.Widevine:
            raise ValueError(f"Only Widevine PSSH Boxes are supported, not {box.system_ID}.")

        if box.version == 1 or box.key_IDs:
            # only use key_IDs if version is 1, or it's already being used
            # this is in case the service stupidly expects it for version 0
            box.key_IDs = key_ids

        init = WidevinePsshData()
        init.ParseFromString(box.init_data)

        init.key_ids[:] = [
            key_id.bytes
            for key_id in key_ids
        ]

        box.init_data = init.SerializeToString()

        return box
