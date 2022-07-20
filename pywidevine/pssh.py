from __future__ import annotations

import base64
from typing import Union
from uuid import UUID

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

    def __init__(self, box: Container):
        self._box = box

    @staticmethod
    def from_init_data(init_data: Union[str, bytes, WidevinePsshData]) -> Container:
        """Craft a new PSSH Box from just Widevine PSSH Data (init data)."""
        if isinstance(init_data, str):
            init_data = base64.b64decode(init_data)
        if isinstance(init_data, bytes):
            cenc_header = WidevinePsshData()
            cenc_header.ParseFromString(init_data)
            init_data = cenc_header
        if not isinstance(init_data, WidevinePsshData):
            raise ValueError(f"Unexpected value for init_data, {init_data!r}")

        box = Box.parse(Box.build(dict(
            type=b"pssh",
            version=0,
            flags=0,
            system_ID=PSSH.SystemId.Widevine,
            init_data=init_data.SerializeToString()
        )))

        return box

    @staticmethod
    def from_playready_pssh(box: Container) -> Container:
        """
        Convert a PlayReady PSSH to a Widevine PSSH.

        Note: The resulting Widevine PSSH will likely not be usable for Licensing. This
        is because there is some data for a Widevine CENC Header that is not going to be
        listed in a PlayReady PSSH.

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
            cenc_header.key_id.append(key_id.bytes)
        if box.version == 1:
            # ensure both cenc header and box has same Key IDs
            # v1 uses both this and within init data for basically no reason
            box.key_IDs = key_ids

        box.init_data = cenc_header.SerializeToString()
        box.system_ID = PSSH.SystemId.Widevine

        return box

    @staticmethod
    def from_key_ids(key_ids: list[UUID]) -> Container:
        """
        Craft a new PSSH Box from just Key IDs.
        This should only be used as a very last measure.
        """
        cenc_header = WidevinePsshData()
        for key_id in key_ids:
            cenc_header.key_id.append(key_id.bytes)
        cenc_header.algorithm = 1  # 0=Clear, 1=AES-CTR

        box = Box.parse(Box.build(dict(
            type=b"pssh",
            version=0,
            flags=0,
            system_ID=PSSH.SystemId.Widevine,
            init_data=cenc_header.SerializeToString()
        )))

        return box

    @staticmethod
    def get_as_box(data: Union[Container, bytes, str]) -> Container:
        """
        Get the possibly arbitrary data as a parsed PSSH mp4 box.
        If the data is just Widevine PSSH Data (init data) then it will be crafted
        into a new PSSH mp4 box.
        If the data could not be recognized as a PSSH box of some form of encoding
        it will raise a ValueError.
        """
        if isinstance(data, str):
            data = base64.b64decode(data)
        if isinstance(data, bytes):
            if base64.b64encode(data) == b"CAES":  # likely widevine pssh data
                try:
                    cenc_header = WidevinePsshData()
                    cenc_header.ParseFromString(data)
                except DecodeError:
                    # not actually init data after all
                    pass
                else:
                    data = Box.parse(Box.build(dict(
                        type=b"pssh",
                        version=0,
                        flags=0,
                        system_ID=PSSH.SystemId.Widevine,
                        init_data=cenc_header.SerializeToString()
                    )))
            data = Box.parse(data)
        if isinstance(data, Container):
            return data
        raise ValueError(f"Unrecognized PSSH data: {data!r}")

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
                for key_id in init.key_id
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

        # TODO: Is there a better way to clear the Key IDs?
        for _ in range(len(init.key_id or [])):
            init.key_id.pop(0)

        # TODO: Is there a .extend or a way to add all without a loop?
        for key_id in key_ids:
            init.key_id.append(key_id.bytes)

        box.init_data = init.SerializeToString()

        return box
