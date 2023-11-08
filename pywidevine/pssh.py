from __future__ import annotations

import base64
import binascii
import string
from io import BytesIO
from typing import Optional, Union
from uuid import UUID
from xml.etree.ElementTree import XML

import construct
from construct import Container
from google.protobuf.message import DecodeError
from pymp4.parser import Box

from pywidevine.license_protocol_pb2 import WidevinePsshData


class PSSH:
    """
    MP4 PSSH Box-related utilities.
    Allows you to load, create, and modify various kinds of DRM system headers.
    """

    class SystemId:
        Widevine = UUID(hex="edef8ba979d64acea3c827dcd51d21ed")
        PlayReady = UUID(hex="9a04f07998404286ab92e65be0885f95")

    def __init__(self, data: Union[Container, str, bytes], strict: bool = False):
        """
        Load a PSSH box, WidevineCencHeader, or PlayReadyHeader.

        When loading a WidevineCencHeader or PlayReadyHeader, a new v0 PSSH box will be
        created and the header will be parsed and stored in the init_data field. However,
        PlayReadyHeaders (and PlayReadyObjects) are not yet currently parsed and are
        stored as bytes.

        [Strict mode (strict=True)]

        Supports the following forms of input data in either Base64 or Bytes form:
        - Full PSSH mp4 boxes (as defined by pymp4 Box).
        - Full Widevine Cenc Headers (as defined by WidevinePsshData proto).
        - Full PlayReady Objects and Headers (as defined by Microsoft Docs).

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
                    widevine_pssh_data = WidevinePsshData()
                    widevine_pssh_data.ParseFromString(data)
                    data_serialized = widevine_pssh_data.SerializeToString()
                    if data_serialized != data:  # not actually a WidevinePsshData
                        raise DecodeError()
                    box = Box.parse(Box.build(dict(
                        type=b"pssh",
                        version=0,
                        flags=0,
                        system_ID=PSSH.SystemId.Widevine,
                        init_data=data_serialized
                    )))
                except DecodeError:  # not a widevine cenc header
                    if "</WRMHEADER>".encode("utf-16-le") in data:
                        # TODO: Actually parse `data` as a PlayReadyHeader object and store that instead
                        box = Box.parse(Box.build(dict(
                            type=b"pssh",
                            version=0,
                            flags=0,
                            system_ID=PSSH.SystemId.PlayReady,
                            init_data=data
                        )))
                    elif strict:
                        raise DecodeError(f"Could not parse data as a {Container} nor a {WidevinePsshData}.")
                    else:
                        # Data is not a WidevineCencHeader nor a PlayReadyHeader.
                        # The license server likely has something custom to parse it.
                        # See doc-string about Lenient mode for more information.
                        box = Box.parse(Box.build(dict(
                            type=b"pssh",
                            version=0,
                            flags=0,
                            system_ID=PSSH.SystemId.Widevine,
                            init_data=data
                        )))

        self.version = box.version
        self.flags = box.flags
        self.system_id = box.system_ID
        self.__key_ids = box.key_IDs
        self.init_data = box.init_data

    def __repr__(self) -> str:
        return f"PSSH<{self.system_id}>(v{self.version}; {self.flags}, {self.key_ids}, {self.init_data})"

    def __str__(self) -> str:
        return self.dumps()

    @classmethod
    def new(
        cls,
        system_id: UUID,
        key_ids: Optional[list[Union[UUID, str, bytes]]] = None,
        init_data: Optional[Union[WidevinePsshData, str, bytes]] = None,
        version: int = 0,
        flags: int = 0
    ) -> PSSH:
        """Craft a new version 0 or 1 PSSH Box."""
        if not system_id:
            raise ValueError("A System ID must be specified.")
        if not isinstance(system_id, UUID):
            raise TypeError(f"Expected system_id to be a UUID, not {system_id!r}")

        if key_ids is not None and not isinstance(key_ids, list):
            raise TypeError(f"Expected key_ids to be a list not {key_ids!r}")

        if init_data is not None and not isinstance(init_data, (WidevinePsshData, str, bytes)):
            raise TypeError(f"Expected init_data to be a {WidevinePsshData}, base64, or bytes, not {init_data!r}")

        if not isinstance(version, int):
            raise TypeError(f"Expected version to be an int not {version!r}")
        if version not in (0, 1):
            raise ValueError(f"Invalid version, must be either 0 or 1, not {version}.")

        if not isinstance(flags, int):
            raise TypeError(f"Expected flags to be an int not {flags!r}")
        if flags < 0:
            raise ValueError("Invalid flags, cannot be less than 0.")

        if version == 0 and key_ids is not None and init_data is not None:
            # v0 boxes use only init_data in the pssh field, but we can use the key_ids within the init_data
            raise ValueError("Version 0 PSSH boxes must use only init_data, not init_data and key_ids.")
        elif version == 1:
            # TODO: I cannot tell if they need either init_data or key_ids exclusively, or both is fine
            #       So for now I will just make sure at least one is supplied
            if init_data is None and key_ids is None:
                raise ValueError("Version 1 PSSH boxes must use either init_data or key_ids but neither were provided")

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

        pssh = cls(Box.parse(Box.build(dict(
            type=b"pssh",
            version=version,
            flags=flags,
            system_ID=system_id,
            init_data=[init_data, b""][init_data is None]
            # key_IDs should not be set yet
        ))))

        if key_ids:
            # We must reinforce the version because pymp4 forces v0 if key_IDs is not set.
            # The set_key_ids() func will set it efficiently in both init_data and the box where needed.
            # The version must be reinforced ONLY if we have key_id data or there's a possibility of making
            # a v1 PSSH box, that did not have key_IDs set in the PSSH box.
            pssh.version = version
            pssh.set_key_ids(key_ids)

        return pssh

    @property
    def key_ids(self) -> list[UUID]:
        """
        Get all Key IDs from within the Box or Init Data, wherever possible.

        Supports:
        - Version 1 PSSH Boxes
        - WidevineCencHeaders
        - PlayReadyHeaders (4.0.0.0->4.3.0.0)
        """
        if self.version == 1 and self.__key_ids:
            return self.__key_ids

        if self.system_id == PSSH.SystemId.Widevine:
            # TODO: What if its not a Widevine Cenc Header but the System ID is set as Widevine?
            cenc_header = WidevinePsshData()
            cenc_header.ParseFromString(self.init_data)
            return [
                # the key_ids value may or may not be hex underlying
                (
                    UUID(bytes=key_id) if len(key_id) == 16 else  # normal
                    UUID(hex=key_id.decode()) if len(key_id) == 32 else  # stored as hex
                    UUID(int=int.from_bytes(key_id, "big"))  # assuming as number
                )
                for key_id in cenc_header.key_ids
            ]

        if self.system_id == PSSH.SystemId.PlayReady:
            # Assuming init data is a PRO (PlayReadyObject)
            # https://learn.microsoft.com/en-us/playready/specifications/playready-header-specification
            pro_data = BytesIO(self.init_data)
            pro_length = int.from_bytes(pro_data.read(4), "little")
            if pro_length != len(self.init_data):
                raise ValueError("The PlayReadyObject seems to be corrupt (too big or small, or missing data).")
            pro_record_count = int.from_bytes(pro_data.read(2), "little")

            for _ in range(pro_record_count):
                prr_type = int.from_bytes(pro_data.read(2), "little")
                prr_length = int.from_bytes(pro_data.read(2), "little")
                prr_value = pro_data.read(prr_length)
                if prr_type != 0x01:
                    # No PlayReady Header, skip and hope for something else
                    # TODO: Add support for Embedded License Stores (0x03)
                    continue

                wrm_ns = {"wrm": "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader"}
                prr_header = XML(prr_value.decode("utf-16-le"))
                prr_header_version = prr_header.get("version")
                if prr_header_version == "4.0.0.0":
                    key_ids = [
                        x.text
                        for x in prr_header.findall("./wrm:DATA/wrm:KID", wrm_ns)
                        if x.text
                    ]
                elif prr_header_version == "4.1.0.0":
                    key_ids = [
                        x.attrib["VALUE"]
                        for x in prr_header.findall("./wrm:DATA/wrm:PROTECTINFO/wrm:KID", wrm_ns)
                    ]
                elif prr_header_version in ("4.2.0.0", "4.3.0.0"):
                    # TODO: Retain the Encryption Scheme information in v4.3.0.0
                    #       This is because some Key IDs can be AES-CTR while some are AES-CBC.
                    #       Conversion to WidevineCencHeader could use this information.
                    key_ids = [
                        x.attrib["VALUE"]
                        for x in prr_header.findall("./wrm:DATA/wrm:PROTECTINFO/wrm:KIDS/wrm:KID", wrm_ns)
                    ]
                else:
                    raise ValueError(f"Unsupported PlayReadyHeader version {prr_header_version}")

                return [
                    UUID(bytes=base64.b64decode(key_id))
                    for key_id in key_ids
                ]

            raise ValueError("Unsupported PlayReadyObject, no PlayReadyHeader within the object.")

        raise ValueError(f"This PSSH is not supported by key_ids() property, {self.dumps()}")

    def dump(self) -> bytes:
        """Export the PSSH object as a full PSSH box in bytes form."""
        return Box.build(dict(
            type=b"pssh",
            version=self.version,
            flags=self.flags,
            system_ID=self.system_id,
            key_IDs=self.key_ids if self.version == 1 and self.key_ids else None,
            init_data=self.init_data
        ))

    def dumps(self) -> str:
        """Export the PSSH object as a full PSSH box in base64 form."""
        return base64.b64encode(self.dump()).decode()

    def to_widevine(self) -> None:
        """
        Convert PlayReady PSSH data to Widevine PSSH data.

        There's only a limited amount of information within a PlayReady PSSH header that
        can be used in a Widevine PSSH Header. The converted data may or may not result
        in an accepted PSSH. It depends on what the License Server is expecting.
        """
        if self.system_id == PSSH.SystemId.Widevine:
            raise ValueError("This is already a Widevine PSSH")

        widevine_pssh_data = WidevinePsshData(
            key_ids=[x.bytes for x in self.key_ids],
            algorithm="AESCTR"
        )

        if self.version == 1:
            # ensure both cenc header and box has same Key IDs
            # v1 uses both this and within init data for basically no reason
            self.__key_ids = self.key_ids

        self.init_data = widevine_pssh_data.SerializeToString()
        self.system_id = PSSH.SystemId.Widevine

    def to_playready(
        self,
        la_url: Optional[str] = None,
        lui_url: Optional[str] = None,
        ds_id: Optional[bytes] = None,
        decryptor_setup: Optional[str] = None,
        custom_data: Optional[str] = None
    ) -> None:
        """
        Convert Widevine PSSH data to PlayReady v4.3.0.0 PSSH data.

        Note that it is impossible to create the CHECKSUM values for AES-CTR Key IDs
        as you must encrypt the Key ID with the Content Encryption Key using AES-ECB.
        This may cause software incompatibilities.

        Parameters:
            la_url: Contains the URL for the license acquisition Web service.
                Only absolute URLs are allowed.
            lui_url: Contains the URL for the license acquisition Web service.
                Only absolute URLs are allowed.
            ds_id: Service ID for the domain service.
            decryptor_setup: This tag may only contain the value "ONDEMAND". It
                indicates to an application that it should not expect the full
                license chain for the content to be available for acquisition, or
                already present on the client machine, prior to setting up the
                media graph. If this tag is not set then it indicates that an
                application can enforce the license to be acquired, or already
                present on the client machine, prior to setting up the media graph.
            custom_data: The content author can add custom XML inside this
                element. Microsoft code does not act on any data contained inside
                this element. The Syntax of this params XML is not validated.
        """
        if self.system_id == PSSH.SystemId.PlayReady:
            raise ValueError("This is already a PlayReady PSSH")

        key_ids_xml = ""
        for key_id in self.key_ids:
            # Note that it's impossible to create the CHECKSUM value without the Key for the KID
            key_ids_xml += f"""
            <KID ALGID="AESCTR" VALUE="{base64.b64encode(key_id.bytes).decode()}"></KID>
            """

        prr_value = f"""
        <WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.3.0.0">
            <DATA>
                <PROTECTINFO>
                    <KIDS>{key_ids_xml}</KIDS>
                </PROTECTINFO>
                {'<LA_URL>%s</LA_URL>' % la_url if la_url else ''}
                {'<LUI_URL>%s</LUI_URL>' % lui_url if lui_url else ''}
                {'<DS_ID>%s</DS_ID>' % base64.b64encode(ds_id).decode() if ds_id else ''}
                {'<DECRYPTORSETUP>%s</DECRYPTORSETUP>' % decryptor_setup if decryptor_setup else ''}
                {'<CUSTOMATTRIBUTES xmlns="">%s</CUSTOMATTRIBUTES>' % custom_data if custom_data else ''}
            </DATA>
        </WRMHEADER>
        """.encode("utf-16-le")

        prr_length = len(prr_value).to_bytes(2, "little")
        prr_type = (1).to_bytes(2, "little")  # Has PlayReadyHeader
        pro_record_count = (1).to_bytes(2, "little")
        pro = pro_record_count + prr_type + prr_length + prr_value
        pro = (len(pro) + 4).to_bytes(4, "little") + pro

        self.init_data = pro
        self.system_id = PSSH.SystemId.PlayReady

    def set_key_ids(self, key_ids: list[Union[UUID, str, bytes]]) -> None:
        """Overwrite all Key IDs with the specified Key IDs."""
        if self.system_id != PSSH.SystemId.Widevine:
            # TODO: Add support for setting the Key IDs in a PlayReady Header
            raise ValueError(f"Only Widevine PSSH Boxes are supported, not {self.system_id}.")

        key_id_uuids = self.parse_key_ids(key_ids)

        if self.version == 1 or self.__key_ids:
            # only use v1 box key_ids if version is 1, or it's already being used
            # this is in case the service stupidly expects it for version 0
            self.__key_ids = key_id_uuids

        cenc_header = WidevinePsshData()
        cenc_header.ParseFromString(self.init_data)

        cenc_header.key_ids[:] = [
            key_id.bytes
            for key_id in key_id_uuids
        ]

        self.init_data = cenc_header.SerializeToString()

    @staticmethod
    def parse_key_ids(key_ids: list[Union[UUID, str, bytes]]) -> list[UUID]:
        """
        Parse a list of Key IDs in hex, base64, or bytes to UUIDs.

        Raises TypeError if `key_ids` is not a list, or the list contains one
        or more items that are not a UUID, str, or bytes object.
        """
        if not isinstance(key_ids, list):
            raise TypeError(f"Expected key_ids to be a list, not {key_ids!r}")

        if not all(isinstance(x, (UUID, str, bytes)) for x in key_ids):
            raise TypeError("Some items of key_ids are not a UUID, str, or bytes. Unsure how to continue...")

        uuids = [
            UUID(bytes=key_id_b)
            for key_id in key_ids
            for key_id_b in [
                key_id.bytes if isinstance(key_id, UUID) else
                (
                    bytes.fromhex(key_id) if all(c in string.hexdigits for c in key_id) else
                    base64.b64decode(key_id)
                ) if isinstance(key_id, str) else
                key_id
            ]
        ]

        return uuids


__all__ = ("PSSH",)
