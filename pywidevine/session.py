from typing import Optional

from Crypto.Random import get_random_bytes

from pywidevine.key import Key
from pywidevine.license_protocol_pb2 import SignedDrmCertificate


class Session:
    def __init__(self, number: int):
        self.number = number
        self.id = get_random_bytes(16)
        self.service_certificate: Optional[SignedDrmCertificate] = None
        self.context: dict[bytes, tuple[bytes, bytes]] = {}
        self.keys: list[Key] = []


__all__ = ("Session",)
