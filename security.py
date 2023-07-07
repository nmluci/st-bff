from __future__ import annotations
from typing import Dict, List, Any
from flask import Request

from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from datetime import datetime
import os
import base64
import uuid


@dataclass
class SecuredPayload:
    payload: str
    iv: str
    key: str

    def toJSON(self):
        return {"payload": self.payload, "iv": self.iv}


def encrypt_payload(payload: str) -> SecuredPayload:
    req_uuid = str(uuid.uuid4())

    iv = os.urandom(16)
    key = req_uuid.replace("-", "")

    cipher = Cipher(algorithms.AES256(key.encode("utf-8")), mode=modes.CBC(iv))
    enc = cipher.encryptor()
    padder = PKCS7(128).padder()

    data_pad = padder.update(payload.encode('utf-8')) + padder.finalize()
    ct = enc.update(data_pad) + enc.finalize()

    return SecuredPayload(
        payload=base64.b64encode(ct).decode("utf-8"),
        iv=base64.b64encode(iv).decode("utf-8"),
        key=key,
    )


def decrypt_payload(payload: SecuredPayload) -> bytes:
    cipher = Cipher(
        algorithms.AES256(payload.key.encode("utf-8")),
        mode=modes.CBC(base64.b64decode(payload.iv.encode('utf-8'))),
    )
    dec = cipher.decryptor()
    pt = dec.update(base64.b64decode(payload.payload.encode('utf-8'))) + dec.finalize()

    unpadder = PKCS7(128).unpadder()
    data_unpad = unpadder.update(pt) + unpadder.finalize()

    return data_unpad
