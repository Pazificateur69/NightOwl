"""Cryptographic utility helpers."""

import base64
import hashlib
import secrets
import string


def generate_random_string(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def hash_string(s: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    h.update(s.encode())
    return h.hexdigest()


def base64_encode(data: str) -> str:
    return base64.b64encode(data.encode()).decode()


def base64_decode(data: str) -> str:
    return base64.b64decode(data.encode()).decode()


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()
