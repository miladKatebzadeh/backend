import base64
import hashlib
import hmac
import os

PREFIX = 'enc:v1:'


def _key() -> bytes:
    from django.conf import settings
    return hashlib.sha256(b'opshub-setting-v1:' + settings.SECRET_KEY.encode()).digest()


def _stream(key: bytes, nonce: bytes, length: int) -> bytes:
    chunks = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) < length:
        chunks.append(hmac.new(key, nonce + counter.to_bytes(4, 'big'), hashlib.sha256).digest())
        counter += 1
    return b''.join(chunks)[:length]


def encrypt_secret(value: str) -> str:
    if not value:
        return ''
    if value.startswith(PREFIX):
        return value
    raw = value.encode()
    nonce = os.urandom(16)
    key = _key()
    cipher = bytes(left ^ right for left, right in zip(raw, _stream(key, nonce, len(raw))))
    mac = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    return PREFIX + base64.urlsafe_b64encode(nonce + mac + cipher).decode()


def decrypt_secret(value: str) -> str:
    if not value or not value.startswith(PREFIX):
        return value
    try:
        blob = base64.urlsafe_b64decode(value[len(PREFIX):].encode())
        nonce, mac, cipher = blob[:16], blob[16:48], blob[48:]
        key = _key()
        expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            return ''
        plain = bytes(left ^ right for left, right in zip(cipher, _stream(key, nonce, len(cipher))))
        return plain.decode()
    except Exception:
        return ''
