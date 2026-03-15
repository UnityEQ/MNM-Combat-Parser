"""
MnM packet decryption pipeline.

Wire format: [IV(16)] [AES-CBC ciphertext(N*16)] [HMAC-SHA256(32, optional)] [CRC32c(4)]

Decryption order (MnMEncryptionLayer.ProcessInboundPacket):
  1. CRC32c:  verify & strip last 4 bytes
  2. HMAC:    verify & strip last 32 bytes (if hmac_key present)
  3. AES-CBC: first 16 bytes = IV, decrypt remaining, PKCS7 unpad
  4. XOR:     XOR each byte with cycling key (if xor_key present)
  Result: plaintext LiteNetLib frame

Requires pycryptodome: pip install pycryptodome
"""

import hashlib
import hmac as hmac_mod
import struct

from Crypto.Cipher import AES


# ===========================================================================
# CRC32c (Castagnoli) — used by Crc32cLayer
# ===========================================================================

_CRC32C_TABLE = None


def _init_crc32c_table():
    global _CRC32C_TABLE
    if _CRC32C_TABLE is not None:
        return
    poly = 0x82F63B78
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        table.append(crc)
    _CRC32C_TABLE = table


def crc32c(data):
    """Compute CRC32c (Castagnoli) over data bytes."""
    _init_crc32c_table()
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ===========================================================================
# Layer operations
# ===========================================================================

def strip_crc32c(data):
    """Strip and verify 4-byte CRC32c from packet end. Returns (payload, verified)."""
    if len(data) < 5:
        return data, False
    payload = data[:-4]
    expected = struct.unpack_from("<I", data, len(data) - 4)[0]
    return payload, (expected == crc32c(payload))


def verify_and_strip_hmac(data, hmac_key):
    """Strip 32-byte HMAC-SHA256 from packet end. Returns (payload, verified)."""
    if len(data) < 33:
        return data, False
    msg = data[:-32]
    tag = data[-32:]
    expected = hmac_mod.new(hmac_key, msg, hashlib.sha256).digest()
    return msg, hmac_mod.compare_digest(tag, expected)


def aes_cbc_decrypt(data, aes_key):
    """
    AES-256-CBC decrypt with IV from first 16 bytes of data.
    Returns unpadded plaintext or None.
    """
    if len(data) < 32 or len(data) % 16 != 0:
        return None
    iv = data[:16]
    ct = data[16:]
    raw = AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(ct)
    return pkcs7_unpad(raw)


def xor_decrypt(data, xor_key):
    """XOR each byte with the corresponding key byte (cycling)."""
    if not xor_key:
        return data
    key_len = len(xor_key)
    return bytes(data[i] ^ xor_key[i % key_len] for i in range(len(data)))


def pkcs7_unpad(data):
    """Remove PKCS7 padding. Returns unpadded data or None if invalid."""
    if not data:
        return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return None
    if len(data) < pad_len:
        return None
    for i in range(pad_len):
        if data[-(i + 1)] != pad_len:
            return None
    return data[:-pad_len]


# ===========================================================================
# Full decryption pipeline
# ===========================================================================

class PacketDecryptor:
    """
    Decrypts MnM game packets.

    Wire format: [IV(16)] [AES-CBC ciphertext] [HMAC(32)?] [CRC32c(4)]
    """

    def __init__(self, aes_key, hmac_key=None, xor_key=None):
        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.xor_key = xor_key

    def decrypt(self, raw_payload, log=None):
        """
        Decrypt a raw UDP payload through the MnM encryption layers.
        Returns (plaintext, info) or (None, info).
        """
        data = raw_payload
        info = {}

        # Minimum size: IV(16) + 1 AES block(16) + CRC(4) = 36 bytes
        if len(data) < 36:
            return None, {"error": "too_short"}

        # 1. CRC32c — strip and verify last 4 bytes
        data, crc_ok = strip_crc32c(data)
        info["crc_verified"] = crc_ok
        if not crc_ok:
            return None, info

        # 2. HMAC — strip and verify last 32 bytes (if key present)
        if self.hmac_key and len(self.hmac_key) > 0:
            data, hmac_ok = verify_and_strip_hmac(data, self.hmac_key)
            info["hmac_verified"] = hmac_ok
            if not hmac_ok:
                if log:
                    log.debug("  HMAC verification failed")
                return None, info

        # 3. AES-CBC — first 16 bytes = IV, decrypt rest, PKCS7 unpad
        plaintext = aes_cbc_decrypt(data, self.aes_key)
        if plaintext is None:
            if log:
                log.debug(f"  AES-CBC decrypt/unpad failed (data={len(data)} bytes)")
            info["error"] = "aes_failed"
            return None, info

        # 4. XOR — decrypt with cycling key (if present)
        if self.xor_key and len(self.xor_key) > 0:
            plaintext = xor_decrypt(plaintext, self.xor_key)

        info["scheme"] = "CRC+AES-CBC+PKCS7"
        return plaintext, info
