import helpers  # noqa: F401  先注入 src 路径
import unittest

from pman import crypto


class CryptoTest(unittest.TestCase):
    def test_roundtrip(self):
        key = bytes(range(32))
        pt = "秘密数据secret".encode("utf-8")
        self.assertEqual(crypto.decrypt(key, crypto.encrypt(key, pt)), pt)

    def test_wrong_key_fails(self):
        k1 = bytes(range(32))
        k2 = bytes(reversed(range(32)))
        ct = crypto.encrypt(k1, b"data")
        with self.assertRaises(Exception):
            crypto.decrypt(k2, ct)

    def test_tampered_ciphertext_fails(self):
        key = bytes(range(32))
        ct = bytearray(crypto.encrypt(key, b"data"))
        ct[15] ^= 0xFF
        with self.assertRaises(Exception):
            crypto.decrypt(key, bytes(ct))

    def test_kdf_deterministic_and_sensitive(self):
        self.assertEqual(crypto.derive_kek("pw", b"salt"), crypto.derive_kek("pw", b"salt"))
        self.assertNotEqual(crypto.derive_kek("pw", b"salt"), crypto.derive_kek("pw2", b"salt"))
        self.assertEqual(len(crypto.derive_kek("pw", b"salt")), 32)


if __name__ == "__main__":
    unittest.main()
