"""
Unit test RSA
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from rsa import rsa_generate_keys, rsa_decrypt, rsa_encrypt, string_to_int, int_to_string

class TestRSA(unittest.TestCase):
    def test_rsa(self):
        public_key, private_key = rsa_generate_keys(10)
        mesaj = 123
        cipher = rsa_encrypt(mesaj, public_key)

        self.assertEqual(mesaj, rsa_decrypt(cipher, private_key))

    def test_rsa_wrong_key(self):
        public_key1, _ = rsa_generate_keys(10)
        _, private_key2 = rsa_generate_keys(10)

        mesaj = 123
        cipher = rsa_encrypt(mesaj, public_key1)

        self.assertNotEqual(mesaj, rsa_decrypt(cipher, private_key2))

    def test_string_to_int(self):
        initial_string = "a"
        int_value = string_to_int(initial_string)

        self.assertEqual(int_value, 97)

    def test_int_to_string(self):
        int_value = 97
        char_value = int_to_string(int_value)

        self.assertEqual(char_value, 'a')

if __name__ == "__main__":
    unittest.main()