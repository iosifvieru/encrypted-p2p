"""
Unit test RSA
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from rsa import rsa_generate_keys, rsa_decrypt, rsa_encrypt

class TestRSA(unittest.TestCase):
    def test_rsa(self):
        public_key, private_key = rsa_generate_keys(10)
        mesaj = 123
        cipher = rsa_encrypt(mesaj, public_key)

        self.assertEqual(123, rsa_decrypt(cipher, private_key))
