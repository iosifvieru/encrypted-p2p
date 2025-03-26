"""
Unit test AES
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from aes import state_from_bytes, bytes_from_state, sub_word

class TestAES(unittest.TestCase):
    def test_state_from_bytes(self):
        test_data = bytearray.fromhex('000102030405060708090A0B0C0D0E0F')

        state = state_from_bytes(test_data)

        expected = [[0, 1, 2, 3], [4, 5, 6, 7],
                    [8, 9, 10, 11], [12, 13, 14, 15]]

        self.assertEqual(state, expected)

if __name__ == "__main__":
    unittest.main()