"""
Unit test AES
"""

import sys
import os

from aes.aes import from_byte_to_sbox, shift_rows, mix_columns, xTimes, mul_gf8, extract_column, multiply_column, \
    aes_encryption, key_expansion, add_round_key, bytes_from_state

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from aes import state_from_bytes, sub_bytes
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:%(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("AES Tests")

class TestAES(unittest.TestCase):
    def test_state_from_bytes(self):
        test_data = bytearray.fromhex('000102030405060708090A0B0C0D0E0F')

        state = state_from_bytes(test_data)
        expected = [[0, 4, 8, 12],
                    [1, 5, 9, 13],
                    [2, 6, 10, 14],
                    [3, 7, 11, 15]]

        self.assertEqual(state, expected)

    def test_from_byte_to_sbox(self):
        test_data = 243
        expected_res = 0x0D
        actual_res = from_byte_to_sbox(test_data)
        assert  expected_res == actual_res

    def test_sub_bytes(self):
        test_data = bytearray.fromhex('328831e0435a3137f6309807a88da234')
        state = state_from_bytes(test_data)
        res = sub_bytes(state)
        expectedRes = [
                    [35,  26,  66, 194],
                    [196, 190, 4,  93],
                    [199, 199, 70, 58],
                    [225, 154, 197, 24]]


        logger.info(f"Actual result for sub_bytes: {res}")
        logger.info(f"Expected result for sub_bytes: {expectedRes}")

        assert res == expectedRes

    def test_shift_rows(self):
        state = [
            [35, 26, 66, 194],
            [196, 190, 4, 93],
            [199, 199, 70, 58],
            [225, 154, 197, 24]]

        shifted = shift_rows(state)
        expected = [
            [35, 26, 66, 194],
            [190, 4, 93, 196],
            [70, 58, 199, 199],
            [24, 225, 154, 197]
        ]

        assert shifted == expected

    def test_xTimes(self):
        actualRes = xTimes(0x57)
        expectedRes = 0xae

        assert actualRes == expectedRes

    def test_mul_gf8_case1(self):
        actualRes = mul_gf8(0x57, 1)
        expectedRes = 0x57

        assert actualRes == expectedRes

    def test_mul_gf8_case2(self):
        actualRes = mul_gf8(0x57, 2)
        expectedRes = 0xae

        assert actualRes == expectedRes

        actualRes = mul_gf8(0x09, 2)
        expectedRes = 0x12

        assert actualRes == expectedRes


    def test_mul_gf8_case3(self):
        actualRes = mul_gf8(0x57, 3)
        expectedRes = 0xf9

        assert actualRes == expectedRes

    def test_extract_columns(self):
        state = [
            [35, 26, 66, 194],
            [196, 190, 4, 93],
            [199, 199, 70, 58],
            [225, 154, 197, 24]]

        column = extract_column(state, 0)
        expected_column = [35, 196, 199, 225]

        assert column == expected_column

    def test_multiply_column(self):
        col = [0xdb, 0x13, 0x53, 0x45]
        res_col = multiply_column(col)
        expected_res_col = [0x8e, 0x4d, 0xa1, 0xbc]

        assert res_col == expected_res_col

    def test_mix_columns(self):
        state = [
            [0xdb, 0xf2, 0x01, 0xc6],
            [0x13, 0x0a, 0x01, 0xc6],
            [0x53, 0x22, 0x01, 0xc6],
            [0x45, 0x5c, 0x01, 0xc6],
        ]

        res = mix_columns(state)
        expected = [
                    [142, 159, 1, 198],
                    [77, 220, 1, 198],
                    [161, 88, 1, 198],
                    [188, 157, 1, 198],
                ]

        logger.info(f"Actual result for mix_columns: {res}")
        logger.info(f"Expected result for mix_columns: {expected}")

        assert res == expected

    def test_key_expansion(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        expected_expansion = [
            [0, 1, 2, 3],
            [4, 5, 6, 7],
            [8, 9, 10, 11],
            [12, 13, 14, 15],
            [214, 170, 116, 253],
            [210, 175, 114, 250],
            [218, 166, 120, 241],
            [214, 171, 118, 254],
            [182, 146, 207, 11],
            [100, 61, 189, 241],
            [190, 155, 197, 0],
            [104, 48, 179, 254],
            [182, 255, 116, 78],
            [210, 194, 201, 191],
            [108, 89, 12, 191],
            [4, 105, 191, 65],
            [71, 247, 247, 188],
            [149, 53, 62, 3],
            [249, 108, 50, 188],
            [253, 5, 141, 253],
            [60, 170, 163, 232],
            [169, 159, 157, 235],
            [80, 243, 175, 87],
            [173, 246, 34, 170],
            [94, 57, 15, 125],
            [247, 166, 146, 150],
            [167, 85, 61, 193],
            [10, 163, 31, 107],
            [20, 249, 112, 26],
            [227, 95, 226, 140],
            [68, 10, 223, 77],
            [78, 169, 192, 38],
            [71, 67, 135, 53],
            [164, 28, 101, 185],
            [224, 22, 186, 244],
            [174, 191, 122, 210],
            [84, 153, 50, 209],
            [240, 133, 87, 104],
            [16, 147, 237, 156],
            [190, 44, 151, 78],
            [19, 17, 29, 127],
            [227, 148, 74, 23],
            [243, 7, 167, 139],
            [77, 43, 48, 197]
        ]

        result = key_expansion(key)
        self.assertEqual(result, expected_expansion)


    def test_add_round_key_basic(self):
        state = [
            [0x00, 0x01, 0x02, 0x03],
            [0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0A, 0x0B],
            [0x0C, 0x0D, 0x0E, 0x0F],
        ]

        round_key = [
            [0xFF, 0xFF, 0xFF, 0xFF],
            [0x00, 0x00, 0x00, 0x00],
            [0xAA, 0xAA, 0xAA, 0xAA],
            [0x11, 0x22, 0x33, 0x44],
        ]

        expected = [
            [0xFF, 0xFE, 0xFD, 0xFC],
            [0x04, 0x05, 0x06, 0x07],
            [0xA2, 0xA3, 0xA0, 0xA1],
            [0x1D, 0x2F, 0x3D, 0x4B],
        ]

        result = add_round_key(state, round_key)
        self.assertEqual(result, expected)

    def test_bytes_from_state(self):
        state = [
            [0x00, 0x04, 0x08, 0x0C],
            [0x01, 0x05, 0x09, 0x0D],
            [0x02, 0x06, 0x0A, 0x0E],
            [0x03, 0x07, 0x0B, 0x0F],
        ]

        expected = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        result = bytes_from_state(state)
        self.assertEqual(result, expected)

    def test_aes(self):
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        cipher = aes_encryption(plaintext, key)
        expected_cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        assert cipher == expected_cipher, f"Expected {expected_cipher.hex()}, got {cipher.hex()}"


if __name__ == "__main__":
    unittest.main()