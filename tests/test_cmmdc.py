"""
Unit Test CMMDC.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from crypto.rsa import alg_euclid_extins

class TestCMMDC(unittest.TestCase):
    """
    CMMDC dintre 126 si 180.

    126 | 2
    63  | 3
    21  | 3
    7   | 7
    1   | 1

    126 = 2 * 3^2 * 7

    180 | 2 * 5
    18  | 2
    9   | 3
    3   | 3
    1   | 1

    180 = 2^2 * 3^2 * 5

    cmmdc(126, 180) = 2 * 3^2 = 18
    """
    def test_cmmdc(self):
        result, _, _ = alg_euclid_extins(126, 180)
        self.assertEqual(result, 18)

    def test_cmmdc_prime_intre_ele(self):
        result, _, _ = alg_euclid_extins(12, 25)
        self.assertEqual(result, 1)

    def test_cmmdc_cu_O(self):
        result, _, _ = alg_euclid_extins(12, 0)
        self.assertEqual(result, 12)

    def test_cmmdc_nr_egale(self):
        result, _, _ = alg_euclid_extins(55, 55)
        self.assertEqual(result, 55)

    def test_cmmdc_nr_mari(self):
        result, _, _ = alg_euclid_extins(789125, 854114)
        self.assertEqual(result, 1)

    def test_cmmdc_nr_mari2(self):
        result, _, _ = alg_euclid_extins(998654, 785466)
        self.assertEqual(result, 2)

if __name__ == "__main__":
    unittest.main()
