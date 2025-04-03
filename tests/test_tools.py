import unittest 
from tools.tools import my_pow
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class MyTestCase(unittest.TestCase):
    def test_should_work_for_power_of_two(self):
        res = my_pow(5, 101, 11)
        assert res == (5)

    def test_should_work_for_not_power_of_two(self):
        res = my_pow(289, 11, 1363)
        assert res == (318)

if __name__ == '__main__':
    unittest.main()
