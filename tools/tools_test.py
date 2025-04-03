import unittest

from BigNumber.BigNumber import BigNumber

from tools import my_pow


class MyTestCase(unittest.TestCase):
    def test_should_work_for_power_of_two(self):
        res = my_pow(BigNumber(5), BigNumber(101), BigNumber(11))
        assert res == BigNumber(5)

    def test_should_work_for_not_power_of_two(self):
        res = my_pow(BigNumber(289), BigNumber(11), BigNumber(1363))
        assert res == BigNumber(318)

if __name__ == '__main__':
    unittest.main()
