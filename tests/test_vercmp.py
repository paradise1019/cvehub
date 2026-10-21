import unittest

from cvehub.vercmp import vercmp


class VercmpTest(unittest.TestCase):
    """結果需與 dpkg --compare-versions 相同"""
    CASES = [
        ("1.0", "1.0", 0), ("1.0", "1.1", -1), ("1.10", "1.9", 1),
        ("1.0~rc1", "1.0", -1), ("1.0~rc1", "1.0~rc2", -1), ("1.0", "1.0+b1", -1),
        ("1:1.0", "2.0", 1), ("0:1.0", "1.0", 0),
        ("3.0.13-0ubuntu3", "3.0.13-0ubuntu3.16", -1), ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.16", -1),
        ("1.1.1f-1ubuntu2.24", "1.1.1f-1ubuntu2.24+esm1", -1), ("1.1.1f-1ubuntu2.24+esm1", "1.1.1f-1ubuntu2.24+esm2", -1),
        ("7.0.0-38.38~24.04.4", "7.0.0-38.38", -1), ("6.8.0-139.139", "6.8.0-147.147", -1),
        ("2.0-1", "2.0-1ubuntu1", -1), ("1.0a", "1.0", 1), ("1.0", "1.0-0", 0),
    ]

    def test_cases(self):
        for a, b, want in self.CASES:
            got = vercmp(a, b)
            got = (got > 0) - (got < 0)
            self.assertEqual(got, want, "%s vs %s" % (a, b))
            self.assertEqual(-((vercmp(b, a) > 0) - (vercmp(b, a) < 0)), want, "reverse %s vs %s" % (b, a))


if __name__ == "__main__":
    unittest.main()
