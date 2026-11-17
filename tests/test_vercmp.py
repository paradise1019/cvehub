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


class NonAsciiDigitTest(unittest.TestCase):
    def test_non_ascii_digit_does_not_hang(self):
        from cvehub.vercmp import vercmp
        self.assertNotEqual(vercmp("1.0²", "1.0"), 0)       # 之前是無窮迴圈
        self.assertNotEqual(vercmp("1.0", "1.0①"), 0)
        from cvehub.vercmp import BadVersion
        with self.assertRaises(BadVersion):
            vercmp("x:1", "1")
        with self.assertRaises(BadVersion):
            vercmp("²:1", "1")

    def test_long_numbers_like_dpkg(self):
        """數字段很長（超過 int() 的 4300 位上限）也照 dpkg 比較；前導零不算（dpkg --compare-versions 實測）。
        epoch 超過 2147483647 時 dpkg 判定不合法，這裡刻意照樣比較（見 vercmp 模組說明）"""
        from cvehub.vercmp import vercmp
        self.assertGreater(vercmp("1." + "9" * 5000, "1.2"), 0)
        self.assertEqual(vercmp("1." + "0" * 5000 + "1", "1.1"), 0)
        self.assertLess(vercmp("1." + "9" * 5000, "1.1" + "0" * 5000), 0)
        self.assertGreater(vercmp("9" * 5000 + ":1.0", "1.0"), 0)            # epoch 也逐位比較（dpkg 拒絕，刻意不同）
        self.assertEqual(vercmp("0" * 5000 + "1:1", "1:1"), 0)
        self.assertLess(vercmp("2:1", "10:1"), 0)
