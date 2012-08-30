#!/usr/bin/env python


import unittest

import parse_pcap as p


class TestParsePcap(unittest.TestCase):

    def test_known_data_1(self):
        """Tests some known input/output pairs"""
        test_pcap = "testdata/test_dump_1.pcap"
        known_output = [ ("Sun, Apr 22,  7:11:53 PM", "http://nostarch.com/", ""),
                        ("Sun, Apr 22,  7:11:54 PM", "http://nostarch.com/", ""),
                        ("Sun, Apr 22,  7:11:55 PM", "http://nostarch.com/catalog/security", ""),
                        ("Sun, Apr 22,  7:11:57 PM", "http://nostarch.com/bughunter", ""),
                        ("Sun, Apr 22,  7:12:01 PM", "http://nostarch.com/catalog/security", ""),
                        ("Sun, Apr 22,  7:12:02 PM", "http://nostarch.com/catalog/business", ""),
                        ("Sun, Apr 22,  7:12:04 PM", "http://nostarch.com/google.htm", "") ]
        self.assertEqual(p.parse_pcap(test_pcap), known_output)

    def test_known_data_2(self):
        """Tests some more known input/output pairs!"""
        test_pcap = "testdata/test_dump_2.pcap"
        known_output = [ ("Sun, Apr 22,  7:16:14 PM", "http://nostarch.com/", ""),
                        ("Sun, Apr 22,  7:16:15 PM", "http://nostarch.com/", ""),
                        ("Sun, Apr 22,  7:16:16 PM", "http://nostarch.com/legoheavyweapons", ""),
                        ("Sun, Apr 22,  7:16:18 PM", "http://nostarch.com/catalog/manga", ""),
                        ("Sun, Apr 22,  7:16:20 PM", "http://nostarch.com/linearalgebra", "") ]
        self.assertEqual(p.parse_pcap(test_pcap), known_output)


class TestUrlShouldDie(unittest.TestCase):

    def test_basic_shit(self):
        pass


if __name__ == "__main__":
    unittest.main()
