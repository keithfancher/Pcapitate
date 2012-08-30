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

    def test_should_die(self):
        """Given URLs should be filtered out of the list"""
        filters = (r"/js/", r"/css/")
        self.assertTrue(p.url_should_die("http://blah.com/js/whatever.js", filters))
        self.assertTrue(p.url_should_die("http://blah.com/css/whatever.js", filters))

    def test_should_not_die(self):
        """Given URLs should NOT be filetered out of the list!"""
        filters = (r"/js/", r"/css/")
        self.assertFalse(p.url_should_die("http://blah.com/whatever", filters))
        self.assertFalse(p.url_should_die("http://blah.com/whatever/asdfot", filters))


class TestGetPageTitle(unittest.TestCase):

    def test_good_page_titles(self):
        """Sites with titles should be returned properly"""
        self.assertEqual(p.get_page_title("http://nostarch.com"), "No Starch Press")
        self.assertEqual(p.get_page_title("http://google.com"), "Google")

    def test_no_title(self):
        """Sites (or resources) with no <title> set should return empty string"""
        self.assertEqual(p.get_page_title("http://nostarch.com/sites/default/files/wabi_logo.png"), "")

    def test_http_error(self):
        """HTTP errors should return... an error!"""
        self.assertEqual(p.get_page_title("http://nostarch.com/asdfasdfasdf"), "HTTP error! Title not retrieved")

    def test_bad_url(self):
        """Bad URLs should return... an error!"""
        self.assertEqual(p.get_page_title("http://asdfasdfasdfasdfasdf/asdfasdfasdf"), "Bad URL! Title not retrieved")


if __name__ == "__main__":
    unittest.main()
