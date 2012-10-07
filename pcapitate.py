#!/usr/bin/env python


# Copyright 2012 Keith Fancher
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import dpkt
import re
import time
import urllib2


# use these to filter out the nonsense
EXCLUDE = (r"/js/", r"/css/", r".png", r".jpg", r".gif", r".swf", r"/_status/",
           r"/applets/", r"/bid/", r"/iframe/")


def pretty_time(timestamp):
    """Returns a string of the given time made pretty"""
    return time.strftime("%a, %b %d, %l:%M:%S %p", time.localtime(timestamp))


def url_should_die(url, filters):
    """Returns True if url matches any of the defined filters, False
    otherwise"""
    for f in filters:
        match = re.search(f, url)
        if match:
            return True # if a single match is found, url should die
    return False # after cycling the filters, the url is okay


def get_page_title(url):
    """Given a URL, gets the title for each page using urllib2; if no title,
    returns empty string"""
    try:
        response = urllib2.urlopen(url)
    except urllib2.HTTPError:
        return "HTTP error! Title not retrieved" # good enough for me!
    except urllib2.URLError:
        return "Bad URL! Title not retrieved"
    html = response.read()
    match = re.search(r"<title>(.*)</title>", html, re.IGNORECASE)
    if match:
        return match.group(1)
    else:
        return ""


def parse_pcap(filename, resolve_titles=False, kill_untitled_pages=False):
    """Takes the filename of a capture file, returns a list of tuples in the
    form (time, url, title).

    If resolve_titles is set to True, pulls in the sites using urllib2 and gets
    their current titles. This can take a bit of time.

    If kill_untitled_pages is set to True, only pages that have a <title> will
    be returned. This is an easy way to cut down on non-page requests (like JS,
    CSS, etc.), though there's always the risk that someone visits a valid page
    with no title..."""
    ret_data = []
    f = open(filename)
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        # only handle IP
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        # only handle TCP
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data
        if tcp.dport == 80 and len(tcp.data) > 0: # http, non-zero data
            # we don't care about all of dpkt's errors -- most likely our pcap
            # files will be truncated, and we don't want dpkt to fail every
            # time because of that
            try:
                http = dpkt.http.Request(tcp.data)
            except dpkt.NeedData: # truncated header
                # Workaround for a dpkt (version 1.6) bug. dpkt will only
                # accept packets that end with \r\n\r\n? Many legit captures
                # were causing exceptions because of this, both with tcpdump
                # and wireshark. See:
                # http://code.google.com/p/dpkt/issues/detail?id=90&thanks=90&ts=1337593947
                http = dpkt.http.Request(tcp.data + "\r\n\r\n")
            except dpkt.UnpackError: # "invalid" header
                pass

            if not url_should_die(http.uri, EXCLUDE): # filter out bullshit
                full_url = "http://" + http.headers['host'] + http.uri
                title = ""
                if resolve_titles:
                    title = get_page_title(full_url)
                    if not title and kill_untitled_pages:
                        continue # don't include this page in output
                ret_data.append((pretty_time(ts), full_url, title))
    f.close()
    return ret_data


def show_output_text(in_tuples):
    """Shows the output as plaintext"""
    for ts, url, title in in_tuples:
        print ts
        print url
        print title + "\n"


def show_output_html(in_tuples):
    """Shows the output as HTML"""
    print '''<html><head><title>Um, whatever</title><style>
             table,td,th {border: 1px solid black; border-collapse: collapse; padding: 5px;}
             </style></head><body><table><tr><td><strong>TIME</strong></td>
             <td><strong>TITLE</strong></td><td><strong>URL</strong></td></tr>'''
    for ts, url, title in in_tuples:
        print '<tr><td>'+ts+'</td><td>'+title+'</td><td><a href="'+url+'">'+url+'</a></td></tr>'
    print '</table></body></html>'


def get_args():
    """Gets and parses command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--output-html', action='store_true', default=False,
                        help='show output in HTML instead of plaintext')
    parser.add_argument('-t', '--get-titles', action='store_true', default=False,
                        help='fetch page titles; note that this can take a bit of time!')
    parser.add_argument('-u', '--kill-untitled', action='store_true', default=False,
                        help='don\'t return untitled pages in the output; this can be a good way to filter out "fake" requests and JS, CSS, etc.')
    parser.add_argument('filename', action='store',
                        help='the pcap file to analyze and parse')
    return parser.parse_args()


def main():
    """My main() man"""
    args = get_args()
    out_data = parse_pcap(args.filename, args.get_titles, args.kill_untitled)
    if args.output_html:
        show_output_html(out_data)
    else:
        show_output_text(out_data)


if __name__ == "__main__":
    main()
