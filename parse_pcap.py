#!/usr/bin/env python


import sys
import time
import re
import dpkt


# use these to filter out the nonsense
FILTERS = (r"/js/", r"/css/")


def get_hostname(http_data):
    """dpkt doesn't seem to have a simple way to grab the hostname"""
    match = re.search(r"host:.*\n", str(http_data))
    if match:
        return match.group(0)[6:-2]


def pretty_time(timestamp):
    """returns a string of the given time made pretty"""
    return time.strftime("%a, %b %d %l:%M:%S %p", time.localtime(timestamp))


def url_should_die(url):
    """returns True if url matches any of the defined FILTERS, False
    otherwise"""
    for f in FILTERS:
        match = re.search(f, url)
        if match:
            return True # if a single match is found, url should die
    return False # after cycling the filters, the url is okay


def parse_pcap(filename):
    """takes the filename of a capture file, returns a list of tuples in the
    form (time, url)"""
    ret_data = []
    f = open(filename)
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        # requests with nonzero data
        if tcp.dport == 80 and len(tcp.data) > 0:
            try:
                http = dpkt.http.Request(tcp.data)
            # we don't care about all of dpkt's errors -- most likely our pcap
            # files will be truncated, and we don't want dpkt to fail every
            # time because of that
            except:
                pass

            if not url_should_die(http.uri): # filter out specified patterns
                full_url = get_hostname(http) + http.uri
                ret_data.append((pretty_time(ts), full_url))

    f.close()
    return ret_data


def prettify_output_text(in_tuples):
    """shows the output in a readable way, plaintext"""
    for t, u in in_tuples:
        print "\n"
        print t
        print u


def prettify_output_html(in_tupes):
    """shows the output in a readable way, HTML"""
    pass


def main(argv):
    if len(argv) < 2:
        print "You're doing it wrong."
        sys.exit(1)

    out_data = parse_pcap(argv[1])
    prettify_output_text(out_data)


if __name__ == "__main__":
    main(sys.argv)
