#!/usr/bin/env python


import time
import re
import urllib2
import argparse
import dpkt


# use these to filter out the nonsense
EXCLUDE = (r"/js/", r"/css/", r".png", r".jpg", r".gif", r".swf", r"/_status/",
           r"/applets")


def get_hostname(http_data):
    """dpkt doesn't seem to have a simple way to grab the hostname, so do it
    manually"""
    match = re.search(r"host:.*\n", str(http_data))
    if match:
        return match.group(0)[6:-2]


def pretty_time(timestamp):
    """Returns a string of the given time made pretty"""
    return time.strftime("%a, %b %d %l:%M:%S %p", time.localtime(timestamp))


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
    html = response.read()
    match = re.search(r"<title>.*</title>", html, re.IGNORECASE)
    if match:
        return match.group(0)[7:-8] # strip tags
    else:
        return ""


def parse_pcap(filename, resolve_titles=False):
    """Takes the filename of a capture file, returns a list of tuples in the
    form (time, url, title). If resolve_titles is set to True, pulls in the
    sites using urllib2 and gets their current titles. This can take some
    time..."""
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

            if not url_should_die(http.uri, EXCLUDE): # filter out bullshit
                full_url = "http://" + get_hostname(http) + http.uri
                title = ""
                if resolve_titles:
                    title = get_page_title(full_url)
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
    print '<html><head><title>Um, whatever</title></head><body>'
    print '<table border="1">'
    print '<tr><td>TIME</td><td>URL</td><td>TITLE</td></tr>'
    for ts, url, title in in_tuples:
        print '<tr><td>'+ts+'</td><td><a href="'+url+'">'+url+'</a></td><td>'+title+'</td></tr>'
    print '</table>'
    print '</body></html>'


def get_args():
    """Gets and parses command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-html', action='store_true', default=False,
                        help='show output in HTML instead of plaintext')
    parser.add_argument('--get-titles', action='store_true', default=False,
                        help='fetch page titles; note that this can take a bit of time!')
    parser.add_argument('filename', action='store',
                        help='the pcap file to analyze and parse')
    return parser.parse_args()


def main():
    """My main() man"""
    args = get_args()
    out_data = parse_pcap(args.filename, args.get_titles)
    if args.output_html:
        show_output_html(out_data)
    else:
        show_output_text(out_data)


if __name__ == "__main__":
    main()
