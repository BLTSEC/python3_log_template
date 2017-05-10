#!/usr/bin/env python3
################################################
# ----------------------------------------------
# gzaapps_stats.py
# ----------------------------------------------
# Author:      Brennan Lee Turner @BLTSEC
# Description: Displays stats for 
#              applications 
################################################

import re
import collections
import argparse
import glob
import gzip


class gzaapps_stats():
    
    def __init__(self, ip, time, name, uri, exclude=[], dnr=[], bad=None, topn=5, debug=False):
        
        self.exclude = exclude
        self.dnr = dnr
        self.ip = ip
        self.time = time
        self.name = name
        self.uri = uri
        self.bad = bad
        self.topn = topn
        self.debug = debug
        self.cnt_ip = collections.Counter()
        self.cnt_time = collections.Counter()
        self.cnt_name = collections.Counter()
        self.cnt_uri = collections.Counter()
        self.cnt_bad = collections.Counter()
        self.gzfiles = glob.glob("./*access*.gz")
        self.regfiles = glob.glob("./*access*.log")
        self.re = re.compile(
            r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+" +
            "(?P<time>\d{1,2}/\w*/\d{4}:\d{2}:\d{2}).+" +
            "(?P<name>[A-Z][a-z]{1,10} [A-Z][a-z]{1,10} (?:...[a-z]{1,10}|[a-z]{1,10}\d{2}[a-z])).+" +
            "(?:(?P<uri>(?:\"GET|\"POST) /acu-application-dates.*[^4]\d{2} )|" +
            "(?P<bad>(?:\"GET|\"POST) /acu-application-dates.*4\d{2} ))"
        )

    def run(self):
        for i in self.gzfiles:
            with gzip.open(i, "rt") as f:
                self.read_data(f)
        for i in self.regfiles:
            with open(i, "r") as f:
                self.read_data(f)
        self.print_summary()
    
    def read_data(self, f):
        for line in f.readlines():
                    m = self.re.match(line)
                    if not m:
                        continue
                    if self.exclude and m.group("ip") in self.exclude:
                        continue
                    if self.ip and m.group("ip") not in self.ip:
                        continue
                    if self.time and m.group("time") not in self.time:
                        continue
                    if self.uri and m.group("uri") not in self.uri:
                        continue
                    if self.bad and m.group("bad") not in self.bad:
                        continue
                    if self.name and self.name not in m.group("name"):
                        continue

                    self.cnt_ip.update([m.group("ip")])
                    self.cnt_time.update([m.group("time")])
                    self.cnt_name.update([m.group("name")])
                    self.cnt_uri.update([m.group("uri")])
                    if m.group("bad"):
                        self.cnt_bad.update([m.group("bad")])

                    if self.debug:
                        print ('Found: %s' % self.exclude[0])
                        print ("ip: %s, name: %s, uri: %s, bad: %s, time: %s" % (
                            m.group("ip"),
                            m.group("name"),
                            m.group("uri"),
                            m.group("bad"),
                            m.group("time")
                        ))

    def print_summary(self):
        if (self.dnr and "ip" not in self.dnr) or (not self.dnr and not self.ip):
            self.print_counts(self.cnt_ip, "IP Addresses")
        if (self.dnr and "name" not in self.dnr) or (not self.dnr and not self.name):
            self.print_counts(self.cnt_name, "Names")
        if (self.dnr and "uri" not in self.dnr) or (not self.dnr and not self.uri):
            self.print_counts(self.cnt_uri, "URI")
        if (self.dnr and "time" not in self.dnr) or (not self.dnr and not self.time):
            self.print_counts(self.cnt_time, "Date/Times")
        if (self.dnr and "bad" not in self.dnr) or (not self.dnr and not self.bad):
            self.print_counts(self.cnt_bad, "Possible Problems/Attacks")

    def print_counts(self, cdict, title):
        print (120 * "-")
        print (" << Top #%2d %s >>" % (self.topn, title))
        print (120 * "-")
        for i, t in enumerate(cdict.most_common(self.topn)):
            if "IP Addresses" in title:
                print ("%2d) %20s: %8d" % (i + 1, t[0], t[1]))
            elif "Names" in title:
                print ("%2d) %25s: %8d" % (i + 1, t[0], t[1]))
            elif "URI" in title:
                print ("%2d) %100s: %8d" % (i + 1, t[0], t[1]))
            elif "Possible Problems/Attacks" in title:
                print ("%2d) %100s: %8d" % (i + 1, t[0], t[1]))
            else:
                print ("%2d) %20s: %8d" % (i + 1, t[0], t[1]))
        print (120 * "-")
        print ("\r\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--exclude", nargs="*",
        help="query types to exclude from statistics"
    )
    parser.add_argument(
        "--dnr", nargs="*",
        help="query types to exclude from printing"
    )
    parser.add_argument(
        "--ip", nargs="*", default=[],
        help="query ip addr(s) to include"
    )
    parser.add_argument(
        "--name",
        help="specify client name to filter by"
    )
    parser.add_argument(
        "--time",
        help="specify time to filter by"
    )
    parser.add_argument(
        "--uri",
        help="specify uri to filter by"
    )
    parser.add_argument(
        "--topn", type=int,
        default=5, help="print top N stats"
    )
    parser.add_argument(
        "--debug", action="store_true",
        default=False,
        help="enable debugging"
    )
    args = parser.parse_args()

    l = gzaapps_stats(
        ip=args.ip,
        exclude=args.exclude,
        dnr=args.dnr,
        name=args.name,
        time=args.time,
        uri=args.uri,
        topn=args.topn,
        debug=args.debug
    )
    l.run()
