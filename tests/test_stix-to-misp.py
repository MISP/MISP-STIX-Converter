#!/usr/bin/env python
import glob
from threatintel.converters import convert
from threatintel.servers import misp


def test_convert():
    # This is a public MISP instance.
    # Just running on AWS, nothing particularly interesting.
    mispAPI = misp.MISP("http://ec2-52-42-201-6.us-west-2.compute.amazonaws.com", "Vjy0ra7wO6w6si7hbjxX52nARfVpaAO6Tm6lxeSm")
    test_files = glob.glob("test_files/*.xml")
    for test_file in test_files:
        print(test_file)
        with open(test_file, "r") as f:
            convert.STIXtoMISP(f.read(), mispAPI.mispAPI)
