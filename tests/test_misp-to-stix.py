#!/usr/bin/env python
from misp_stix_converter.converters import convert


def test_convert():
    mispfile = "test_files/test.json"
    converted = convert.MISPtoSTIX(open(mispfile).read())
