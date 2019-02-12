import glob
from misp_stix_converter.converters import convert
from misp_stix_converter.servers import misp


def test_convert():
    # This is a public MISP instance.
    # Just running on AWS, nothing particularly interesting.
    test_files = glob.glob("test_files/*.xml")
    for test_file in test_files:
        with open(test_file, "r") as f:
            convert.STIXtoMISP(f.read(), None)
