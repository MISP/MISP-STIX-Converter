import glob
from misp_stix_converter.converters import convert
from misp_stix_converter.converters.buildMISPAttribute import uniq
from misp_stix_converter.converters.buildMISPAttribute import identifyHash
from misp_stix_converter.servers import misp


def test_convert():
    # This is a public MISP instance.
    # Just running on AWS, nothing particularly interesting.
    test_files = glob.glob("test_files/*.xml")
    for test_file in test_files:
        with open(test_file, "r") as f:
            convert.STIXtoMISP(f.read(), None)


def test_uniq():
    """Utility function should match uniqueness expectation."""
    uniques = (
        [42],
        [1, 2, "a", 3, -1, False, None, (), {}],
        list(set([1, 2, 1, 2])),
    )
    redundants = (
        [42, 42, 42],
        [1, 2, "a", 3, -1, False, None, (), {}, False, 1, 2],
        [1, 2, 1, 2],
    )
    for u, r in zip(uniques, redundants):
        assert uniq(u) == u
        assert uniq(r) == u


def test_identifyHash():
    """Returned list of hashes should be not empty for valid hash lengths."""
    fadeface_hashes = (
        "fadeface" * 4,
        "fadeface" * 8,
        "fadeface" * 16,
    )
    for fadeface_hash in fadeface_hashes:
        print(fadeface_hash, identifyHash(fadeface_hash))
        assert identifyHash(fadeface_hash)
