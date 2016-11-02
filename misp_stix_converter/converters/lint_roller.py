#!/usr/bin/env python3

# A method to get allllll objects out of a STIX package.


def lintRoll(pkg):
    # Make sure it'll return itself
    objs = [pkg]
    if hasattr(pkg, "walk"):
        # This means we can get more objects out of it
        for x in pkg.walk():
            objs += lintRoll(x)
    return objs
