#!/usr/bin/env python3

# A method to get allllll objects out of a STIX package.


def lintRoll(pkg):
    objs = []
    if hasattr(pkg, "walk"):
        # This means we can get more objects out of it
        for x in pkg.walk():
            #print(type(x), x)
            objs += lintRoll(x)
    else:
        # Make sure it'll return itself
        objs.append(pkg)
    return objs
