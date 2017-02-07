#!/usr/bin/env python3

##########################
#     WRAPPER SCRIPT     #
#     DEALS WITH STIX    #
#     TO MISP            #
##########################


import argparse
import pyaml
import time
import sys
import os

from misp_stix_converter.servers import misp
from misp_stix_converter.converters.buildMISPAttribute import open_stix

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument("-c", "--config", help="Path to config file. Default is misp.login.")
parser.add_argument("file", help="The STIX file to push")

args = parser.parse_args()

# Set the config file
if args.config:
    configfile = args.config
else:
    configfile = os.path.expanduser("~/.misptostix/misp.login")

try:
    with open(configfile, "r") as f:
        CONFIG = pyaml.yaml.load(f)
except FileNotFoundError:
    print("Could not find config file {}".format(configfile))
    sys.exit(1)

# Backwards compatability, if users haven't updated config
if "SSL" not in CONFIG["MISP"]:
    print("Please update your config file using the misp.login.example to include SSL")
    time.sleep(1)
    CONFIG["MISP"]["SSL"] = False

# This is just a file conversion
# Relatively quick and easy
MISP = misp.MISP(CONFIG["MISP"]["URL"], CONFIG["MISP"]["KEY"], CONFIG["MISP"].get("SSL", True))

# Load the package
pkg = open_stix(args.file)

# We'll use my nice little misp module
MISP.push(pkg)
