#!/usr/bin/env python3

##########################
#     WRAPPER SCRIPT     #
#     DEALS WITH STIX    #
#     TO MISP            #
##########################


import argparse
import logging
import os
import pyaml
import sys
import time

from misp_stix_converter.servers import misp
from misp_stix_converter.converters.convert import load_stix

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument("-c", "--config", help="Path to config file. Default is misp.login.")
parser.add_argument("-v", "--verbose", help="Increase logging verbosity.", default=False, action="store_true")
parser.add_argument("file", help="The STIX file to push")

args = parser.parse_args()

# Set up a logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG if args.verbose else logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

# Set the config file
cfg_path = args.config if args.config else os.path.expanduser(
    "~/.misptostix/misp.login")

try:
    with open(cfg_path, "r") as f:
        CONFIG = pyaml.yaml.load(f)
except FileNotFoundError:
    log.fatal("Could not find config file %s", cfg_path)
    sys.exit(1)

# Backwards compatability, if users haven't updated config
if "SSL" not in CONFIG["MISP"]:
    log.warning("Please update your config file using the misp.login.example to include SSL")
    time.sleep(1)
    CONFIG["MISP"]["SSL"] = False

# Load the package
in_path = args.file
log.info("Opening STIX file %s", in_path)
try:
    with open(in_path, "r") as f:  # Sometimes it's thrown as bytes?
        pkg = load_stix(f)
except OSError:
    log.fatal("Could not open STIX file %s", in_path)
    sys.exit(1)

# This is just a file conversion - relatively quick and easy
MISP = misp.MISP(CONFIG["MISP"]["URL"], CONFIG["MISP"]["KEY"], CONFIG["MISP"].get("SSL", True))

# We'll use my nice little misp module
log.info("Pushing to MISP...")
MISP.push(pkg)
log.info("COMPLETE")
