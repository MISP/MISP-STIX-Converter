#!/usr/bin/env python3

##########################
#     WRAPPER SCRIPT     #
#     DEALS WITH MISP    #
#     TO STIX            #
##########################


import argparse
from conversion import misp
import pyaml
import sys
import json

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('-o', '--outfile', help="The file to output to. Default is stdout")
parser.add_argument("-c", "--config", help="Path to config file. Default is misp.login.")
parser.add_argument("-f", "--file", help="The MISP JSON file to convert")
parser.add_argument("-i", "--eid", help="The MISP event ID to pull and convert")
parser.add_argument("--format", help="The output format [JSON/XML]. Default JSON.")

args = parser.parse_args()

# Set the config file
if args.config:
    configfile = args.config
else:
    configfile = "misp.login"

try:
    with open(configfile, "r") as f:
        CONFIG = pyaml.yaml.load(f)
except FileNotFoundError:
    print("Could not find config file {}".format(configfile))
    sys.exit(1)

# We either need a file or an event ID
if not (args.file or args.eid):
    print("We need something to convert!")
    print("Please either specify a file with -f [FILENAME]")
    print("Or a MISP ID with -i [ID]")
    sys.exit()

if (args.file and args.eid):
    print("We can't convert both at once!")
    print("*EITHER* provide -i or -f. Not both.")
    sys.exit()

if args.format:
    args.format = args.format.lower()
    if args.format not in ["json", "xml"]:
        print("Only possible output formats are JSON and XML.")
        print("{} is not valid".format(args.format))
        sys.exit()
else:
    args.format = "json"

if (args.file):
    # This is just a file conversion
    # Relatively quick and easy
    # Create a non-connected misp instance
    MISP = misp.MISP(None, None)
    
    try:
        with open(args.file, "r") as f:
            jsondata = f.read()
        package = MISP.buildPackage(jsoninfo=json.loads(jsondata))
    except FileNotFoundError:
        print("Could not open {}".format(args.file))
        sys.exit()
        
else:
    # This requires a connection to MISP
    # As we need to pull an event
    # Connect to MISP
    MISP = misp.MISP(CONFIG["MISP"]["URL"], CONFIG["MISP"]["KEY"])
    package = MISP.pull(args.eid)[0]

if args.format == "json":
    # Output to JSON
    if not args.outfile:
        # Output to stdout
        print(package.to_json())
    else:
        # Output to file
        with open(args.outfile, "w") as f:
            f.write(package.to_json())
else:
    # Output to XML
    if not args.outfile:
        # Output to stdout
        print(package.to_xml())
    else:
        # Output to file
        with open(args.outfile, "wb") as f:
            f.write(package.to_xml())

