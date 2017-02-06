#!/usr/bin/env python3

##########################
#     WRAPPER SCRIPT     #
#     DEALS WITH MISP    #
#     TO STIX            #
##########################


import argparse
import pyaml
import sys
import os
import logging

from misp_stix_converter.servers import misp
from misp_stix_converter.converters import convert
from misp_stix_converter.converters import lint_roller

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('-o', '--outfile', help="The file to output to. Default is stdout. ")
parser.add_argument("-d", "--outdir", help="Directory to output to")
parser.add_argument("-c", "--config", help="Path to config file. Default is misp.login.")
parser.add_argument("-f", "--file", help="The MISP JSON file to convert")
parser.add_argument("-i", "--eid", help="The MISP event ID to pull and convert")
parser.add_argument("-t", "--tag", help="Download all of a single tag")
parser.add_argument("-v", "--verbose", help="More output", default="1.2")
parser.add_argument("-l", "--logfile", help="Where to send the log to", default="converter.log")
parser.add_argument("--format", help="The output format [JSON/XML]. Default JSON.")
parser.add_argument("--stix-version", help="Set the STIX output version. Default 1.2.")

args = parser.parse_args()

log = logging.getLogger(__name__)
handler = logging.FileHandler(args.logfile)
formatter =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')

handler.setFormatter(formatter)
log.addHandler(handler)
log.setLevel(logging.INFO if args.verbose else logging.DEBUG)

log.info("MISP<->STIX Converter")

# Set the config file
if args.config:
    configfile = args.config
else:
    configfile = os.path.expanduser("~/.misptostix/misp.login")

log.debug("Using config file at %s", configfile)

try:
    with open(configfile, "r") as f:
        CONFIG = pyaml.yaml.load(f)
except FileNotFoundError:
    print("Could not find config file {}".format(configfile))
    sys.exit(1)

# We either need a file or an event ID
if not (args.file or args.eid or args.tag):
    print("We need something to convert!")
    print("Please either specify a file with -f [FILENAME]")
    print("Or a MISP ID with -i [ID]")
    sys.exit()

if (args.file and args.eid) or (args.file and args.tag) or (args.eid and args.tag):
    print("We can't convert both at once!")
    print("*EITHER* provide -i, -f or -t. Only one.")
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

    log.debug("Converting file at %s", args.file)

    # This is just a file conversion
    # Relatively quick and easy
    # Create a non-connected misp instance
    try:
        with open(args.file, "r") as f:
            jsondata = f.read()
        package = convert.MISPtoSTIX(jsondata)
    except FileNotFoundError:
        print("Could not open {}".format(args.file))
        sys.exit()

else:
    # This requires a connection to MISP
    # As we need to pull an event
    # Connect to MISP
    MISP = misp.MISP(CONFIG["MISP"]["URL"], CONFIG["MISP"]["KEY"])

    if args.tag:
        log.debug("Converting all events tagged with %s", args.tag)
        package = MISP.pull(tags=[args.tag])
    else:
        log.debug("Converting event %s", args.eid)
        package = MISP.pull(args.eid)[0]

def write_pkg(pkg, outfile):
    # Set the version
    log.debug("Writing to %s", outfile)
    log.debug("As stix v%s", args.stix_version)
    
    if args.stix_version:
        if args.stix_version == "1.1.1":
            objs = lint_roller.lintRoll(pkg)
            for i in objs:
                # Set the object's version
                if hasattr(i, "version"):
                    i.version = args.stix_version

        elif args.stix_version == "1.2":
            pass  # Is default
        else:
            print("INVALID STIX VERSION {}".format(args.stix_version))
            sys.exit()

    if args.format == "json":
        log.debug("In JSON format")
        # Output to JSON
        if not outfile:
            # Output to stdout
            print(pkg.to_json())
        else:
            # Output to file
            with open(outfile, "w") as f:
                f.write(pkg.to_json())
    else:
        log.debug("In XML format")
        # Output to XML
        if not outfile:
            # Output to stdout
            print(pkg.to_xml())
        else:
            # Output to file
            with open(outfile, "wb") as f:
                f.write(pkg.to_xml())

    log.debug("Written!")

if not args.tag:
    write_pkg(package, args.outfile)
else:
    for p in package:
        write_pkg(p, args.outfile.format(p.MISPID))    
