#!/usr/bin/env python3

##########################
#     WRAPPER SCRIPT     #
#     DEALS WITH MISP    #
#     TO STIX            #
##########################


import argparse
import pyaml
import time
import sys
import os
import logging

try:
    from stix.utils import idgen
except ImportError:
    from mixbox import idgen
from cybox.utils import Namespace
from misp_stix_converter.servers import misp
from misp_stix_converter.converters import convert
from misp_stix_converter.converters import lint_roller

parser = argparse.ArgumentParser(description='Convert MISP to STIX.')
inputg = parser.add_mutually_exclusive_group(required=True)

inputg.add_argument("-f", "--file", help="The MISP JSON file to convert")
inputg.add_argument("-i", "--eid", help="The MISP event ID to pull and convert")
inputg.add_argument("-t", "--tag", help="Download all of a single tag")

parser.add_argument('-o', '--outfile', help="The file to output to. Default is stdout.", default="stdout")
parser.add_argument("-c", "--config", help="Path to config file. Default is misp.login.")
parser.add_argument("-v", "--verbose", help="More output", default=False, action="store_true")
parser.add_argument("-l", "--logfile", help="Where to send the log to", default="converter.log")
parser.add_argument("--format", help="The output format [JSON/XML]. Default JSON.")
parser.add_argument("--stix-version", help="Set the STIX output version. Default 1.2.")
parser.add_argument("--namespace", help="Set the output namespace")
parser.add_argument("--ns-alias", help="Set the NS alias")

args = parser.parse_args()

log = logging.getLogger(__name__)
handler = logging.FileHandler(args.logfile)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

handler.setFormatter(formatter)
log.addHandler(handler)
log.setLevel(logging.DEBUG if args.verbose else logging.INFO)

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

if args.tag and not ("{}" in args.outfile):
    args.outfile += ".{}"

if args.format:
    args.format = args.format.lower()
    if args.format not in ["json", "xml"]:
        print("Only possible output formats are JSON and XML.")
        print("{} is not valid".format(args.format))
        sys.exit()
else:
    args.format = "json"

if (args.namespace or args.ns_alias) and not (args.namespace and args.ns_alias):
    print("If you want to provide namespace config, we need both --namespace and --ns-alias")
    sys.exit()

ns_url = "https://misp.software"
ns_alias = "MISPtoSTIX"

if (args.namespace):
    ns_url = args.namespace
    ns_alias = args.ns_alias
 
try:    
    idgen.set_id_namespace({ns_url: ns_alias})
except ValueError:
    idgen.set_id_namespace(Namespace(ns_url, ns_alias))

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
    # Backwards compatability, if users haven't updated config
    if "SSL" not in CONFIG["MISP"]:
        print("Please update your config file using the misp.login.example to include SSL\n")
        time.sleep(1)
        CONFIG["MISP"]["SSL"] = False

    # This requires a connection to MISP
    # As we need to pull an event
    # Connect to MISP
    MISP = misp.MISP(CONFIG["MISP"]["URL"], CONFIG["MISP"]["KEY"], CONFIG["MISP"].get("SSL", True))

    if args.tag:
        log.debug("Converting all events tagged with %s", args.tag)
        package = MISP.pull(tags=[args.tag])
    else:
        log.debug("Converting event %s", args.eid)
        try:
            package = MISP.pull(args.eid)[0]
        except IndexError:
            log.fatal("Could not find event %s", args.eid)
            print("ERROR :: SEE LOG FILE")
            sys.exit(1)


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
        if outfile == "stdout":
            # Output to stdout
            print(pkg.to_json())
        else:
            # Output to file
            with open(outfile, "w") as f:
                f.write(pkg.to_json())
    else:
        log.debug("In XML format")
        # Output to XML
        if outfile == "stdout":
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
