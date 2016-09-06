#!/usr/bin/env python3

##########################
#     WRAPPER SCRIPT     #
#     DEALS WITH STIX    #
#     TO MISP            #
##########################


import argparse
import misp
import pyaml
import sys
import json
from stix.common import STIXPackage
import base64
import stiximport

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument("-c", "--config", help="Path to config file. Default is misp.login.")
parser.add_argument("file", help="The STIX file to push")

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

# This is just a file conversion
# Relatively quick and easy
MISP = misp.MISP(CONFIG["MISP"]["URL"], CONFIG["MISP"]["KEY"])

# We'll use my nice little misp module
with open(args.file, "rb") as f:
    dataraw = f.read()
    # Encode the data
    datareq = base64.b64encode(dataraw)
    
request = {"data":str(datareq, 'utf-8')}

r = stiximport.handler(json.dumps(request))

# Create an event
api = MISP.mispAPI
ev = api.new_event(0, 3, 0, "STIX Converted Event")
for res in r["results"]:
    t = res["types"][0]
    for v in res["values"]:
        if t == "ip-dst":
            api.add_ipdst(ev, v)
        elif t == "ip-src":
            api.add_ipsrc(ev, v)
        elif t == "domain":
            api.add_domain(ev, v)
        elif t == "url":
            api.add_url(ev, v)
        elif t == "threat-actor":
            api.add_threat_actor(ev, v)

