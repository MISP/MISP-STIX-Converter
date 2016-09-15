#MISP to STIX and back again
##Or at least that's the idea

This is the open-sourced version of our internal
sync script. It's a bit limited, and it isn't perfect, nor is it bug-free.

But it works™

##Installation

`sudo python3 setup.py install`

This should install everything it needs!

Useful, huh?

##Usage:

Once 

###The config file

Copy over the example config to a live version

The default location of this config file is at `~/.misptostx`, but this can be
overridden with the `-c FILE` flag when running the scripts.

`cp /path/to/config/misp.login.example /path/to/config/misp.login`

Then open it and change the variables. This is YAML format, so make sure
you don't do a silly and format it wrong!

###For MISP to STIX: 

To get all usage information:

`misp-to-stix.py -h`

So to convert a MISP JSON file to stix json, use

`misp-to-stix.py -f INFILE.json --format JSON -o OUTFILE.json`
(the --format flag is used to specify output format, just for reference)

And to pull a specific event from the MISP instance

`./misp-to-stix.py -i EVENT_ID...`

###For STIX to MISP

This *only* works if you have a live MISP instance to connect the API
to. 

`./stix-to-misp.py INFILE.json`

This will convert the file to MISP format and push it. 
Quite a few bits and bobs get converted, not all of them (I for one blame CyBoX for being
weird and layered worse than an onion).

Feel free to add more to the stix-to-misp.py file.
