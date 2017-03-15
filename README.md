# MISP to STIX and back again
## Or at least that's the idea

[![Coverage Status](https://coveralls.io/repos/github/MISP/MISP-STIX-Converter/badge.svg?branch=master)](https://coveralls.io/github/MISP/MISP-STIX-Converter?branch=master)
[![Build Status](https://travis-ci.org/MISP/MISP-STIX-Converter.svg?branch=master)](https://travis-ci.org/MISP/MISP-STIX-Converter)
[![Code Health](https://landscape.io/github/MISP/MISP-STIX-Converter/master/landscape.svg?style=flat)](https://landscape.io/github/MISP/MISP-STIX-Converter/master)

This is the open-sourced version of BAE Systems' internal
sync script. It's a bit limited, and it isn't perfect, nor is it bug-free.

But it works™

## Installation

If you don't wanna use git, 
```bash
sudo pip3 install misp_stix_converter
```
should have you covered. This relies on me actually updating PyPI every time I update the project, so I'd use the 
git repo wherever possible.

```
sudo python3 setup.py install
```

This should install everything it needs!

Useful, huh?

### The config file

Copy over the example config to a live version

The default location of this config file is at `~/.misptostix`, but this can be
overridden with the `-c FILE` flag when running the scripts.

`cp /path/to/config/misp.login.example /path/to/config/misp.login`

Then open it and change the variables. This is YAML format, so make sure
you don't do a silly and format it wrong!

## Usage

### For MISP to STIX: 

To get all usage information:

`misp-to-stix.py -h`

So to convert a MISP JSON file to stix json, use

`misp-to-stix.py -f INFILE.json --format JSON -o OUTFILE.json`
(the --format flag is used to specify output format, just for reference)

And to pull a specific event from the MISP instance

`misp-to-stix.py -i EVENT_ID...`

Alternatively, if you want to pull every event of a certain tag, you can run

`misp-to-stix.py -t tlp:white -o out.{}.xml`

Which will write all "tlp:white" tagged events to a file formatted by the event's ID, e.g out.29.xml

### For STIX to MISP

This *only* works if you have a live MISP instance to connect the API
to. 

`./stix-to-misp.py INFILE.json`

This will convert the file to MISP format and push it. 
Quite a few bits and bobs get converted, not all of them (I for one blame CyBoX for being
weird and layered worse than an onion).

Feel free to add more to the stix-to-misp.py file.
