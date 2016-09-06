#MISP to STIX and back again
##Or at least that's the idea

This is the open-sourced version of our internal
sync script. It's a bit limited, nor perfect, nor is it bug-free.

But it works™

##Usage:

First, add exec perms on the relevent files.

`chmod +x misp-to-stix.py stix-to-misp.py`

###The config file

Copy over the example config to a live version

`cp misp.login.example misp.login`

Then open it and change the variables. This is YAML format, so make sure
you don't do a silly and format it wrong!

###For MISP to STIX: 

To get all usage information:

`./misp-to-stix.py -h`

So to convert a MISP JSON file to stix json, use

`./misp-to-stix.py -f INFILE.json --format JSON -o OUTFILE.json`

And to pull a specific event from the MISP instance

`./misp-to-stix.py -i EVENT_ID...`

###For STIX to MISP

This *only* works if you have a live MISP instance to connect the API
to. 

`./stix-to-misp.py INFILE.json`

This will convert the file to MISP format and push it. 
Currently only ip, domain, url and threat actor objects are converted.

Feel free to add more to the stix-to-misp.py file.
