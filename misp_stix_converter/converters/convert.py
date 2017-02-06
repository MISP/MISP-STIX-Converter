#!/usr/bin/env python3

# A decoupled converter for misp<->Stix

# Imports
# Sys imports
import logging
from tempfile import SpooledTemporaryFile
import json
import base64
import random

from pymisp import mispevent

# Stix imports
from stix.core import STIXPackage
from stix.core import STIXHeader
from stix.indicator import Indicator

# Local imports
from misp_stix_converter.errors import STIXLoadError
from misp_stix_converter.converters import buildSTIXAttribute
from misp_stix_converter.converters import buildMISPAttribute

log = logging.getLogger("__main__")


def MISPtoSTIX(mispJSON):
    """
        Function to convert from a MISP JSON to a STIX stix

        :param mispJSON: A dict (json) containing a misp Event.
        :returns stix: A STIX stix with as much of the original
                          data as we could convert.
    """
    if isinstance(mispJSON, mispevent.MISPEvent):
        misp_event = mispJSON
    else:
        misp_event = mispevent.MISPEvent()
        misp_event.load(mispJSON)

    # We should now have a proper MISP JSON loaded.

    # Create a base stix
    stix = STIXPackage()
    try:
        stix.MISPID = mispJSON["Event"]["id"]
    except:
        # We don't have an ID?
        # Generate a random number and use that
        stix.MISPID = random.randint(1,9000)

    # Create a header for the new stix
    stix.stix_header = STIXHeader()

    # Try to use the event title as the stix title
    stix.stix_header.title = misp_event.info

    # We're going to store our observables inside an indicator
    indicator = Indicator()

    # Go through each attribute and transfer what we can.
    for one_attrib in misp_event.attributes:
        # Build an attribute from the JSON. Is all nice.
        buildSTIXAttribute.buildAttribute(one_attrib, stix, indicator)
    stix.add_indicator(indicator)
    return stix


def load_stix(stix):
    # Just save the pain and load it if the first character is a <

    if isinstance(stix, STIXPackage):
        # Oh cool we're ok 
        # Who tried to load this? Honestly.
        return stix

    elif hasattr(stix, 'read'):
        # It's a file!
        try:
            # Try loading from JSON
            stix_package = STIXPackage.from_json(stix)
        except (TypeError, json.JSONDecodeError):
            # Ok then try loading from XML
            # Loop zoop
            stix.seek(0)
            try:
                stix_package = STIXPackage.from_xml(stix)
            except Exception as ex:
                # No joy. Quit.
                raise STIXLoadError("Could not load stix file. {}".format(ex))

        return stix_package

    elif isinstance(stix, str):
        # It's text, we'll need to use a temporary file  
        
        # Create a temporary file to load from
        # Y'know I should probably give it a max size before jumping to disk
        # idk, 10MB? Sounds reasonable. 
        f = SpooledTemporaryFile(max_size=10*1024)
        
        # O I have idea for sneak
        # Will be very sneak

        # Write the (probably) XML to file
        f.write(stix.encode("utf-8"))

        # Reset the file so we can read from it
        f.seek(0)

        # AHA SNEAK DIDN'T EXPECT RECURSION DID YOU
        return load_stix(f)


def STIXtoMISP(stix, mispAPI, **kwargs):
    """Function to convert from something stixxy ( as we have 3 possible representations )
    to something mispy. Specifically JSON. Because XML is satan.

    :param stix: Something stixxy.
    """

    log.info("Converting a package from STIX to MISP...")
    stixPackage = load_stix(stix)
    # Ok by now we should have a proper STIX object.

    # We'll try to extract a filename
    filename = "STIX_File.xml"
    if isinstance(stix, str) and "\n" not in stix:
        # It's probably just a filename
        filename = stix
    elif hasattr(stix, "name"):
        # Steal this one!
        filename = stix.name
    elif hasattr(stixPackage, "stix_header"):
        # Well it has a header, maybe we can steal it
        if stixPackage.stix_header:
            if stixPackage.stix_header.title not in  ["", None]:
                filename = stixPackage.stix_header.title + ".xml"
    misp_event = buildMISPAttribute.buildEvent(stixPackage, **kwargs)
    b64Pkg = base64.b64encode(stixPackage.to_xml()).decode("utf-8")
    misp_event.add_attribute(type="attachment", value=filename, data=b64Pkg)
    if misp_event.attributes:
        response = mispAPI.add_event(json.dumps(misp_event, cls=mispevent.EncodeUpdate))
        if response.get('errors'):
            raise Exception("PACKAGE: {}\nERROR: {}".format(json.dumps(misp_event, cls=mispevent.EncodeUpdate), 
                                                            response.get('errors')))
            
        return response
