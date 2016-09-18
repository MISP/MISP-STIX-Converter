#!/usr/bin/env python3

# A decoupled converter for misp<->Stix

# Imports
# Sys imports
import logging
import json
import sys

# Stix imports
from stix.core import STIXPackage
from stix.core import STIXHeader
from stix.indicator import Indicator, Observable

# Local imports
from threatintel.errors import *
from threatintel.converters import buildSTIXAttribute
from threatintel.converters import buildMISPAttribute

log = logging.getLogger("__main__")

def MISPtoSTIX(mispJSON):
    """
        Function to convert from a MISP JSON to a STIX stix
        
        :param mispJSON: A dict (json) containing a misp Event.
        :returns stix: A STIX stix with as much of the original
                          data as we could convert.
    """
    if not isinstance(mispJSON, dict):
        # It's likely not a loaded JSON. Attempt to load it.
        try:
            mispJSON = json.loads(mispJSON)
        except json.decoder.JSONDecodeError:
            # We couldn't make head nor tail of it
            raise MISPLoadError("COULD NOT LOAD MISP JSON!")

    # We should now have a proper MISP JSON loaded.
    
    # Create a base stix
    stix = STIXPackage()
    
    # Create a header for the new stix
    stix.stix_header = STIXHeader()

    # Try to use the event title as the stix title
    if "info" in mispJSON:
        stix.stix_header.title = mispJSON["Event"]["info"]
    else:
        # We don't have an easy name for it
        stix.stix_header.title = "MISP Export" 
        # Best we can do really
    
    # Get the event Attributes
    attributes =  mispJSON["Event"]["Attribute"]
    
    # We're going to store our observables inside an indicator
    indicator = Indicator()

    # Go through each attribute and transfer what we can.
    for one_attrib in attributes:
        # Build an attribute from the JSON. Is all nice.
        buildSTIXAttribute.buildAttribute(one_attrib, stix, indicator)
    stix.add_indicator(indicator)
    return stix

def STIXtoMISP(stix, mispAPI, **kwargs):
    """
        Function to convert from something stixxy ( as we have 3 possible representations )
        to something mispy. Specifically JSON. Because XML is satan. 
        
        :param stix: Something stixxy.
    """

    log.info("Converting a package from STIX to MISP...")

    if not isinstance(stix, STIXPackage):
        # Oh no we have to try and load it now
        try:
            # Try loading from JSON
            stix = STIXPackage().from_json(stix)
        except:
            # Ok then try loading from XML
            try:
                stix = STIXPackage().from_xml(stix)
            except:
                # No joy. Quit.
                raise STIXLoadError("Could not load stix file.")
    
    # Ok by now we should have a proper STIX object.
    return buildMISPAttribute.buildEvent(stix, mispAPI) 
