#!/usr/bin/env python3

# A decoupled converter for misp<->Stix

# Imports
# Sys imports
import logging
from tempfile import NamedTemporaryFile
import json

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
        return stix

    f = NamedTemporaryFile(mode="w+")
    f.write(stix)
    f.seek(0)
    # Oh no we have to try and load it now
    try:
        # Try loading from JSON
        stix_package = STIXPackage().from_json(f.name)
    except:
        # Ok then try loading from XML
        try:
            stix_package = STIXPackage().from_xml(f.name)
        except Exception as ex:
            # No joy. Quit.
            raise STIXLoadError("Could not load stix file. {}".format(ex))
    return stix_package


def STIXtoMISP(stix, mispAPI, **kwargs):
    """
        Function to convert from something stixxy ( as we have 3 possible representations )
        to something mispy. Specifically JSON. Because XML is satan.

        :param stix: Something stixxy.
    """

    log.info("Converting a package from STIX to MISP...")
    stix = load_stix(stix)
    # Ok by now we should have a proper STIX object.

    misp_event = buildMISPAttribute.buildEvent(stix, **kwargs)
    if misp_event.attributes:
        response = mispAPI.add_event(json.dumps(misp_event, cls=mispevent.EncodeUpdate))
        if response.get('errors'):
            # FIXME *maybe* we want to raise a thing there....
            pass
            # raise Exception(response.get('errors'))

        return response
