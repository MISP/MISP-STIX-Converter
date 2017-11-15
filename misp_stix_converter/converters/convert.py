#!/usr/bin/env python3

# A decoupled converter for misp<->Stix

# Imports
# Sys imports
import logging
from tempfile import SpooledTemporaryFile
import json
import base64
import random
import sys
from pymisp.abstract import MISPEncode
from pymisp import mispevent
from lxml import etree

# Stix imports
from stix.core import STIXPackage
from stix.core import STIXHeader
from stix.indicator import Indicator
from stix.utils import nsparser
import mixbox.namespaces
from mixbox.namespaces import Namespace

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
    except Exception:
        # We don't have an ID?
        # Generate a random number and use that
        stix.MISPID = random.randint(1, 9000)
    # it's being silly
    # backup the ID
    backupID = stix.MISPID

    # Create a header for the new stix
    stix.stix_header = STIXHeader()

    # Try to use the event title as the stix title
    stix.stix_header.title = misp_event.info

    # Go through each attribute and transfer what we can.
    for one_attrib in misp_event.attributes:
        # We're going to store our observables inside an indicator
        # One for each attribute because @iglocska said so
        # I swear STIX is gonna be the death of me.
        indicator = Indicator()

        # Build an attribute from the JSON. Is all nice.
        buildSTIXAttribute.buildAttribute(one_attrib, stix, indicator)

        stix.add_indicator(indicator)

    stix.MISPID = backupID

    return stix


def load_stix(stix):
    # Just save the pain and load it if the first character is a <
    log.debug("Loading STIX...")
    if sys.version_info < (3, 5):
        json_exception = ValueError
    else:
        json_exception = json.JSONDecodeError

    if isinstance(stix, STIXPackage):
        log.debug("Argument was already STIX package, ignoring.")
        # Oh cool we're ok
        # Who tried to load this? Honestly.
        return stix

    elif hasattr(stix, 'read'):
        log.debug("Argument has 'read' attribute, assuming file-like.")
        # It's a file!
        # But somehow, sometimes, reading it returns a bytes stream and the loader dies on python 3.4.
        # Luckily, STIXPackage.from_json (which is mixbox.Entity.from_json) will happily load a string.
        # So we're going to play dirty.
        data = stix.read()
        log.debug("Read file, type %s.", type(data))

        if isinstance(data, bytes):
            data = data.decode()
        try:
            log.debug("Attempting to load from JSON...")
            # Try loading from JSON
            stix_package = STIXPackage.from_json(data)
        except json_exception:
            log.debug("Attempting to load from XML...")
            # Ok then try loading from XML
            # Loop zoop
            # Read the STIX into an Etree
            stix.seek(0)
            stixXml = etree.fromstring(stix.read())

            ns_map = stixXml.nsmap

            # Remove any "marking" sections because the US-Cert is evil
            log.debug("Removing Marking elements...")
            for element in stixXml.findall(".//{http://data-marking.mitre.org/Marking-1}Marking"):
                element.getparent().remove(element)

            log.debug("Writing cleaned XML to Tempfile")
            f = SpooledTemporaryFile(max_size=10 * 1024)
            f.write(etree.tostring(stixXml))
            f.seek(0)

            # Pray to anything you hold sacred
            ns_objmap = map(lambda x: Namespace(ns_map[x], x), ns_map)

            for ns in ns_objmap:
                log.debug("Trying to add namespace %s", ns)
                try:
                    nsparser.STIX_NAMESPACES.add_namespace(ns)
                    mixbox.namespaces.register_namespace(ns)
                except Exception as ex:
                    log.exception(ex)
    
            try:
                log.debug("Attempting to read clean XML into STIX...")
                stix_package = STIXPackage.from_xml(f)
            except Exception as ex:
                # No joy. Quit.
                print(ex)
                log.fatal("Could not :<")
                f.seek(0)
                with open("FAILED_STIX.xml", "wb") as g:
                    g.write(f.read())
                raise STIXLoadError("Could not load stix file. {}".format(ex))

        return stix_package

    elif isinstance(stix, (str, bytes)):
        if isinstance(stix, bytes):
            stix = stix.decode()

        # It's text, we'll need to use a temporary file

        # Create a temporary file to load from
        # Y'know I should probably give it a max size before jumping to disk
        # idk, 10MB? Sounds reasonable.
        f = SpooledTemporaryFile(max_size=10 * 1024)

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
    log.debug("Package loaded")

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
            if stixPackage.stix_header.title not in ["", None]:
                filename = stixPackage.stix_header.title + ".xml"

    log.debug("Using filename %s", filename)

    misp_event = buildMISPAttribute.buildEvent(stixPackage, **kwargs)

    log.debug("Encoding to b64...")
    b64Pkg = base64.b64encode(stixPackage.to_xml()).decode("utf-8")
    log.debug("Attaching original document...")

    misp_event.add_attribute(type="attachment", value=filename, data=b64Pkg)

    if misp_event.attributes:
        log.debug("Attributes exist. Pushing...")
        if mispAPI:
            response = mispAPI.add_event(json.dumps(misp_event, cls=MISPEncode))
            if response.get('errors'):
                raise Exception("PACKAGE: {}\nERROR: {}".format(
                                                        json.dumps(misp_event, cls=MISPEncode),
                                                        response.get('errors')))

            return response
        else:
            return True # Dry run
    else:
        log.warning("No attributes found, ignoring.")
