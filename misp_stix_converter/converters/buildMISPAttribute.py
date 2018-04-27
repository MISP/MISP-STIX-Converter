#!/usr/bin/env python3
import re
import cybox
import logging
import hashlib
import ast
from pymisp import mispevent
from misp_stix_converter.converters.lint_roller import lintRoll
from stix.core import STIXPackage


# Cybox cybox don't we all love cybox children
from cybox.objects import email_message_object, file_object, address_object, socket_address_object
from cybox.objects import domain_name_object, hostname_object, uri_object
from cybox.objects import mutex_object, whois_object
from cybox.objects import as_object, http_session_object
from cybox.objects import pipe_object, network_packet_object, win_registry_key_object
from cybox.objects import x509_certificate_object, win_executable_file_object, win_process_object


# Just a little containment file for STIX -> MISP conversion
ipre = re.compile("([0-9]{1,3}.){3}[0-9]{1,3}")
log = logging.getLogger("__main__")


def uniq(lst):
    return_list = []
    for elem in lst:
        if elem not in return_list:
            return_list.append(elem)
    return return_list


def ast_eval(node):
    try:
        node = ast.literal_eval(node)
        if isinstance(node, list):
            node = uniq(node)
        return node
    except ValueError:
        return str(node)
    except SyntaxError:
        return str(node)


def parseRelated(obj, mispEvent, pkg):
    """Dedicated to parse related object
    Support for first level "importRelated.related_objects"
    """

    for i in obj.related_object:
        type_ = type(i.properties)
        # Here comes the sun (and of course the fun) for related objects! (DB)
        if type_ == address_object.Address:
            buildAddressAttribute(i.properties, mispEvent, pkg)

        elif type_ == domain_name_object.DomainName:
            buildDomainNameAttribute(i.properties, mispEvent, pkg)

        elif type_ == hostname_object.Hostname:
            buildHostnameAttribute(i.properties, mispEvent, pkg)

        elif type_ == socket_address_object.SocketAddress:
            buildAddressAttribute(i.properties, mispEvent, pkg, True)

        elif type_ == uri_object.URI:
            buildURIAttribute(i.properties, mispEvent, pkg)

        elif type_ == file_object.File:
            buildFileAttribute(i.properties, mispEvent, pkg)

        elif type_ == email_message_object.EmailMessage:
            buildEmailMessageAttribute(i.properties, mispEvent, pkg)

    return mispEvent


def parseAttachment(obj, mispEvent, pkg):
    """
    Limited support for email attachments, just consider this a work in progress
    """

    for i in obj:
        # Assuming any email attached file is a... file!
        buildFileAttribute(i.properties, mispEvent, pkg)

    return mispEvent


def buildFileAttribute(obj, mispEvent, pkg, importRelated=False):
    """
    All you can get by a File object in a single method
    TODO: all possible attributes are not yet parsed
    """

    if obj.file_name:
        mispEvent.add_attribute('filename', ast_eval(str(obj.file_name)), comment=pkg.title or None)

    # Added support to file_extension
    # No MISP object available for file extension
    # I propose to use pattern-in-file. Suggestions are welcome! (DB)
    if obj.file_extension:
        mispEvent.add_attribute('pattern-in-file', ast_eval(str(obj.file_extension)), comment=pkg.title or None)

    if obj.size_in_bytes:
        mispEvent.add_attribute('size-in-bytes', ast_eval(str(obj.size_in_bytes)), comment=pkg.title or None)

    if obj.md5:
        # We actually have to check the length
        # An actual report had supposed md5s of length 31. Silly.
        if len(str(obj.md5)) == 32:
            mispEvent.add_attribute('md5', ast_eval(str(obj.md5)), comment=pkg.title or None)

    if obj.sha1:
        if len(str(obj.sha1)) == 40:
            mispEvent.add_attribute('sha1', ast_eval(str(obj.sha1)), comment=pkg.title or None)

    if obj.sha256:
        if len(str(obj.sha256)) == 64:
            mispEvent.add_attribute('sha256', ast_eval(str(obj.sha256)), comment=pkg.title or None)

    # Added support for SHA512 (DB)
    if obj.sha512:
        if len(str(obj.sha512)) == 128:
            mispEvent.add_attribute('sha512', ast_eval(str(obj.sha512)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return mispEvent


def buildAddressAttribute(obj, mispEvent, pkg, importRelated=False):

    # See issue #34
    # Apparently this can be an email?
    if obj.category == "e-mail":
        # it's an email address (for some reason)
        if obj.is_source:
            mispEvent.add_attribute("email-src", ast_eval(str(obj.address_value)),
                                    comment=pkg.title or None)

        elif obj.is_destination:
            mispEvent.add_attribute("email-dst", ast_eval(str(obj.address_value)),
                                    comment=pkg.title or None)
        else:
            mispEvent.add_attribute("email-src", ast_eval(str(obj.address_value)),
                                    comment=pkg.title or None)
           
    elif obj.category == "ipv4-addr":
        if obj.is_source:
            mispEvent.add_attribute('ip-src', ast_eval(str(obj.address_value)), 
                                    comment=pkg.title or None)

        elif obj.is_destination:
            mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)), 
                                    comment=pkg.title or None)
    
        else:
            # We don't know, first check if it's an IP range
            if hasattr(obj, "condition") and obj.condition:
                if obj.condition == "InclusiveBetween":
                    # Ok, so it's a range. hm. Shall we add them seperately#comma#or together?
                    mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value[0])))
                    mispEvent.add_attribute('ip-dst', ast_eval(str(obj.add_attribute[1])))
            
                elif obj.condition == "Equals":
                    mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)), 
                                            comment=pkg.title or None)
        
                else:
                    # Don't have anything to go on
                    mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)), 
                                            comment=pkg.title or None)
            else:
                # Don't have anything to go on
                mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)),
                                        comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return mispEvent


def buildEmailMessageAttribute(obj, mispEvent, pkg, importRelated=False):
    if obj.header:
        # We have a header, can check for to/from etc etc
        if obj.header.from_:
            mispEvent.add_attribute('email-src',
                                    ast_eval(str(obj.header.from_.address_value)),
                                    comment=pkg.title or None)
        if obj.header.to:
            for mail in obj.header.to:
                mispEvent.add_attribute('email-dst', ast_eval(mail.address_value), comment=pkg.title or None)
        if obj.header.subject:
            mispEvent.add_attribute('email-subject', ast_eval(str(obj.header.subject)), comment=pkg.title or None)

    if obj.attachments and pkg.object_.related_objects:
        parseAttachment(pkg.object_.related_objects, mispEvent, pkg)

    elif importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return mispEvent


def buildDomainNameAttribute(obj, mispEvent, pkg, importRelated=False):
    mispEvent.add_attribute('domain', ast_eval(str(obj.value)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return mispEvent


def buildHostnameAttribute(obj, mispEvent, pkg, importRelated=False):
    mispEvent.add_attribute('hostname', ast_eval(str(obj.hostname_value)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return mispEvent


def buildURIAttribute(obj, mispEvent, pkg, importRelated=False):
    mispEvent.add_attribute('url', ast_eval(str(obj.value)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return mispEvent


def identifyHash(hsh):
    """
    What's that hash!?
    """

    possible_hashes = []

    hashes = [x for x in hashlib.algorithms_guaranteed]

    for h in hashes:
        if len(str(hsh)) == len(hashlib.new(h).hexdigest()):
            possible_hashes.append(h)
            possible_hashes.append("filename|{}".format(h))
    return possible_hashes


def buildEvent(pkg, **kwargs):
    log.info("Building Event...")
    if not pkg.stix_header:
        title = "STIX Import"
    else:
        if not pkg.stix_header.title:
            title = "STIX Import"
        else:
            title = pkg.stix_header.title
    log.info("Using title %s", title)

    log.debug("Seting up MISPEvent...")
    event = mispevent.MISPEvent()
    event.distribution = kwargs.get("distribution", 0)
    event.threat_level_id = kwargs.get("threat_level_id", 3)
    event.analysis = kwargs.get("analysis", 0)
    event.info = title

    if hasattr(pkg, "description"):
        log.debug("Found description %s", pkg.description)
        event.add_attribute("comment", pkg.description)

    log.debug("Beginning to Lint_roll...")
    ids = []
    to_process = []
    for obj in lintRoll(pkg):
        if isinstance(obj, cybox.core.observable.Observable):
            if obj.id_ not in ids:
                ids.append(obj.id_)
                to_process.append(obj)

    log.debug("Processing %s object...", len(to_process))
    for obj in to_process:
        log.debug("Working on %s...", obj)
        # This will find literally every object ever.
        try:
            event = buildAttribute(obj, event)
        except Exception as ex:
            log.exception(ex)
    # Now make sure we only have unique items
    log.debug("Making sure we only have Unique attributes...")
    
    uniqueAttribValues = []

    for attrindex, attrib in enumerate(event.attributes):
        if attrib.value not in uniqueAttribValues:
            uniqueAttribValues.append(attrib.value)
        else:
            log.debug("Removed duplicated attribute in package: %s", attrib.value)
            event.attributes.pop(attrindex)

    log.debug("Finished parsing attributes.")
    return event


def buildAttribute(pkg, mispEvent):
    try:
        # Check if the object is a cybox observable
        if isinstance(pkg, cybox.core.observable.Observable):
            if hasattr(pkg, "object_") and pkg.object_:

                obj = pkg.object_.properties

                # It's a proper object!
                type_ = type(obj)
                # Here comes the fun!
                if type_ == address_object.Address:
                    # Now script uses buildAddressAttribute (DB)
                    buildAddressAttribute(obj, mispEvent, pkg, True)

                elif type_ == domain_name_object.DomainName:
                    # Now script uses buildDomainNameAttribute (DB)
                    buildDomainNameAttribute(obj, mispEvent, pkg, True)

                elif type_ == hostname_object.Hostname:
                    # Now script uses buildHostnameAttribute
                    buildHostnameAttribute(obj, mispEvent, pkg, True)

                elif type_ == socket_address_object.SocketAddress:
                    if obj.ip_address:
                        buildAddressAttribute(obj.ip_address, mispEvent, pkg, True)
                    if obj.hostname:
                        buildHostnameAttribute(obj.hostname, mispEvent, pkg, True)

                elif type_ == uri_object.URI:
                    # Now script uses buildURIAttribute (DB)
                    buildURIAttribute(obj, mispEvent, pkg, True)

                elif type_ == file_object.File:
                    # Now script uses buildFileAttribute (DB)
                    buildFileAttribute(obj, mispEvent, pkg, True)

                elif type_ == email_message_object.EmailMessage:
                    # Now script uses buildEmailMessageAttribute (DB)
                    buildEmailMessageAttribute(obj, mispEvent, pkg, True)

                elif type_ == mutex_object.Mutex:
                    mispEvent.add_attribute('mutex', ast_eval(str(obj.name)), comment=pkg.title or None)
                elif type_ == whois_object.WhoisEntry:
                    pass
                elif type_ == win_registry_key_object.WinRegistryKey:
                    pass
                elif type_ == network_packet_object.NetworkPacket:
                    pass
                elif type_ == http_session_object.HTTPSession:
                    pass
                elif type_ == pipe_object.Pipe:
                    mispEvent.add_attribute('named pipe', ast_eval(str(obj.name)), comment=pkg.title or None)
                elif type_ == as_object.AS:
                    mispEvent.add_attribute('AS', ast_eval(str(obj.number)),
                                            comment=pkg.title or ast_eval(str(obj.name)) or None)
                elif type_ == win_executable_file_object.WinExecutableFile:
                    pass
                elif type_ == win_process_object.WinProcess:
                    pass
                elif type_ == x509_certificate_object.X509Certificate:
                    pass
                else:
                    log.debug("Type not syncing %s", type_)
            else:
                pass
        else:
            pass  # Other objects. TODO.
    except Exception as ex:
        log.error(ex)
        log.exception(ex, exc_info=True)

    return mispEvent
