#!/usr/bin/env python3
import re
import cybox
import logging
import hashlib
import six

from pymisp import mispevent

from misp_stix_converter.converters.lint_roller import lintRoll

from stix.core import STIXPackage

# Cybox cybox don't we all love cybox children
from cybox.objects import email_message_object, file_object, address_object
from cybox.objects import domain_name_object, hostname_object, uri_object
from cybox.objects import mutex_object, whois_object
from cybox.objects import as_object, http_session_object
from cybox.objects import pipe_object, network_packet_object, win_registry_key_object
from cybox.objects import x509_certificate_object, win_executable_file_object, win_process_object

# Just a little containment file for STIX -> MISP conversion
ipre = re.compile("([0-9]{1,3}.){3}[0-9]{1,3}")
log = logging.getLogger("__main__")


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


def open_stix(stix_thing):
    # Load the package
    if not hasattr(stix_thing, 'read'):
        stix_thing = open(stix_thing, "r")

    pkg = None
    try:
        pkg = STIXPackage().from_xml(stix_thing)
    except Exception:
        try:
            pkg = STIXPackage.from_json(stix_thing)
        except Exception:
            raise Exception("Could not load package!")
    return pkg


def buildEvent(pkg, **kwargs):
    log.info("Building Event...")
    if not pkg.stix_header:
        title = "STIX Import"
    else:
        if not pkg.stix_header.title:
            title = "STIX Import"
        else:
            title = pkg.stix_header.title
    log.info(title)
    event = mispevent.MISPEvent()
    event.distribution = kwargs.get("distribution", 0)
    event.threat_level_id = kwargs.get("threat_level_id", 3)
    event.analysis = kwargs.get("analysis", 0)
    event.info = title

    ids = []
    to_process = []
    for obj in lintRoll(pkg):
        if isinstance(obj, cybox.core.observable.Observable):
            if obj.id_ not in ids:
                ids.append(obj.id_)
                to_process.append(obj)

    for obj in to_process:
        # This will find literally every object ever.
        event = buildAttribute(obj, event)
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
                    # We've got an address object, naturally
                    # We can check if it's a source or dest
                    if obj.is_source:
                        mispEvent.add_attribute('ip-src', six.text_type(obj.address_value),
                                                comment=pkg.title or None)
                    elif obj.is_destination:
                        mispEvent.add_attribute('ip-dst', six.text_type(obj.address_value),
                                                comment=pkg.title or None)
                    else:
                        # We don't know, first check if it's an IP range
                        if hasattr(obj, "condition") and obj.condition:
                            if obj.condition == "InclusiveBetween":
                                # Ok, so it's a range. hm. Shall we add them seperately#comma#or together?
                                mispEvent.add_attribute('ip-dst', six.text_type(obj.address_value[0]))
                                mispEvent.add_attribute('ip-dst', six.text_type(obj.add_attribute[1]))
                        else:
                            # Don't have anything to go on
                            mispEvent.add_attribute('ip-dst', six.text_type(obj.address_value),
                                                    comment=pkg.title or None)
                elif type_ == domain_name_object.DomainName:
                    mispEvent.add_attribute('domain', six.text_type(obj.value), comment=pkg.title or None)
                elif type_ == hostname_object.Hostname:
                    mispEvent.add_attribute('hostname', six.text_type(obj.hostname_value),
                                            comment=pkg.title or None)
                elif type_ == uri_object.URI:
                    mispEvent.add_attribute('url', six.text_type(obj.value),
                                            comment=pkg.title or None)
                elif type_ == file_object.File:
                    # This is a bit harder
                    # NOTE: Work in progress, only getting hashes
                    if obj.md5:
                        # We actually have to check the length
                        # An actual report had supposed md5s of length 31. Silly.
                        if len(obj.md5) == 32:
                            mispEvent.add_attribute('md5', six.text_type(obj.md5), comment=pkg.title or None)
                    if obj.sha1:
                        if len(obj.sha1) == 40:
                            mispEvent.add_attribute('sha1', six.text_type(obj.sha1), comment=pkg.title or None)
                    if obj.sha256:
                        if len(obj.sha256) == 64:
                            mispEvent.add_attribute('sha256', six.text_type(obj.sha256), comment=pkg.title or None)


                elif type_ == email_message_object.EmailMessage:
                    if obj.header:
                        # We have a header, can check for to/from etc etc
                        if obj.header.from_:
                            mispEvent.add_attribute('email-src', six.text_type(obj.header.from_.address_value),
                                                    comment=pkg.title or None)
                        if obj.header.to:
                            for mail in obj.header.to:
                                mispEvent.add_attribute('email-dst', six.text_type(mail.address_value),
                                                        comment=pkg.title or None)
                        if obj.header.subject:
                            mispEvent.add_attribute('email-subject', six.text_type(obj.header.subject),
                                                    comment=pkg.title or None)
                    if obj.attachments:
                        # FIXME that's definitely broken, but I have no sample.
                        for att in obj.attachments:
                            mispEvent.add_attribute('email-attachment', att.value,
                                                    comment=pkg.title or None)
                elif type_ == mutex_object.Mutex:
                    mispEvent.add_attribute('mutex', six.text_type(obj.name), comment=pkg.title or None)
                elif type_ == whois_object.WhoisEntry:
                    pass
                elif type_ == win_registry_key_object.WinRegistryKey:
                    pass
                elif type_ == network_packet_object.NetworkPacket:
                    pass
                elif type_ == http_session_object.HTTPSession:
                    pass
                elif type_ == pipe_object.Pipe:
                    mispEvent.add_attribute('named pipe', six.text_type(obj.name), comment=pkg.title or None)
                elif type_ == as_object.AS:
                    mispEvent.add_attribute('AS', six.text_type(obj.number),
                                            comment=pkg.title or six.text_type(obj.name) or None)
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
    return mispEvent
