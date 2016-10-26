#!/usr/bin/env python3
import re
import cybox
import logging
import hashlib
import json

from pymisp import mispevent

from threatintel.converters.lint_roller import lintRoll

# Cybox cybox don't we all love cybox children
from cybox.objects import email_message_object, file_object, address_object
from cybox.objects import domain_name_object, hostname_object, uri_object
from cybox.objects import mutex_object, whois_object
from cybox.objects import as_object, http_session_object
from cybox.objects import pipe_object, network_packet_object, win_registry_key_object


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


def buildEvent(pkg, mispAPI, **kwargs):
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

    for obj in lintRoll(pkg):
        # This will find literally every object ever.
        event = buildAttribute(obj, event)
    if event.attributes:
        response = mispAPI.add_event(json.dumps(event, cls=mispevent.EncodeUpdate))
        if response.get('errors'):
            # FIXME *maybe* we want to raise a thing there....
            pass
            # raise Exception(response.get('errors'))


def buildAttribute(pkg, mispEvent):
    try:
        # Check if the object is a cybox observable
        if type(pkg) == cybox.core.observable.Observable:
            if hasattr(pkg, "object_") and pkg.object_:
                obj = pkg.object_.properties
                # It's a proper object!
                type_ = type(obj)
                # Here comes the fun!
                if type_ == address_object.Address:
                    # We've got an address object, naturally
                    # We can check if it's a source or dest
                    if obj.is_source:
                        mispEvent.add_attribute('ip-src', obj.address_value.value,
                                                comment=pkg.title or "IP Source")
                    elif obj.is_destination:
                        mispEvent.add_attribute('ip-dst', obj.address_value.value,
                                                comment=pkg.title or "IP Dest")
                    else:
                        # Don't have anything to go on
                        mispEvent.add_attribute('ip-dst', obj.address_value.value,
                                                comment=pkg.title or "IP Addr")
                elif type_ == domain_name_object.DomainName:
                    mispEvent.add_attribute('domain', obj.value,
                                            comment=pkg.title or "Domain")
                elif type_ == hostname_object.Hostname:
                    mispEvent.add_attribute('hostname', obj.hostname_value,
                                            comment=pkg.title or "Hostname")
                elif type_ == uri_object.URI:
                    mispEvent.add_attribute('url', obj.value.value,
                                            comment=pkg.title or "Hostname")
                elif type_ == file_object.File:
                    # This is a bit harder
                    # TODO: This
                    pass

                elif type_ == email_message_object.EmailMessage:
                    if obj.header:
                        # We have a header, can check for to/from etc etc
                        if obj.header.from_:
                            mispEvent.add_attribute('email-src', obj.header.from_, comment="Email From Addr")
                        if obj.header.to:
                            mispEvent.add_attribute('email-dst', obj.header.to, comment="Email to Addr")
                        if obj.header.subject:
                            mispEvent.add_attribute('email-subject', obj.header.subject.value, comment="Email Sub")
                    if obj.attachments:
                        for att in obj.attachments:
                            mispEvent.add_attribute('email-attachment', att.value, comment="Email Attachment")
                elif type_ == mutex_object.Mutex:
                    mispEvent.add_attribute('mutex', obj.name, comment=pkg.title or "MUTEX")
                elif type_ == whois_object.WhoisEntry:
                    pass
                elif type_ == win_registry_key_object.WinRegistryKey:
                    pass
                elif type_ == network_packet_object.NetworkPacket:
                    pass
                elif type_ == http_session_object.HTTPSession:
                    pass
                elif type_ == pipe_object.Pipe:
                    # FIXME supported
                    log.debug("Named Pipe not supported by API.")
                elif type_ == as_object.AS:
                    # FIXME supported
                    log.debug("AS Attribute not supported by API.")
                else:
                    log.debug("Type not syncing {}".format(type_))
            else:
                pass
        else:
            pass  # Other objects. TODO.
    except Exception as ex:
        log.error(ex)
    return mispEvent
