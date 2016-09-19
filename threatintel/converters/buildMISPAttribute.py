#!/usr/bin/env python3
import re
import json
import stix
import cybox
import logging
import hashlib

from threatintel.converters.lint_roller import lintRoll
from stix.core import STIXPackage

#Cybox cybox don't we all love cybox children
from cybox.objects import email_message_object,file_object, address_object
from cybox.objects import domain_name_object, hostname_object, uri_object
from cybox.objects import link_object, mutex_object, whois_object
from cybox.objects import x509_certificate_object, as_object, http_session_object
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
    event = mispAPI.new_event(
                               distribution = kwargs.get("distribution",0),
                               threat_level_id = kwargs.get("threat_level_id", 3),
                               analysis = kwargs.get("analysis", 0),
                               info = title
                              )
    
    for obj in lintRoll(pkg):
        # This will find literally every object ever.
        buildAttribute(obj, event, mispAPI)
    e2 = mispAPI.get(event["Event"]["id"])
    if len(e2["Event"]["Attribute"]) == 0:
        mispAPI.delete_event(event["Event"]["id"])

def buildAttribute(pkg, mispEvent, mispAPI):
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
                        mispAPI.add_ipsrc(mispEvent, obj.address_value.value, 
                                          comment = pkg.title or "IP Source")
                    
                    elif obj.is_destination:
                        mispAPI.add_ipdst(mispEvent, obj.address_value.value,
                                          comment = pkg.title or "IP Dest")
                    else:
                        # Don't have anything to go on
                        mispAPI.add_ipdst(mispEvent, obj.address_value.value,
                                          comment = pkg.title or "IP Addr")

                elif type_ == domain_name_object.DomainName:
                    mispAPI.add_domain(mispEvent, obj.value, comment=pkg.title or "Domain")

                elif type_ == hostname_object.Hostname:
                    mispAPI.add_hostname(mispEvent, obj.hostname_value, comment=pkg.title or "Hostname")
    
                elif type_ == uri_object.URI:
                    mispAPI.add_url(mispEvent, obj.value, comment=pkg.title or "URI")

                elif type_ == file_object.File:
                    # This is a bit harder
                    # TODO: This
                    pass

                elif type_ == email_message_object.EmailMessage:
                    if obj.header:
                        # We have a header, can check for to/from etc etc
                        if obj.header.from_:
                            mispAPI.add_email_src(mispEvent, obj.header.from_, comment="Email From Addr")
                        if obj.header.to:
                            mispAPI.add_email_dst(mispEvent, obj.header.to, comment="Email to Addr")
                        if obj.header.subject:
                            mispAPI.add_email_subject(mispEvent, obj.header.subject, comment="Email Sub")
                    if emsg.attachments:
                        for att in emsg.attachments:
                            mispAPI.add_email_attachment(mispEvent, att, comment = "Email Attachment")

                elif type_ == mutex_object.Mutex:
                    mispAPI.add_mutex(mispEvent, obj.name, comment = pkg.title or "MUTEX")

                elif type_ == whois_object.WhoisEntry:
                    pass
    
                elif type_ == win_registry_key_object.WinRegistryKey:
                    pass

                elif type_ == network_packet_object.NetworkPacket:
                    pass

                elif type_ == http_session_object.HTTPSession:
                    pass

                elif type_ == pipe_object.Pipe:
                    # Not supported
                    log.debug("Named Pipe not supported by API.")
    
                elif type_ == as_object.AS:
                    # Not supposed by API
                    log.debug("AS Attribute not supported by API.")
                
                else:
                    log.debug("Type not syncing {}".format(type_))                
            else:
                pass
        else:
            pass #Other objects. TODO.
    except Exception as ex:
        log.error(ex)

