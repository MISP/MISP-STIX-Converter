#!/usr/bin/env python3
import re
import cybox
import logging
import hashlib
import ast
from pymisp import mispevent
from misp_stix_converter.converters.lint_roller import lintRoll


# Cybox cybox don't we all love cybox children
from cybox.objects import email_message_object, file_object, address_object, socket_address_object
from cybox.objects import domain_name_object, hostname_object, uri_object
from cybox.objects import mutex_object, whois_object, link_object
from cybox.objects import as_object, http_session_object
from cybox.objects import pipe_object, network_packet_object, win_registry_key_object
from cybox.objects import x509_certificate_object, win_executable_file_object, win_process_object


# Just a little containment file for STIX -> MISP conversion
ipre = re.compile("([0-9]{1,3}.){3}[0-9]{1,3}")

# Precompilie regex patterns for threatconnect
src_pattern = r"src:\s+([^\|]+)"
threatassess_pattern = r"threatassess:\s+([^\|]+)"
falsepositives_pattern = r"falsepositives:\s+([^\|]+)"
owner_pattern = r"owner:\s+([^\|]+)"

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
    attribute = None
    if obj.file_name:
        attribute = mispEvent.add_attribute('filename', ast_eval(
            str(obj.file_name)), comment=pkg.title or None)

    # Added support to file_extension
    # No MISP object available for file extension
    # I propose to use pattern-in-file. Suggestions are welcome! (DB)
    if obj.file_extension:
        attribute = mispEvent.add_attribute(
            'pattern-in-file', ast_eval(str(obj.file_extension)), comment=pkg.title or None)

    if obj.size_in_bytes:
        attribute = mispEvent.add_attribute(
            'size-in-bytes', ast_eval(str(obj.size_in_bytes)), comment=pkg.title or None)

    if obj.md5:
        # We actually have to check the length
        # An actual report had supposed md5s of length 31. Silly.
        if len(str(obj.md5)) == 32:
            attribute = mispEvent.add_attribute(
                'md5', ast_eval(str(obj.md5)), comment=pkg.title or None)

    if obj.sha1:
        if len(str(obj.sha1)) == 40:
            attribute = mispEvent.add_attribute(
                'sha1', ast_eval(str(obj.sha1)), comment=pkg.title or None)

    if obj.sha256:
        if len(str(obj.sha256)) == 64:
            attribute = mispEvent.add_attribute('sha256', ast_eval(
                str(obj.sha256)), comment=pkg.title or None)

    # Added support for SHA512 (DB)
    if obj.sha512:
        if len(str(obj.sha512)) == 128:
            attribute = mispEvent.add_attribute('sha512', ast_eval(
                str(obj.sha512)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return attribute, mispEvent


def buildAddressAttribute(obj, mispEvent, pkg, importRelated=False):
    attribute = None
    # See issue #34
    # Apparently this can be an email?
    if obj.category == "e-mail":
        # it's an email address (for some reason)
        if obj.is_source:
            attribute = mispEvent.add_attribute("email-src", ast_eval(str(obj.address_value)),
                                                comment=pkg.title or None)

        elif obj.is_destination:
            attribute = mispEvent.add_attribute("email-dst", ast_eval(str(obj.address_value)),
                                                comment=pkg.title or None)
        else:
            attribute = mispEvent.add_attribute("email-src", ast_eval(str(obj.address_value)),
                                                comment=pkg.title or None)

    elif obj.category == "ipv4-addr":
        if obj.is_source:
            attribute = mispEvent.add_attribute('ip-src', ast_eval(str(obj.address_value)),
                                                comment=pkg.title or None)

        elif obj.is_destination:
            attribute = mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)),
                                                comment=pkg.title or None)

        else:
            # We don't know, first check if it's an IP range
            if hasattr(obj, "condition") and obj.condition:
                if obj.condition == "InclusiveBetween":
                    # Ok, so it's a range. hm. Shall we add them
                    # seperately#comma#or together?
                    attribute = mispEvent.add_attribute(
                        'ip-dst', ast_eval(str(obj.address_value[0])))
                    mispEvent.add_attribute(
                        'ip-dst', ast_eval(str(obj.add_attribute[1])))

                elif obj.condition == "Equals":
                    attribute = mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)),
                                                        comment=pkg.title or None)

                else:
                    # Don't have anything to go on
                    attribute = mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)),
                                                        comment=pkg.title or None)
            else:
                # Don't have anything to go on
                attribute = mispEvent.add_attribute('ip-dst', ast_eval(str(obj.address_value)),
                                                    comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return attribute, mispEvent


def buildEmailMessageAttribute(obj, mispEvent, pkg, importRelated=False):
    attribute = None
    if obj.header:
        # We have a header, can check for to/from etc etc
        if obj.header.from_:
            attribute = mispEvent.add_attribute('email-src',
                                                ast_eval(
                                                    str(obj.header.from_.address_value)),
                                                comment=pkg.title or None)
        if obj.header.to:
            for mail in obj.header.to:
                attribute = mispEvent.add_attribute(
                    'email-dst', ast_eval(mail.address_value), comment=pkg.title or None)
        if obj.header.subject:
            attribute = mispEvent.add_attribute(
                'email-subject', ast_eval(str(obj.header.subject)), comment=pkg.title or None)

    if obj.attachments and pkg.object_.related_objects:
        parseAttachment(pkg.object_.related_objects, mispEvent, pkg)

    elif importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return attribute, mispEvent


def buildDomainNameAttribute(obj, mispEvent, pkg, importRelated=False):
    attribute = None
    attribute = mispEvent.add_attribute('domain', ast_eval(
        str(obj.value)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return attribute, mispEvent


def buildHostnameAttribute(obj, mispEvent, pkg, importRelated=False):
    attribute = None
    attribute = mispEvent.add_attribute('hostname', ast_eval(
        str(obj.hostname_value)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return attribute, mispEvent


def buildURIAttribute(obj, mispEvent, pkg, importRelated=False):
    attribute = None
    attribute = mispEvent.add_attribute('url', ast_eval(
        str(obj.value)), comment=pkg.title or None)

    if importRelated and pkg.object_.related_objects:
        parseRelated(pkg.object_.related_objects, mispEvent, pkg)

    return attribute, mispEvent


def identifyHash(hsh):
    """
    What's that hash!?
    """

    possible_hashes = []

    hashes = [x for x in hashlib.algorithms_guaranteed]

    for h in hashes:
        try:
            if len(str(hsh)) == len(hashlib.new(h).hexdigest()):
                possible_hashes.append(h)
                possible_hashes.append("filename|{}".format(h))
        except TypeError:
            pass
    return possible_hashes


def parseThreatConnectTags(event, attribute, description):
    """
    Parse threatconnect metrics and add them as tags for MISP attributes
    https://threatconnect.com/stix-taxii/
    """
    try:
        tags = {"source": "", "threatassess": "",
                "falsepositives": "", "owner": ""}
        description = str(description)

        match = re.search(src_pattern, description)
        if match and len(match.groups()) == 1:
            tags["source"] = match.group(1)

        match = re.search(threatassess_pattern, description)
        if match and len(match.groups()) == 1:
            tags["threatassess"] = match.group(1)

        match = re.search(falsepositives_pattern, description)
        if match and len(match.groups()) == 1:
            tags["falsepositives"] = match.group(1)

        match = re.search(owner_pattern, description)
        if match and len(match.groups()) == 1:
            tags["owner"] = match.group(1)

        for tag in tags:
            if tags[tag]:
                event.add_attribute_tag("Threatconnect:{}={}".format(
                    str(tag), str(tags[tag]).strip()), attribute.uuid)

    except Exception as ex:
        log.exception("Exception Parsing Threatconnect tags")

    return attribute, event

def parseIndicatorHeader(stix_header,event):
    header = {"information_source.identity.name": "","event_info":"",
              "information_source.description": "", "information_source.references": ""}

    # Parse select vocabulary from stix_header
    try:
        if hasattr(stix_header,
                   "information_source") and stix_header.information_source:
            information_source = stix_header.information_source
            if (hasattr(information_source, "identity") and information_source.identity
                    and hasattr(information_source.identity, "name") and information_source.identity.name):
                header["information_source.identity.name"] = information_source.identity.name
                event.add_tag("STIX:Producer={}".format(
                    header["information_source.identity.name"]))
                log.debug("Information Source:%s",
                          header["information_source.identity.name"])
            if hasattr(information_source,
                       "decription") and information_source.description:
                header["information_source.description"] = information_source.description
                log.debug("Information source description:%s",
                          header["information_source.description"])
            if hasattr(information_source,
                       "references") and information_source.references:
                header["information_source.references"] = ';'.join(
                    list(information_source.references)).strip(';')
                log.debug("Information source references:%s",
                          header["information_source.references"])
        event_info = "Description:{}\nProducer:{}\nReferernces:{}\n".format(
            header["information_source.description"], header["information_source.identity.name"], header["information_source.references"]
        )
    except Exception as ex:
        log.exception("Error parsing STIX header:%s",str(ex))
        return header,'',event
    return header,event_info,event

def parseIndicatorMeta(indicator,event,attribute,header):
    meta = {"title": "", "description": "", "producer.identity.name": "",
            "producer.references": "", "producer.time.produced_time": ""}
    producers=set()
    try:
        if indicator.id_.startswith("threatconnect"):
            meta["threatconnect"] = True

        if not hasattr(attribute, "comment"):
            attribute.comment = ""
        if hasattr(indicator, "title") and indicator.title:
            meta["title"] = indicator.title
            log.debug("Title:%s", meta["title"])
        if hasattr(indicator, "description") and indicator.description:
            meta["description"] = indicator.description
            log.debug("Description:%s", meta["description"])

            # Parse threatconnect metrics:
            # https://threatconnect.com/stix-taxii/
            if "threatconnect" in meta and meta["threatconnect"]:
                parseThreatConnectTags(event, attribute, meta["description"])

        if hasattr(indicator, "confidence") and indicator.confidence and hasattr(
                indicator.confidence, "value") and indicator.confidence.value:
            log.debug("Confidence:%s", indicator.confidence.value)
            event.add_attribute_tag("STIX:Confidence={}".format(
                str(indicator.confidence.value)), attribute.uuid)
        if hasattr(indicator, "producer") and indicator.producer:
            producer = indicator.producer
            if hasattr(producer, "identity") and producer.identity and hasattr(
                    producer.identity, "name") and producer.identity.name:
                meta["producer.identity.name"] = producer.identity.name
                log.debug("Producer:%s", producer.identity.name)
                producers.add(producer.identity.name)
                event.add_attribute_tag("STIX:Producer={}".format(
                    str(producer.identity.name)), attribute.uuid)
            if hasattr(producer, "references") and producer.references:
                meta["producer.references"] = ';'.join(
                    list(producer.references)).strip(';')
                log.debug("Producer references:%s", meta["producer.references"])
            if hasattr(producer, "time") and producer.time and hasattr(
                    producer.time, "produced_time") and producer.time.produced_time:
                meta["producer.time.produced_time"] = str(
                    producer.time.produced_time.to_dict())
                log.debug("Produced time:%s",
                          meta["producer.time.produced_time"])
        if hasattr(indicator, "sightings") and indicator.sightings and hasattr(
                indicator.sightings, "sightings_count") and indicator.sightings.sightings_count:
            log.debug("Sightings:%s", indicator.sightings.sightings_count)
            misp_sighting = {"id": attribute.id, "uuid": attribute.uuid,
                             "value": indicator.sightings.sightings_count, "type": 0}
            if meta["producer.identity.name"]:
                misp_sighting["source"] = meta["producer.identity.name"]
            event.add_sighting(misp_sighting, attribute=attribute)

        attribute.comment = "{comment}\nTitle:{title}\nTime:{time}\n\nDescription:{description}\nProducer:{producer}\nReferences:{references}\n\nEvent Information:{info}\n".format(
            comment=attribute.comment, title=meta["title"], time=meta["producer.time.produced_time"],
            description=meta["description"], producer=meta["producer.identity.name"], references=meta["producer.references"], info=header["event_info"])
        meta["producers"] = list(producers)
    except Exception as ex:
        log.exception("Error parsing indicator metadata:%s",str(ex))

    return meta,attribute,event
        
def parseIndicators(event, pkg):
    stix_header = pkg.stix_header

    header,event_info,event = parseIndicatorHeader(stix_header,event)

    has_indicators = False
    for intent in pkg.stix_header.package_intents:
        if str(intent).lower() == "indicators":
            has_indicators = True
            break

    indicators = None
    if has_indicators:
        indicators = pkg.indicators
    else:
        log.info("No indicators!")
        return event

    processed = set()
    for indicator in indicators:

        # Loop through each indicator object and parse tags,comment data and
        # sighting
        if hasattr(indicator, "observable") and isinstance(
                indicator.observable, cybox.core.observable.Observable):
            if indicator.observable.id_ in processed:
                continue

        attribute, event_ = buildAttribute(indicator.observable, event)
        if event_:
            event = event_

        if not attribute:
            log.info("Failed to get an attribute object")
            return event

        meta, attribute, event = parseIndicatorMeta(indicator,event,attribute,header)
        # Add an event tag that includes a list of all the information sources
        # for the attributes in the feed.
        if len(meta["producers"]) > 0:
            event.add_tag("STIX:Producer={}".format(
                ','.join(meta["producers"]).strip(',')))
    return event


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
    event.distribution = kwargs.get("distribution", 1)
    event.threat_level_id = kwargs.get("threat_level_id", 3)
    event.analysis = kwargs.get("analysis", 0)
    event.info = title

    if hasattr(pkg, "description"):
        log.debug("Found description %s", pkg.description)
        event.add_attribute("comment", pkg.description)

    # Attempt to explicitly parse attributes using indicators object metadata
    event = parseIndicators(event, pkg)

    log.debug("Beginning to Lint_roll...")
    ids = []
    to_process = []

    # if we failed to parse any attributes for some reason, attempt the
    # lint_roll based parsing
    if not event or len(event.attributes) < 1:
        log.info("Resorting to Lint Roll:%s",str(pkg.to_json()))


        for obj in lintRoll(pkg):
            if isinstance(obj, cybox.core.observable.Observable):
                if obj.id_ not in ids:
                    ids.append(obj.id_)
                    to_process.append(obj)

        log.debug("Processing %s object...", len(to_process))
        for obj in to_process:
            # This will find literally every object ever.
            try:
                attribute, event_ = buildAttribute(obj, event)
                if event_:
                    event = event_
            except Exception as ex:
                log.exception(ex)
    # Now make sure we only have unique items
    log.debug("Making sure we only have Unique attributes...")

    uniqueAttribValues = []

    for attrindex, attrib in enumerate(event.attributes):
        if attrib.value not in uniqueAttribValues:
            uniqueAttribValues.append(attrib.value)
        else:
            log.debug(
                "Removed duplicated attribute in package: %s",
                attrib.value)
            event.attributes.pop(attrindex)

    log.debug("Finished parsing attributes.")
    return event


def buildAttribute(pkg, mispEvent):
    try:
        attribute = None
        # Check if the object is a cybox observable
        if isinstance(pkg, cybox.core.observable.Observable):
            if hasattr(pkg, "object_") and pkg.object_:

                obj = pkg.object_.properties

                # It's a proper object!
                type_ = type(obj)
                # Here comes the fun!
                if type_ == address_object.Address:
                    # Now script uses buildAddressAttribute (DB)
                    attribute, event_ = buildAddressAttribute(
                        obj, mispEvent, pkg, True)

                elif type_ == domain_name_object.DomainName:
                    # Now script uses buildDomainNameAttribute (DB)
                    attribute, event_ = buildDomainNameAttribute(
                        obj, mispEvent, pkg, True)

                elif type_ == hostname_object.Hostname:
                    # Now script uses buildHostnameAttribute
                    attribute, event_ = buildHostnameAttribute(
                        obj, mispEvent, pkg, True)

                elif type_ == socket_address_object.SocketAddress:
                    if obj.ip_address:
                        attribute, event_ = buildAddressAttribute(
                            obj.ip_address, mispEvent, pkg, True)
                    if obj.hostname:
                        attribute, event_ = buildHostnameAttribute(
                            obj.hostname, mispEvent, pkg, True)

                elif type_ == uri_object.URI or type_ == link_object.URI or link_object.Link:
                    # Now script uses buildURIAttribute (DB)
                    attribute, event_ = buildURIAttribute(
                        obj, mispEvent, pkg, True)

                elif type_ == file_object.File:
                    # Now script uses buildFileAttribute (DB)
                    attribute, event_ = buildFileAttribute(
                        obj, mispEvent, pkg, True)

                elif type_ == email_message_object.EmailMessage:
                    # Now script uses buildEmailMessageAttribute (DB)
                    attribute, event_ = buildEmailMessageAttribute(
                        obj, mispEvent, pkg, True)

                elif type_ == mutex_object.Mutex:
                    attribute = mispEvent.add_attribute(
                        'mutex', ast_eval(str(obj.name)), comment=pkg.title or None)
                elif type_ == whois_object.WhoisEntry:
                    pass
                elif type_ == win_registry_key_object.WinRegistryKey:
                    pass
                elif type_ == network_packet_object.NetworkPacket:
                    pass
                elif type_ == http_session_object.HTTPSession:
                    pass
                elif type_ == pipe_object.Pipe:
                    attribute = mispEvent.add_attribute(
                        'named pipe', ast_eval(str(obj.name)), comment=pkg.title or None)
                elif type_ == as_object.AS:
                    attribute, event_ = mispEvent.add_attribute('AS', ast_eval(str(obj.number)),
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

    return attribute, mispEvent
