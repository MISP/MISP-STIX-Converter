#!/usr/bin/env python3

# A file to store the buildAttribute() function
# as it goes on for quite a while.

# It's... well, it's a containment file.

# Cybox is awful
import stix
from stix.extensions.test_mechanism import snort_test_mechanism, yara_test_mechanism

# No you can't go
# from cybox.objects import *
# Because cybox is terrible.
from cybox.objects import email_message_object, file_object, address_object
from cybox.objects import domain_name_object, hostname_object, uri_object
from cybox.objects import link_object, mutex_object, whois_object
from cybox.objects import x509_certificate_object, as_object, http_session_object
from cybox.objects import pipe_object, network_packet_object, win_registry_key_object
from cybox.common.hashes import Hash

import logging
log = logging.getLogger("__main__")


def buildAttribute(attr, pkg, ind):
    """Given a MISP attribute, create a stix
    attribute, add it to an indicator for
    easy lookings up.

    There are quite a few assumptions here,
    including that there should only be one
    threat-actor per MISP event in order to
    give proper attribution.

    :param attr: The misp JSON attribute to parse and build from
    :param pkg : The STIX package to push the created object to
    :param ind : The STIX indicator to push observables to
   """

    # Extract type and value from the attribute
    type_ = attr.type
    value = attr.value

    if type_ == "ip-src":
        # An IP address. Add it as an Address Object.
        addr = address_object.Address(address_value=value)
        addr.is_source = True
        addr.is_destination = False
        obs = stix.indicator.Observable(addr)
        obs.title = attr.comment or "IP Source"
        ind.add_observable(obs)

    elif type_ == "ip-dst":
        # An IP address. Add it as an Address Object.
        addr = address_object.Address(address_value=value)
        addr.is_source = False
        addr.is_destination = True
        obs = stix.indicator.Observable(addr)
        obs.title = attr.comment or "IP Destination"
        ind.add_observable(obs)

    elif type_ == "domain":
        # A domain. Add as a DomainName Object.
        dn = domain_name_object.DomainName()
        dn.value = value
        obs = stix.indicator.Observable(dn)
        obs.title = attr.comment or "Domain"
        ind.add_observable(obs)

    elif type_ == "hostname":
        # A hostname. Add as Hostname Object.
        hst = hostname_object.Hostname()
        hst.hostname_value = value
        obs = stix.indicator.Observable(hst)
        obs.title = attr.comment or "Hostname"
        ind.add_observable(obs)

    elif type_ in ["url", "uri"]:
        # UR(i|l). I guess we'll use a URI object (as URLs are a subset of URIs).
        url = uri_object.URI(value)
        obs = stix.indicator.Observable(url)
        obs.title = attr.comment or "URI"
        ind.add_observable(obs)

    elif type_ in ["md5", "sha1", "sha256", "sha512"]:
        # A definite hash. They all come under SimpleHashValue.
        hsh = Hash(value)
        f = file_object.File()
        if type_ == "md5":
            f.md5 = value
        elif type_ == "sha1":
            f.sha1 = value
        elif type_ == "sha256":
            f.sha256 = value
        elif type_ == "sha512":
            f.sha512 = value
        obs = stix.indicator.Observable(f)
        obs.title = attr.comment or "Hash (Simple)"
        ind.add_observable(f)

    elif type_ == "filename":
        # Just a filename. Add it to a File Object, then add that.
        f = file_object.File()
        f.file_name = value
        obs = stix.indicator.Observable(f)
        obs.title = attr.comment or "Filename"
        ind.add_observable(f)

    elif type_ in ["filename|md5", "filename|sha1", "filename|sha256", "filename|sha512"]:
        # A filename AND a hash! Aren't we lucky!
        # Add the Hash to a File object.
        fname, _, hsh = value.partition("|")
        f = file_object.File()
        if "md5" in type_:
            f.md5 = hsh
        elif "sha1" in type_:
            f.sha1 = hsh
        elif "sha256" in type_:
            f.sha256 = hsh
        elif "sha512" in type_:
            f.sha512 = hsh
        f.file_name = fname
        obs = stix.indicator.Observable(f)
        obs.title = attr.comment or "File"
        ind.add_observable(f)

    elif type_ in ["ssdeep", "authentihash", "imphash"]:
        # A fuzzy hash. They're a bit weirder, but
        # we'll handle them nonetheless.
        hsh = Hash()
        f = file_object.File()
        hsh.fuzzy_hash_value = value
        f.add_hash(hsh)
        obs = stix.indicator.Observable(f)
        obs.title = attr.comment or "Hash (Fuzzy)"
        ind.add_observable(f)

    elif type_ == "threat-actor":
        # Threat Actors. Whilst we don't have proper attribution,
        # we can still add them as a thing.
        ta = stix.core.ThreatActor()
        ta.title = value
        if attr.comment:
            ta.description = attr.comment
        pkg.add_threat_actor(ta)

    elif type_ == "campaign-name":
        # Just a campaign name. Is nice.
        # Would be nice if we could structure it
        # so that it went Camp -> Obs, but sadly
        # we can't rely on a campaign existing.
        camp = stix.core.Campaign(title=value)
        pkg.add_campaign(camp)

    elif type_ == "link":
        # Arbritary link value.
        lnk = link_object.Link(value)
        obs = stix.indicator.Observable(lnk)
        obs.title = attr.comment or "Link"
        ind.add_observable(obs)

    elif type_ == "email-src":
        # Email Source. Create an Email Object,
        # then add the address in the header.
        emsg = email_message_object.EmailMessage()
        esrc = email_message_object.EmailHeader()
        esrc.from_ = value
        emsg.header = esrc
        obs = stix.indicator.Observable(emsg)
        obs.title = attr.comment or "Email Source Address"
        ind.add_observable(obs)

    elif type_ == "email-subject":
        # Same as above, but a subject. Add it
        # to the header.
        emsg = email_message_object.EmailMessage()
        esub = email_message_object.EmailHeader()
        esub.subject = value
        emsg.header = esub
        obs = stix.indicator.Observable(emsg)
        obs.title = attr.comment or "Email Subject Line"
        ind.add_observable(obs)

    elif type_ == "email-attachment":
        # Filename of an attachment.
        emsg = email_message_object.EmailMessage()
        att = email_message_object.Attachments()
        att.append(value)
        emsg.attachments = att
        obs = stix.indicator.Observable(emsg)
        obs.title = attr.comment or "Email Attachment"
        ind.add_observable(obs)

    elif type_ in ["email-dst", "target-email"]:
        # The "TO" field of an email address
        # Easy enough, just create an email object and shove it
        # in the hdr.
        emsg = email_message_object.EmailMessage()
        esub = email_message_object.EmailHeader()
        esub.to = value
        emsg.header = esub
        obs = stix.indicator.Observable(emsg)
        obs.title = attr.comment or "Email Destination Address"
        ind.add_observable(obs)

    elif type_ == "attachment":
        # This one is debatable.
        # I'll ignore it for now.
        pass

    elif type_ == "mutex":
        # A malware Mutex.
        # Just an fancy observable.
        mut = mutex_object.Mutex()
        mut.name = value
        obs = stix.indicator.Observable(mut)
        obs.title = attr.comment or "Mutex"
        ind.add_observable(obs)

    elif type_ == "x509-fingerprint-sha1":
        # Not directly transferrable. Best we can do
        # it putting it on the signature.
        cert = x509_certificate_object.X509CertificateSignature()
        cert.signature = "FINGERPRINT: {}".format(value)
        # TODO: Figure out how to add this to a package

    elif type_ == "whois-registrant-email":
        # This is far too much work for an email
        # Goddamnit STIX.
        # Create a whois entry
        whois = whois_object.WhoisEntry()
        # And a list of registrants
        # Which is apparently its own object for some reason
        regs = whois_object.WhoisRegistrants()
        reg = whois_object.WhoisRegistrant()
        # And add the email address
        reg.email_address = value
        regs.append(reg)
        whois.registrants = regs
        obs = stix.indicator.Observable(whois)
        obs.title = attr.comment or "WHOIS Email"
        ind.add_observable(obs)

    elif type_ == "whois-registrant-name":
        # I swear stix just LOVES to add layers
        # Just a name of the registrant
        whois = whois_object.WhoisEntry()
        regs = whois_object.WhoisRegistrants()
        reg = whois_object.WhoisRegistrant()
        reg.name = value
        regs.append(reg)
        whois.registrants = regs
        obs = stix.indicator.Observable(whois)
        obs.title = attr.comment or "WHOIS Registrant Name"
        ind.add_observable(obs)

    elif type_ == "whois-creation-date":
        # And the date the whois was created.
        # Nothing out of the ordinary
        whois = whois_object.WhoisEntry()
        whois.creation_date = value
        obs = stix.indicator.Observable(whois)
        obs.title = attr.comment or "WHOIS Creation Date"
        ind.add_observable(obs)

    elif type_ == "whois-registrar":
        # Aaaand the registrar
        whois = whois_object.WhoisEntry()
        reg = whois_object.WhoisRegistrar()
        reg.name = value
        whois.registrar_info = reg
        obs = stix.indicator.Observable(whois)
        obs.title = attr.comment or "WHOIS Registrar"
        ind.add_observable(obs)

    elif type_ == "pdb":
        # NOT SUPPORTED
        pass

    elif type_ == "domain|ip":
        # Oooh we've got both!
        # We'll add them in turn
        dom, _, ip = value.partition("|")

        # Add the IP
        addr = address_object.Address(address_value=ip)
        obs = stix.indicator.Observable(addr, title=attr.comment)
        obs.title = attr.comment or "IP Address"
        ind.add_observable(obs)

        # Now add the domain
        dn = domain_name_object.DomainName()
        dn.value = dom
        obs = stix.indicator.Observable(dn)
        obs.title = attr.comment or "Domain"
        ind.add_observable(obs)

    elif type_ == "vulnerability":
        # It's a CVE. Easy enough to deal with.
        vuln = stix.exploit_target.Vulnerability()
        vuln.cve_id = value
        et = stix.exploit_target.ExploitTarget()
        et.title = attr.comment or "Vulnerability"
        et.add_vulnerability(vuln)
        pkg.add_exploit_target(et)

    elif type_ == "snort":
        # Some snort rule. Idk what Snort is or does,
        # but still, we'll take it.
        snort = snort_test_mechanism.SnortTestMechanism()
        snort.rules.append(value)
        ind.test_mechanisms.append(snort)

    elif type_ == "yara":
        # Now this I know. YARA test rules.
        # Add it to the list of test mechanisms.
        yara = yara_test_mechanism.YaraTestMechanism()
        yara.rule = value
        ind.test_mechanisms.append(yara)

    elif type_ == "regkey|value":
        # A windows registry key and a value
        # Split them and add seperately
        regkey, _, value = value.partition("|")
        regentry = win_registry_key_object.WinRegistryKey()
        val = win_registry_key_object.RegistryValue()
        val.name = regkey
        val.data = value
        vals = win_registry_key_object.RegistryValues()
        vals.append(val)
        regentry.values = vals
        obs = stix.indicator.Observable(regentry)
        ind.add_observable(obs)

    elif type_ == "regkey":
        # Just a reg key without a value.
        regkey, _, value = value.partition("|")
        regentry = win_registry_key_object.WinRegistryKey()
        val = win_registry_key_object.RegistryValue()
        val.name = regkey
        vals = win_registry_key_object.RegistryValues()
        vals.append(val)
        regentry.values = vals
        obs = stix.indicator.Observable(regentry)
        obs.title = attr.comment or "Registry Key"
        ind.add_observable(obs)

    elif type_ == "pattern-in-traffic":
        # Create a packet and set the pattern as the data
        pack = network_packet_object.IPv4Packet()
        pack.data = value
        lay = network_packet_object.InternetLayer()
        lay.ipv4 = pack
        net = network_packet_object.NetworkPacket()
        net.internet_layer = lay
        obs = stix.indicator.Observable(net)
        obs.title = attr.comment or "Pattern In Traffic"
        ind.add_observable(obs)

    elif type_ == "user-agent":
        # Probably in the hdr of a HTTP req
        # My god this goes on for a while
        http = http_session_object.HTTPRequestHeaderFields()
        http.user_agent = value
        hdr = http_session_object.HTTPRequestHeader()
        hdr.parsed_header = http
        req = http_session_object.HTTPClientRequest()
        req.http_request_header = hdr
        resp = http_session_object.HTTPRequestResponse()
        resp.http_client_request = req
        ses = http_session_object.HTTPSession()
        ses.http_request_response = resp
        obs = stix.indicator.Observable(ses)
        obs.title = attr.comment or "User Agent"
        ind.add_observable(obs)

    elif type_ == "named pipe":
        # Pipe pipe pipe pipe pipe pipe
        p = pipe_object.Pipe()
        p.name = value
        obs = stix.indicator.Observable(p)
        obs.title = attr.comment or "Named Pipe"
        ind.add_observable(obs)

    elif type_ == "AS":
        as_ = as_object.AS()
        try:
            as_.number = value
        except ValueError:
            as_.name = value
        obs = stix.indicator.Observable(as_)
        obs.title = attr.comment or "Autonomous System"
        ind.add_observable(obs)

    else:
        # Known unsupported
        if type_ not in ["campaign-id", "comment", "text",
                         "malware-sample", "pattern-in-file",
                         "other"]:
            log.debug("Not adding %s", type_)
