#!/usr/bin/env python3

#############################
#           MISP            #
#    Wrapper to PyMISP      #
#                           #
#   Provides push/pull      #
#############################

__author__ = "Hannah Ward"

#A load of random imports
#Very very useful
import getpass
import requests
import json
import sys
import os
import argparse
import re
import warnings
import time
import cabby
import pyaml
import pymisp
import stix
import cybox
import base64
import logging
import hashlib
from . import stixtomisp
from . import utils
from stix.common import STIXPackage
from stix.extensions.test_mechanism import snort_test_mechanism, yara_test_mechanism
from cybox.objects import email_message_object,file_object, address_object, domain_name_object, hostname_object, uri_object, link_object, mutex_object, whois_object, x509_certificate_object
from cybox.objects import as_object, http_session_object, pipe_object, network_packet_object, win_registry_key_object
from cybox.common.hashes import Hash
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
log = logging.getLogger("__main__")


def tostr(v):
  """
    A slightly hacky way to convert from
    a possible StructuredText object to a string

    :param v: The string/structuredtext to convert
  """
  
  #Check if it is a StructuredTextObject
  if isinstance(v, stix.common.structured_text.StructuredText):
    
    #Shove back the value
    return v.value
  
  else:
    
    #Make sure it's not null 
    if not v:
      
      #We've got nothing
      return "None"
    
    #Otherwise, just cast to str
    return str(v)

class MISP:
  """
    Wrapper to MISP API -- allows easy exporting and
    importing of STIX data
  """

  def __init__(self, url, key, verify=False, misp_modules = False):
    """
      Initialise the MISP instance

      :param url: The URL of the MISP instance
      :param key: The API key to authenticate with
      :param verify: Shall we verify SSL? Can be bool or location of a signature
    """
    log.debug("Starting MISP")
    log.debug("{} -- {}".format(url, key))
    self.url = url
    self.key = key
    self.verify = verify
    if url:
        self.mispAPI = pymisp.PyMISP(url, key, ssl=self.verify, debug=False)
    self.misp_modules = misp_modules

  def pull(self,id_=None, tags=None, from_=None, to=None):
    """
      Pull the requested events from the MISP server

      :param id_: Only export events with matching IDs
      :param tags: Only export events matching these tags
      :param from_: Only export events created after this date (YYYY-MM-DD)
      :param to: Only export events created before this date (YYYY-MM-DD)
    """

    log.debug("MISP PULL")
    log.debug("IDS:  {}".format(id_))
    log.debug("TAGS: {}".format(tags))
    log.debug("FROM: {}".format(from_))
    log.debug("TO:   {}".format(to))
    
    #Attempt to request the data
    try:
      log.info("Sending now...") 
      recent = self.mispAPI.search_index(eventid=id_,
                                         tag=tags,
                                         datefrom=from_,
                                         dateto=to,
                                         )

    except requests.exceptions.HTTPError as ex:

      #500 Internal -- Usually when there's no results
      log.error("MISP returned an error")
      log.error(ex)
      #Just send back nothing
      return []
    
    except AttributeError as ex:
      log.warning(ex)
      log.error("Server error - no data recieved")
    log.info("Response recieved, MISP pull complete.")

    packages = []
    for event in recent["response"]:
      packages.append(self.buildPackage(event["id"]))
      log.debug("{}% done...".format(100*(recent["response"].index(event) / len(recent["response"]))))
    return packages

  
  def buildPackage(self, id_=None, jsoninfo=None):
      if not (id_ or jsoninfo):
        log.error("No ID or JSON given to MISP's buildpackage")
        return None

      if jsoninfo:
        data = jsoninfo
      else:
        try:
          data = self.mispAPI.get(id_)
        except requests.exceptions.HTTPError:
          log.error("Could not get info for {}".format(id_))
          return None

      package = STIXPackage()
      package.stix_header = stix.core.STIXHeader()
      try:
        package.stix_header.title = data["Event"]["info"]
      except KeyError:
        package.stix_header.title = "MISP Export"

      attr = data["Event"]["Attribute"]

      indicator = stix.indicator.Indicator(title=data["Event"]["info"])
      for attribute in attr:
        self.buildAttribute(attribute, package, indicator)
     
      package.add(indicator)
 
      return package

  def buildAttribute(self, attr, pkg, ind):
      """
        Given a MISP attribute, create a stix
        attribute, add it to an indicator for
        easy lookings up. 

        There are quite a few assumptions here, 
        including that there should only be one
        threat-actor per MISP event in order to
        give proper attribution.
      """
      
      # Extract 
      cat = attr["category"]
      type_ = attr["type"]
      value = attr["value"]

      if  type_ in ["ip-src", "ip-dst"]:
        # An IP address. Add it as an Address Object.
        addr = address_object.Address(address_value=value)
        obs = stix.indicator.Observable(addr, title = attr["comment"])
        ind.add_observable(obs)

      elif type_ == "domain":
        # A domain. Add as a DomainName Object.
        dn = domain_name_object.DomainName()
        dn.value = value
        obs = stix.indicator.Observable(dn)
        ind.add_observable(obs)

      elif type_ == "hostname":
        # A hostname. Add as Hostname Object.
        hst = hostname_object.Hostname()
        hst.hostname_value = value
        obs = stix.indicator.Observable(hst)
        ind.add_observable(obs)

      elif type_ in ["url", "uri"]:
        # UR(i|l). I guess we'll use a URI object (as URLs ⊆ URIs).
        url = uri_object.URI(value)
        obs = obs = stix.indicator.Observable(url)
        ind.add_observable(obs)

      elif type_ in ["md5", "sha1", "sha256", "sha256"]:
        # A definite hash. They all come under SimpleHashValue.
        hsh = Hash(value)
        f = file_object.File()
        f.add_hash(hsh)
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)
    
      elif type_ == "filename":
        # Just a filename. Add it to a File Object, then add that.
        f = file_object.File()
        f.file_name = value
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)
      
      elif type_ in ["filename|md5", "filename|sha1", "filename|sha256"]:
        # A filename AND a hash! Aren't we lucky!
        # Add the Hash to a File object.
        fname, sep, hsh = value.partition("|")
        f = file_object.File()
        f.add_hash(hsh)
        f.file_name = fname
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)

      elif type_ in ["ssdeep", "authentihash", "imphash"]:
        # A fuzzy hash. They're a bit weirder, but
        # we'll handle them nonetheless. 
        hsh = Hash(value)
        f = file_object.File()
        f.fuzzy_hash_value = hsh
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)

      elif type_ == "threat-actor":
        # Threat Actors. Whilst we don't have proper attribution,
        # we can still add them as a thing.
        ta = stix.common.ThreatActor()
        ta.title = value
        if "comment" in attr:
          ta.description = attr["comment"]
        pkg.add_threat_actor(ta)

      elif type_ == "campaign-name":
        # Just a campaign name. Is nice. 
        # Would be nice if we could structure it
        # so that it went Camp -> Obs, but sadly
        # we can't rely on a campaign existing.
        camp = stix.common.Campaign(title = value)
        pkg.add_campaign(camp)
 
      elif type_ == "link":
        # Arbritary link value. 
        lnk = link_object.Link(value)
        obs = stix.indicator.Observable(lnk)
        ind.add_observable(obs)

      elif type_ == "email-src":
        # Email Source. Create an Email Object,
        # then add the address in the header.
        emsg = email_message_object.EmailMessage()
        esrc = email_message_object.EmailHeader()
        esrc.from_ = value
        emsg.header = esrc
        obs = stix.indicator.Observable(emsg)
        ind.add_observable(obs)

      elif type_ == "email-subject":
        # Same as above, but a subject. Add it
        # to the header.
        emsg = email_message_object.EmailMessage()
        esub = email_message_object.EmailHeader()
        esub.subject = value
        emsg.header = esub
        obs = stix.indicator.Observable(emsg)
        ind.add_observable(obs)

      elif type_ == "email-attachment":
        # Filename of an attachment. 
        emsg = email_message_object.EmailMessage()
        att  = email_message_object.Attachments()
        att.append(value)
        emsg.attachments = att
        obs = stix.indicator.Observable(emsg)
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
        regs  = whois_object.WhoisRegistrants()
        reg   = whois_object.WhoisRegistrant()
        # And add the email address
        reg.email_address = value
        regs.append(reg)
        whois.registrants = regs
        obs = stix.indicator.Observable(whois)
        ind.add_observable(obs)

      elif type_ == "whois-registrant-name":
        # I swear stix just LOVES to add layers
        # Just a name of the registrant
        whois = whois_object.WhoisEntry()
        regs  = whois_object.WhoisRegistrants()
        reg   = whois_object.WhoisRegistrant()
        reg.name = value
        regs.append(reg)
        whois.registrants = regs
        obs = stix.indicator.Observable(whois)
        ind.add_observable(obs)
      
      elif type_ == "whois-creation-date":
        # And the date the whois was created.
        # Nothing out of the ordinary
        whois = whois_object.WhoisEntry()
        whois.creation_date = value
        obs = stix.indicator.Observable(whois)
        ind.add_observable(obs)

      elif type_ == "whois-registrar":
        # Aaaand the registrar
        whois = whois_object.WhoisEntry()
        reg = whois_object.WhoisRegistrar()
        reg.name = value
        whois.registrar_info = reg
        obs = stix.indicator.Observable(whois)
        ind.add_observable(obs)

      elif type_ == "pdb":
        # NOT SUPPORTED
        pass

      elif type_ == "domain|ip":
        # Oooh we've got both!
        # We'll add them in turn
        dom,sep,ip = value.partition("|")        
        
        #Add the IP
        addr = address_object.Address(address_value=ip)
        obs = stix.indicator.Observable(addr, title = attr["comment"])
        ind.add_observable(obs)
        
        # Now add the domain
        dn = domain_name_object.DomainName()
        dn.value = dom
        obs = stix.indicator.Observable(dn)
        ind.add_observable(obs)

      elif type_ == "vulnerability":
        # It's a CVE. Easy enough to deal with.
        vuln = stix.exploit_target.Vulnerability()
        vuln.cve_id = value
        et = stix.exploit_target.ExploitTarget()
        et.add_vulnerability(vuln)
        pkg.add_exploit_target(et)      
        
      elif type_ == "snort":
        # Some snort rule. Idk what Snort is or does,
        # but still, we'll take it.
        snort = snort_test_mechanism.SnortTestMechanism()
        snort.add_rule(value)
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
        regkey,sep,value = value.partition("|")
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
        regkey,sep,value = value.partition("|")
        regentry = win_registry_key_object.WinRegistryKey()
        val = win_registry_key_object.RegistryValue()
        val.name = regkey
        vals = win_registry_key_object.RegistryValues()
        vals.append(val)
        regentry.values = vals
        obs = stix.indicator.Observable(regentry)
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
        ind.add_observable(obs)

      elif type_ == "named pipe":
        # Pipe pipe pipe pipe pipe pipe
        p = pipe_object.Pipe()
        p.name = value
        obs = stix.indicator.Observable(p)
        ind.add_observable(obs)

      elif type_ == "AS":
        as_ = as_object.AS()
        try:
            as_.number = value
        except ValueError:
            as_.name = value
        obs = stix.indicator.Observable(as_)
        ind.add_observable(obs)
        

      else:
        #Known unsupported
        if not type_ in ["campaign-id", "comment", "text", "malware-sample", "pattern-in-file", "other"]:
          print("Not adding {}".format(type_))

  def push(self, data, dryrun=False, **kwargs):
    """
      Push a package to the MISP instance

      :param data: The STIX package to push
      :param distribution: The dist number of the event [0,1,2,3]
      :param threat_level_id: How much of a threat is posed? [1-4, 1 highest]
      :param analysis: How far are we through analysis? [0-3, 3 highest]
      :param tags: The tags to assign the new event. 
      :param verified: Is the event verified? Default False.  
  """

    #If we've been given a list, push each in turn
    if isinstance(data, list):
      for i in data:
        self.push(i)

    else:

      #Check that it is indeed a STIX package
      if isinstance(data, STIXPackage):

        if not data.stix_header:
          data.stix_header = stix.core.STIXHeader()
        if not data.stix_header.title:
          data.stix_header.title = utils.getDescriptor(data)

        #Make sure this event wasn't from a previous MISP export
        if "MISP" not in data.stix_header.title:
          log.debug("Creating event...") 
          #Create a new event on the server
          event = self.mispAPI.new_event(
                  distribution = kwargs.get("distribution",0),
                  threat_level_id = kwargs.get("threat_level_id", 3),
                  analysis = kwargs.get("analysis", 0),
                  info = data.stix_header.title)

        #Dump and base64 encode the package
        pkg = str(base64.b64encode(bytes(data.to_json(), 'utf-8')), 'utf-8')
        #Call the MISP-Modules script
        request = json.dumps({"data":pkg})
        attributes = stixtomisp.handler(request)
        for attr in attributes["results"]:
            print(attr)
            # This can return multiple types, just take the first one.
            type_ = attr["types"][0] 
            for value in attr["values"]:
                if type_ == "ip-src":
                    self.mispAPI.add_ipsrc(event, value, comment="Net {}".format(value))
                if type_ == "ip-dst":
                    self.mispAPI.add_ipdst(event, value, comment="Net {}".format(value))
                if type_ == "threat-actor":
                    self.mispAPI.add_threat_actor(event, value, comment="TA {}".format(value))
                if type_ == "domain":
                    self.mispAPI.add_domain(event, value, comment="Net {}".format(value))
                if type_ == "hostname":
                    self.mispAPI.add_hostname(event, value, comment="Net {}".format(value))
                if type_ == "link":
                    self.mispAPI.av_detection_link(event, value, comment="Link {}".format(value))
                if type_ in ["md5", "sha1", "sha256"]:
                    args = {type_:value, "event":event, "comment":"Hash {}".format(value)}
                    self.mispAPI.add_hashes(**args)
        return event["Event"]["id"]     
