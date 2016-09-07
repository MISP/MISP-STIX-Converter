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
import stixtomisp
from smash import utils
from stix.common import STIXPackage
from cybox.objects import file_object, address_object, domain_name_object, hostname_object, uri_object, link_object
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
      cat = attr["category"]
      type_ = attr["type"]
     
      if  type_ in ["ip-src", "ip-dst"]:
        obs = stix.indicator.Observable(
                address_object.Address(address_value=attr["value"]),
                title = attr["comment"]
              )
        ind.add_observable(obs)
          #pkg.add(obs)

      elif type_ == "domain":
        dn = domain_name_object.DomainName()
        dn.value = attr["value"]
        obs = stix.indicator.Observable(dn)
        ind.add_observable(obs)

      elif type_ == "hostname":
        hst = hostname_object.Hostname()
        hst.hostname_value = attr["value"]
        obs = stix.indicator.Observable(hst)
        ind.add_observable(obs)

      elif type_ == "url":
        url = uri_object.URI(attr["value"])
        obs = obs = stix.indicator.Observable(url)
        ind.add_observable(obs)

      elif type_ in ["md5", "sha1", "sha256"]:
        hsh = Hash(attr["value"])
        f = file_object.File()
        f.add_hash(hsh)
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)
    
      elif type_ == "filename":
        f = file_object.File()
        f.file_name = attr["value"]
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)
      
      elif type_ in ["filename|md5", "filename|sha1", "filename|sha256"]:
        fname, sep, hsh = attr["value"].partition("|")
        f = file_object.File()
        f.add_hash(hsh)
        f.file_name = fname
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)

      elif type_ in ["ssdeep", "authentihash"]:
        hsh = Hash(attr["value"])
        f = file_object.File()
        f.fuzzy_hash_value = hsh
        obs = stix.indicator.Observable(f)
        ind.add_observable(f)

      elif type_ == "campaign-name":
        camp = stix.common.Campaign(title = attr["value"])
        pkg.add_campaign(camp)
 
      elif type_ == "link":
        lnk = link_object.Link(attr["value"])
        obs = stix.indicator.Observable(lnk)
        ind.add_observable(obs)

      else:
        #Known unsupported
        if not type_ in ["comment", "pattern-in-file", "other"]:
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
            
