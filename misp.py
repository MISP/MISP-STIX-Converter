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
from smash import utils
from stix.common import STIXPackage
from cybox.objects import file_object, address_object, domain_name_object, hostname_object, uri_object, link_object
from cybox.common.hashes import Hash

# Disable Insecure Request Warning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Get logger
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
    if url != None:
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

        #Check if we have an active misp-modules option
        if self.misp_modules:
          #Try connecting to it
          try:
            module_call = requests.get(self.misp_modules + "/modules").json()
            #Check the server offers stiximport
            for mod in module_call:
              if mod["name"] == "stiximport":
                #Encode the file and send it to the import module
                filedata = str(base64.b64encode(data.to_xml()), 'utf-8')
                misp_import = requests.post(self.misp_modules + "/query",
                                            data = json.dumps({"module":"stiximport",
                                                    "data":filedata
                                                    })
                                            ).json() 
                self.mispAPI.add_event(misp_import)                            
                return True
            raise ValueError("STIXImport not supported")      
          except Exception as ex:
            print(ex)
            #Fallback to inbuilt conversion      
        #Add a title for displaying 
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
          #Save the ID for future use
          eventID = event["Event"]["id"]
          
          log.debug("Created event {}".format(eventID))
          log.debug(event)
          #TODO: Get this to work. Currently the server responds 500 
          ##Share with signature group
          ##event["Event"]["distribution"] = 4
          ##event["Event"]["sharing_group_id"] = 1
          ##event["Event"]["timestamp"] = int(event["Event"]["timestamp"])+1
          log.debug("Adding threat actors..."); 
          #Add all actors          
          if data.threat_actors:
            for i in data.threat_actors:
              try:
                log.debug("Adding {}".format(tostr(i.title)))
                event=self.mispAPI.add_threat_actor(event, 
                                                    tostr(i.title),
                                               comment=tostr(i.description))
                 
              except Exception as ex:
                log.error(ex)
                log.error(event)
                pass
          
          #Utility regex for assisting in identifying IPs
          ipre = re.compile("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
          log.debug("Adding observables...")
          #Add all observables
          if data.observables:
            log.debug("We can see {} observables".format(len(data.observables)))
            for i in data.observables:
                log.debug("Trying to add {}".format(i.object_))
                try:
                  addr = i.object_.properties.address_value.value   
                  log.debug("Adding address {}".format(addr)) 
                  if ipre.match(addr):
                    event = self.mispAPI.add_ipdst(event, str(addr), comment="Net: {}".format(addr))
                  else:
                    event = self.mispAPI.add_domain(event, str(addr), comment="Net: {}".format(addr))
                except Exception as ex:
                  log.error("ERROR ADDING OBSERVABLE")
                  log.error(event)
                  log.error(ex)

          #Add indicators -- this is a wide range, so we'll need a lot
          if data.indicators:
            for i in data.indicators:
              for o in i.observables:
                try:
                  log.debug("Trying to add {}".format(o))
                  props = o.object_.properties
                  log.debug("Adding {}".format(props))
                  #FILE HASHES
                  if props.hashes:
                    for hash_ in props.hashes:
                      val = hash_.simple_hash_value.value
                      type_ = hash_.type_

                      #Check the hash type, so we don't categorise it wrongly
                      if type_ == "MD5":
                        event = self.mispAPI.add_hashes(
                                      event, 
                                      md5=val
                                )
                      elif type_ == "SHA256":
                        event = self.mispAPI.add_hashes(
                                      event,
                                      sha256=val
                        )
                except Exception as ex:
                  pass
          log.debug(event) 
          #Check if any attributes have actually been added
          if len(event["Event"]["Attribute"]) != 0:
            try:
              #Tell MISP about the new attributes
              self.mispAPI.update_event(eventID, event)
              
              #Tag the event as un/verified
              self.mispAPI.add_tag(
               event,
               "OK" if kwargs.get("verified", False) else "Unverified")
              tags = kwargs.get("tags", [])
              
              #If we've only been given one tag, make it a list for iteration
              if not isinstance(tags, list):
                tags = [tags]  

              #Add the tags
              for i in tags:
                self.mispAPI.add_tag(event, i)
              return True
            except:
              return False
          else:
            
            #No attributes. You may as well get rid of it.
            return self.mispAPI.delete_event(eventID)
