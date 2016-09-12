#!/usr/bin/env python3

from stix.core import STIXPackage

def loadXML(filename):
  return STIXPackage().from_xml(open(filename, "r"))

def loadJSON(filename):
  return STIXPackage().from_json(open(filename, "r"))

#Get a list of observables
def getObservables(package):
  if package.observables and len(package.observables) > 0:
    return [i for i in package.observables]
  else:
    return []

#Get *something* to use as a title
def getDescriptor(package):
  if package.stix_header:
    if str == type(package.stix_header.title):
      return package.stix_header.title
  if package.threat_actors:
    for i in package.threat_actors:
      if str == type(i.title):
        return i.title
  if package.indicators:
    #Best we can do at this point
    for i in package.indicators:
      if str == type(i.title):
        return i.title
  #Out of ideas
  return "Synced Signatures"
