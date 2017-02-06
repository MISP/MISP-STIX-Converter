#!/usr/bin/env python3

#############################
#           MISP            #
#    Wrapper to PyMISP      #
#                           #
#   Provides push/pull      #
#############################

# A load of random imports
# Very very useful
import requests
import pymisp
import logging
from misp_stix_converter.converters import convert

__author__ = "Hannah Ward"

log = logging.getLogger(__name__)


class MISP(object):
    """
      Wrapper to MISP API -- allows easy exporting and
      importing of STIX data
    """

    def __init__(self, url, key, verify=False, misp_modules=False):
        """
          Initialise the MISP instance

          :param url: The URL of the MISP instance
          :param key: The API key to authenticate with
          :param verify: Shall we verify SSL? Can be bool or location of a signature
        """
        log.debug("Starting MISP")
        log.debug("%s -- %s", url, key)
        self.url = url
        self.key = key
        self.verify = verify
        self.mispAPI = pymisp.PyMISP(url, key, ssl=self.verify, debug=False)
        self.misp_modules = misp_modules

    def pull(self, id_=None, tags=None, from_=None, to=None):
        """
          Pull the requested events from the MISP server

          :param id_: Only export events with matching IDs
          :param tags: Only export events matching these tags
          :param from_: Only export events created after this date (YYYY-MM-DD)
          :param to: Only export events created before this date (YYYY-MM-DD)
        """

        log.debug("MISP PULL")
        log.debug("IDS:  %s", id_)
        log.debug("TAGS: %s", tags)
        log.debug("FROM: %s", from_)
        log.debug("TO:   %s", to)

        # Attempt to request the data
        try:
            log.info("Sending now...")

            recent = self.mispAPI.search_index(eventid=id_,
                                               tag=tags,
                                               datefrom=from_,
                                               dateuntil=to,
                                               )

        except requests.exceptions.HTTPError as ex:
            # 500 Internal -- Usually when there's no results
            log.error("MISP returned an error")
            log.error(ex)
            # Just send back nothing
            return []

        except AttributeError as ex:
            log.warning(ex)
            log.error("Server error - no data recieved")
        log.info("Response recieved, MISP pull complete.")

        log.info("%s packages recieved", len(recent["response"]))
        packages = [convert.MISPtoSTIX(self.mispAPI.get(x["id"])) for x in recent["response"]]
        return packages

    def push(self, data, **kwargs):
        """
          Push a package to the MISP instance

          :param data: The STIX package to push
          :param distribution: The dist number of the event [0,1,2,3]
          :param threat_level_id: How much of a threat is posed? [1-4, 1 highest]
          :param analysis: How far are we through analysis? [0-3, 3 highest]
          :param tags: The tags to assign the new event.
          :param verified: Is the event verified? Default False.
        """

        # If we've been given a list, push each in turn
        if isinstance(data, list):
            for i in data:
                self.push(i)

        else:
            convert.STIXtoMISP(data, self.mispAPI, **kwargs)
        return True
