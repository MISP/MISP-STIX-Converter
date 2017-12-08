#!/usr/bin/env python3
"""Wrapper script providing STIX to MISP conversion. """

import argparse
import logging
import os
import sys
import time

import pyaml

from misp_stix_converter.converters.convert import load_stix
from misp_stix_converter.servers import misp

LOGGER_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
CONFIG_DEFAULT_PATH = "~/.misptostix/misp.login"
MISP_CONFIG_KEY = "MISP"
SSL_CONFIG_KEY = "SSL"
BLAST_FROM_PAST_PENALTY_SECS = 1.0
args_src = sys.argv


def get_logger(options):
    """Instantiate customized logger."""
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG if options.verbose else logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if options.verbose else logging.INFO)
    formatter = logging.Formatter(LOGGER_FORMAT)
    ch.setFormatter(formatter)
    log.addHandler(ch)

    return log


def parse_args(args):
    """Caller is queen."""
    parser = argparse.ArgumentParser(
        description='STIX to MISP paramter parser.')
    parser.add_argument(
        "-c", "--config", help="Path to config file. Default is misp.login.")
    parser.add_argument(
        "-v", "--verbose", help="Increase logging verbosity.",
        default=False, action="store_true")
    parser.add_argument("file", help="The STIX file to push")

    return parser.parse_args(args)


def main():
    """Drive the conversion."""
    options = parse_args(args_src)
    log = get_logger(options)

    cfg_path = options.config if options.config else os.path.expanduser(
        CONFIG_DEFAULT_PATH)
    try:
        with open(cfg_path, "r") as f:
            config = pyaml.yaml.load(f)
    except FileNotFoundError:
        log.fatal("Could not find config file %s", cfg_path)
        return(1)

    # Backwards compatibility, if users haven't updated config
    if SSL_CONFIG_KEY not in config[MISP_CONFIG_KEY]:
        log.warning("Please update your config file using the"
                    " misp.login.example to include " + SSL_CONFIG_KEY)
        time.sleep(BLAST_FROM_PAST_PENALTY_SECS)
        config[MISP_CONFIG_KEY][SSL_CONFIG_KEY] = False

    # This is just a file conversion - relatively quick and easy
    in_path = options.file
    log.info("Opening STIX file %s", in_path)
    try:
        with open(in_path, "r") as f:  # Read binary, as maybe just bytes
            pkg = load_stix(f)
    except OSError:
        log.fatal("Could not open STIX file %s", in_path)
        return (1)

    misp_args = (
        config[MISP_CONFIG_KEY]["URL"],
        config[MISP_CONFIG_KEY]["KEY"],
        config[MISP_CONFIG_KEY].get(SSL_CONFIG_KEY, True)
    )
    planet_misp = misp.MISP(*misp_args)

    log.info("Pushing to MISP...")
    planet_misp.push(pkg)
    log.info("COMPLETE")


if __name__ == '__main__':
    sys.exit(main())
