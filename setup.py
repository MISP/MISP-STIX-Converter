#!/usr/bin/env python3

#Setup script for ThreatIntel Conversion

from setuptools import *
import os

setup(
        name = "Stix<->MISP Converter",
        description = "A tool to convert between STIX and MISP format",
        version = "0.2",
        author = "Hannah Ward",
        author_email = "hannah.ward@baesystems.com",
        url = "https://github.com/FloatingGhost/MISP-STIX-Converter",
        packages = find_packages(),        
        data_files = [(os.path.expanduser("~/.misptostix"),
                      ['misp.login.example'])]
    )


