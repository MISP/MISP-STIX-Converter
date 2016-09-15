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
        install_requires = ["pymisp>=2.4.50", "requests>=2.9.1", "pyaml>=3.11", 
                            "stix>=1.2", "cybox>=2.0", "nose"],
        dependency_links = ["https://github.com/STIXProject/python-stix.git" ,
                            "https://github.com/CybOXProject/python-cybox.git"],
        scripts = ["threatintel/misp-to-stix.py", "threatintel/stix-to-misp.py"], 
        data_files = [(os.path.expanduser("~/.misptostix"),
                      ['misp.login.example'])]
    )


