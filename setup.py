#!/usr/bin/env python3

# Setup script for ThreatIntel Conversion

from setuptools import setup
import os

setup(
    name="misp_stix_converter",
    description="A tool to convert between STIX and MISP format",
    version="0.2.3",
    author="Hannah Ward",
    author_email="hannah.ward@baesystems.com",
    url="https://github.com/FloatingGhost/MISP-STIX-Converter",
    packages=['misp_stix_converter', "misp_stix_converter.servers", "misp_stix_converter.converters"],
    install_requires=["pymisp>=2.4.53", "requests>=2.9.1", "pyaml>=3.11",
                      "stix>=1.2", "cybox>=2.0", "nose", "cabby"],
    dependency_links=["https://github.com/MISP/PyMISP.git",
                      "https://github.com/STIXProject/python-stix.git",
                      "https://github.com/CybOXProject/python-cybox.git"],
    scripts=["misp_stix_converter/misp-to-stix.py", "misp_stix_converter/stix-to-misp.py"],
    data_files=[(os.path.expanduser("~/.misptostix"),
                ['misp.login.example'])]
)
