#!/usr/bin/env python3

import json

class MISPLoadError(json.decoder.JSONDecodeError):
    pass

class STIXLoadError(Exception):
    pass

class STIXConversionError(STIXLoadError):
    pass

class MISPConversionError(MISPLoadError):
    pass
