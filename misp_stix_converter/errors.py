#!/usr/bin/env python3


class MISPLoadError(Exception):
    pass


class STIXLoadError(Exception):
    pass


class STIXConversionError(STIXLoadError):
    pass


class MISPConversionError(MISPLoadError):
    pass
