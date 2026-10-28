"""Check registry. Add a new class here and it is picked up by the engine and CLI."""
from .transport import (HttpInsteadOfHttps, MissingHsts, MixedContent, CookieSecureFlag,
                        CookieAuthFlags, LoginFormOverHttp)
from .headers import SecurityHeaders, VersionDisclosure, MissingSri
from .exposure import SensitiveFiles, DirectoryListing, StackTraceDisclosure
from .access import MissingCsrfToken, OpenRedirect, CorsMisconfiguration, PathTraversalIndicator
from .injection import SqlInjectionError, ReflectedXss

ALL_CHECKS = [
    HttpInsteadOfHttps, MissingHsts, MixedContent, CookieSecureFlag,       # A02
    CookieAuthFlags, LoginFormOverHttp,                                    # A07
    SecurityHeaders, SensitiveFiles, DirectoryListing, StackTraceDisclosure,  # A05
    VersionDisclosure,                                                     # A06
    MissingSri,                                                            # A08
    MissingCsrfToken, OpenRedirect, CorsMisconfiguration, PathTraversalIndicator,  # A01
    SqlInjectionError, ReflectedXss,                                       # A03
]


def select_checks(only=None, skip=None):
    """Return instantiated checks filtered by id (case-insensitive)."""
    only = {c.upper() for c in (only or [])}
    skip = {c.upper() for c in (skip or [])}
    chosen = []
    for cls in ALL_CHECKS:
        cid = cls.id.upper()
        if only and cid not in only:
            continue
        if cid in skip:
            continue
        chosen.append(cls())
    return chosen
