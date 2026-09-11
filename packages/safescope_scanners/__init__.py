"""SafeScope passive scanner plugins."""

from .cookies import CookieScanner
from .cors import CorsScanner
from .csp import CspScanner
from .dns import DnsScanner
from .exposed_files import ExposedFilesScanner
from .headers import SecurityHeadersScanner
from .javascript import JavaScriptScanner
from .technology import TechnologyScanner
from .tls import TLSScanner
from .zap import ZapBaselineScanner, zap_available

PASSIVE_SCANNERS = (
    TLSScanner,
    SecurityHeadersScanner,
    CookieScanner,
    CorsScanner,
    DnsScanner,
    TechnologyScanner,
    JavaScriptScanner,
    ExposedFilesScanner,
)

# Optional integrations are deliberately excluded from default jobs. The API
# adds one only when the analyst requests it and the executable is present.
OPTIONAL_PASSIVE_SCANNERS = (ZapBaselineScanner,)
ALL_PASSIVE_SCANNERS = PASSIVE_SCANNERS + OPTIONAL_PASSIVE_SCANNERS

__all__ = [
    "ALL_PASSIVE_SCANNERS",
    "OPTIONAL_PASSIVE_SCANNERS",
    "PASSIVE_SCANNERS",
    "CookieScanner",
    "CorsScanner",
    "CspScanner",
    "DnsScanner",
    "ExposedFilesScanner",
    "JavaScriptScanner",
    "SecurityHeadersScanner",
    "TLSScanner",
    "TechnologyScanner",
    "ZapBaselineScanner",
    "zap_available",
]
