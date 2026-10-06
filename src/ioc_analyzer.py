import ipaddress
import re
from urllib.parse import urlparse


# ---------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")

MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")

CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE
)


# ---------------------------------------------------------
# IP address analysis
# ---------------------------------------------------------

def analyze_ip(indicator):
    """
    Analyze an IP address without connecting to it.
    """

    try:
        ip = ipaddress.ip_address(indicator)

        return {
            "indicator": indicator,
            "type": "IP ADDRESS",
            "valid_format": True,
            "version": f"IPv{ip.version}",
            "is_private": ip.is_private,
            "is_loopback": ip.is_loopback,
            "is_reserved": ip.is_reserved,
            "is_global": ip.is_global,
            "analysis": "IP address format is valid."
        }

    except ValueError:

        return {
            "indicator": indicator,
            "type": "IP ADDRESS",
            "valid_format": False,
            "analysis": "Invalid IP address format."
        }


# ---------------------------------------------------------
# Domain analysis
# ---------------------------------------------------------

def analyze_domain(indicator):
    """
    Analyze a domain name without resolving or contacting it.
    """

    indicator = indicator.strip().lower()

    valid = bool(DOMAIN_PATTERN.match(indicator))

    is_reserved_demo_domain = (
        indicator.endswith(".invalid")
        or indicator.endswith(".example")
        or indicator.endswith(".test")
    )

    return {
        "indicator": indicator,
        "type": "DOMAIN",
        "valid_format": valid,
        "is_reserved_demo_domain": is_reserved_demo_domain,
        "analysis": (
            "Domain format is valid."
            if valid
            else "Domain format is invalid."
        )
    }


# ---------------------------------------------------------
# URL analysis
# ---------------------------------------------------------

def analyze_url(indicator):
    """
    Analyze URL structure without visiting the URL.
    """

    try:
        parsed = urlparse(indicator)

        valid_scheme = parsed.scheme.lower() in {
            "http",
            "https"
        }

        valid_host = bool(parsed.hostname)

        valid = valid_scheme and valid_host

        return {
            "indicator": indicator,
            "type": "URL",
            "valid_format": valid,
            "scheme": parsed.scheme.lower(),
            "hostname": parsed.hostname,
            "path": parsed.path,
            "analysis": (
                "URL structure is valid."
                if valid
                else "URL structure is invalid."
            )
        }

    except Exception:

        return {
            "indicator": indicator,
            "type": "URL",
            "valid_format": False,
            "analysis": "Unable to parse URL."
        }


# ---------------------------------------------------------
# File hash analysis
# ---------------------------------------------------------

def analyze_hash(indicator):
    """
    Identify the likely hash algorithm based only on length
    and hexadecimal format.
    """

    indicator = indicator.strip()

    if MD5_PATTERN.fullmatch(indicator):
        hash_type = "MD5"

    elif SHA1_PATTERN.fullmatch(indicator):
        hash_type = "SHA-1"

    elif SHA256_PATTERN.fullmatch(indicator):
        hash_type = "SHA-256"

    else:
        hash_type = "UNKNOWN"

    return {
        "indicator": indicator,
        "type": "FILE HASH",
        "hash_type": hash_type,
        "valid_format": hash_type != "UNKNOWN",
        "analysis": (
            f"Valid {hash_type} hexadecimal hash format."
            if hash_type != "UNKNOWN"
            else "Hash format could not be identified."
        )
    }


# ---------------------------------------------------------
# Email / sender domain analysis
# ---------------------------------------------------------

def analyze_email_domain(indicator):
    """
    Analyze an email sender domain as text.
    No email system is contacted.
    """

    result = analyze_domain(indicator)

    result["type"] = "EMAIL/SENDER DOMAIN"

    return result


# ---------------------------------------------------------
# CVE analysis
# ---------------------------------------------------------

def analyze_cve(indicator):
    """
    Validate the structure of a CVE identifier.
    """

    indicator = indicator.strip().upper()

    valid = bool(CVE_PATTERN.fullmatch(indicator))

    return {
        "indicator": indicator,
        "type": "CVE ID",
        "valid_format": valid,
        "analysis": (
            "CVE identifier format is valid."
            if valid
            else "CVE identifier format is invalid."
        )
    }


# ---------------------------------------------------------
# Main IOC analyzer
# ---------------------------------------------------------

def analyze_ioc(indicator, indicator_type):
    """
    Analyze an indicator based on its declared type.

    This function performs local/passive analysis only.
    """

    if not isinstance(indicator, str):
        return {
            "indicator": indicator,
            "type": indicator_type,
            "valid_format": False,
            "analysis": "Indicator must be text."
        }

    indicator = indicator.strip()

    if indicator_type == "IP ADDRESS":
        return analyze_ip(indicator)

    elif indicator_type == "DOMAIN":
        return analyze_domain(indicator)

    elif indicator_type == "URL":
        return analyze_url(indicator)

    elif indicator_type == "FILE HASH":
        return analyze_hash(indicator)

    elif indicator_type == "EMAIL/SENDER DOMAIN":
        return analyze_email_domain(indicator)

    elif indicator_type == "CVE ID":
        return analyze_cve(indicator)

    else:
        return {
            "indicator": indicator,
            "type": indicator_type,
            "valid_format": False,
            "analysis": "Unsupported indicator type."
        }