"""
patch_sources.py — Trusted domain allowlist for patch / advisory link filtering.

Only URLs whose hostname matches a domain in this list (or is a subdomain of one)
are surfaced to the CISO dashboard as actionable patch links.  Third-party blogs,
mailing-list archives, exploit aggregators, and community forums are excluded.
"""

import urllib.parse

# Authoritative base domains.  Suffix-match applies automatically, so
# 'logging.apache.org' → matches 'apache.org', 'portal.msrc.microsoft.com' → 'microsoft.com', etc.
TRUSTED_PATCH_DOMAINS: frozenset[str] = frozenset({
    # Security authorities
    'nist.gov',
    'cisa.gov', 'us-cert.cisa.gov',
    'cve.org', 'cve.mitre.org', 'mitre.org',
    'cert.org', 'kb.cert.org',
    'first.org',
    # Microsoft
    'microsoft.com',
    # Apple
    'apple.com',
    # Google / Android
    'google.com', 'android.com', 'googlesource.com',
    # Oracle
    'oracle.com',
    # Red Hat / CentOS / Fedora
    'redhat.com', 'centos.org', 'fedoraproject.org',
    # Debian / Ubuntu / Canonical
    'debian.org', 'ubuntu.com', 'canonical.com',
    # SUSE / openSUSE
    'suse.com', 'suse.de', 'opensuse.org',
    # Gentoo / Arch / BSD
    'gentoo.org', 'archlinux.org', 'freebsd.org', 'openbsd.org', 'netbsd.org',
    # Apache Software Foundation
    'apache.org',
    # OpenSSL / OpenSSH
    'openssl.org', 'openssh.com',
    # Mozilla
    'mozilla.org',
    # nginx / HAProxy
    'nginx.com', 'nginx.org', 'haproxy.com', 'haproxy.org',
    # Language / package ecosystems
    'php.net', 'python.org', 'nodejs.org', 'npmjs.com', 'rubygems.org',
    'rust-lang.org', 'packagist.org', 'pypi.org',
    # GitHub — security advisories, fix commits, official releases
    'github.com', 'github.io',
    # CMS
    'wordpress.org', 'drupal.org', 'joomla.org',
    # Networking / security vendors
    'cisco.com',
    'vmware.com',
    'paloaltonetworks.com',
    'fortinet.com', 'fortiguard.com',
    'juniper.net',
    'f5.com',
    'checkpoint.com',
    'sonicwall.com',
    'sophos.com',
    'crowdstrike.com',
    'broadcom.com',
    'citrix.com',
    'barracuda.com',
    'cloudflare.com',
    'akamai.com',
    'netscout.com',
    # ICS / OT / SCADA vendors
    'siemens.com',
    'abb.com',
    'schneider-electric.com', 'se.com',
    'rockwellautomation.com',
    'honeywell.com',
    'yokogawa.com',
    'emerson.com',
    # Enterprise / platform vendors
    'sap.com',
    'ibm.com',
    'hpe.com',
    'dell.com',
    'intel.com',
    'amd.com',
    'qualcomm.com',
    'arm.com',
    'atlassian.com',
    'elastic.co',
    'hashicorp.com',
    'mongodb.com',
    'confluent.io',
    'adobe.com',
    'jetbrains.com',
    'spring.io',
    # Storage / NAS
    'netapp.com',
    'qnap.com',
    'synology.com',
    # Container / Cloud-native
    'kubernetes.io',
    'istio.io',
    'envoyproxy.io',
    # Vulnerability intelligence platforms (curated, authoritative data)
    'snyk.io',
    'jfrog.com',
    'sonatype.com',
    # Other well-known open-source projects
    'curl.se',
    'bentley.com',
})

# Specific hostnames excluded even when their parent domain is in the allowlist.
# Covers community forums, gists, mailing-list archives, and bug trackers.
EXCLUDED_PATCH_HOSTS: frozenset[str] = frozenset({
    'gist.github.com',          # anyone can post
    'groups.google.com',        # Google Groups discussion
    'bugzilla.redhat.com',      # bug tracker, not a patch page
    'bugzilla.suse.com',
    'forums.swift.org',
    'community.traefik.io',
    'community.fortinet.com',
    'openwall.com',             # oss-security mailing list
    'lists.openwall.com',
})


def is_trusted_patch_source(url: str) -> bool:
    """Return True only for OEM / authoritative security-authority patch links."""
    try:
        host = (urllib.parse.urlparse(url).hostname or '').lower().removeprefix('www.')
        if not host:
            return False
        if host in EXCLUDED_PATCH_HOSTS:
            return False
        if host in TRUSTED_PATCH_DOMAINS:
            return True
        for domain in TRUSTED_PATCH_DOMAINS:
            if host.endswith('.' + domain):
                return True
        return False
    except Exception:
        return False
