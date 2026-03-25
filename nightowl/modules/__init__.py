"""NightOwl scanner modules registry."""

BUILTIN_MODULES = {
    # Recon
    "dns-enum": "nightowl.modules.recon.dns_enum",
    "subdomain-enum": "nightowl.modules.recon.subdomain",
    "port-scanner": "nightowl.modules.recon.port_scanner",
    "service-fingerprint": "nightowl.modules.recon.service_fingerprint",
    "whois-lookup": "nightowl.modules.recon.whois_lookup",
    "tech-detect": "nightowl.modules.recon.tech_detect",
    "web-spider": "nightowl.modules.recon.web_spider",
    "cloud-enum": "nightowl.modules.recon.cloud_enum",
    "subdomain-takeover": "nightowl.modules.recon.subdomain_takeover",
    "email-harvester": "nightowl.modules.recon.email_harvester",
    "js-analyzer": "nightowl.modules.recon.js_analyzer",
    "secrets-scanner": "nightowl.modules.recon.secrets_scanner",
    # Web
    "header-analyzer": "nightowl.modules.web.header_analyzer",
    "sqli-scanner": "nightowl.modules.web.sqli_scanner",
    "xss-scanner": "nightowl.modules.web.xss_scanner",
    "csrf-scanner": "nightowl.modules.web.csrf_scanner",
    "ssrf-scanner": "nightowl.modules.web.ssrf_scanner",
    "path-traversal": "nightowl.modules.web.path_traversal",
    "dir-bruteforce": "nightowl.modules.web.dir_bruteforce",
    "ssl-analyzer": "nightowl.modules.web.ssl_analyzer",
    "cors-checker": "nightowl.modules.web.cors_checker",
    "auth-tester": "nightowl.modules.web.auth_tester",
    "api-scanner": "nightowl.modules.web.api_scanner",
    "waf-detect": "nightowl.modules.web.waf_detect",
    "jwt-attack": "nightowl.modules.web.jwt_attack",
    "graphql-introspect": "nightowl.modules.web.graphql_introspect",
    "websocket-fuzzer": "nightowl.modules.web.websocket_fuzzer",
    "ssti-scanner": "nightowl.modules.web.ssti_scanner",
    "deserialization-scanner": "nightowl.modules.web.deserialization",
    "xxe-scanner": "nightowl.modules.web.xxe_scanner",
    "crlf-injection": "nightowl.modules.web.crlf_injection",
    "open-redirect": "nightowl.modules.web.open_redirect",
    "http-smuggling": "nightowl.modules.web.http_smuggling",
    "param-miner": "nightowl.modules.web.param_miner",
    "cache-poisoning": "nightowl.modules.web.cache_poisoning",
    "race-condition": "nightowl.modules.web.race_condition",
    "prototype-pollution": "nightowl.modules.web.prototype_pollution",
    "host-header-injection": "nightowl.modules.web.host_header_injection",
    "idor-scanner": "nightowl.modules.web.idor_scanner",
    # Network
    "deep-port-scan": "nightowl.modules.network.port_deep_scan",
    "vuln-matcher": "nightowl.modules.network.vuln_matcher",
    "smb-enum": "nightowl.modules.network.smb_enum",
    "snmp-scanner": "nightowl.modules.network.snmp_scanner",
    "ssh-audit": "nightowl.modules.network.ssh_audit",
    "ftp-scanner": "nightowl.modules.network.ftp_scanner",
    "network-map": "nightowl.modules.network.network_map",
    # AD
    "ldap-enum": "nightowl.modules.ad.ldap_enum",
    "kerberos-scanner": "nightowl.modules.ad.kerberos",
    "password-spray": "nightowl.modules.ad.password_spray",
    "ad-recon": "nightowl.modules.ad.ad_recon",
    # Exploit
    "msf-bridge": "nightowl.modules.exploit.msf_bridge",
    "exploit-db": "nightowl.modules.exploit.exploit_db",
    "auto-exploit": "nightowl.modules.exploit.auto_exploit",
    # Post-exploit
    "privesc-check": "nightowl.modules.postexploit.privesc_check",
    "file-enum": "nightowl.modules.postexploit.file_enum",
    "credential-dump": "nightowl.modules.postexploit.credential_dump",
    "lateral-movement": "nightowl.modules.postexploit.lateral_movement",
}


def get_all_modules() -> list[dict]:
    return [{"name": k, "path": v} for k, v in BUILTIN_MODULES.items()]
