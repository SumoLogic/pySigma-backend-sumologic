"""
Mapping from Sigma logsource to CSE vendor/product metadata.

Based on CSE Parser EventID Analysis (April 2026):
- 252 parsers analyzed from CSE test logs
- Covers Windows, AWS, Azure, GCP, Linux, Network devices
- Maps Sigma (product, service, category) → CSE (vendor, product, parser pattern)
"""

from typing import Optional, Tuple, Dict


class VendorProductMapper:
    """
    Maps Sigma logsource to CSE metadata_vendor and metadata_product.

    Based on actual CSE parser analysis from /Users/jcrowley/git/sumo/sana/sana-test/csiem-parsers/
    """

    # Mapping: (product, service, category) → (vendor, product, parser_pattern_type)
    # Pattern types: "concatenation" (dynamic), "simple" (field-based), "constant" (static)
    LOGSOURCE_TO_VENDOR_PRODUCT = {
        # ===== WINDOWS =====
        ("windows", "sysmon", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "security", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "system", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "application", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "powershell", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "powershell-classic", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "taskscheduler", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "wmi", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "dns-server", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "firewall-as", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "windefend", None): ("Microsoft", "Windows", "concatenation"),
        ("windows", "driver-framework", None): ("Microsoft", "Windows", "concatenation"),

        # Windows by category (when service not specified)
        ("windows", None, "process_creation"): ("Microsoft", "Windows", "concatenation"),
        ("windows", None, "network_connection"): ("Microsoft", "Windows", "concatenation"),
        ("windows", None, "dns_query"): ("Microsoft", "Windows", "concatenation"),
        ("windows", None, "file_event"): ("Microsoft", "Windows", "concatenation"),
        ("windows", None, "registry_event"): ("Microsoft", "Windows", "concatenation"),
        ("windows", None, "image_load"): ("Microsoft", "Windows", "concatenation"),

        # ===== AWS =====
        ("aws", "cloudtrail", None): ("Amazon AWS", "CloudTrail", "concatenation"),
        ("aws", "s3", None): ("Amazon AWS", "AWS S3 Server Access Logs", "simple"),
        ("aws", "guardduty", None): ("Amazon AWS", "GuardDuty", "simple"),
        ("aws", "vpc", None): ("Amazon AWS", "VpcFlowLogs", "simple"),
        ("aws", "waf", None): ("Amazon AWS", "Web Application Firewall (WAF)", "simple"),
        ("aws", "route53", None): ("Amazon AWS", "Route53", "simple"),
        ("aws", "config", None): ("Amazon AWS", "Config", "simple"),
        ("aws", "eks", None): ("Amazon AWS", "EKS", "simple"),
        ("aws", "elb", None): ("Amazon AWS", "Elastic Load Balancer", "simple"),
        ("aws", "alb", None): ("Amazon AWS", "Application Load Balancer", "simple"),
        ("aws", "cloudwatch", None): ("Amazon AWS", "CloudWatch", "simple"),
        ("aws", "cloudfront", None): ("Amazon AWS", "CloudFront", "simple"),
        ("aws", "apigateway", None): ("Amazon AWS", "API Gateway", "simple"),
        ("aws", "inspector", None): ("Amazon AWS", "Inspector", "simple"),
        ("aws", "networkfirewall", None): ("Amazon AWS", "Network Firewall", "simple"),
        ("aws", "securityhub", None): ("Amazon AWS", "Security Hub", "simple"),
        ("aws", "redshift", None): ("Amazon AWS", "Redshift", "simple"),
        ("aws", "vpn", None): ("Amazon AWS", "VPN", "simple"),
        ("aws", "trustedadvisor", None): ("Amazon AWS", "Trusted Advisor", "simple"),

        # ===== AZURE =====
        ("azure", "signinlogs", None): ("Microsoft", "Azure", "constant"),
        ("azure", "auditlogs", None): ("Microsoft", "Azure", "constant"),
        ("azure", "activitylogs", None): ("Microsoft", "Azure", "simple"),
        ("azure", "azuread", None): ("Microsoft", "Azure", "simple"),
        ("azure", "firewall", None): ("Microsoft", "Azure", "constant"),

        # ===== GCP =====
        ("gcp", "audit", None): ("Google", "Google Cloud Platform", "transform"),
        ("gcp", "gce", None): ("Google", "Google Cloud Platform", "transform"),
        ("gcp", "gcs", None): ("Google", "Google Cloud Platform", "simple"),
        ("gcp", "bigquery", None): ("Google", "BigQuery", "simple"),
        ("gcp", "securitycenter", None): ("Google", "Security Command Center", "simple"),

        # ===== GOOGLE WORKSPACE =====
        ("gsuite", None, None): ("Google", "Google Workspace", "simple"),
        ("google_workspace", None, None): ("Google", "Google Workspace", "simple"),

        # ===== LINUX =====
        ("linux", "syslog", None): ("Linux", "Linux OS Syslog", "simple"),
        ("linux", "auditd", None): ("Linux", "Auditd", "simple"),
        ("linux", "cron", None): ("Linux", "Linux OS Syslog", "simple"),
        ("linux", "auth", None): ("Linux", "Secure", "simple"),
        ("linux", "sysmon", None): ("Linux", "Sysmon for Linux", "simple"),
        ("linux", "systemd", None): ("Linux", "Systemd Journal", "simple"),

        # ===== NETWORK DEVICES =====
        # Cisco
        ("cisco", "aaa", None): ("Cisco Systems", "Secure Access Control Server (ACS)", "simple"),
        ("cisco", "asa", None): ("Cisco Systems", "ASA", "simple"),
        ("cisco", "ios", None): ("Cisco Systems", "Router and Switch IOS", "simple"),
        ("cisco", "amp", None): ("Cisco Systems", "Advanced Malware Protection (AMP)", "simple"),
        ("cisco", "firepower", None): ("Cisco Systems", "Firepower", "simple"),
        ("cisco", "ise", None): ("Cisco Systems", "Identity Services Engine", "simple"),
        ("cisco", "ironport", None): ("Cisco Systems", "Ironport", "simple"),
        ("cisco", "meraki", None): ("Cisco Systems", "Meraki", "simple"),
        ("cisco", "stealthwatch", None): ("Cisco Systems", "Stealthwatch", "simple"),
        ("cisco", "umbrella", None): ("Cisco Systems", "Umbrella", "simple"),
        ("cisco", "anyconnect", None): ("Cisco Systems", "AnyConnect", "simple"),
        ("cisco", "secureemail", None): ("Cisco Systems", "Secure Email", "simple"),

        # Palo Alto Networks
        ("paloaltonetworks", "threat", None): ("Palo Alto Networks", "Next Generation Firewall", "simple"),
        ("paloaltonetworks", "traffic", None): ("Palo Alto Networks", "Next Generation Firewall", "simple"),
        ("paloaltonetworks", "firewall", None): ("Palo Alto Networks", "Next Generation Firewall", "simple"),
        ("paloaltonetworks", "cortex", None): ("Palo Alto Networks", "Cortex XDR", "simple"),
        ("paloaltonetworks", "globalprotect", None): ("Palo Alto Networks", "GlobalProtect", "simple"),
        ("paloaltonetworks", "prismacloud", None): ("Palo Alto Networks", "Prisma Cloud", "simple"),
        ("paloaltonetworks", "traps", None): ("Palo Alto Networks", "Traps", "simple"),

        # Fortinet
        ("fortinet", "fortigate", None): ("Fortinet", "Fortigate", "simple"),
        ("fortinet", "forticlient", None): ("Fortinet", "Forticlient", "simple"),

        # Check Point
        ("checkpoint", "firewall", None): ("Check Point", "Firewall", "simple"),

        # ===== APPLICATIONS =====
        ("okta", None, None): ("Okta", "Single Sign-On", "simple"),
        ("onelogin", None, None): ("OneLogin", "OneLogin", "simple"),
        ("github", None, None): ("GitHub", "GitHub", "simple"),
        ("m365", None, None): ("Microsoft", "Office 365", "simple"),
        ("office365", None, None): ("Microsoft", "Office 365", "simple"),
        ("exchange", None, None): ("Microsoft", "Exchange", "simple"),

        # ===== MACOS =====
        ("macos", None, None): ("Apple", "macOS", "simple"),

        # ===== KUBERNETES =====
        ("kubernetes", "audit", None): ("Kubernetes", "Audit", "simple"),

        # ===== GENERIC CATEGORIES (when product not specified) =====
        # These are fallbacks when only category is specified
        (None, None, "proxy"): ("Generic", "Proxy", "simple"),
        (None, None, "firewall"): ("Generic", "Firewall", "simple"),
        (None, None, "dns"): ("Generic", "DNS", "simple"),
        (None, None, "webserver"): ("Generic", "Web Server", "simple"),
    }

    @classmethod
    def get_vendor_product(
        cls,
        product: Optional[str],
        service: Optional[str] = None,
        category: Optional[str] = None
    ) -> Optional[Tuple[str, str, str]]:
        """
        Get CSE vendor, product, and pattern type for a Sigma logsource.

        Args:
            product: Sigma logsource product (e.g., "windows", "aws")
            service: Sigma logsource service (e.g., "sysmon", "cloudtrail")
            category: Sigma logsource category (e.g., "process_creation")

        Returns:
            Tuple of (vendor, product, pattern_type) or None if not found

        Example:
            >>> get_vendor_product("windows", "sysmon")
            ("Microsoft", "Windows", "concatenation")
            >>> get_vendor_product("aws", "cloudtrail")
            ("Amazon AWS", "CloudTrail", "concatenation")
        """
        # Normalize to lowercase
        product_lower = product.lower() if product else None
        service_lower = service.lower() if service else None
        category_lower = category.lower() if category else None

        # Try exact match: (product, service, category)
        key = (product_lower, service_lower, category_lower)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            return cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]

        # Try (product, service, None)
        key = (product_lower, service_lower, None)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            return cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]

        # Try (product, None, category)
        key = (product_lower, None, category_lower)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            return cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]

        # Try (product, None, None)
        key = (product_lower, None, None)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            return cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]

        # Try generic category fallback (None, None, category)
        key = (None, None, category_lower)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            return cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]

        return None

    @classmethod
    def has_cse_parser(
        cls,
        product: Optional[str],
        service: Optional[str] = None,
        category: Optional[str] = None
    ) -> bool:
        """
        Check if a CSE parser exists for this Sigma logsource.

        Returns:
            True if mapping exists, False otherwise
        """
        return cls.get_vendor_product(product, service, category) is not None

    @classmethod
    def get_coverage_stats(cls) -> Dict[str, int]:
        """
        Get coverage statistics.

        Returns:
            Dictionary with counts by product
        """
        stats: Dict[str, int] = {}
        for (product, _, _), _ in cls.LOGSOURCE_TO_VENDOR_PRODUCT.items():
            if product is not None:
                stats[product] = stats.get(product, 0) + 1
        return stats
