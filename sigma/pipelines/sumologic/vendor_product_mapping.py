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

    Based on CSE parser configuration analysis.
    """

    # Mapping: (product, service, category) → (vendor, product, parser_pattern_type, source_classification)
    # Pattern types: "concatenation" (dynamic), "simple" (field-based), "constant" (static)
    # Source classifications: "endpoint", "identity", "cloud_audit", "network", "application",
    #                         "cloud_infrastructure", "security_tool"
    LOGSOURCE_TO_VENDOR_PRODUCT = {
        # ===== WINDOWS =====
        ("windows", "sysmon", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "security", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "system", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "application", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "powershell", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "powershell-classic", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "taskscheduler", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "wmi", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "dns-server", None): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", "firewall-as", None): ("Microsoft", "Windows", "concatenation", "network"),
        ("windows", "windefend", None): ("Microsoft", "Windows", "concatenation", "security_tool"),
        ("windows", "driver-framework", None): ("Microsoft", "Windows", "concatenation", "endpoint"),

        # Windows by category (when service not specified)
        ("windows", None, "process_creation"): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", None, "network_connection"): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", None, "dns_query"): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", None, "file_event"): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", None, "registry_event"): ("Microsoft", "Windows", "concatenation", "endpoint"),
        ("windows", None, "image_load"): ("Microsoft", "Windows", "concatenation", "endpoint"),

        # ===== AWS =====
        ("aws", "cloudtrail", None): ("Amazon AWS", "CloudTrail", "concatenation", "cloud_audit"),
        ("aws", "s3", None): ("Amazon AWS", "AWS S3 Server Access Logs", "simple", "cloud_infrastructure"),
        ("aws", "guardduty", None): ("Amazon AWS", "GuardDuty", "simple", "security_tool"),
        ("aws", "vpc", None): ("Amazon AWS", "VpcFlowLogs", "simple", "cloud_infrastructure"),
        ("aws", "waf", None): ("Amazon AWS", "Web Application Firewall (WAF)", "simple", "network"),
        ("aws", "route53", None): ("Amazon AWS", "Route53", "simple", "cloud_infrastructure"),
        ("aws", "config", None): ("Amazon AWS", "Config", "simple", "cloud_audit"),
        ("aws", "eks", None): ("Amazon AWS", "EKS", "simple", "cloud_infrastructure"),
        ("aws", "elb", None): ("Amazon AWS", "Elastic Load Balancer", "simple", "cloud_infrastructure"),
        ("aws", "alb", None): ("Amazon AWS", "Application Load Balancer", "simple", "cloud_infrastructure"),
        ("aws", "cloudwatch", None): ("Amazon AWS", "CloudWatch", "simple", "cloud_infrastructure"),
        ("aws", "cloudfront", None): ("Amazon AWS", "CloudFront", "simple", "cloud_infrastructure"),
        ("aws", "apigateway", None): ("Amazon AWS", "API Gateway", "simple", "cloud_infrastructure"),
        ("aws", "inspector", None): ("Amazon AWS", "Inspector", "simple", "security_tool"),
        ("aws", "networkfirewall", None): ("Amazon AWS", "Network Firewall", "simple", "network"),
        ("aws", "securityhub", None): ("Amazon AWS", "Security Hub", "simple", "security_tool"),
        ("aws", "redshift", None): ("Amazon AWS", "Redshift", "simple", "cloud_infrastructure"),
        ("aws", "vpn", None): ("Amazon AWS", "VPN", "simple", "network"),
        ("aws", "trustedadvisor", None): ("Amazon AWS", "Trusted Advisor", "simple", "cloud_audit"),

        # ===== AZURE =====
        ("azure", "signinlogs", None): ("Microsoft", "Azure", "constant", "identity"),
        ("azure", "auditlogs", None): ("Microsoft", "Azure", "constant", "cloud_audit"),
        ("azure", "activitylogs", None): ("Microsoft", "Azure", "simple", "cloud_audit"),
        ("azure", "azuread", None): ("Microsoft", "Azure", "simple", "identity"),
        ("azure", "firewall", None): ("Microsoft", "Azure", "constant", "network"),
        ("azure", "riskdetection", None): ("Microsoft", "Azure", "simple", "identity"),
        ("azure", "pim", None): ("Microsoft", "Azure", "simple", "identity"),

        # ===== GCP =====
        ("gcp", "audit", None): ("Google", "Google Cloud Platform", "transform", "cloud_audit"),
        ("gcp", "gce", None): ("Google", "Google Cloud Platform", "transform", "cloud_infrastructure"),
        ("gcp", "gcs", None): ("Google", "Google Cloud Platform", "simple", "cloud_infrastructure"),
        ("gcp", "bigquery", None): ("Google", "BigQuery", "simple", "cloud_infrastructure"),
        ("gcp", "securitycenter", None): ("Google", "Security Command Center", "simple", "security_tool"),

        # ===== GOOGLE WORKSPACE =====
        ("gsuite", None, None): ("Google", "Google Workspace", "simple", "application"),
        ("google_workspace", None, None): ("Google", "Google Workspace", "simple", "application"),
        ("gcp", "google_workspace.admin", None): ("Google", "Google Workspace", "simple", "application"),
        ("gcp", "google_workspace.login", None): ("Google", "Google Workspace", "simple", "application"),


        # ===== NETWORK DEVICES =====
        # Cisco
        ("cisco", "aaa", None): ("Cisco Systems", "Secure Access Control Server (ACS)", "simple", "identity"),
        ("cisco", "asa", None): ("Cisco Systems", "ASA", "simple", "network"),
        ("cisco", "ios", None): ("Cisco Systems", "Router and Switch IOS", "simple", "network"),
        ("cisco", "amp", None): ("Cisco Systems", "Advanced Malware Protection (AMP)", "simple", "security_tool"),
        ("cisco", "firepower", None): ("Cisco Systems", "Firepower", "simple", "network"),
        ("cisco", "ise", None): ("Cisco Systems", "Identity Services Engine", "simple", "identity"),
        ("cisco", "ironport", None): ("Cisco Systems", "Ironport", "simple", "network"),
        ("cisco", "meraki", None): ("Cisco Systems", "Meraki", "simple", "network"),
        ("cisco", "stealthwatch", None): ("Cisco Systems", "Stealthwatch", "simple", "network"),
        ("cisco", "umbrella", None): ("Cisco Systems", "Umbrella", "simple", "network"),
        ("cisco", "anyconnect", None): ("Cisco Systems", "AnyConnect", "simple", "network"),
        ("cisco", "secureemail", None): ("Cisco Systems", "Secure Email", "simple", "network"),

        # Palo Alto Networks
        ("paloaltonetworks", "threat", None): ("Palo Alto Networks", "Next Generation Firewall", "simple", "network"),
        ("paloaltonetworks", "traffic", None): ("Palo Alto Networks", "Next Generation Firewall", "simple", "network"),
        ("paloaltonetworks", "firewall", None): ("Palo Alto Networks", "Next Generation Firewall", "simple", "network"),
        ("paloaltonetworks", "cortex", None): ("Palo Alto Networks", "Cortex XDR", "simple", "security_tool"),
        ("paloaltonetworks", "globalprotect", None): ("Palo Alto Networks", "GlobalProtect", "simple", "network"),
        ("paloaltonetworks", "prismacloud", None): ("Palo Alto Networks", "Prisma Cloud", "simple", "security_tool"),
        ("paloaltonetworks", "traps", None): ("Palo Alto Networks", "Traps", "simple", "security_tool"),

        # Fortinet
        ("fortinet", "fortigate", None): ("Fortinet", "Fortigate", "simple", "network"),
        ("fortinet", "forticlient", None): ("Fortinet", "Forticlient", "simple", "security_tool"),

        # FortiGate - Sigma uses "fortigate" as product, not "fortinet"
        ("fortigate", None, None): ("Fortinet", "Fortigate", "simple", "network"),
        ("fortigate", "event", None): ("Fortinet", "Fortigate", "simple", "network"),
        ("fortigate", "traffic", None): ("Fortinet", "Fortigate", "simple", "network"),
        ("fortigate", "utm", None): ("Fortinet", "Fortigate", "simple", "network"),

        # Palo Alto - Sigma uses "paloalto" as product, not "paloaltonetworks"
        ("paloalto", None, None): ("Palo Alto Networks", "Next Generation Firewall", "simple", "network"),
        ("paloalto", "traffic", None): ("Palo Alto Networks", "Next Generation Firewall", "simple", "network"),
        ("paloalto", "threat", None): ("Palo Alto Networks", "Next Generation Firewall", "simple", "network"),
        ("paloalto", "globalprotect", None): ("Palo Alto Networks", "GlobalProtect", "simple", "network"),

        # Check Point
        ("checkpoint", "firewall", None): ("Check Point", "Firewall", "simple", "network"),

        # ===== APPLICATIONS =====
        ("okta", None, None): ("Okta", "Single Sign-On", "simple", "identity"),
        ("onelogin", None, None): ("OneLogin", "OneLogin", "simple", "identity"),
        ("github", None, None): ("GitHub", "GitHub", "simple", "application"),
        ("m365", None, None): ("Microsoft", "Office 365", "simple", "application"),
        ("office365", None, None): ("Microsoft", "Office 365", "simple", "application"),
        ("exchange", None, None): ("Microsoft", "Exchange", "simple", "application"),


        # ===== KUBERNETES =====
        ("kubernetes", "audit", None): ("Kubernetes", "Audit", "simple", "cloud_infrastructure"),

        # ===== GENERIC CATEGORIES (when product not specified) =====
        # These are fallbacks when only category is specified
        (None, None, "proxy"): ("Generic", "Proxy", "simple", None),
        (None, None, "firewall"): ("Generic", "Firewall", "simple", None),
        (None, None, "dns"): ("Generic", "DNS", "simple", None),
        (None, None, "webserver"): ("Generic", "Web Server", "simple", None),
        (None, None, "antivirus"): ("Generic", "Antivirus", "simple", "security_tool"),
        (None, None, "database"): ("Generic", "Database", "simple", "application"),

        # ===== OTHER PRODUCTS =====
        ("bitbucket", "audit", None): ("Atlassian", "Bitbucket", "simple", "application"),
        ("cisco", "duo", None): ("Cisco Systems", "Duo Security", "simple", "identity"),
        ("zeek", "dns", None): ("Zeek", "Zeek", "simple", "network"),
        ("zeek", "http", None): ("Zeek", "Zeek", "simple", "network"),
        ("zeek", "smb_files", None): ("Zeek", "Zeek", "simple", "network"),
        ("zeek", None, None): ("Zeek", "Zeek", "simple", "network"),
    }

    @classmethod
    def get_vendor_product(
        cls,
        product: Optional[str],
        service: Optional[str] = None,
        category: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Get CSE vendor, product, pattern type, and source classification for a Sigma logsource.

        Args:
            product: Sigma logsource product (e.g., "windows", "aws")
            service: Sigma logsource service (e.g., "sysmon", "cloudtrail")
            category: Sigma logsource category (e.g., "process_creation")

        Returns:
            Tuple of (vendor, product, pattern_type, classification) or (None, None, None, None) if not found.
            Handles both 3-tuple (legacy) and 4-tuple (new) mappings for backward compatibility.

        Example:
            >>> get_vendor_product("windows", "sysmon")
            ("Microsoft", "Windows", "concatenation", "endpoint")
            >>> get_vendor_product("aws", "cloudtrail")
            ("Amazon AWS", "CloudTrail", "concatenation", "cloud_audit")
            >>> get_vendor_product("okta")
            ("Okta", "Single Sign-On", "simple", "identity")
        """
        # Normalize to lowercase
        product_lower = product.lower() if product else None
        service_lower = service.lower() if service else None
        category_lower = category.lower() if category else None

        # Try exact match: (product, service, category)
        key = (product_lower, service_lower, category_lower)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            result = cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]
            # Handle both 3-tuple (legacy) and 4-tuple (new) for backward compatibility
            if len(result) == 3:
                return (*result, None)  # vendor, product, pattern_type, None
            return result  # vendor, product, pattern_type, classification

        # Try (product, service, None)
        key = (product_lower, service_lower, None)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            result = cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]
            if len(result) == 3:
                return (*result, None)
            return result

        # Try (product, None, category)
        key = (product_lower, None, category_lower)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            result = cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]
            if len(result) == 3:
                return (*result, None)
            return result

        # Try (product, None, None)
        key = (product_lower, None, None)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            result = cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]
            if len(result) == 3:
                return (*result, None)
            return result

        # Try generic category fallback (None, None, category)
        key = (None, None, category_lower)
        if key in cls.LOGSOURCE_TO_VENDOR_PRODUCT:
            result = cls.LOGSOURCE_TO_VENDOR_PRODUCT[key]
            if len(result) == 3:
                return (*result, None)
            return result

        return (None, None, None, None)

    @classmethod
    def get_source_classification(
        cls,
        product: Optional[str],
        service: Optional[str] = None,
        category: Optional[str] = None
    ) -> Optional[str]:
        """
        Get source classification for entity selection.

        Source classifications map products to entity selection patterns:
        - "endpoint": Windows, Linux, macOS endpoints
        - "identity": SSO/authentication systems (Okta, Azure SigninLogs)
        - "cloud_audit": Cloud control plane audit logs (CloudTrail, Azure AuditLogs)
        - "network": Firewalls, network devices
        - "application": SaaS applications (GitHub, O365)
        - "cloud_infrastructure": Cloud data plane logs (VPC Flow, ELB)
        - "security_tool": EDR, AV, security products

        Args:
            product: Sigma logsource product
            service: Sigma logsource service
            category: Sigma logsource category

        Returns:
            Source classification string or None if not found

        Example:
            >>> get_source_classification("okta")
            "identity"
            >>> get_source_classification("aws", "cloudtrail")
            "cloud_audit"
            >>> get_source_classification("windows", "sysmon")
            "endpoint"
        """
        vendor, product, pattern_type, classification = cls.get_vendor_product(product, service, category)
        return classification

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
