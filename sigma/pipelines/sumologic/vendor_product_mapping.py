"""
Mapping from Sigma logsource to CSE vendor/product metadata.

Based on CSE Parser EventID Analysis (April 2026):
- 252 parsers analyzed from CSE test logs
- Covers Windows, AWS, Azure, GCP, Linux, Network devices
- Maps Sigma (product, service, category) → CSE (vendor, product, parser pattern)

Configuration is loaded from logsource_mappings.yaml.
"""

from typing import Optional, Tuple, Dict

from sigma.pipelines.sumologic.logsource_config import get_vendor_product_map


class VendorProductMapper:
    """
    Maps Sigma logsource to CSE metadata_vendor and metadata_product.

    Based on CSE parser configuration analysis.
    Mapping data is loaded from logsource_mappings.yaml.
    """

    LOGSOURCE_TO_VENDOR_PRODUCT = get_vendor_product_map()

    @classmethod
    def get_vendor_product(
        cls,
        product: Optional[str],
        service: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Get CSE vendor, product, pattern type, and source classification for a Sigma logsource.

        Args:
            product: Sigma logsource product (e.g., "windows", "aws")
            service: Sigma logsource service (e.g., "sysmon", "cloudtrail")
            category: Sigma logsource category (e.g., "process_creation")

        Returns:
            Tuple of (vendor, product, pattern_type, classification) or (None, None, None, None) if not found.

        Example:
            >>> get_vendor_product("windows", "sysmon")
            ("Microsoft", "Windows", "concatenation", "endpoint")
            >>> get_vendor_product("aws", "cloudtrail")
            ("Amazon AWS", "CloudTrail", "concatenation", "cloud_audit")
            >>> get_vendor_product("okta")
            ("Okta", "Single Sign-On", "simple", "identity")
        """
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

        return (None, None, None, None)

    @classmethod
    def get_source_classification(
        cls,
        product: Optional[str],
        service: Optional[str] = None,
        category: Optional[str] = None,
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
        """
        vendor, product_name, pattern_type, classification = cls.get_vendor_product(
            product, service, category
        )
        return classification

    @classmethod
    def has_cse_parser(
        cls,
        product: Optional[str],
        service: Optional[str] = None,
        category: Optional[str] = None,
    ) -> bool:
        """
        Check if a CSE parser exists for this Sigma logsource.

        Returns:
            True if mapping exists, False otherwise
        """
        vendor, _, _, _ = cls.get_vendor_product(product, service, category)
        return vendor is not None

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
