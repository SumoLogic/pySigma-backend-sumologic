"""
Loader for the unified logsource_mappings.yaml configuration.

Provides access to vendor/product metadata and field mappings from a single YAML source.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


_CONFIG_PATH = Path(__file__).parent / "logsource_mappings.yaml"
_cached_data: Optional[dict] = None


def _load() -> dict:
    global _cached_data
    if _cached_data is None:
        with open(_CONFIG_PATH) as f:
            _cached_data = yaml.safe_load(f)
    return _cached_data


def get_vendor_product_map() -> Dict[
    Tuple[Optional[str], Optional[str], Optional[str]],
    Tuple[str, str, str, Optional[str]],
]:
    """
    Build the (product, service, category) → (vendor, product_name, pattern_type, classification)
    lookup dict from the YAML config.

    Only entries with a `vendor` key are included.
    """
    data = _load()
    result = {}
    for entry in data["mappings"]:
        if "vendor" not in entry:
            continue
        logsource = entry.get("logsource", {})
        key = (
            logsource.get("product"),
            logsource.get("service"),
            logsource.get("category"),
        )
        value = (
            entry["vendor"],
            entry["product_name"],
            entry["pattern_type"],
            entry.get("classification"),
        )
        result[key] = value
    return result


def get_field_mappings() -> List[dict]:
    """
    Return ordered list of field mapping entries for pipeline construction.

    Each dict has keys: name, logsource (optional), fields.
    Only entries with a `fields` key are included.
    Order matches YAML list order (defines processing priority).
    """
    data = _load()
    return [entry for entry in data["mappings"] if "fields" in entry]
