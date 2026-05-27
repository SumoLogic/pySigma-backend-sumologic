"""
Schema loader for Sumo Logic Cloud SIEM (CSE) schema.

Parses descriptions.yaml and provides structured access to field metadata
for confidence scoring and validation.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


@dataclass
class FieldSchema:
    """Represents a single CSE schema field with its metadata."""

    field_name: str
    description: str
    field_type: str  # string, int, long, etc.
    entity_type: str  # hostname, ip, mac, etc.
    enrichment_attribute: bool
    related_attributes: Dict[str, str]  # field_name -> explanation
    example_usage: List[Dict]  # Examples from schema

    def is_general_purpose(self) -> bool:
        """
        Check if this is a general-purpose field (action, description, resource).
        General-purpose fields are penalized in specificity scoring.
        """
        general_fields = {
            "action",
            "description",
            "resource",
            "resourceType",
            "application",
            "normalizedAction",
            "normalizedResource",
        }
        return self.field_name in general_fields

    def get_keywords(self) -> Set[str]:
        """
        Extract keywords from field name and description for semantic similarity.
        Returns lowercase tokens for matching.
        """
        keywords = set()

        # Tokenize field name (split on underscores, camelCase)
        name_tokens = self.field_name.replace("_", " ")
        # Split camelCase: device_hostname -> device hostname
        import re

        name_tokens = re.sub(r"([a-z])([A-Z])", r"\1 \2", name_tokens)
        keywords.update(name_tokens.lower().split())

        # Tokenize description (first sentence is most relevant)
        if self.description:
            first_sentence = self.description.split(".")[0]
            desc_tokens = re.findall(r"\b\w+\b", first_sentence.lower())
            keywords.update(desc_tokens)

        return keywords


class SchemaIndex:
    """
    In-memory index of CSE schema fields for fast lookup and validation.
    """

    def __init__(self, fields: Dict[str, FieldSchema]):
        self.fields = fields

        # Build reverse indexes for fast lookup
        self._entity_type_index = {}
        self._enrichment_fields = set()
        self._general_purpose_fields = set()

        for field_name, field in fields.items():
            # Index by entity type
            if field.entity_type:
                if field.entity_type not in self._entity_type_index:
                    self._entity_type_index[field.entity_type] = []
                self._entity_type_index[field.entity_type].append(field_name)

            # Index enrichment fields
            if field.enrichment_attribute:
                self._enrichment_fields.add(field_name)

            # Index general-purpose fields
            if field.is_general_purpose():
                self._general_purpose_fields.add(field_name)

    def get_field(self, field_name: str) -> Optional[FieldSchema]:
        """Get field schema by name."""
        return self.fields.get(field_name)

    def field_exists(self, field_name: str) -> bool:
        """Check if a field exists in the schema."""
        return field_name in self.fields

    def is_enrichment_field(self, field_name: str) -> bool:
        """Check if field is marked as enrichment-only."""
        return field_name in self._enrichment_fields

    def is_general_purpose(self, field_name: str) -> bool:
        """Check if field is a general-purpose field."""
        return field_name in self._general_purpose_fields

    def get_related_fields(self, field_name: str) -> Dict[str, str]:
        """Get related attributes for a field (semantic relationships)."""
        field = self.get_field(field_name)
        return field.related_attributes if field else {}

    def get_fields_by_entity_type(self, entity_type: str) -> List[str]:
        """Get all fields associated with an entity type (ip, hostname, etc.)."""
        return self._entity_type_index.get(entity_type, [])


class SchemaLoader:
    """
    Loads and caches Sumo Logic CSE schema from descriptions.yaml.
    """

    _cached_schema: Optional[SchemaIndex] = None
    _cache_path: Optional[str] = None

    @classmethod
    def get_bundled_schema_path(cls) -> Path:
        """Get path to bundled schema file."""
        return Path(__file__).parent / "schema" / "descriptions.yaml"

    @classmethod
    def resolve_schema_path(cls, explicit_path: Optional[str] = None) -> Optional[Path]:
        """
        Resolve schema path using priority order:
        1. Explicit path parameter
        2. Environment variable SUMOLOGIC_CSE_SCHEMA_PATH
        3. Bundled schema in package

        Returns None if no valid schema found (graceful degradation).
        """
        # Priority 1: Explicit path
        if explicit_path:
            path = Path(explicit_path)
            if path.exists():
                return path
            else:
                import warnings

                warnings.warn(f"Explicit schema path not found: {explicit_path}")
                return None

        # Priority 2: Environment variable
        env_path = os.getenv("SUMOLOGIC_CSE_SCHEMA_PATH")
        if env_path:
            path = Path(env_path)
            if path.exists():
                return path
            else:
                import warnings

                warnings.warn(f"SUMOLOGIC_CSE_SCHEMA_PATH not found: {env_path}")

        # Priority 3: Bundled schema
        bundled_path = cls.get_bundled_schema_path()
        if bundled_path.exists():
            return bundled_path

        # No schema found - will skip validation
        import warnings

        warnings.warn(
            "CSE schema file (descriptions.yaml) not found. "
            "Confidence scoring will work but schema validation will be skipped. "
            "Set SUMOLOGIC_CSE_SCHEMA_PATH environment variable or use -O schema_path=<path>"
        )
        return None

    @classmethod
    def load(
        cls, schema_path: Optional[str] = None, force_reload: bool = False
    ) -> Optional[SchemaIndex]:
        """
        Load and parse CSE schema from YAML.

        Args:
            schema_path: Optional explicit path to schema file
            force_reload: Force reload even if cached

        Returns:
            SchemaIndex or None if schema not found (graceful degradation)
        """
        # Check cache
        if not force_reload and cls._cached_schema and cls._cache_path == schema_path:
            return cls._cached_schema

        # Resolve schema path
        resolved_path = cls.resolve_schema_path(schema_path)
        if not resolved_path:
            return None  # Graceful degradation - no schema

        # Parse YAML
        try:
            with open(resolved_path, "r") as f:
                # descriptions.yaml is a stream of documents (----separated)
                docs = list(yaml.safe_load_all(f))

            # Build field index
            fields = {}
            for doc in docs:
                if not doc or "field_name" not in doc:
                    continue

                field_name = doc["field_name"]

                # Parse related_attributes (can be dict or None)
                related_attrs = {}
                if "related_attributes" in doc and doc["related_attributes"]:
                    related_attrs = doc["related_attributes"]

                # Parse example_usage
                example_usage = doc.get("example_usage", [])

                field = FieldSchema(
                    field_name=field_name,
                    description=doc.get("description", "").strip(),
                    field_type=str(doc.get("type", "string")),
                    entity_type=doc.get("entity_type", ""),
                    enrichment_attribute=doc.get("enrichment_attribute", False),
                    related_attributes=related_attrs,
                    example_usage=(
                        example_usage if isinstance(example_usage, list) else []
                    ),
                )

                fields[field_name] = field

            # Create index
            schema_index = SchemaIndex(fields)

            # Cache
            cls._cached_schema = schema_index
            cls._cache_path = schema_path

            return schema_index

        except Exception as e:
            import warnings

            warnings.warn(f"Failed to load CSE schema from {resolved_path}: {e}")
            return None  # Graceful degradation

    @classmethod
    def clear_cache(cls):
        """Clear cached schema (useful for testing)."""
        cls._cached_schema = None
        cls._cache_path = None
