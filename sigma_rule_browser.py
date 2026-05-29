#!/usr/bin/env python3
"""
Sigma Rule Browser and Converter
A Streamlit app for browsing Sigma rules and converting them to Sumo Logic CSE format.
"""

import streamlit as st
import os
import yaml
import json
from pathlib import Path
from typing import List, Dict, Any
from sigma.backends.sumologic import SumoLogicCSERuleBackend
from sigma.pipelines.sumologic import sumologic_cse_pipeline
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

# Configuration
SIGMA_REPO_PATH = Path(os.getenv("SIGMA_REPO_PATH", "./sigma-rules"))
RULE_DIRS = [
    "rules",
    "rules-dfir",
    "rules-compliance",
    "rules-threat-hunting",
    "rules-emerging-threats",
    "rules-placeholder",
]


def find_sigma_rules(base_path: Path, rule_dirs: List[str]) -> Dict[str, List[Path]]:
    """Find all Sigma rule files organized by directory."""
    rules_by_dir = {}

    for rule_dir in rule_dirs:
        dir_path = base_path / rule_dir
        if not dir_path.exists():
            continue

        rule_files = []
        for ext in ["*.yml", "*.yaml"]:
            rule_files.extend(dir_path.rglob(ext))

        if rule_files:
            rules_by_dir[rule_dir] = sorted(rule_files)

    return rules_by_dir


def load_rule_yaml(rule_path: Path) -> Dict[str, Any]:
    """Load and parse a Sigma rule YAML file."""
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        return {"error": str(e)}


def extract_confidence_metadata(pipeline: ProcessingPipeline) -> Dict[str, Any]:
    """Extract confidence metadata from a pipeline.

    Args:
        pipeline: Processing pipeline (may contain confidence-aware transformations)

    Returns:
        Dictionary with confidence metadata, or empty dict if not available
    """
    confidence_data = {"field_mappings": [], "logsource_category": None}

    try:
        for item in pipeline.items:
            transformation = getattr(item, "transformation", None)
            if transformation and hasattr(transformation, "get_confidence_metadata"):
                metadata = transformation.get_confidence_metadata()
                confidence_data["field_mappings"].extend(
                    metadata.get("field_mappings", [])
                )
                if not confidence_data["logsource_category"]:
                    confidence_data["logsource_category"] = metadata.get(
                        "logsource_category"
                    )
    except Exception:
        pass

    return confidence_data


# Confidence thresholds from the CLI tool (must match confidence.py)
CATEGORY_THRESHOLDS = {
    "authentication": 0.80,
    "process_creation": 0.75,
    "image_load": 0.75,
    "registry_event": 0.75,
    "network_connection": 0.70,
    "dns_query": 0.70,
    "firewall": 0.70,
    "file_event": 0.70,
    "proxy": 0.60,
    "default": 0.70,
}


def check_confidence_gate(confidence_metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Check if a rule would pass the confidence gate.

    Args:
        confidence_metadata: Confidence metadata from conversion

    Returns:
        Dictionary with gate status and details
    """
    if not confidence_metadata or not confidence_metadata.get("field_mappings"):
        return {
            "would_pass": True,
            "reason": "No field mappings to check",
            "failed_mappings": [],
            "threshold": None,
        }

    category = confidence_metadata.get("logsource_category", "default")
    threshold = CATEGORY_THRESHOLDS.get(category, CATEGORY_THRESHOLDS["default"])

    failed_mappings = []
    for mapping in confidence_metadata["field_mappings"]:
        confidence = mapping.get("confidence", 1.0)
        if confidence < threshold:
            failed_mappings.append(
                {
                    "sigma_field": mapping["sigma_field"],
                    "cse_field": mapping["cse_field"],
                    "confidence": confidence,
                    "threshold": threshold,
                    "gap": threshold - confidence,
                }
            )

    would_pass = len(failed_mappings) == 0

    return {
        "would_pass": would_pass,
        "reason": (
            f"All mappings meet threshold"
            if would_pass
            else f"{len(failed_mappings)} mapping(s) below threshold"
        ),
        "failed_mappings": failed_mappings,
        "threshold": threshold,
        "category": category,
    }


def convert_rules(
    rule_paths: List[Path], enable_confidence: bool = True
) -> List[Dict[str, Any]]:
    """Convert selected Sigma rules to Sumo Logic CSE format.

    Args:
        rule_paths: List of paths to Sigma rule files
        enable_confidence: If True, use confidence-aware pipeline (currently always enabled)

    Returns:
        List of conversion results with metadata
    """
    # For now, always use the standard pipeline
    # The confidence toggle is informational - showing confidence metadata
    # Future: Could implement pipeline variants with different confidence thresholds
    pipeline = sumologic_cse_pipeline()

    backend = SumoLogicCSERuleBackend(processing_pipeline=pipeline)
    results = []

    for rule_path in rule_paths:
        rule_yaml = None
        try:
            # Read the rule file (do this first so we have it even if conversion fails)
            with open(rule_path, "r", encoding="utf-8") as f:
                rule_yaml = f.read()

            # Convert using the backend
            collection = SigmaCollection.from_yaml(rule_yaml)
            converted = backend.convert(collection)

            # Parse the JSON result - now wrapped in {"rules": [...]}
            if converted:
                for json_str in converted:
                    parsed = json.loads(json_str)
                    # Extract rules from wrapper
                    if "rules" in parsed:
                        for rule_json in parsed["rules"]:
                            results.append(
                                {
                                    "source_file": str(
                                        rule_path.relative_to(SIGMA_REPO_PATH)
                                    ),
                                    "rule": rule_json,
                                    "source_yaml": rule_yaml,
                                    "confidence_metadata": rule_json.get(
                                        "mapping_confidence", {}
                                    ),
                                    "success": True,
                                }
                            )
                    else:
                        results.append(
                            {
                                "source_file": str(
                                    rule_path.relative_to(SIGMA_REPO_PATH)
                                ),
                                "rule": parsed,
                                "source_yaml": rule_yaml,
                                "confidence_metadata": parsed.get(
                                    "mapping_confidence", {}
                                ),
                                "success": True,
                            }
                        )
        except Exception as e:
            results.append(
                {
                    "source_file": str(rule_path.relative_to(SIGMA_REPO_PATH)),
                    "error": str(e),
                    "source_yaml": rule_yaml,  # Store YAML even on failure
                    "success": False,
                }
            )

    return results


def main():
    st.set_page_config(
        page_title="Sigma Rule Browser & Converter", page_icon="🔍", layout="wide"
    )

    # Custom CSS inspired by Sumo Logic CSE
    st.markdown(
        """
        <style>
        /* CSE-inspired styling */
        .main {
            background-color: #101827;
        }

        /* Card-like containers */
        .stExpander {
            background-color: #151e30;
            border: 1px solid rgba(160, 193, 250, 0.15);
            border-radius: 4px;
        }

        /* Metrics styling */
        [data-testid="stMetricValue"] {
            font-size: 1.8rem;
            color: #2063d6;
        }

        /* Code blocks */
        .stCodeBlock {
            background-color: #151e30;
            border: 1px solid rgba(160, 193, 250, 0.15);
        }

        /* Buttons */
        .stButton > button {
            border-radius: 4px;
            font-weight: 500;
            text-transform: none;
        }

        .stButton > button[kind="primary"] {
            background-color: #2063d6;
            color: white;
        }

        .stButton > button[kind="primary"]:hover {
            background-color: #0e70c0;
        }

        /* Success/error colors matching CSE */
        .stSuccess {
            background-color: rgba(120, 189, 49, 0.1);
            color: #78bd31;
        }

        .stError {
            background-color: rgba(247, 90, 79, 0.1);
            color: #f75a4f;
        }

        /* Divider */
        hr {
            border-color: rgba(160, 193, 250, 0.15);
        }

        /* Selection boxes */
        .stSelectbox, .stMultiSelect {
            background-color: #151e30;
        }

        /* Headers */
        h1, h2, h3 {
            color: #f5f8fa;
        }

        /* Sidebar */
        section[data-testid="stSidebar"] {
            background-color: #0e1420;
        }

        /* JSON viewer */
        .stJson {
            background-color: #151e30;
            border: 1px solid rgba(160, 193, 250, 0.15);
        }
        </style>
    """,
        unsafe_allow_html=True,
    )

    # Header with CSE-style branding
    col_logo, col_reload = st.columns([6, 1])
    with col_logo:
        st.markdown(
            """
            <div style="padding: 1rem 0;">
                <h1 style="margin: 0; color: #f5f8fa; font-size: 2rem; font-weight: 600;">
                    🔍 Sigma Rule Browser
                </h1>
                <p style="margin: 0.5rem 0 0 0; color: #9db4c7; font-size: 1rem;">
                    Browse and convert Sigma rules to Sumo Logic Cloud SIEM format
                </p>
            </div>
        """,
            unsafe_allow_html=True,
        )

    with col_reload:
        # Show backend info to verify we're using latest version
        from datetime import datetime
        from sigma.backends.sumologic import SumoLogicCSEBackend

        # Show last reload time to verify fresh imports
        if "last_reload" not in st.session_state:
            st.session_state.last_reload = datetime.now().strftime("%H:%M:%S")
        st.caption(f"Backend: {st.session_state.last_reload}")
        if st.button(
            "🔄", help="Force reload conversion backend", key="reload_backend"
        ):
            # Force reimport
            import importlib
            import sys

            if "sigma.backends.sumologic.sumologic" in sys.modules:
                del sys.modules["sigma.backends.sumologic.sumologic"]
            if "sigma.backends.sumologic" in sys.modules:
                del sys.modules["sigma.backends.sumologic"]
            st.session_state.last_reload = datetime.now().strftime("%H:%M:%S")
            st.rerun()

    st.divider()

    # Check if Sigma repo exists
    if not SIGMA_REPO_PATH.exists():
        st.error(f"Sigma repository not found at: {SIGMA_REPO_PATH}")
        st.info(
            "Please update SIGMA_REPO_PATH in the script to point to your Sigma repository."
        )
        return

    # Find all rules
    with st.spinner("Loading Sigma rules..."):
        rules_by_dir = find_sigma_rules(SIGMA_REPO_PATH, RULE_DIRS)

    if not rules_by_dir:
        st.warning("No Sigma rules found in the specified directories.")
        return

    # Sidebar for directory and rule selection
    st.sidebar.header("Rule Selection")

    # Directory selector
    selected_dir = st.sidebar.selectbox(
        "Select Rule Directory",
        options=list(rules_by_dir.keys()),
        format_func=lambda x: f"{x} ({len(rules_by_dir[x])} rules)",
    )

    # Get rules for selected directory
    available_rules = rules_by_dir[selected_dir]

    # Search/filter
    search_term = st.sidebar.text_input("🔎 Search rules", "")

    # Filter rules by search term
    if search_term:
        filtered_rules = [
            r
            for r in available_rules
            if search_term.lower() in r.name.lower()
            or search_term.lower() in str(r.parent).lower()
        ]
    else:
        filtered_rules = available_rules

    st.sidebar.info(f"Found {len(filtered_rules)} rules")

    # Initialize session state for selected rules
    if "selected_rules" not in st.session_state:
        st.session_state.selected_rules = []

    # Rule browsing and selection area
    st.sidebar.subheader("Browse & Select Rules")

    # Initialize preview state
    if "preview_rule" not in st.session_state:
        st.session_state.preview_rule = None

    # Organize rules by subdirectory for better navigation
    rules_by_subdir = {}
    for rule_path in filtered_rules:
        # Get the immediate subdirectory under the selected rule dir
        rel_path = rule_path.relative_to(SIGMA_REPO_PATH / selected_dir)
        subdir = str(rel_path.parts[0]) if len(rel_path.parts) > 1 else "root"
        if subdir not in rules_by_subdir:
            rules_by_subdir[subdir] = []
        rules_by_subdir[subdir].append(rule_path)

    # Subdirectory filter
    if rules_by_subdir:
        sorted_subdirs = sorted(rules_by_subdir.keys())
        subdir_counts = {sd: len(rules_by_subdir[sd]) for sd in sorted_subdirs}

        selected_subdir = st.sidebar.selectbox(
            "📁 Subdirectory",
            options=["All"] + sorted_subdirs,
            format_func=lambda x: (
                f"All ({len(filtered_rules)} rules)"
                if x == "All"
                else f"{x} ({subdir_counts.get(x, 0)} rules)"
            ),
            key="subdir_selector",
        )

        # Filter rules by subdirectory
        if selected_subdir == "All":
            browsable_rules = filtered_rules
        else:
            browsable_rules = rules_by_subdir[selected_subdir]

        # Rule selector for preview (limit to 500 for performance)
        if browsable_rules:
            display_limit = min(500, len(browsable_rules))
            rule_options = {
                str(r.relative_to(SIGMA_REPO_PATH / selected_dir)): r
                for r in browsable_rules[:display_limit]
            }

            selected_preview = st.sidebar.selectbox(
                f"👁️ Preview Rule ({display_limit} shown)",
                options=[""] + list(rule_options.keys()),
                format_func=lambda x: "Select a rule to preview..." if x == "" else x,
                key="preview_selector",
            )

            if selected_preview and selected_preview != "":
                st.session_state.preview_rule = rule_options[selected_preview]

            if len(browsable_rules) > display_limit:
                st.sidebar.caption(
                    f"Showing first {display_limit} of {len(browsable_rules)} rules. Use search to narrow down."
                )

    st.sidebar.divider()
    st.sidebar.subheader("✅ Select for Conversion")

    # Use browsable_rules from subdirectory filter
    display_for_selection = (
        browsable_rules[:50] if "browsable_rules" in locals() else filtered_rules[:50]
    )

    # Select all / Clear all buttons (for currently visible rules)
    col1, col2 = st.sidebar.columns(2)
    if col1.button("Select Visible", help="Select all visible rules"):
        for rule in display_for_selection:
            if rule not in st.session_state.selected_rules:
                st.session_state.selected_rules.append(rule)
        st.rerun()
    if col2.button("Clear All"):
        st.session_state.selected_rules = []
        st.rerun()

    st.sidebar.caption(f"Showing {len(display_for_selection)} rules for selection")

    # Rule checkboxes in sidebar
    for rule_path in display_for_selection:
        relative_path = rule_path.relative_to(SIGMA_REPO_PATH / selected_dir)
        is_selected = rule_path in st.session_state.selected_rules

        if st.sidebar.checkbox(
            str(relative_path), value=is_selected, key=f"rule_{rule_path}"
        ):
            if rule_path not in st.session_state.selected_rules:
                st.session_state.selected_rules.append(rule_path)
        else:
            if rule_path in st.session_state.selected_rules:
                st.session_state.selected_rules.remove(rule_path)

    # Main content area
    # Live Preview Panel (top of page)
    if st.session_state.preview_rule:
        st.markdown("### 👁️ Rule Preview")
        rule_data = load_rule_yaml(st.session_state.preview_rule)

        if "error" in rule_data:
            st.error(f"Error loading rule: {rule_data['error']}")
        else:
            # Show preview in a nice card layout
            with st.container():
                st.markdown(
                    f"""
                    <div style="background-color: #151e30; padding: 1.5rem; border-radius: 4px; border: 1px solid rgba(160, 193, 250, 0.15); margin-bottom: 1rem;">
                        <h3 style="margin: 0 0 1rem 0; color: #f5f8fa;">📄 {rule_data.get('title', 'Untitled')}</h3>
                    </div>
                """,
                    unsafe_allow_html=True,
                )

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.markdown(f"**Severity**")
                    st.markdown(
                        f"<span style='color: #2063d6; font-size: 1.3rem; font-weight: 600;'>{rule_data.get('level', 'N/A').upper()}</span>",
                        unsafe_allow_html=True,
                    )
                with col2:
                    st.markdown(f"**Status**")
                    st.markdown(
                        f"<span style='color: #2063d6; font-size: 1.3rem; font-weight: 600;'>{rule_data.get('status', 'N/A')}</span>",
                        unsafe_allow_html=True,
                    )
                with col3:
                    st.markdown(f"**Rule ID**")
                    rule_id = rule_data.get("id", "N/A")
                    display_id = (
                        rule_id[:13] + "..."
                        if rule_id and len(rule_id) > 16
                        else rule_id
                    )
                    st.markdown(
                        f"<span style='color: #9db4c7; font-size: 1rem; font-family: monospace;'>{display_id}</span>",
                        unsafe_allow_html=True,
                    )
                with col4:
                    st.markdown(f"**Author**")
                    author = rule_data.get("author", "Unknown").split(",")[0]
                    st.markdown(
                        f"<span style='color: #9db4c7; font-size: 1rem;'>{author}</span>",
                        unsafe_allow_html=True,
                    )

                st.markdown(
                    f"**Description:** {rule_data.get('description', 'No description available')}"
                )

                # Show tags if present
                if "tags" in rule_data and rule_data["tags"]:
                    tags_display = " ".join(
                        [f"`{tag}`" for tag in rule_data["tags"][:10]]
                    )
                    st.markdown(f"**Tags:** {tags_display}")
                    if len(rule_data["tags"]) > 10:
                        st.caption(f"...and {len(rule_data['tags']) - 10} more tags")

                # Two columns for logsource and detection
                col_left, col_right = st.columns(2)

                with col_left:
                    if "logsource" in rule_data:
                        st.markdown("**Log Source:**")
                        st.json(rule_data["logsource"])

                with col_right:
                    if "detection" in rule_data:
                        st.markdown("**Detection Logic:**")
                        st.code(
                            yaml.dump(rule_data["detection"], default_flow_style=False),
                            language="yaml",
                        )

                # Quick convert button
                st.divider()

                col_convert, col_add = st.columns([2, 1])

                with col_convert:
                    if st.button(
                        "🚀 Convert This Rule", use_container_width=True, type="primary"
                    ):
                        with st.spinner("Converting..."):
                            results = convert_rules([st.session_state.preview_rule])

                            if results and results[0].get("success"):
                                rule_json = results[0]["rule"]

                                st.success("✅ Conversion successful!")

                                # Show key fields
                                st.markdown("### Converted CSE Rule")

                                info_col1, info_col2, info_col3, info_col4 = st.columns(
                                    4
                                )
                                # Handle new score_mapping structure
                                score_value = (
                                    rule_json.get("score_mapping", {}).get(
                                        "default", "N/A"
                                    )
                                    if isinstance(rule_json.get("score_mapping"), dict)
                                    else rule_json.get("score", "N/A")
                                )
                                info_col1.metric("Score", score_value)
                                info_col2.metric(
                                    "Enabled", str(rule_json.get("enabled", "N/A"))
                                )
                                info_col3.metric(
                                    "Prototype",
                                    str(
                                        rule_json.get(
                                            "is_prototype",
                                            rule_json.get("prototype", "N/A"),
                                        )
                                    ),
                                )
                                info_col4.metric(
                                    "Category", rule_json.get("category", "N/A")
                                )

                                # Expression
                                st.markdown("**CSE Expression:**")
                                st.code(
                                    rule_json.get("expression", "N/A"), language="sql"
                                )

                                # Full JSON in expander
                                with st.expander("📋 View Full JSON (with wrapper)"):
                                    wrapped_rule = {"rules": [rule_json]}
                                    st.json(wrapped_rule)

                                # Download button - wrap in rules structure
                                wrapped_rule = {"rules": [rule_json]}
                                json_output = json.dumps(wrapped_rule, indent=2)
                                st.download_button(
                                    label="📥 Download JSON (ready to import)",
                                    data=json_output,
                                    file_name=f"{st.session_state.preview_rule.stem}_cse.json",
                                    mime="application/json",
                                    use_container_width=True,
                                )
                            else:
                                st.error(f"❌ Conversion failed")
                                st.markdown("**Error:**")
                                st.code(
                                    results[0].get("error", "Unknown error"),
                                    language="text",
                                )

                                # Show original YAML for debugging
                                if results[0].get("source_yaml"):
                                    with st.expander("📥 View Original Sigma Rule"):
                                        st.code(
                                            results[0]["source_yaml"], language="yaml"
                                        )

                with col_add:
                    is_in_selection = (
                        st.session_state.preview_rule in st.session_state.selected_rules
                    )
                    if not is_in_selection:
                        if st.button("➕ Add to Batch", use_container_width=True):
                            st.session_state.selected_rules.append(
                                st.session_state.preview_rule
                            )
                            st.rerun()
                    else:
                        if st.button("➖ Remove", use_container_width=True):
                            st.session_state.selected_rules.remove(
                                st.session_state.preview_rule
                            )
                            st.rerun()

        st.divider()

    st.header(f"Selected for Conversion: {len(st.session_state.selected_rules)}")

    # Tabs for different views
    tab_compare, tab1, tab2, tab3 = st.tabs(
        ["⚡ Compare Mode", "📋 Selected Rules", "🔄 Convert", "📊 Results"]
    )

    with tab_compare:
        st.markdown("### ⚡ Live Compare Mode")
        st.info(
            "Browse rules and see instant conversion results. Perfect for rapid iteration!"
        )

        # Confidence toggle
        col_toggle, col_info = st.columns([1, 3])
        with col_toggle:
            use_confidence = st.toggle(
                "🎯 Confidence Gate",
                value=True,
                key="compare_confidence_toggle",
                help="Enable confidence-based field mapping validation",
            )
        with col_info:
            if use_confidence:
                st.caption(
                    "✅ Confidence gate enabled - low-confidence field mappings will be flagged"
                )
            else:
                st.caption(
                    "⚠️ Confidence gate disabled - all field mappings will be used"
                )

        st.divider()

        # Rule selector for compare mode
        if st.session_state.preview_rule:
            # Auto-convert the previewed rule
            with st.spinner("Converting..."):
                compare_results = convert_rules(
                    [st.session_state.preview_rule], enable_confidence=use_confidence
                )

            if compare_results and compare_results[0].get("success"):
                result = compare_results[0]
                rule_json = result["rule"]
                source_yaml = result.get("source_yaml", "")
                confidence_metadata = result.get("confidence_metadata", {})

                # Check confidence gate status
                gate_status = check_confidence_gate(confidence_metadata)

                # Show prominent gate status banner
                if gate_status["would_pass"]:
                    if gate_status["threshold"] is not None:
                        st.success(
                            f"✅ **WOULD CONVERT** — All field mappings meet confidence threshold ({gate_status['threshold']:.0%} for `{gate_status.get('category', 'default')}`)"
                        )
                    else:
                        st.success(f"✅ **WOULD CONVERT** — {gate_status['reason']}")
                else:
                    st.error(
                        f"🚫 **BLOCKED BY DEFAULT** — {len(gate_status['failed_mappings'])} mapping(s) below threshold ({gate_status['threshold']:.0%} for `{gate_status.get('category', 'default')}`)"
                    )

                    # Show which mappings failed
                    with st.expander("⚠️ View Failed Mappings", expanded=True):
                        for fm in gate_status["failed_mappings"]:
                            st.markdown(
                                f"- `{fm['sigma_field']}` → `{fm['cse_field']}`: "
                                f"**{fm['confidence']:.0%}** (need {fm['threshold']:.0%}, gap: {fm['gap']:.0%})"
                            )

                st.divider()

                # Side-by-side comparison
                col_input, col_output = st.columns(2)

                with col_input:
                    st.markdown("#### 📥 Input: Sigma Rule")
                    rule_data = load_rule_yaml(st.session_state.preview_rule)

                    # Show key metadata
                    if "error" not in rule_data:
                        mcol1, mcol2, mcol3 = st.columns(3)
                        mcol1.metric("Level", rule_data.get("level", "N/A").upper())
                        mcol2.metric("Status", rule_data.get("status", "N/A"))
                        mcol3.metric(
                            "Category",
                            rule_data.get("logsource", {}).get("category", "N/A"),
                        )

                    st.code(source_yaml, language="yaml", line_numbers=False)

                with col_output:
                    st.markdown("#### 📤 Output: CSE Rule")

                    # Show key CSE fields in readable format
                    st.markdown("**Rule Metadata:**")
                    meta_col1, meta_col2 = st.columns(2)

                    with meta_col1:
                        st.markdown(f"- **Name:** `{rule_json.get('name', 'N/A')}`")
                        st.markdown(
                            f"- **Content Type:** `{rule_json.get('content_type', 'N/A')}`"
                        )
                        st.markdown(
                            f"- **Pattern Type:** `{rule_json.get('pattern_type', 'N/A')}`"
                        )
                        st.markdown(f"- **Stream:** `{rule_json.get('stream', 'N/A')}`")
                        st.markdown(
                            f"- **Rule Source:** `{rule_json.get('rule_source', 'N/A')}`"
                        )

                    with meta_col2:
                        score_value = rule_json.get("score_mapping", {}).get(
                            "default", "N/A"
                        )
                        st.markdown(
                            f"- **Score:** `{score_value}` (type: `{rule_json.get('score_mapping', {}).get('type', 'N/A')}`)"
                        )
                        st.markdown(
                            f"- **Enabled:** `{rule_json.get('enabled', 'N/A')}`"
                        )
                        st.markdown(
                            f"- **Prototype:** `{rule_json.get('is_prototype', 'N/A')}`"
                        )
                        st.markdown(
                            f"- **Category:** `{rule_json.get('category', 'N/A')}`"
                        )

                    st.divider()

                    # CSE Expression (prominent, with word wrap)
                    st.markdown("**CSE Expression:**")
                    expression = rule_json.get("expression", "N/A")
                    # Use text_area for word wrap instead of code block
                    # Key must be unique per rule to force refresh
                    rule_key = (
                        st.session_state.preview_rule.stem
                        if st.session_state.preview_rule
                        else "none"
                    )
                    st.text_area(
                        label="expression",
                        value=expression,
                        height=150,
                        label_visibility="collapsed",
                        key=f"compare_expression_{rule_key}",
                    )

                    # Entity Selectors
                    if rule_json.get("entity_selectors"):
                        st.markdown("**Entity Selectors:**")
                        for selector in rule_json["entity_selectors"]:
                            st.markdown(
                                f"- `{selector.get('entity_type')}` ← `{selector.get('expression')}`"
                            )

                    # Tags
                    if rule_json.get("tags"):
                        st.markdown("**Tags:**")
                        tags_str = ", ".join(
                            [f"`{tag}`" for tag in rule_json["tags"][:5]]
                        )
                        st.markdown(tags_str)
                        if len(rule_json["tags"]) > 5:
                            st.caption(f"...and {len(rule_json['tags']) - 5} more")

                    st.divider()

                    # Full JSON in expander (for copy/paste)
                    with st.expander("📋 Full JSON (for copy/paste)"):
                        wrapped_rule = {"rules": [rule_json]}
                        st.json(wrapped_rule)

                        # Add copy button
                        json_output = json.dumps(wrapped_rule, indent=2)
                        st.download_button(
                            label="📥 Download JSON",
                            data=json_output,
                            file_name=f"{st.session_state.preview_rule.stem}_cse.json",
                            mime="application/json",
                            key="compare_download",
                        )

                st.divider()

                # Confidence metadata below
                if confidence_metadata and confidence_metadata.get("field_mappings"):
                    with st.expander(
                        "🎯 Field Mapping Confidence Analysis", expanded=False
                    ):
                        st.markdown("**Confidence Scores for Field Mappings:**")

                        # Create a table of confidence scores
                        mappings = confidence_metadata["field_mappings"]

                        for mapping in mappings:
                            sigma_field = mapping["sigma_field"]
                            cse_field = mapping["cse_field"]
                            confidence = mapping["confidence"]
                            factors = mapping["factors"]
                            warnings = mapping.get("warnings", [])

                            # Color code confidence
                            if confidence >= 0.80:
                                conf_color = "#78bd31"  # Green
                                conf_emoji = "✅"
                            elif confidence >= 0.70:
                                conf_color = "#d67302"  # Orange
                                conf_emoji = "⚠️"
                            else:
                                conf_color = "#f75a4f"  # Red
                                conf_emoji = "❌"

                            # Display mapping
                            col_map, col_score, col_details = st.columns([3, 1, 1])

                            with col_map:
                                st.markdown(f"`{sigma_field}` → `{cse_field}`")

                            with col_score:
                                st.markdown(
                                    f"<span style='color: {conf_color}; font-weight: bold;'>{conf_emoji} {confidence:.2f}</span>",
                                    unsafe_allow_html=True,
                                )

                            with col_details:
                                with st.popover("Details"):
                                    st.markdown("**Factor Breakdown:**")
                                    st.markdown(
                                        f"- Semantic: {factors['semantic_similarity']:.2f}"
                                    )
                                    st.markdown(
                                        f"- Data Preservation: {factors['data_preservation']:.2f}"
                                    )
                                    st.markdown(
                                        f"- Type Compatibility: {factors['type_compatibility']:.2f}"
                                    )
                                    st.markdown(
                                        f"- Field Specificity: {factors['field_specificity']:.2f}"
                                    )

                                    if warnings:
                                        st.markdown("**Warnings:**")
                                        for warning in warnings:
                                            st.warning(warning)

                        st.divider()
                        st.caption(
                            f"Category: {confidence_metadata.get('logsource_category', 'N/A')}"
                        )

                else:
                    st.caption(
                        "💡 Confidence metadata not available for this conversion"
                    )

            else:
                # Show error
                st.error("❌ Conversion failed")
                if compare_results:
                    st.code(compare_results[0].get("error", "Unknown error"))
                    if compare_results[0].get("source_yaml"):
                        with st.expander("View Original Sigma Rule"):
                            st.code(compare_results[0]["source_yaml"], language="yaml")

        else:
            st.info("👈 Select a rule from the sidebar to see live conversion")

    with tab1:
        if st.session_state.selected_rules:
            st.info(
                f"These {len(st.session_state.selected_rules)} rule(s) will be converted when you click the Convert button"
            )

            # Show compact list of selected rules
            for idx, rule_path in enumerate(st.session_state.selected_rules, 1):
                rule_data = load_rule_yaml(rule_path)
                relative_path = rule_path.relative_to(SIGMA_REPO_PATH)

                col1, col2, col3 = st.columns([6, 2, 1])

                with col1:
                    st.markdown(f"**{idx}.** `{relative_path}`")
                    if "error" not in rule_data:
                        st.caption(
                            f"{rule_data.get('title', 'Untitled')} - {rule_data.get('level', 'N/A')}"
                        )

                with col2:
                    if "error" not in rule_data:
                        if (
                            "logsource" in rule_data
                            and "category" in rule_data["logsource"]
                        ):
                            st.markdown(f"`{rule_data['logsource']['category']}`")

                with col3:
                    if st.button(
                        "❌", key=f"remove_{idx}", help="Remove from selection"
                    ):
                        st.session_state.selected_rules.remove(rule_path)
                        st.rerun()

                st.divider()
        else:
            st.info(
                "No rules selected for conversion. Use the sidebar to select rules, or use the preview panel above to browse and add rules."
            )

    with tab2:
        st.subheader("Convert Selected Rules")

        if st.session_state.selected_rules:
            st.info(f"Ready to convert {len(st.session_state.selected_rules)} rule(s)")

            if st.button(
                "🚀 Convert to Sumo Logic CSE", type="primary", key="batch_convert"
            ):
                try:
                    with st.spinner("Converting rules..."):
                        results = convert_rules(st.session_state.selected_rules)
                        st.session_state.conversion_results = results

                        # Show immediate feedback
                        success_count = sum(1 for r in results if r.get("success"))
                        error_count = len(results) - success_count

                        if success_count > 0:
                            st.success(
                                f"✅ Conversion complete! {success_count} successful, {error_count} errors"
                            )
                        else:
                            st.error(
                                f"❌ All conversions failed. Check the Results tab for details."
                            )

                        # Switch to results tab
                        st.info("👉 Go to the 'Results' tab to view converted rules")
                except Exception as e:
                    st.error(f"Error during conversion: {str(e)}")
                    import traceback

                    st.code(traceback.format_exc())
        else:
            st.warning("Please select at least one rule to convert.")

    with tab3:
        if "conversion_results" in st.session_state:
            results = st.session_state.conversion_results

            # Summary
            success_count = sum(1 for r in results if r.get("success"))
            error_count = len(results) - success_count

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Rules", len(results))
            col2.metric("Successful", success_count)
            col3.metric("Errors", error_count)

            # Download all results
            if success_count > 0:
                all_rules = [r["rule"] for r in results if r.get("success")]
                # Wrap in rules structure to match backend format
                wrapped_output = {"rules": all_rules}
                json_output = json.dumps(wrapped_output, indent=2)

                st.download_button(
                    label="📥 Download All CSE Rules (JSON)",
                    data=json_output,
                    file_name="cse_rules.json",
                    mime="application/json",
                )

            # Show individual results
            st.subheader("Conversion Results")

            for result in results:
                source_file = result["source_file"]

                if result.get("success"):
                    with st.expander(f"✅ {source_file}"):
                        rule_json = result["rule"]

                        # Show key fields with new field names
                        col_info1, col_info2, col_info3, col_info4, col_info5 = (
                            st.columns(5)
                        )
                        col_info1.metric(
                            "Name",
                            (
                                rule_json.get("name", "N/A")[:20] + "..."
                                if len(rule_json.get("name", "")) > 20
                                else rule_json.get("name", "N/A")
                            ),
                        )
                        score_value = (
                            rule_json.get("score_mapping", {}).get("default", "N/A")
                            if isinstance(rule_json.get("score_mapping"), dict)
                            else rule_json.get("score", "N/A")
                        )
                        col_info2.metric("Score", score_value)
                        col_info3.metric("Enabled", rule_json.get("enabled", "N/A"))
                        col_info4.metric(
                            "Prototype",
                            rule_json.get(
                                "is_prototype", rule_json.get("prototype", "N/A")
                            ),
                        )
                        col_info5.metric(
                            "Category",
                            (
                                rule_json.get("category", "N/A")[:15] + "..."
                                if len(str(rule_json.get("category", ""))) > 15
                                else rule_json.get("category", "N/A")
                            ),
                        )

                        st.divider()

                        # Side-by-side comparison: Input YAML vs Output JSON
                        col_input, col_output = st.columns(2)

                        with col_input:
                            st.markdown("#### 📥 Input: Sigma Rule (YAML)")
                            if "source_yaml" in result:
                                st.code(result["source_yaml"], language="yaml")
                            else:
                                st.info("Original YAML not available")

                        with col_output:
                            st.markdown("#### 📤 Output: CSE Rule (JSON)")

                            # Show CSE Expression prominently
                            st.markdown("**CSE Expression:**")
                            st.code(rule_json.get("expression", "N/A"), language="sql")

                            # Full JSON in expander
                            with st.expander("View Full JSON"):
                                wrapped_rule = {"rules": [rule_json]}
                                st.json(wrapped_rule)

                        st.divider()

                        # Download individual rule - wrap in rules structure
                        wrapped_rule = {"rules": [rule_json]}
                        st.download_button(
                            label="📥 Download CSE Rule JSON (ready to import)",
                            data=json.dumps(wrapped_rule, indent=2),
                            file_name=f"{Path(source_file).stem}_cse.json",
                            mime="application/json",
                            key=f"download_{source_file}",
                            use_container_width=True,
                        )
                else:
                    with st.expander(f"❌ {source_file}"):
                        st.error(f"**Conversion Failed**")

                        # Show error details
                        st.markdown("**Error Message:**")
                        st.code(result.get("error", "Unknown error"), language="text")

                        st.divider()

                        # Show original YAML for context
                        if "source_yaml" in result and result["source_yaml"]:
                            col_yaml, col_info = st.columns([2, 1])

                            with col_yaml:
                                st.markdown("#### 📥 Original Sigma Rule (YAML)")
                                st.code(result["source_yaml"], language="yaml")

                            with col_info:
                                st.markdown("#### 🔍 Troubleshooting")
                                st.markdown(
                                    """
                                **Common Issues:**
                                - Unsupported field mappings
                                - Invalid YAML syntax
                                - Missing required fields
                                - Unsupported detection logic
                                - Pipeline processing errors

                                Review the error message and the original rule to identify the issue.
                                """
                                )
                        else:
                            st.warning(
                                "Original YAML not available (file read may have failed)"
                            )
        else:
            st.info(
                "No conversion results yet. Go to the 'Convert' tab to convert selected rules."
            )


if __name__ == "__main__":
    main()
