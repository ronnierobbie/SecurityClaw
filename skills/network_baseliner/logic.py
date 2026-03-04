"""
skills/network_baseliner/logic.py

Field-agnostic network behavior baseliner. Discovers available fields
in logs, performs comprehensive network analytics (IP-to-IP relationships,
port patterns, protocols, direction, GeoIP, DNS, service identification),
and stores the result in the RAG vector index for ThreatAnalyst retrieval.

Context keys consumed:
    context["db"]     -> BaseDBConnector
    context["llm"]    -> BaseLLMProvider
    context["memory"] -> AgentMemory
    context["config"] -> Config
"""
from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "network_baseliner"


def run(context: dict) -> dict:
    """Entry point called by the Runner."""
    db = context.get("db")
    llm = context.get("llm")
    memory = context.get("memory")
    cfg = context.get("config")

    if db is None or llm is None:
        logger.warning("[%s] db or llm not available — skipping.", SKILL_NAME)
        return {"status": "skipped", "reason": "no db/llm"}

    instruction = INSTRUCTION_PATH.read_text(encoding="utf-8")
    logs_index = cfg.get("db", "logs_index", default="securityclaw-logs")
    vector_index = cfg.get("db", "vector_index", default="securityclaw-vectors")

    # ── 1. Fetch recent logs (last 6 hours) ──────────────────────────────────
    since = _epoch_ms_ago(hours=6)
    query = {
        "query": {
            "range": {"@timestamp": {"gte": since, "format": "epoch_millis"}}
        },
    }
    raw_logs = db.search(logs_index, query, size=10000)

    if not raw_logs:
        logger.info("[%s] No logs found in the last 6 hours.", SKILL_NAME)
        return {"status": "no_data"}

    # ── 2. Detect network/sensor identifier and group logs ────────────────────
    identifier_field = _detect_identifier_field(raw_logs)
    grouped_logs = _group_logs_by_identifier(raw_logs, identifier_field)
    
    logger.info(
        "[%s] Detected identifier field: %s. Found %d networks/sensors.",
        SKILL_NAME,
        identifier_field,
        len(grouped_logs),
    )

    # ── 3. Check embedding dimension vs existing index dimension ─────────────
    # Use the LLM's actual embedding dimension
    current_embed_dim = llm.embedding_dimension if llm is not None else None
    index_dim = _get_index_dim(db, vector_index)
    fresh_start = False

    if current_embed_dim and index_dim and current_embed_dim != index_dim:
        logger.warning(
            "[%s] Embedding dimension mismatch: index has %d dims, embed model produces %d dims. "
            "Deleting and recreating vector index with new dimensions…",
            SKILL_NAME, index_dim, current_embed_dim,
        )
        # Delete the incompatible index so RAGEngine creates a fresh one
        try:
            if hasattr(db, '_client'):
                client = db._client
                if client.indices.exists(index=vector_index):
                    client.indices.delete(index=vector_index)
                    logger.info("[%s] Deleted vector index '%s' due to dimension mismatch.", SKILL_NAME, vector_index)
        except Exception as exc:
            logger.warning("[%s] Could not delete vector index: %s", SKILL_NAME, exc)
        fresh_start = True
    elif index_dim is None:
        fresh_start = True  # No existing index — starting fresh

    # ── 4. Read existing baselines before RAGEngine init ─
    existing_baselines_by_id: dict[str, dict[str, str]] = {}
    if not fresh_start:
        for ident in grouped_logs:
            prior = _fetch_existing_baselines(db, vector_index, ident)
            if prior:
                existing_baselines_by_id[ident] = prior
                logger.info(
                    "[%s] Loaded %d existing baseline docs for '%s' — will update them.",
                    SKILL_NAME, len(prior), ident,
                )

    # ── 5. Init RAGEngine (creates fresh index with correct dimensions) ────────
    from core.rag_engine import RAGEngine

    rag = RAGEngine(db=db, llm=llm)

    all_stored_docs = []
    for identifier, logs_group in grouped_logs.items():
        if not logs_group:
            continue
        
        logger.info(
            "[%s] Processing %s (%d logs)…",
            SKILL_NAME,
            identifier,
            len(logs_group),
        )
        
        # Analyze this network/sensor's logs
        analytics = _analyze_network_logs(logs_group)
        analytics_text = _format_analytics(analytics)

        # Include any existing baselines for this identifier as prior context
        prior_baselines = existing_baselines_by_id.get(identifier, {})

        # Generate baselines specific to this network/sensor
        baselines = _generate_baseline_documents(
            analytics,
            analytics_text,
            llm,
            instruction,
            existing_baselines=prior_baselines,
        )

        if not baselines:
            logger.warning(
                "[%s] Failed to generate baselines for %s",
                SKILL_NAME,
                identifier,
            )
            continue

        # Check which baselines have actually changed before storing
        stored_count = 0
        for baseline in baselines:
            category = baseline["category"]
            summary = baseline["summary"]
            
            # Extract current metrics
            metrics = _extract_analytics_metrics(analytics, category)
            
            # Check if this baseline has changed
            prior_baseline_text = prior_baselines.get(category)
            has_changed, change_summary = _has_baseline_changed(metrics, prior_baseline_text)
            
            if not has_changed:
                logger.info(
                    "[%s] Skipping %s for %s — %s",
                    SKILL_NAME,
                    category,
                    identifier,
                    change_summary,
                )
                continue
            
            # Store baseline since it changed
            doc_id = rag.store(
                text=summary,
                category=category,
                source=SKILL_NAME,
                metadata={
                    "identifier_field": identifier_field,
                    "identifier_value": identifier,
                    "dimension": category.replace("network_baseline_", ""),
                    "change_summary": change_summary,
                },
            )
            all_stored_docs.append(
                {
                    "category": category,
                    "identifier": identifier,
                    "doc_id": doc_id,
                    "change_summary": change_summary,
                }
            )
            stored_count += 1
            logger.info(
                "[%s] Stored %s for %s (id=%s) — %s",
                SKILL_NAME,
                category,
                identifier,
                doc_id[:8],
                change_summary,
            )
        
        # Store schema observation (field mapping discovery) separately
        discovered_fields = analytics.get("discovered_fields", {})
        if discovered_fields:
            # Check if field schema has changed
            prior_schema = prior_baselines.get("schema_observation")
            field_metrics = {"unique_fields": len(discovered_fields)}
            schema_changed, schema_change_summary = _has_baseline_changed(field_metrics, prior_schema)
            
            if schema_changed:
                schema_text = _format_schema_observation(discovered_fields, identifier_field)
                schema_doc_id = rag.store(
                    text=schema_text,
                    category="schema_observation",
                    source=SKILL_NAME,
                    metadata={
                        "identifier_field": identifier_field,
                        "identifier_value": identifier,
                        "field_count": len(discovered_fields),
                        "change_summary": schema_change_summary,
                    },
                )
                all_stored_docs.append({
                    "category": "schema_observation",
                    "identifier": identifier,
                    "doc_id": schema_doc_id,
                    "change_summary": schema_change_summary,
                })
                logger.info(
                    "[%s] Stored schema observation for %s (%d fields, id=%s) — %s",
                    SKILL_NAME,
                    identifier,
                    len(discovered_fields),
                    schema_doc_id[:8],
                    schema_change_summary,
                )
            else:
                logger.info(
                    "[%s] Skipping schema observation for %s — %s",
                    SKILL_NAME,
                    identifier,
                    schema_change_summary,
                )

    # ── 4. Update agent memory ────────────────────────────────────────────────
    if memory:
        memory.add_decision(
            f"NetworkBaseliner analyzed {len(grouped_logs)} networks/sensors across "
            f"{len(raw_logs)} logs. Stored {len(all_stored_docs)} baseline documents "
            f"with context: {identifier_field}={', '.join(grouped_logs.keys())}"
        )

    return {
        "status": "ok",
        "records_processed": len(raw_logs),
        "networks_analyzed": len(grouped_logs),
        "documents_stored": len(all_stored_docs),
        "identifier_field": identifier_field,
        "identifiers": list(grouped_logs.keys()),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Network/Sensor Detection and Grouping
# ──────────────────────────────────────────────────────────────────────────────

def _detect_identifier_field(logs: list[dict]) -> str:
    """
    Detect which field is the likely network/sensor identifier.
    
    Candidates (in order of preference):
      1. agent_id, sensor_id, client_id, source_id - explicit identifiers
      2. host.hostname, hostname - machine identity
      3. host.ip, source.ip (first octet or /24) - network segment
      4. event.source - log source
      5. None - treat all logs as single network
    """
    if not logs:
        return "sensor_id"  # Default fallback
    
    # Sample first 100 logs to check for identifier fields
    sample = logs[:100]
    
    # Candidate fields to check
    candidates = [
        ("agent_id", "exact"),
        ("sensor_id", "exact"),
        ("client_id", "exact"),
        ("source_id", "exact"),
        ("host.hostname", "exact"),
        ("hostname", "exact"),
        ("event.source", "exact"),
        ("source.ip", "subnet"),  # Group by /24 subnet
        ("host.ip", "subnet"),
    ]
    
    for field_path, mode in candidates:
        found_values = set()
        populated_count = 0
        
        for log in sample:
            value = _extract_value(log, [field_path])
            if value is not None:
                populated_count += 1
                if mode == "subnet":
                    # Extract /24 subnet from IP
                    if isinstance(value, str):
                        parts = value.split(".")
                        if len(parts) == 4:
                            value = ".".join(parts[:3]) + ".0"
                found_values.add(value)
        
        # If this field is populated in >80% of samples and has multiple distinct values
        if populated_count >= len(sample) * 0.8 and len(found_values) > 1:
            logger.info(
                "[%s] Auto-detected identifier field: %s (found %d distinct values)",
                SKILL_NAME,
                field_path,
                len(found_values),
            )
            return field_path
    
    # No good identifier field found - treat all as one network
    logger.info("[%s] No multi-network identifier detected; treating all logs as single network", SKILL_NAME)
    return "sensor_id"


def _group_logs_by_identifier(logs: list[dict], identifier_field: str) -> dict[str, list[dict]]:
    """
    Group logs by the identified field to separate network/sensor baselines.
    
    Returns dict mapping identifier value → list of logs for that network/sensor.
    """
    groups = defaultdict(list)
    
    for log in logs:
        value = _extract_value(log, [identifier_field])
        
        if value is None:
            value = "unknown"
        
        # For subnet grouping, extract /24
        if "." in str(value):
            parts = str(value).split(".")
            if len(parts) == 4 and identifier_field in ("source.ip", "host.ip"):
                try:
                    int(parts[0])  # Verify it's an IP
                    value = ".".join(parts[:3]) + ".0"
                except ValueError:
                    pass
        
        groups[str(value)].append(log)
    
    return dict(groups)


# ──────────────────────────────────────────────────────────────────────────────
# Embedding dimension helpers
# ──────────────────────────────────────────────────────────────────────────────

def _detect_embed_dim(llm) -> int | None:
    """Return the current embedding dimension produced by the LLM provider, or None."""
    try:
        return len(llm.embed("test"))
    except Exception as exc:
        logger.warning("[%s] Could not detect embedding dimension: %s", SKILL_NAME, exc)
        return None


def _get_index_dim(db, vector_index: str) -> int | None:
    """Return the embedding dimension stored in the index mapping, or None if unavailable."""
    try:
        if not hasattr(db, "_client"):
            return None
        client = db._client
        if not client.indices.exists(index=vector_index):
            return None
        mapping = client.indices.get_mapping(index=vector_index)
        return (
            mapping.get(vector_index, {})
            .get("mappings", {})
            .get("properties", {})
            .get("embedding", {})
            .get("dimension")
        )
    except Exception as exc:
        logger.warning("[%s] Could not read index dimension: %s", SKILL_NAME, exc)
        return None


def _fetch_existing_baselines(db, vector_index: str, identifier_value: str) -> dict[str, str]:
    """Return existing baseline docs for this network/sensor as {category: text}."""
    try:
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"source": SKILL_NAME}},
                        {"term": {"identifier_value": identifier_value}},
                    ]
                }
            },
            "_source": ["text", "category"],
        }
        docs = db.search(vector_index, query, size=50)
        result: dict[str, str] = {}
        for doc in docs:
            cat = doc.get("category", "")
            text = doc.get("text", "")
            if cat and text:
                result[cat] = text
        return result
    except Exception as exc:
        logger.warning(
            "[%s] Could not fetch existing baselines for '%s': %s",
            SKILL_NAME, identifier_value, exc,
        )
        return {}


def _with_prior(prompt: str, existing_baselines: dict, category: str) -> str:
    """Append existing baseline text to the prompt so the LLM can update it."""
    prior = existing_baselines.get(category, "")
    if not prior:
        return prompt
    return (
        prompt
        + "\n\nPRIOR BASELINE (incorporate into your updated summary;"
        " note any changes if network behaviour has evolved):\n"
        + prior
    )


def _extract_analytics_metrics(analytics: dict, category: str) -> dict:
    """Extract key metrics from analytics for comparison against existing baselines."""
    metrics = {
        "category": category,
        "unique_src_ips": len(analytics.get("source_ips", {})),
        "unique_dst_ips": len(analytics.get("dest_ips", {})),
        "unique_src_ports": len(analytics.get("source_ports", {})),
        "unique_dst_ports": len(analytics.get("dest_ports", {})),
        "unique_protocols": len(analytics.get("protocols", {})),
        "unique_dns_domains": len(analytics.get("dns_queries", {})),
        "total_flows": analytics.get("flow_stats", {}).get("total_flows", 0),
        "total_bytes": analytics.get("flow_stats", {}).get("total_bytes", 0),
        "total_packets": analytics.get("flow_stats", {}).get("total_packets", 0),
        "unique_fields": len(analytics.get("discovered_fields", {})),
    }
    
    # Extract top items for comparison
    src_ips = analytics.get("source_ips", {})
    metrics["top_5_src_ips"] = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]
    
    dst_ips = analytics.get("dest_ips", {})
    metrics["top_5_dst_ips"] = sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]
    
    dst_ports = analytics.get("dest_ports", {})
    metrics["top_5_dst_ports"] = sorted(dst_ports.items(), key=lambda x: x[1], reverse=True)[:5]
    
    protocols = analytics.get("protocols", {})
    metrics["top_protocols"] = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return metrics


def _has_baseline_changed(new_metrics: dict, baseline_text: str | None) -> tuple[bool, str]:
    """
    Compare new metrics against existing baseline text.
    Returns (changed: bool, change_summary: str).
    
    Detects meaningful changes like new IPs, port distribution changes, traffic growth, etc.
    """
    if not baseline_text:
        return True, "New baseline (no prior baseline exists)"
    
    changes = []
    
    # Try to parse metrics from baseline text
    # Look for patterns like "Total flows: 10000" or "unique IPs: 42"
    
    # Check for field count changes (indicates schema evolution)
    if "unique_fields" in baseline_text:
        # Extract old field count using regex
        match = re.search(r"(\d+) fields", baseline_text)
        if match:
            old_field_count = int(match.group(1))
            new_field_count = new_metrics["unique_fields"]
            if abs(new_field_count - old_field_count) > 2:  # Allow small variance
                changes.append(f"Field count: {old_field_count} → {new_field_count}")
    
    # Check for flow count changes (significant growth/shrinkage)
    if "Total flows:" in baseline_text or "total flows:" in baseline_text.lower():
        match = re.search(r"[Tt]otal flows[:\s]+(\d+)", baseline_text)
        if match:
            old_flows = int(match.group(1))
            new_flows = new_metrics["total_flows"]
            change_pct = abs(new_flows - old_flows) / max(old_flows, 1) * 100
            if change_pct > 10:  # >10% change
                changes.append(f"Total flows: {old_flows:,} → {new_flows:,} ({change_pct:.0f}% change)")
    
    # Check for traffic volume changes
    if "Total bytes:" in baseline_text:
        match = re.search(r"[Tt]otal bytes[:\s]+(\d+)", baseline_text)
        if match:
            old_bytes = int(match.group(1))
            new_bytes = new_metrics["total_bytes"]
            change_pct = abs(new_bytes - old_bytes) / max(old_bytes, 1) * 100
            if change_pct > 15:  # >15% change
                changes.append(f"Traffic volume: {old_bytes:,} → {new_bytes:,} bytes")
    
    # Check for new IPs in top talkers
    if "TOP SOURCE IPs" in baseline_text or "TOP DESTINATION IPs" in baseline_text:
        new_src_ips = set(ip for ip, _ in new_metrics.get("top_5_src_ips", []))
        new_dst_ips = set(ip for ip, _ in new_metrics.get("top_5_dst_ips", []))
        
        # Simple heuristic: if top 5 IPs have changed, something changed
        baseline_mentions_ips = bool(
            re.search(r"\d+\.\d+\.\d+\.\d+", baseline_text)
        )
        
        if baseline_mentions_ips and (new_src_ips or new_dst_ips):
            # Extract IPs from baseline text
            old_ips = set(re.findall(r"\d+\.\d+\.\d+\.\d+", baseline_text))
            if old_ips and new_src_ips | new_dst_ips:
                new_ips = (new_src_ips | new_dst_ips) - old_ips
                if new_ips:
                    changes.append(f"New IPs detected: {', '.join(sorted(new_ips)[:3])}")
    
    # Check for port usage changes
    if "TOP DESTINATION PORTS" in baseline_text:
        match = re.findall(r"(\d+)/[^:]+:\s+(\d+) flows", baseline_text)
        if match:
            old_top_ports = {int(m[0]): int(m[1]) for m in match[:3]}
            new_top_ports = {port: count for port, count in new_metrics.get("top_5_dst_ports", [])[:3]}
            
            # Check if port distribution significantly changed
            old_port_set = set(old_top_ports.keys())
            new_port_set = set(new_top_ports.keys())
            
            if old_port_set != new_port_set:
                added = new_port_set - old_port_set
                removed = old_port_set - new_port_set
                change_note = []
                if added:
                    change_note.append(f"new ports {added}")
                if removed:
                    change_note.append(f"removed ports {removed}")
                if change_note:
                    changes.append(f"Port distribution changed: {', '.join(change_note)}")
    
    if changes:
        return True, "; ".join(changes)
    else:
        return False, "No significant changes detected"


# ──────────────────────────────────────────────────────────────────────────────

def _generate_baseline_documents(
    analytics: dict,
    analytics_text: str,
    llm,
    instruction: str,
    existing_baselines: dict | None = None,
) -> list[dict]:
    """
    Generate baseline documents that comprehensively document the discovered fields.
    
    Instead of analyzing specific aspects, document WHAT FIELDS EXIST and WHAT THEY CONTAIN.
    This allows RAG querier to be truly data-agnostic: it just extracts search terms and 
    searches - the LLM knows from the field documentation what to extract from results.
    
    If existing_baselines ({category: prior_text}) is supplied, each LLM prompt
    will include the prior summary so the model can update rather than replace it.

    Returns list of dicts with "summary" and "category" for each baseline.
    """
    existing_baselines = existing_baselines or {}
    baselines = []
    
    # ── PRIMARY: Comprehensive Field Documentation ─────────────────────────────
    # Generate a detailed field documentation that tells users exactly what data is available
    discovered_fields = analytics.get("discovered_fields", {})
    src_ips = analytics.get("source_ips", {})
    dst_ips = analytics.get("dest_ips", {})
    dest_ports = analytics.get("dest_ports", {})
    protocols = analytics.get("protocols", {})
    flow_stats = analytics.get("flow_stats", {})
    dns = analytics.get("dns_queries", {})
    geoip = analytics.get("geoip_data", {})
    
    if discovered_fields:
        # Build a comprehensive field documentation
        field_doc_lines = [
            "COMPREHENSIVE FIELD DOCUMENTATION",
            "=" * 60,
            "",
        ]
        
        # Sort fields by frequency
        sorted_fields = sorted(discovered_fields.items(), key=lambda x: x[1], reverse=True)
        total_records = flow_stats.get("total_flows", 1)
        
        for field_name, count in sorted_fields[:40]:  # Top 40 fields
            frequency_pct = (count / total_records) * 100
            
            # Extract example values for this field from logs
            field_doc_lines.append(f"\nFIELD: {field_name}")
            field_doc_lines.append(f"  Frequency: {frequency_pct:.1f}% ({count} of {total_records} records)")
            
            # Try to infer field type and provide examples
            if "@timestamp" in field_name:
                field_doc_lines.append(f"  Type: ISO 8601 timestamp string")
                field_doc_lines.append(f"  Description: When the network event occurred")
                field_doc_lines.append(f"  Example: 2026-02-13T14:32:51.123Z")
            
            elif "ip" in field_name.lower() or "address" in field_name.lower():
                field_doc_lines.append(f"  Type: IPv4 address string")
                field_doc_lines.append(f"  Description: IP address involved in traffic")
                # Get examples
                if "source" in field_name.lower() or "orig" in field_name.lower():
                    examples = list(src_ips.keys())[:3]
                    field_doc_lines.append(f"  Examples: {', '.join(examples)}")
                else:
                    examples = list(dst_ips.keys())[:3]
                    field_doc_lines.append(f"  Examples: {', '.join(examples)}")
            
            elif "port" in field_name.lower():
                field_doc_lines.append(f"  Type: integer (1-65535)")
                field_doc_lines.append(f"  Description: Port number in network traffic")
                examples = list(dest_ports.keys())[:3]
                field_doc_lines.append(f"  Examples: {', '.join(str(e) for e in examples)}")
            
            elif "protocol" in field_name.lower() or "proto" in field_name.lower() or "transport" in field_name.lower():
                field_doc_lines.append(f"  Type: protocol name string")
                field_doc_lines.append(f"  Description: Network protocol in use")
                examples = list(protocols.keys())[:3]
                if examples:
                    field_doc_lines.append(f"  Examples: {', '.join(examples)}")
            
            elif "dns" in field_name.lower() or "query" in field_name.lower() or "domain" in field_name.lower():
                field_doc_lines.append(f"  Type: domain name string")
                field_doc_lines.append(f"  Description: DNS query or domain name")
                examples = list(dns.keys())[:3]
                if examples:
                    field_doc_lines.append(f"  Examples: {', '.join(examples)}")
            
            elif "bytes" in field_name.lower():
                field_doc_lines.append(f"  Type: integer")
                field_doc_lines.append(f"  Description: Number of bytes transmitted")
                field_doc_lines.append(f"  Example: {flow_stats.get('total_bytes', 0)}")
            
            elif "packet" in field_name.lower():
                field_doc_lines.append(f"  Type: integer")
                field_doc_lines.append(f"  Description: Number of packets")
                field_doc_lines.append(f"  Example: {flow_stats.get('total_packets', 0)}")
            
            elif "geo" in field_name.lower():
                field_doc_lines.append(f"  Type: geographic location string")
                field_doc_lines.append(f"  Description: Country/city where IP is located")
                examples = list(geoip.values())[:3]
                if examples:
                    field_doc_lines.append(f"  Examples: {', '.join(examples)}")
            
            else:
                field_doc_lines.append(f"  Type: string or numeric")
                field_doc_lines.append(f"  Description: Network traffic data")
        
        field_doc_lines.extend([
            "",
            "=" * 60,
            "Use these field names exactly as shown when searching for specific data.",
            "The LLM will use this documentation to extract answers from log records.",
        ])
        
        field_doc_text = "\n".join(field_doc_lines)
        
        response = llm.chat([
            {"role": "system", "content": "You are documenting data fields. Be precise and factual. Return exactly what was provided."},
            {"role": "user", "content": _with_prior(
                f"Document these fields perfectly:\n\n{field_doc_text}",
                existing_baselines, 
                "field_documentation"
            )},
        ])
        baselines.append({
            "summary": response,
            "category": "field_documentation",
        })
    
    # ── NETWORK BEHAVIOR BASELINE ──────────────────────────────────────────────
    # Document traffic patterns: IP-to-IP flows, volume trends, common connections
    ip_pairs = analytics.get("ip_pairs", {})
    flow_stats = analytics.get("flow_stats", {})
    
    if ip_pairs or flow_stats:
        behavior_lines = [
            "NETWORK BASELINE BEHAVIOR PATTERNS",
            "=" * 60,
            "",
            "FLOW STATISTICS:",
            f"  Total flows: {flow_stats.get('total_flows', 0):,}",
            f"  Total bytes: {flow_stats.get('total_bytes', 0):,}",
            f"  Total packets: {flow_stats.get('total_packets', 0):,}",
            f"  Average bytes per flow: {flow_stats.get('avg_bytes_per_flow', 0):.1f}",
            f"  Average duration: {flow_stats.get('avg_duration_us', 0):.0f} microseconds",
            "",
            "COMMON IP-TO-IP CONNECTIONS (Source → Destination):",
        ]
        
        for (src, dst), count in list(ip_pairs.items())[:20]:
            pct = (count / max(flow_stats.get("total_flows", 1), 1)) * 100
            behavior_lines.append(f"  {src} → {dst}: {count} flows ({pct:.1f}%)")
        
        behavior_lines.extend([
            "",
            "=" * 60,
            "These patterns represent the established baseline for this network.",
            "Use these to identify anomalies or unexpected communication patterns.",
        ])
        
        behavior_text = "\n".join(behavior_lines)
        response = llm.chat([
            {"role": "system", "content": "You are documenting network baseline behavior. Be precise about traffic patterns."},
            {"role": "user", "content": _with_prior(
                f"Document this network baseline:\n\n{behavior_text}",
                existing_baselines,
                "network_behavior_baseline"
            )},
        ])
        baselines.append({
            "summary": response,
            "category": "network_behavior_baseline",
        })
    
    # ── PROTOCOL & PORT ANALYSIS BASELINE ──────────────────────────────────────
    # Document which protocols and ports are used in normal baseline traffic
    protocols = analytics.get("protocols", {})
    dest_ports = analytics.get("dest_ports", {})
    source_ports = analytics.get("source_ports", {})
    services = analytics.get("services", {})
    
    if protocols or dest_ports:
        protocol_lines = [
            "PROTOCOL AND PORT USAGE BASELINE",
            "=" * 60,
            "",
        ]
        
        if protocols:
            protocol_lines.append("PROTOCOL DISTRIBUTION:")
            total_flows = max(flow_stats.get("total_flows", 1), 1)
            for proto, count in list(protocols.items())[:15]:
                pct = (count / total_flows) * 100
                protocol_lines.append(f"  {proto}: {count} flows ({pct:.1f}%)")
            protocol_lines.append("")
        
        if dest_ports:
            protocol_lines.append("TOP DESTINATION PORTS (Server Ports):")
            for port, count in list(dest_ports.items())[:20]:
                service = services.get(port, "unknown")
                pct = (count / total_flows) * 100
                protocol_lines.append(f"  {port}/{service}: {count} flows ({pct:.1f}%)")
            protocol_lines.append("")
        
        if source_ports:
            protocol_lines.append("TOP SOURCE PORTS (Client Ports):")
            for port, count in list(source_ports.items())[:10]:
                pct = (count / total_flows) * 100
                protocol_lines.append(f"  {port}: {count} flows ({pct:.1f}%)")
        
        protocol_lines.extend([
            "",
            "=" * 60,
            "These ports represent normal baseline communication.",
            "Unused ports or unexpected protocols may indicate threats.",
        ])
        
        protocol_text = "\n".join(protocol_lines)
        response = llm.chat([
            {"role": "system", "content": "You are documenting protocol and port usage. Be specific about what is normal."},
            {"role": "user", "content": _with_prior(
                f"Document this protocol baseline:\n\n{protocol_text}",
                existing_baselines,
                "protocol_port_baseline"
            )},
        ])
        baselines.append({
            "summary": response,
            "category": "protocol_port_baseline",
        })
    
    # ── IP RELATIONSHIPS BASELINE ──────────────────────────────────────────────
    # Document which IPs communicate internally, which are external, geographic patterns
    src_ips = analytics.get("source_ips", {})
    dst_ips = analytics.get("dest_ips", {})
    geoip = analytics.get("geoip_data", {})
    
    if src_ips or dst_ips or geoip:
        ip_lines = [
            "IP COMMUNICATION BASELINE",
            "=" * 60,
            "",
        ]
        
        if src_ips:
            ip_lines.append("TOP SOURCE IPs (Internal Hosts):")
            for ip, count in list(src_ips.items())[:15]:
                pct = (count / max(flow_stats.get("total_flows", 1), 1)) * 100
                is_private = _is_private_ip(ip)
                ip_type = "Internal" if is_private else "External"
                ip_lines.append(f"  {ip} ({ip_type}): {count} flows ({pct:.1f}%)")
            ip_lines.append("")
        
        if dst_ips:
            ip_lines.append("TOP DESTINATION IPs (Targets):")
            for ip, count in list(dst_ips.items())[:15]:
                pct = (count / max(flow_stats.get("total_flows", 1), 1)) * 100
                is_private = _is_private_ip(ip)
                ip_type = "Internal" if is_private else "External"
                location = geoip.get(ip, "Unknown")
                ip_lines.append(f"  {ip} ({ip_type}) from {location}: {count} flows ({pct:.1f}%)")
        
        ip_lines.extend([
            "",
            "=" * 60,
            "These IPs represent established communication patterns.",
            "New or unexpected IPs may warrant investigation.",
        ])
        
        ip_text = "\n".join(ip_lines)
        response = llm.chat([
            {"role": "system", "content": "You are documenting IP communication patterns. Distinguish internal vs external."},
            {"role": "user", "content": _with_prior(
                f"Document this IP baseline:\n\n{ip_text}",
                existing_baselines,
                "ip_communication_baseline"
            )},
        ])
        baselines.append({
            "summary": response,
            "category": "ip_communication_baseline",
        })
    
    # ── DNS BASELINE ────────────────────────────────────────────────────────────
    # Document which domains are queried in normal baseline traffic
    dns = analytics.get("dns_queries", {})
    
    if dns:
        dns_lines = [
            "DNS QUERY BASELINE",
            "=" * 60,
            "",
            "COMMON DNS QUERIES:",
        ]
        
        for domain, count in list(dns.items())[:20]:
            dns_lines.append(f"  {domain}: {count} queries")
        
        dns_lines.extend([
            "",
            "=" * 60,
            "These DNS queries represent normal baseline domain lookups.",
            "Unexpected DNS queries to suspicious domains may indicate threats.",
        ])
        
        dns_text = "\n".join(dns_lines)
        response = llm.chat([
            {"role": "system", "content": "You are documenting DNS query patterns. List the domains accessed."},
            {"role": "user", "content": _with_prior(
                f"Document this DNS baseline:\n\n{dns_text}",
                existing_baselines,
                "dns_baseline"
            )},
        ])
        baselines.append({
            "summary": response,
            "category": "dns_baseline",
        })
    
    return baselines


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."""
    if not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1]) if first == 172 else 0
        return (first == 10 or 
                (first == 172 and 16 <= second <= 31) or 
                first == 192)
    except (ValueError, IndexError):
        return False


# ──────────────────────────────────────────────────────────────────────────────

def _epoch_ms_ago(hours: int = 6) -> int:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return int(dt.timestamp() * 1000)


def _extract_value(obj: Any, paths: list[str]) -> Any:
    """Recursively extract value from nested dict using multiple potential paths."""
    for path in paths:
        current = obj
        for key in path.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                current = None
                break
        if current is not None:
            return current
    return None


def _analyze_network_logs(logs: list[dict]) -> dict:
    """
    Perform comprehensive field-agnostic network analytics.
    
    Returns dict with:
      - source_ips: {ip: count}
      - dest_ips: {ip: count}
      - source_ports: {port: count}
      - dest_ports: {port: count}
      - protocols: {protocol: count}
      - directions: {direction: count}
      - ip_pairs: [(src, dst): count]
      - ip_port_pairs: {ip: {port: count}}
      - services: {port: name}
      - geoip_data: {ip: location}
      - dns_queries: {domain: count}
      - flow_stats: {metric: value}
      - discovered_fields: {field_name: count} — schema observation
    """
    source_ips = Counter()
    dest_ips = Counter()
    source_ports = Counter()
    dest_ports = Counter()
    protocols = Counter()
    directions = Counter()
    ip_pairs = Counter()
    ip_port_connections = defaultdict(Counter)  # src_ip -> {dest_ip: count}
    ip_port_usage = defaultdict(Counter)  # ip -> {port: count}
    services = {}
    geoip_data = {}
    dns_queries = Counter()
    discovered_fields = Counter()  # Track which fields we actually find
    
    total_bytes = 0
    total_packets = 0
    durations = []

    for log in logs:
        # Track all top-level fields we discover
        for field in log.keys():
            discovered_fields[field] += 1
        
        # ── Extract source info (multiple possible field paths) ────────────────
        src_ip = _extract_value(log, ["source.ip", "src_ip", "source_address", "id.orig_h"])
        src_port = _extract_value(log, ["source.port", "src_port", "source_port", "id.orig_p"])
        
        # ── Extract destination info ───────────────────────────────────────────
        dst_ip = _extract_value(log, ["destination.ip", "dest_ip", "destination_address", "id.resp_h"])
        dst_port = _extract_value(log, ["destination.port", "dest_port", "destination_port", "id.resp_p"])
        
        # ── Extract protocol/service info ──────────────────────────────────────
        protocol = _extract_value(log, ["network.transport", "protocol", "transport", "proto"])
        service = _extract_value(log, ["network.protocol", "service", "app_proto"])
        
        # ── Extract direction ──────────────────────────────────────────────────
        direction = _extract_value(log, ["network.direction", "direction", "flow_direction", "event.direction"])
        
        # ── Extract volume metrics ─────────────────────────────────────────────
        src_bytes = _extract_value(log, ["source.bytes", "bytes_sent", "src_bytes", "orig_bytes"])
        dst_bytes = _extract_value(log, ["destination.bytes", "bytes_recv", "bytes_received", "resp_bytes"])
        total_net_bytes = _extract_value(log, ["network.bytes", "bytes_total"])
        packets = _extract_value(log, ["network.packets", "packets_total", "event.packets"])
        duration = _extract_value(log, ["event.duration", "duration_us", "duration_ms"])
        
        # ── Extract GeoIP info (data-agnostic) ─────────────────────────────────
        # Try multiple field paths for destination GeoIP
        dst_geo = _extract_value(log, [
            "destination.geo",           # ECS format
            "destination.geoip",
            "geoip",                     # Suricata format (flat)
            "dest_geoip",
        ])
        
        if dst_ip and dst_geo:
            # Handle both dict and string formats
            geo_info = dst_geo
            if isinstance(dst_geo, dict):
                # Try multiple field names for country/city
                country = _extract_value(dst_geo, ["country_name", "country", "iso_code"])
                city = _extract_value(dst_geo, ["city_name", "city"])
                geo_info = f"{country or '?'} {city or ''}".strip()
            geoip_data[dst_ip] = geo_info
        
        # ── Extract DNS info if available ──────────────────────────────────────
        dns_question = _extract_value(log, ["dns.question.name", "dns.query", "query"])
        if dns_question:
            dns_queries[dns_question] += 1
        
        # ── Aggregate counters ─────────────────────────────────────────────────
        if src_ip:
            source_ips[src_ip] += 1
        if dst_ip:
            dest_ips[dst_ip] += 1
        if src_port:
            source_ports[src_port] += 1
        if dst_port:
            dest_ports[dst_port] += 1
        if protocol:
            protocols[protocol] += 1
        if direction:
            directions[direction] += 1
        
        # ── Track IP-to-IP relationships ───────────────────────────────────────
        if src_ip and dst_ip:
            ip_pairs[(src_ip, dst_ip)] += 1
            ip_port_connections[src_ip][dst_ip] += 1
        
        # ── Track port usage per IP ────────────────────────────────────────────
        if src_ip and src_port:
            ip_port_usage[src_ip][src_port] += 1
        if dst_ip and dst_port:
            ip_port_usage[dst_ip][dst_port] += 1
        
        # ── Map service names to ports ────────────────────────────────────────
        if dst_port and service:
            services[dst_port] = service
        
        # ── Accumulate volume stats ────────────────────────────────────────────
        if src_bytes and isinstance(src_bytes, (int, float)):
            total_bytes += src_bytes
        if dst_bytes and isinstance(dst_bytes, (int, float)):
            total_bytes += dst_bytes
        if total_net_bytes and isinstance(total_net_bytes, (int, float)):
            total_bytes += total_net_bytes
        if packets and isinstance(packets, (int, float)):
            total_packets += packets
        if duration and isinstance(duration, (int, float)):
            durations.append(duration)

    # ── Compute flow statistics ────────────────────────────────────────────────
    avg_duration = sum(durations) / len(durations) if durations else 0
    flow_stats = {
        "total_flows": len(logs),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "avg_bytes_per_flow": total_bytes / max(len(logs), 1),
        "avg_duration_us": avg_duration,
    }

    return {
        "source_ips": dict(source_ips.most_common(50)),
        "dest_ips": dict(dest_ips.most_common(50)),
        "source_ports": dict(source_ports.most_common(30)),
        "dest_ports": dict(dest_ports.most_common(30)),
        "protocols": dict(protocols.most_common(10)),
        "directions": dict(directions.most_common(5)),
        "ip_pairs": dict(ip_pairs.most_common(50)),
        "ip_port_connections": {k: dict(v.most_common(20)) for k, v in ip_port_connections.items()},
        "ip_port_usage": {k: dict(v.most_common(20)) for k, v in ip_port_usage.items()},
        "services": services,
        "geoip_data": dict(list(geoip_data.items())[:30]),
        "dns_queries": dict(dns_queries.most_common(30)),
        "flow_stats": flow_stats,
        "discovered_fields": dict(discovered_fields.most_common(50)),  # New: field discovery
    }


def _format_analytics(analytics: dict) -> str:
    """Format comprehensive analytics into readable text for LLM."""
    lines = []
    
    # ── Discovered Field Mapping (Schema Observation) ───────────────────────────
    discovered = analytics.get("discovered_fields", {})
    if discovered:
        lines.append("═ DETECTED FIELDS IN DATA ═")
        lines.append("(This schema information is stored for future queries)")
        for field, count in list(discovered.items())[:20]:
            pct = (count / max(sum(discovered.values()), 1)) * 100
            lines.append(f"  {field}: {pct:.1f}%")
        lines.append("")
    
    # Flow statistics
    stats = analytics.get("flow_stats", {})
    lines.append("═ FLOW STATISTICS ═")
    lines.append(f"  Total flows: {stats.get('total_flows', 0)}")
    lines.append(f"  Total bytes: {stats.get('total_bytes', 0):,}")
    lines.append(f"  Total packets: {stats.get('total_packets', 0):,}")
    lines.append(f"  Avg bytes/flow: {stats.get('avg_bytes_per_flow', 0):.1f}")
    lines.append(f"  Avg duration: {stats.get('avg_duration_us', 0):.0f} µs")
    lines.append("")

    # Protocols
    protocols = analytics.get("protocols", {})
    if protocols:
        lines.append("═ PROTOCOLS ═")
        for proto, count in list(protocols.items())[:10]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {proto}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # Directions
    directions = analytics.get("directions", {})
    if directions:
        lines.append("═ TRAFFIC DIRECTION ═")
        for direction, count in directions.items():
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {direction}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # Destination ports
    dest_ports = analytics.get("dest_ports", {})
    services = analytics.get("services", {})
    if dest_ports:
        lines.append("═ TOP DESTINATION PORTS ═")
        for port, count in list(dest_ports.items())[:15]:
            service = services.get(port, "unknown")
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {port}/{service}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # Source ports
    source_ports = analytics.get("source_ports", {})
    if source_ports:
        lines.append("═ TOP SOURCE PORTS ═")
        for port, count in list(source_ports.items())[:10]:
            lines.append(f"  {port}: {count} flows")
        lines.append("")

    # Source and destination IPs
    src_ips = analytics.get("source_ips", {})
    dst_ips = analytics.get("dest_ips", {})
    if src_ips:
        lines.append("═ TOP SOURCE IPs ═")
        for ip, count in list(src_ips.items())[:10]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {ip}: {count} flows ({pct:.1f}%)")
        lines.append("")

    if dst_ips:
        lines.append("═ TOP DESTINATION IPs ═")
        for ip, count in list(dst_ips.items())[:10]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {ip}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # IP-to-IP relationships
    ip_pairs = analytics.get("ip_pairs", {})
    if ip_pairs:
        lines.append("═ COMMON IP PAIRS (Source → Destination) ═")
        for (src, dst), count in list(ip_pairs.items())[:15]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {src} → {dst}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # IP-Port usage (which IPs use which ports)
    ip_port_usage = analytics.get("ip_port_usage", {})
    if ip_port_usage:
        lines.append("═ IP-PORT USAGE (Most Active) ═")
        for ip, ports in list(ip_port_usage.items())[:10]:
            port_list = ", ".join(str(p) for p, _ in list(ports.items())[:5])
            lines.append(f"  {ip}: ports {port_list}")
        lines.append("")

    # GeoIP data
    geoip = analytics.get("geoip_data", {})
    if geoip:
        lines.append("═ GEOLOCATION DATA ═")
        for ip, location in list(geoip.items())[:10]:
            lines.append(f"  {ip}: {location}")
        lines.append("")

    # DNS queries
    dns = analytics.get("dns_queries", {})
    if dns:
        lines.append("═ DNS QUERIES ═")
        for domain, count in list(dns.items())[:15]:
            lines.append(f"  {domain}: {count} queries")
        lines.append("")

    return "\n".join(lines)


def _parse_json_response(text: str) -> dict | None:
    """Extract and parse a JSON block from LLM output."""
    # Try the whole string first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Extract first JSON block from markdown
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Heuristic: find first { ... } block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def _format_schema_observation(discovered_fields: dict, identifier_field: str) -> str:
    """
    Format discovered fields as a schema observation document for RAG.
    
    This document helps future queries understand what fields are available
    and their frequency, enabling smarter field selection for searches.
    """
    lines = [
        "SCHEMA OBSERVATION",
        f"Identifier field: {identifier_field}",
        "",
        "DETECTED FIELDS (by frequency):",
    ]
    
    total_fields = sum(discovered_fields.values())
    for field, count in list(discovered_fields.items())[:30]:
        pct = (count / max(total_fields, 1)) * 100
        lines.append(f"  {field}: {pct:.1f}% ({count} occurrences)")
    
    lines.extend([
        "",
        "FIELD CATEGORIES:",
        "  IP-related: source.ip, src_ip, destination.ip, dest_ip, id.orig_h, id.resp_h",
        "  Port-related: source.port, src_port, destination.port, dest_port, id.orig_p, id.resp_p",
        "  Protocol: protocol, proto, transport, network.transport, app_proto",
        "  Geographic: destination.geo, geoip, dest_geoip, country_name, city_name",
        "  Timing: @timestamp, timestamp, event.created, event.duration",
        "  Volume: bytes, bytes_sent, bytes_received, event.packets, network.bytes",
        "",
        "Use this schema to craft searches that will find the right fields.",
    ])
    
    return "\n".join(lines)
