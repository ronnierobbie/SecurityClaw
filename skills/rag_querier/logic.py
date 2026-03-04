"""
skills/rag_querier/logic.py

Data-agnostic RAG querier skill. Searches stored baseline knowledge
to answer user questions about network/system behavior.

Context keys consumed:
    context["db"]         -> BaseDBConnector
    context["llm"]        -> BaseLLMProvider
    context["memory"]     -> AgentMemory
    context["config"]     -> Config
    context["parameters"] -> {"question": "user question"}
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "rag_querier"


def run(context: dict) -> dict:
    """Entry point called by the Runner."""
    db = context.get("db")
    llm = context.get("llm")
    cfg = context.get("config")
    parameters = context.get("parameters", {})

    if db is None or llm is None:
        logger.warning("[%s] db or llm not available — skipping.", SKILL_NAME)
        return {"status": "skipped", "reason": "no db/llm"}

    user_question = parameters.get("question")
    if not user_question:
        logger.warning("[%s] No question provided in parameters.", SKILL_NAME)
        return {"status": "no_question"}
    
    # Extract conversation history if available
    conversation_history = parameters.get("conversation_history", [])

    instruction = INSTRUCTION_PATH.read_text(encoding="utf-8")
    logs_index = cfg.get("db", "logs_index", default="securityclaw-logs")
    vector_index = cfg.get("db", "vector_index", default="securityclaw-vectors")

    # ── 0. Query schema observations to learn available fields ──────────────────
    # This makes the system data-agnostic by discovering what fields exist
    schema_observations = []
    try:
        from core.rag_engine import RAGEngine
        rag_temp = RAGEngine(db=db, llm=llm)
        
        # Ask for field mappings from schema observations
        schema_question = "What fields and data structure are in this dataset?"
        schema_docs = rag_temp.retrieve(schema_question, k=3)
        schema_observations = [
            doc for doc in schema_docs 
            if doc.get("category") == "schema_observation"
        ]
        
        if schema_observations:
            logger.info(
                "[%s] Found %d schema observations — using for intelligent field selection.",
                SKILL_NAME, len(schema_observations)
            )
    except Exception as exc:
        logger.debug("[%s] Schema observation lookup failed (non-critical): %s", SKILL_NAME, exc)
        # Continue without schema info; the multi-format search will still work

    # ── 1. Search RAG for relevant baselines ──────────────────────────────────
    logger.info("[%s] Searching for: %s", SKILL_NAME, user_question)

    rag_docs = []
    try:
        from core.rag_engine import RAGEngine

        rag = RAGEngine(db=db, llm=llm)
        rag_docs = rag.retrieve(user_question, k=5)
        logger.info("[%s] Found %d relevant baselines in RAG.", SKILL_NAME, len(rag_docs))
    except Exception as exc:
        logger.warning("[%s] RAG retrieval failed: %s", SKILL_NAME, exc)
        # Continue with raw logs even if RAG fails

    # ── 2. Search raw logs for matching data ──────────────────────────────────
    raw_logs = []
    search_terms_used = []
    try:
        raw_logs, search_terms_used = _search_raw_logs(
            user_question, db, logs_index, llm, conversation_history
        )
        logger.info(
            "[%s] Found %d matching records in logs (search terms: %s).",
            SKILL_NAME, len(raw_logs), search_terms_used
        )
    except Exception as exc:
        logger.error("[%s] Raw log search failed: %s", SKILL_NAME, exc)

    # ── 3. If neither RAG nor raw logs have data, return no_data ──────────────
    if not rag_docs and not raw_logs:
        logger.info("[%s] No data found (RAG or logs).", SKILL_NAME)
        return {
            "status": "no_data",
            "findings": {
                "question": user_question,
                "answer": "No data found to answer this question.",
                "confidence": 0.0,
            },
        }

    # ── 4. Analyze combined data with LLM to extract answer ──────────────────
    combined_context = _format_combined_context(
        rag_docs, raw_logs, user_question, search_terms_used
    )
    answer = _extract_answer_from_data(user_question, combined_context, instruction, llm)

    findings = {
        "question": user_question,
        "answer": answer,
        "rag_sources": len(rag_docs),
        "log_records": len(raw_logs),
        "confidence": 0.85 if (rag_docs or raw_logs) else 0.0,
        "summary": {
            "baseline_insights": len(rag_docs),
            "raw_observations": len(raw_logs),
        },
    }

    logger.info(
        "[%s] Answer compiled from %d baselines + %d log records. "
        "RAG docs delivered: %d/%d, Raw logs delivered: %d/%d",
        SKILL_NAME,
        len(rag_docs),
        len(raw_logs),
        len(rag_docs),
        len(rag_docs),
        min(len(raw_logs), 25),  # Up to 25 raw logs shown to LLM
        len(raw_logs),
    )

    return {
        "status": "ok",
        "findings": findings,
    }


def _search_raw_logs(
    question: str,
    db: Any,
    logs_index: str,
    llm: Any = None,
    conversation_history: list[dict] = None,
) -> tuple[list[dict], list[str]]:
    """
    Search raw logs for data matching the user question.
    DATA-AGNOSTIC: Tries field names from RAG schema observations or falls back to common formats.
    
    Returns (logs, search_terms_used) tuple so caller knows what was searched.
    
    Intelligently extracts keywords from the question and searches,
    including geographic, temporal, and pattern-based queries.
    
    Supports any log format by trying common field names from multiple formats
    (Suricata EVE, ECS, Zeek, NetFlow, etc.)
    """
    # Extract potential search terms from the question and conversation history
    search_terms = _extract_search_terms(question, conversation_history)
    
    if not search_terms:
        return [], []
    
    # TODO: Query RAG for schema observations to determine actual field names
    # For now, use multi-format fallback approach
    
    import re as _re
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    port_pattern = r'^\d{1,5}$'
    protocol_names = {'tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh', 'rdp', 'smb'}

    # Build should_clauses with multiple field format attempts
    # This allows search to work regardless of whether data is in Suricata/ECS/Zeek format
    should_clauses = []

    for term in search_terms:
        if _re.match(ip_pattern, term):
            # IP addresses — try all common field name formats
            for src_field in ["src_ip", "source.ip", "id.orig_h"]:
                for dst_field in ["dest_ip", "destination.ip", "id.resp_h"]:
                    should_clauses += [
                        {"term": {dst_field: term}},
                        {"term": {src_field: term}},
                        {"term": {f"{dst_field}.keyword": term}},
                        {"term": {f"{src_field}.keyword": term}},
                    ]
        elif _re.match(port_pattern, term):
            # Port numbers — try all common field name formats
            try:
                port_int = int(term)
                for src_port in ["src_port", "source.port", "id.orig_p"]:
                    for dst_port in ["dest_port", "destination.port", "id.resp_p"]:
                        should_clauses += [
                            {"term": {dst_port: port_int}},
                            {"term": {src_port: port_int}},
                        ]
            except ValueError:
                pass
        elif term.lower() in protocol_names:
            # Protocols — try common field names (TCP/tcp, proto, etc.)
            for proto_field in ["proto", "protocol", "network.protocol", "service"]:
                should_clauses += [
                    {"term": {proto_field: term.upper()}},
                    {"term": {f"{proto_field}.keyword": term.upper()}},
                    {"match": {proto_field: term.lower()}},
                ]
        else:
            # Hostnames, domains, other strings — try common app protocol fields
            for app_field in ["app_proto", "network.application", "service", "application_protocol"]:
                should_clauses += [
                    {"match": {app_field: {"query": term}}},
                    {"wildcard": {f"{app_field}.keyword": {"value": f"*{term}*"}}},
                ]
        
        # Try any term as a potential geographic location (data-agnostic)
        # Apply to all terms—if it's not a country/region, the search just won't match
        for geo_field in ["geoip.country_name", "destination.geo.country_name", "source.geo.country_name",
                         "geoip.country", "destination.country", "source.country"]:
            should_clauses += [
                {"match": {geo_field: {"query": term}}},
            ]

    if not should_clauses:
        return [], []

    query = {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "filter": {
                    "range": {
                        "@timestamp": {"gte": "now-90d"}  # Broader window for testing/demo data
                    }
                },
            }
        },
        "size": 50,
    }
    
    logger.info(
        "[%s] DATA-AGNOSTIC search: trying multiple field formats for terms: %s",
        SKILL_NAME, search_terms
    )
    
    try:
        results = db.search(logs_index, query, size=50)
        return results, search_terms
    except Exception as exc:
        logger.warning("[%s] Raw log search error: %s", SKILL_NAME, exc)
        return [], []


def _extract_search_terms(question: str, conversation_history: list[dict] = None) -> list[str]:
    """
    Extract potential search terms from a user question.
    Looks for IPs, hostnames, ports, protocols, etc.
    Returns each as a string; _search_raw_logs categorises them.
    Data-agnostic: doesn't assume what countries exist.
    
    Also extracts context from conversation history to maintain continuity.
    E.g., if previous Q mentioned "Iran", include "iran" in search for follow-ups.
    For follow-up questions, prior search context (IPs, ports, locations) is re-prioritized.
    """
    import re

    terms = []
    remaining = question

    # Regex patterns
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    port_pattern = r'\bport\s+(\d{1,5})\b|:(\d{2,5})\b|\b(\d{1,5})\b'  # More flexible port matching
    protocols = ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh', 'rdp', 'smb', 'ftp', 'smtp', 'ntp']
    hostname_pattern = r'\b([a-zA-Z][a-zA-Z0-9\-]{1,62}(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,62})*)\b'

    # ── PRIORITY 1: Extract from conversation history first (for follow-ups) ──
    history_ips = []
    history_ports = []
    history_protocols = []
    history_geos = []
    
    if conversation_history:
        # Look at previous user questions and assistant responses
        for msg in conversation_history:
            if msg.get("role") in ["user", "assistant"]:
                content = msg.get("content", "")
                
                # Extract IPs from history
                hist_ips = re.findall(ip_pattern, content)
                history_ips.extend(hist_ips)
                
                # Extract port numbers from history (be more aggressive)
                # Look for patterns like "port 1194", ":1194", or even "1194" if preceded by port/number context
                for match in re.finditer(r'\b(\d{1,5})\b', content):
                    port_candidate = match.group(1)
                    port_num = int(port_candidate)
                    # Accept if it looks like a port (1-65535) and appears in port-like context
                    if 1 <= port_num <= 65535:
                        # Check if there's "port" nearby or if it comes after an IP
                        start_pos = max(0, match.start() - 30)
                        context_before = content[start_pos:match.start()].lower()
                        end_pos = min(len(content), match.end() + 30)
                        context_after = content[match.end():end_pos].lower()
                        if 'port' in context_before or 'tcp' in context_before or 'udp' in context_before:
                            history_ports.append(port_candidate)
                        # Also accept if it's a common port
                        elif port_num in [80, 443, 22, 3306, 5432, 1194, 8080, 8443]:
                            history_ports.append(port_candidate)
                
                # Extract protocols from history
                for proto in protocols:
                    if re.search(rf'\b{proto}\b', content, re.IGNORECASE):
                        history_protocols.append(proto)
                
                # Extract geographic terms from history
                for word in content.split():
                    word_clean = re.sub(r'[.,;:!?]$', '', word)
                    if word_clean and word_clean[0].isupper() and len(word_clean) > 2:
                        word_lower = word_clean.lower()
                        if word_lower not in ['found', 'based', 'from', 'the', 'and', 'or', 'user', 'agent', 'is', 'are', 'was', 'were', 'traffic', 'connections', 'tcp', 'udp']:
                            if 2 < len(word_clean) < 15 and word_lower not in history_geos:
                                history_geos.append(word_lower)
    
    # Add history terms with dedup
    for ip in history_ips:
        if ip not in terms:
            terms.append(ip)
    for port in history_ports:
        if port not in terms:
            terms.append(port)
    for proto in history_protocols:
        if proto not in terms:
            terms.append(proto)
    for geo in history_geos:
        if geo not in terms:
            terms.append(geo)

    # ── PRIORITY 2: Extract from current question ──
    
    # 1. Extract IPv4 addresses from question
    ips = re.findall(ip_pattern, remaining)
    for ip in ips:
        if ip not in terms:
            terms.append(ip)
    remaining = re.sub(ip_pattern, ' ', remaining)

    # 2. Extract explicit port numbers from question
    for m in re.finditer(port_pattern, remaining):
        port_num = m.group(1) or m.group(2) or m.group(3)
        if port_num and port_num not in terms:
            terms.append(port_num)
    remaining = re.sub(port_pattern, ' ', remaining)

    # 3. Extract known protocol names from question
    for proto in protocols:
        if re.search(rf'\b{proto}\b', remaining, re.IGNORECASE) and proto not in terms:
            terms.append(proto)

    # 4. Extract hostnames / domain names from question
    for m in re.finditer(hostname_pattern, remaining):
        hostname = m.group(1)
        if hostname not in terms:
            terms.append(hostname)

    # ── PRIORITY 3: Deduplicate and filter only structural noise ──
    # Minimal stopwords: only truly structural words that add no search value
    # Data-agnostic principle: Let OpenSearch rank by relevance, LLM decides importance
    stopwords = {
        'the', 'a', 'an', 'and', 'or', 'is', 'are', 'was', 'were',
        'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did',
        'will', 'would', 'should', 'could', 'can', 'may', 'might',
        'at', 'in', 'on', 'to', 'for', 'of', 'by', 'with', 'as',
        'but', 'if', 'not', 'this', 'that', 'which', 'who', 'what', 'where', 'why', 'how',
    }
    
    seen = set()
    unique = []
    for t in terms:
        t_low = t.lower()
        # IP addresses and ports are always valuable, even if short
        is_ip_or_port = '.' in t or (t_low.isdigit() and 1 <= int(t_low) <= 65535) if t_low.isdigit() else False
        if t_low not in stopwords and t_low not in seen and (len(t) > 2 or is_ip_or_port):
            seen.add(t_low)
            unique.append(t_low)

    return unique


def _format_combined_context(
    rag_docs: list[dict], raw_logs: list[dict], question: str, search_terms: list[str] = None
) -> str:
    """Format both RAG baseline data and raw logs for LLM analysis."""
    if search_terms is None:
        search_terms = []
    
    context_parts = []
    
    # Add user's question for clarity
    context_parts.append(f"User Question: {question}")
    
    # Add search terms used if any
    if search_terms:
        context_parts.append(f"Search Terms Extracted: {', '.join(search_terms)}")
    
    if rag_docs:
        context_parts.append("=== BASELINE KNOWLEDGE (from stored baselines) ===")
        for i, doc in enumerate(rag_docs, 1):  # All retrieved RAG docs (typically 5)
            category = doc.get("category", "unknown")
            source = doc.get("source", "unknown")
            text = doc.get("text", "")
            similarity = doc.get("similarity", 0.0)
            context_parts.append(
                f"[Baseline {i} | {source} | {category} | Match: {similarity:.1%}]\n{text}"
            )
    
    if raw_logs:
        context_parts.append("\n=== OBSERVED DATA (from recent logs) ===")
        # Add note about what was searched for
        if search_terms:
            context_parts.append(
                f"Note: These logs were selected because they match your search for: {', '.join(search_terms)}"
            )
        context_parts.append(_summarize_raw_logs(raw_logs, question, search_terms))
    
    return "\n\n".join(context_parts)


def _summarize_raw_logs(logs: list[dict], question: str, search_terms: list[str] = None) -> str:
    """
    Return raw logs with all fields intact for the LLM to parse.
    Shows up to 25 records (enough for analysis, manageable token count).
    No guessing about "relevant" fields - the LLM decides what matters.
    """
    if search_terms is None:
        search_terms = []
        
    if not logs:
        return "No recent log records found."
    
    # Cap at 25 records for reasonable LLM token usage while still showing plenty of data
    display_logs = logs[:25]
    
    summary_lines = [
        f"Found {len(logs)} matching log records (showing first {len(display_logs)}):"
    ]
    
    if search_terms:
        summary_lines.append(f"(matched on search terms: {', '.join(search_terms)})")
    
    summary_lines.append("")
    
    # Show all fields from each record (no filtering, no guessing)
    # LLM is smart enough to find @timestamp and extract what it needs
    for i, log in enumerate(display_logs, 1):
        summary_lines.append(f"Record {i}:")
        
        # Display all fields from the record, sorted for readability
        for field in sorted(log.keys()):
            value = log[field]
            
            # Handle nested structures
            if isinstance(value, dict):
                value = str(value)[:100]  # Truncate very long nested structures
            elif isinstance(value, (list, str)):
                value = str(value)[:200]
            
            summary_lines.append(f"  {field}: {value}")
        
        summary_lines.append("")
    
    if len(logs) > len(display_logs):
        summary_lines.append(f"(... {len(logs) - len(display_logs)} more records omitted for brevity)")
    
    return "\n".join(summary_lines)


def _extract_answer_from_data(
    question: str,
    context_text: str,
    instruction: str,
    llm: Any,
) -> str:
    """Use LLM to extract specific, detailed answers from RAG baselines and raw logs."""
    prompt = f"""User Question: "{question}"

Available Context (baselines and raw log records):
{context_text}

Follow the Data Extraction Rules from your instructions to answer this question:
- Extract EXACT values from the data (timestamps, IPs, ports, protocols)
- Quote ALL matching records with complete field information
- Handle timezone conversions if requested
- Use exact counts, not vague language
- Never say data is unavailable if it's in the records shown above"""

    messages = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": prompt},
    ]

    try:
        response = llm.chat(messages)
        return response.strip()
    except Exception as exc:
        logger.error("Failed to extract answer: %s", exc)
        return f"Error analyzing data: {exc}"
