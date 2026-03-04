"""
skills/forensic_examiner/logic.py

Data-agnostic forensic timeline reconstructor. Takes an incident report
and uses RAG field documentation to understand the data schema, then lets the LLM
decide what to search for and how to build a timeline.

Context keys consumed:
    context["db"]         -> BaseDBConnector
    context["llm"]        -> BaseLLMProvider
    context["memory"]     -> AgentMemory
    context["config"]     -> Config
    context["parameters"] -> {"question": "incident description"}
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = __import__("pathlib").Path(__file__).parent / "instruction.md"
SKILL_NAME = "forensic_examiner"


def run(context: dict) -> dict:
    """Entry point called by the Runner."""
    db = context.get("db")
    llm = context.get("llm")
    cfg = context.get("config")
    parameters = context.get("parameters", {})
    conversation_history = context.get("conversation_history", [])

    if db is None or llm is None:
        logger.warning("[%s] db or llm not available — skipping.", SKILL_NAME)
        return {"status": "skipped", "reason": "no db/llm"}

    incident_question = parameters.get("question")
    if not incident_question:
        logger.warning("[%s] No incident question provided.", SKILL_NAME)
        return {"status": "no_question"}

    instruction = INSTRUCTION_PATH.read_text(encoding="utf-8")
    logs_index = cfg.get("db", "logs_index", default="securityclaw-logs")
    vector_index = cfg.get("db", "vector_index", default="securityclaw-vectors")

    logger.info("[%s] Analyzing incident: %s", SKILL_NAME, incident_question)

    # ── 1. Fetch field documentation from RAG ───────────────────────────────
    field_docs = _fetch_field_documentation(db, vector_index, llm)
    
    if not field_docs:
        logger.warning("[%s] No field documentation found in RAG; cannot proceed", SKILL_NAME)
        return {
            "status": "failed",
            "reason": "Field documentation not available from RAG (network baseliner not run)"
        }
    
    logger.info("[%s] Retrieved field documentation from RAG", SKILL_NAME)

    # ── 2. Ask LLM to design search strategy ──────────────────────────────────
    incident_context = _extract_basic_context(incident_question, conversation_history)
    
    search_strategy = _ask_llm_for_search_strategy(
        llm, incident_question, conversation_history, field_docs, incident_context
    )
    
    logger.info("[%s] LLM search strategy: %s", SKILL_NAME, search_strategy.get("summary", ""))

    # ── 3. Execute searches based on LLM guidance ────────────────────────────
    search_results = _execute_searches(db, logs_index, search_strategy, field_docs)
    logger.info("[%s] Found %d total results from searches", SKILL_NAME, len(search_results))

    # ── 4. Ask LLM to build timeline from results ────────────────────────────
    if search_results:
        timeline_narrative = _ask_llm_for_timeline(
            llm, incident_question, search_results, field_docs, instruction
        )
    else:
        timeline_narrative = _ask_llm_for_timeline_no_results(
            llm, incident_question, search_strategy, field_docs, instruction
        )

    # ── 5. Return forensic report ────────────────────────────────────────────
    forensic_report = {
        "incident_summary": incident_question,
        "search_strategy": search_strategy,
        "results_found": len(search_results),
        "timeline_narrative": timeline_narrative,
    }

    return {
        "status": "ok",
        "forensic_report": forensic_report,
    }


def _fetch_field_documentation(db: Any, vector_index: str, llm: Any) -> str:
    """Fetch field documentation baselines from RAG."""
    try:
        from core.rag_engine import RAGEngine
        rag = RAGEngine(db=db, llm=llm)
        
        docs = rag.retrieve("field names schema", k=5)
        field_docs = [
            doc.get("text", "")
            for doc in docs
            if doc.get("category") == "field_documentation"
        ]
        
        if field_docs:
            return "\n\n".join(field_docs[:2])
        
        return ""
    except Exception as exc:
        logger.warning("[%s] Could not fetch field documentation: %s", SKILL_NAME, exc)
        return ""




def _parse_field_mappings(field_docs: str) -> dict:
    """Parse field documentation to extract field mappings (data-agnostic).
    
    Discovers actual field names from field_documentation baseline instead of
    hardcoding them. Returns mapping of field types to actual names found in data.
    """
    mappings = {
        "ip_fields": [],
        "text_fields": [],
        "port_fields": [],
        "protocol_fields": [],
        "timestamp_fields": [],
        "dns_fields": [],
        "all_text_fields": [],  # Fallback for multi_match
    }
    
    if not field_docs:
        return mappings
    
    lines = field_docs.split("\n")
    for line in lines:
        lower = line.lower()
        
        # Extract field name
        field = None
        if "field:" in lower:
            parts = line.split(":", 1)
            field = parts[1].strip() if len(parts) > 1 else None
        elif "name:" in lower:
            parts = line.split(":", 1)
            field = parts[1].strip() if len(parts) > 1 else None
        elif line.strip().startswith("- "):
            field = line.strip()[2:].split("(")[0].strip()
        
        if not field:
            continue
        
        # Classify by keywords  in the documentation
        if any(kw in lower for kw in ["ipv4", "ip address", "source ip", "destination ip", "src_ip", "dest_ip"]):
            if field not in mappings["ip_fields"]:
                mappings["ip_fields"].append(field)
        elif "port" in lower:
            if field not in mappings["port_fields"]:
                mappings["port_fields"].append(field)
        elif any(kw in lower for kw in ["protocol", "transport", "proto"]):
            if field not in mappings["protocol_fields"]:
                mappings["protocol_fields"].append(field)
        elif any(kw in lower for kw in ["timestamp", "@timestamp", "datetime"]):
            if field not in mappings["timestamp_fields"]:
                mappings["timestamp_fields"].append(field)
        elif any(kw in lower for kw in ["dns", "query"]):
            if field not in mappings["dns_fields"]:
                mappings["dns_fields"].append(field)
        
        # Track text fields
        if any(kw in lower for kw in ["text", "message", "description", "body", "content", "log", "event", "reason"]):
            if field not in mappings["all_text_fields"]:
                mappings["all_text_fields"].append(field)
        else:
            # Fallback: anything is potential text field
            if field not in mappings["all_text_fields"]:
                mappings["all_text_fields"].append(field)
    
    logger.debug("[%s] Parsed mappings: ip=%s text=%s", SKILL_NAME, len(mappings["ip_fields"]), len(mappings["all_text_fields"]))
    return mappings



def _parse_field_mappings(field_docs: str) -> dict:
    """Parse field documentation to extract field mappings (DATA-AGNOSTIC).
    
    Discovers actual field names from field_documentation baseline instead of
    hardcoding them. This makes searches work with any data schema.
    """
    mappings = {
        "ip_fields": [],
        "text_fields": [],
        "all_text_fields": [],  
    }
    
    if not field_docs:
        return mappings
    
    for line in field_docs.split("\n"):
        lower = line.lower()
        field = None
        
        if "field:" in lower:
            field = line.split(":", 1)[1].strip() if ":" in line else None
        elif "name:" in lower:
            field = line.split(":", 1)[1].strip() if ":" in line else None
        elif "- " in line:
            field = line.strip()[2:].split("(")[0].strip()
        
        if not field:
            continue
        
        if any(kw in lower for kw in ["ipv4", "ip address", "src_ip", "dest_ip"]):
            if field not in mappings["ip_fields"]:
                mappings["ip_fields"].append(field)
        
        # All fields  are potential text fields
        if field not in mappings["all_text_fields"]:
            mappings["all_text_fields"].append(field)
    
    return mappings


def _extract_basic_context(question: str, conversation_history: list = None) -> dict:
    """Extract IPs, domains, keywords from incident."""
    context = {
        "ips": [],
        "domains": [],
        "keywords": [],
    }

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    context["ips"] = list(set(re.findall(ip_pattern, question)))

    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    context["domains"] = list(set(re.findall(domain_pattern, question.lower())))

    if conversation_history:
        history_text = " ".join([
            msg.get("content", "")
            for msg in conversation_history
            if msg.get("content")
        ])
        
        ips = re.findall(ip_pattern, history_text)
        context["ips"].extend([ip for ip in ips if ip not in context["ips"]])
        
        domains = re.findall(domain_pattern, history_text.lower())
        context["domains"].extend([d for d in domains if d not in context["domains"]])

    return context


def _ask_llm_for_search_strategy(
    llm: Any, incident_question: str, conversation_history: list,
    field_docs: str, incident_context: dict
) -> dict:
    """Ask LLM to design a search strategy."""
    
    history_summary = ""
    if conversation_history:
        history_summary = "\n\nConversation history:\n" + "\n".join([
            f"  {msg.get('role', '?').upper()}: {msg.get('content', '')[:200]}"
            for msg in conversation_history[-5:]
        ])

    extracted_context = ""
    if incident_context.get("ips") or incident_context.get("domains"):
        extracted_context = f"\n\nAlready identified:\n"
        if incident_context["ips"]:
            extracted_context += f"  IPs: {', '.join(incident_context['ips'])}\n"
        if incident_context["domains"]:
            extracted_context += f"  Domains: {', '.join(incident_context['domains'])}\n"

    prompt = f"""You are a forensic analyst designing searches for incident investigation.

INCIDENT: {incident_question}
{history_summary}
{extracted_context}

AVAILABLE FIELDS:
{field_docs}

Design a search strategy. Output JSON:
{{
  "summary": "brief summary",
  "search_queries": [
    {{"description": "what to find", "keywords": ["term1", "term2"]}}
  ],
  "time_window": "YYYY-MM-DD to YYYY-MM-DD (or leave empty for 30 days back)",
  "reasoning": "why these searches"
}}"""

    messages = [{"role": "user", "content": prompt}]

    try:
        response = llm.chat(messages)
        response = response.strip()
        if "```" in response:
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
            response = response.strip()
        
        return json.loads(response)
    except:
        return {
            "summary": "Search for incident context",
            "search_queries": [{"description": "Broad search", "keywords": [incident_question[:50]]}],
            "time_window": None,
            "reasoning": "Fallback search"
        }


def _execute_searches(db: Any, logs_index: str, strategy: dict, field_docs: str) -> list:
    """Execute searches using DISCOVERED FIELD MAPPINGS (data-agnostic).
    
    Instead of hardcoding field names, this parses the field_documentation
    to learn which fields actually exist in the data, then uses those.
    """
    results = []
    
    # Parse field documentation to discover actual field names
    field_mappings = _parse_field_mappings(field_docs)
    ip_fields = field_mappings.get("ip_fields", [])
    text_fields = field_mappings.get("all_text_fields", [])
    
    for sq in strategy.get("search_queries", []):
        keywords = sq.get("keywords", [])
        description = sq.get("description", "")
        
        if not keywords:
            continue
        
        logger.info("[%s] Searching: %s (using %d IP fields, %d text fields)", 
                    SKILL_NAME, description, len(ip_fields), len(text_fields))
        
        should_clauses = []
        for kw in keywords:
            # Check if keyword is an IP address
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, kw):
                # IP address — search discovered IP fields
                if ip_fields:
                    for field in ip_fields:
                        should_clauses.append({"term": {field: kw}})
                        should_clauses.append({"match": {field: kw}})
                else:
                    logger.warning("[%s] No IP fields discovered; skipping IP search for %s", SKILL_NAME, kw)
            else:
                # Text keyword — search discovered text fields
                if text_fields:
                    should_clauses.append({
                        "multi_match": {
                            "query": kw,
                            "fields": text_fields,
                        }
                    })
                else:
                    logger.warning("[%s] No text fields discovered; skipping text search for %s", SKILL_NAME, kw)
        
        if not should_clauses:
            logger.warning("[%s] No search clauses built for: %s", SKILL_NAME, description)
            continue
        
        query = {
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
            "size": 100,
        }
        
        try:
            search_results = db.search(logs_index, query, size=100)
            results.extend(search_results)
            logger.info("[%s] Found %d results", SKILL_NAME, len(search_results))
        except Exception as exc:
            logger.warning("[%s] Search failed: %s", SKILL_NAME, exc)
    
    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        rid = r.get("_id") or str(r)
        if rid not in seen:
            seen.add(rid)
            unique.append(r)
    
    return unique


def _ask_llm_for_timeline(
    llm: Any, incident_question: str, search_results: list,
    field_docs: str, instruction: str
) -> str:
    """Ask LLM to build timeline from raw results."""
    
    results_text = json.dumps(search_results[:20], indent=2, default=str)
    
    prompt = f"""Build a forensic timeline for this incident:

INCIDENT: {incident_question}

AVAILABLE FIELDS:
{field_docs}

RAW LOGS:
{results_text}

GENERATE: Detailed chronological timeline showing WHEN, WHERE, WHAT, WHO, HOW.
Include timestamps, IPs, ports, protocols, and explain the sequence of events."""

    messages = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": prompt},
    ]

    try:
        return llm.chat(messages).strip()
    except Exception as exc:
        logger.error("[%s] Timeline generation failed: %s", SKILL_NAME, exc)
        return "Unable to generate timeline"


def _ask_llm_for_timeline_no_results(
    llm: Any, incident_question: str, strategy: dict,
    field_docs: str, instruction: str
) -> str:
    """Handle case when no results found."""
    
    prompt = f"""No logs were found for this incident investigation.

INCIDENT: {incident_question}

SEARCH STRATEGY ATTEMPTED:
{json.dumps(strategy, indent=2)}

AVAILABLE FIELDS:
{field_docs}

ANALYZE: Why might no logs exist? Possible explanations:
1. Incident occurred before logs started
2. Search terms don't match field values
3. Logs were deleted/rotated
4. Different field structure than expected

What does this tell us? Suggest next steps."""

    messages = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": prompt},
    ]

    try:
        return llm.chat(messages).strip()
    except Exception as exc:
        logger.error("[%s] Analysis failed: %s", SKILL_NAME, exc)
        return "Unable to analyze results"
