"""
skills/chat_router/logic.py

Intelligent skill router for conversational SOC queries.
Routes user questions to appropriate skills, handles multi-skill workflows,
and maintains conversation context.

This is not a periodic skill—it's invoked interactively via the chat command.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "chat_router"


def route_question(
    user_question: str,
    available_skills: list[dict],
    llm: Any,
    instruction: str,
    conversation_history: list[dict] = None,
) -> dict:
    """
    Analyze user question and decide which skill(s) to invoke.
    
    Args:
        user_question: Current user input
        available_skills: List of skill definitions
        llm: LLM provider
        instruction: System instruction
        conversation_history: Prior Q&A turns for context (optional)
    
    Returns dict with:
      - reasoning: Why this skill was chosen
      - skills: List of skill names to invoke (can be multiple for workflows)
      - parameters: Parameters to pass to skills (includes the question)
    """
    skills_description = "\n".join([
        f"- {s['name']}: {s['description']}"
        for s in available_skills
    ])

    # Build conversation context if history is provided
    history_context = ""
    if conversation_history:
        history_lines = []
        for msg in conversation_history:
            if msg.get("role") == "user":
                history_lines.append(f"User: {msg.get('content', '')}")
            elif msg.get("role") == "assistant":
                history_lines.append(f"Agent: {msg.get('content', '')}")
        if history_lines:
            history_context = "\n\nRECENT CONVERSATION HISTORY (for context):\n" + "\n".join(history_lines)

    prompt = f"""Analyze this security question and decide which available skills to use.
Consider the recent conversation history to maintain context.

Current Question: "{user_question}"{history_context}

Available skills:
{skills_description}

ROUTING GUIDELINES:
- If asking to INVESTIGATE AN INCIDENT or RECONSTRUCT A TIMELINE (what happened, sequence of events, 
  before/after an incident, timeline around an event), use forensic_examiner to build a ±5 min timeline 
  linking DNS → network flows → alerts.
- If asking for THREAT INTELLIGENCE or REPUTATION DATA (threat intel, threat score, reputation, 
  AbuseIPDB, VirusTotal, malicious status, threat level, is it malicious), use threat_analyst 
  to fetch external reputation from AbuseIPDB, AlienVault, VirusTotal, Talos.
- If the question asks for SPECIFIC FIELDS or ATTRIBUTES (when, where, how, port, protocol, etc.) 
  from previously found data, use rag_querier to extract those details.
- If the question is a FOLLOW-UP about data mentioned in history (even if rephrased), 
  likely needs rag_querier to query/extract from that data.
- Questions about TIMING (when did X happen, what time, date, timestamp) require rag_querier 
  to extract temporal data from logs.
- Questions about LOCATION/SOURCE (where from, who, what country) require rag_querier 
  to search geographic fields.
- If asking for DEEPER ANALYSIS of found anomalies, use anomaly_watcher or threat_analyst.
- Skills can be chained if needed (e.g., forensic_examiner then threat_analyst for timeline + reputation).

Respond with ONLY a JSON object (no markdown, no extra text):
{{
  "reasoning": "Why you chose these skills (consider history context, field extraction needs)",
  "skills": ["skill_name_1", "skill_name_2"],
  "parameters": {{"question": "{user_question}", "any_param": "value"}}
}}

If question asks for specific data/fields from previously found records, include rag_querier.
Always include the user question in parameters."""

    messages = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": prompt},
    ]

    response = llm.chat(messages)
    
    try:
        result = json.loads(response)
        # Ensure parameters has the question
        if "parameters" not in result:
            result["parameters"] = {}
        if "question" not in result["parameters"]:
            result["parameters"]["question"] = user_question
        
        # Include conversation history in parameters for skills that need context
        if conversation_history:
            result["parameters"]["conversation_history"] = conversation_history
        
        # Filter out network_baseliner if not explicitly requested
        result["skills"] = _filter_explicit_only_skills(
            result.get("skills", []),
            user_question,
        )
        return result
    except json.JSONDecodeError:
        logger.warning("[%s] Failed to parse LLM routing response: %s", SKILL_NAME, response)
        # Fallback: try to extract JSON from response
        try:
            import re
            match = re.search(r"\{.*\}", response, re.DOTALL)
            if match:
                result = json.loads(match.group(0))
                if "parameters" not in result:
                    result["parameters"] = {}
                if "question" not in result["parameters"]:
                    result["parameters"]["question"] = user_question
                return result
        except:
            pass
        
        # If all else fails, return no skills
        return {
            "reasoning": "Unable to determine relevant skill",
            "skills": [],
            "parameters": {"question": user_question},
        }


def _filter_explicit_only_skills(skills: list[str], user_question: str) -> list[str]:
    """
    Filter out skills that are explicit-only (like network_baseliner)
    unless the user explicitly mentions them by name or a variant.
    
    network_baseliner is explicit-only: user must say:
      - "network_baseliner"
      - "baseliner"
      - "create baseline"
      - "generate baseline"
      - "build baseline"
    
    Otherwise, replace with rag_querier to search existing baselines.
    """
    filtered = []
    question_lower = user_question.lower()
    
    # Keywords that explicitly invoke network_baseliner
    explicit_keywords = [
        "network_baseliner",
        "baseliner",
        "create baseline",
        "generate baseline",
        "build baseline",
        "create a baseline",
        "generate a baseline",
        "build a baseline",
        "create new baseline",
        "generate new baseline",
    ]
    explicit_requested = any(kw in question_lower for kw in explicit_keywords)
    
    for skill in skills:
        if skill == "network_baseliner" and not explicit_requested:
            logger.info(
                "[%s] Blocked auto-routing to network_baseliner; user must explicitly request it.",
                SKILL_NAME,
            )
            # Replace with rag_querier for baseline queries
            if "rag_querier" not in filtered:
                filtered.append("rag_querier")
        else:
            filtered.append(skill)
    
    return filtered


def execute_skill_workflow(
    skills: list[str],
    runner: Any,
    context: dict,
    routing_decision: dict,
    conversation_history: list[dict] = None,
) -> dict:
    """
    Execute one or more skills in sequence, passing context between them.
    
    Args:
        skills: List of skill names to execute
        runner: Runner instance
        context: Shared context dict
        routing_decision: Dict with 'parameters' key for skill inputs
        conversation_history: Conversation history for context (optional)
    
    Returns dict with results from each skill execution.
    """
    results = {}
    params = routing_decision.get("parameters", {})
    
    for skill_name in skills:
        logger.info("[%s] Executing skill: %s", SKILL_NAME, skill_name)
        
        try:
            # Build context with parameters
            skill_context = runner._build_context()
            skill_context["parameters"] = params
            
            # Pass conversation history for context-aware skills
            if conversation_history:
                skill_context["conversation_history"] = conversation_history
            
            # Dispatch skill with context
            result = runner.dispatch(skill_name, context=skill_context)
            results[skill_name] = result
            logger.info("[%s] Skill %s completed with status: %s", 
                       SKILL_NAME, skill_name, result.get("status"))
        except Exception as e:
            logger.error("[%s] Skill %s failed: %s", SKILL_NAME, skill_name, e)
            results[skill_name] = {
                "status": "error",
                "error": str(e),
            }
    
    return results


def format_response(
    user_question: str,
    routing_decision: dict,
    skill_results: dict,
    llm: Any,
    cfg: Any = None,  # Pass config for anti-hallucination setting
) -> str:
    """
    Format skill results into a natural language response with thinking-action-reflection loop.
    
    Implements:
      1. THINK: Analyze what the question is asking for
      2. ACTION: Execute skills (already done)
      3. REFLECTION: Check if results answer the question
      4. ANTI-HALLUCINATION: Recheck before presenting
    """
    if not routing_decision.get("skills"):
        return "I couldn't determine which skills would help with that question. Available skills are: network_baseliner, anomaly_watcher, threat_analyst."
    
    # ── PHASE 1: THINK ──────────────────────────────────────────────────────
    think_prompt = f"""Analyze what the user is asking for.

Question: "{user_question}"

Extract:
1. Main intent (what are they trying to understand?)
2. Key entities (IPs, domains, services, etc.)
3. Success criteria (what would constitute a complete answer?)

Be specific and concise."""
    
    think_response = llm.chat([
        {"role": "system", "content": "You are a security analyst. Extract structured intent."},
        {"role": "user", "content": think_prompt},
    ])
    
    # ── PHASE 2: ACTION (already done above) ──────────────────────────────
    # skill_results already contains results from executed skills
    
    # ── PHASE 3: REFLECTION ─────────────────────────────────────────────────
    results_text = "\n".join([
        f"\n[{skill_name}]\n{json.dumps(result, indent=2)}"
        for skill_name, result in skill_results.items()
    ])
    
    reflection_prompt = f"""You extracted the user's intent as:
{think_response}

Now you received these skill results:
{results_text}

REFLECTION QUESTIONS:
1. Do the results address the main intent?
2. Are all key entities covered?
3. Do results meet the success criteria?
4. Are there any inconsistencies or gaps?

Briefly assess coverage (2-3 sentences)."""
    
    reflection_response = llm.chat([
        {"role": "system", "content": "You are a critical analyst. Assess if results are sufficient."},
        {"role": "user", "content": reflection_prompt},
    ])
    
    # ── PHASE 4: ANTI-HALLUCINATION CHECK ───────────────────────────────────
    # Check if anti-hallucination is enabled in config
    anti_hallucination_enabled = True  # Default to enabled
    if cfg:
        anti_hallucination_enabled = cfg.get("llm", "anti_hallucination_check", default=True)
    
    final_response = ""
    if anti_hallucination_enabled:
        verification_prompt = f"""Internally verify your answer against these facts:

User question: "{user_question}"
Skill results:
{results_text}

VERIFICATION (DO INTERNALLY, DO NOT SHOW IN ANSWER):
- Are statements supported by the skill results?
- Did you infer something NOT in the data?
- Did you make up or assume any facts?
- Is everything grounded in actual findings?

NOW PROVIDE ONLY THE ANSWER to the user's question (2-4 sentences).
Do NOT include verification text. Do NOT say "Based on the skill results..." or "Here is the answer:".
Just provide the direct answer."""
        
        final_response = llm.chat([
            {"role": "system", "content": "You are a rigorous security analyst. Verify internally but output only clean answers without preamble."},
            {"role": "user", "content": verification_prompt},
        ])
    else:
        # Standard response without extra verification
        final_prompt = f"""Based on these skill execution results, provide a concise response to the user.

User question: "{user_question}"

Skill results:
{results_text}

Provide a clear, actionable answer (2-4 sentences)."""
        
        final_response = llm.chat([
            {"role": "system", "content": "You are a helpful SOC analyst. Provide clear, actionable insights."},
            {"role": "user", "content": final_prompt},
        ])
    
    # ── APPEND THREAT INTEL APIs INFO if threat_analyst was used ──────────────
    threat_analyst_result = skill_results.get("threat_analyst", {})
    if threat_analyst_result and threat_analyst_result.get("status") == "ok":
        # Extract API query information from verdicts
        all_apis = set()
        if threat_analyst_result.get("verdicts"):
            for verdict in threat_analyst_result["verdicts"]:
                apis = verdict.get("_queried_apis", [])
                if apis:
                    all_apis.update(apis)
        
        if all_apis:
            apis_str = ", ".join(sorted(all_apis))
            final_response += f"\n\n_[Threat Intelligence Sources Queried: {apis_str}]_"
    
    return final_response


# ──────────────────────────────────────────────────────────────────────────────
# Conversation Memory Management
# ──────────────────────────────────────────────────────────────────────────────

CONVERSATIONS_DIR = Path(__file__).parent.parent.parent / "conversations"


def _ensure_conversations_dir():
    """Create conversations directory if it doesn't exist."""
    CONVERSATIONS_DIR.mkdir(parents=True, exist_ok=True)


def load_conversation_history(conversation_id: str) -> list[dict]:
    """Load conversation history from disk."""
    _ensure_conversations_dir()
    conv_file = CONVERSATIONS_DIR / f"{conversation_id}.json"
    
    if not conv_file.exists():
        return []
    
    try:
        with open(conv_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to load conversation %s: %s", conversation_id, e)
        return []


def save_conversation_history(conversation_id: str, history: list[dict]) -> None:
    """Save conversation history to disk."""
    _ensure_conversations_dir()
    conv_file = CONVERSATIONS_DIR / f"{conversation_id}.json"
    
    try:
        with open(conv_file, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        logger.error("Failed to save conversation %s: %s", conversation_id, e)


def list_conversations() -> list[dict]:
    """List all saved conversations with metadata."""
    _ensure_conversations_dir()
    conversations = []
    
    for conv_file in sorted(CONVERSATIONS_DIR.glob("*.json")):
        try:
            with open(conv_file, "r") as f:
                history = json.load(f)
            
            if history:
                conversations.append({
                    "id": conv_file.stem,
                    "messages": len(history),
                    "first_question": history[0].get("question", "Unknown"),
                    "last_update": history[-1].get("timestamp", "Unknown"),
                })
        except Exception as e:
            logger.warning("Failed to read conversation file %s: %s", conv_file, e)
    
    return conversations


def add_to_history(conversation_id: str, question: str, answer: str, 
                  routing: dict, skill_results: dict) -> None:
    """Add a Q&A exchange to conversation history."""
    from datetime import datetime, timezone
    
    history = load_conversation_history(conversation_id)
    
    # Save user question
    user_entry = {
        "role": "user",
        "content": question,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    history.append(user_entry)
    
    # Save assistant answer
    assistant_entry = {
        "role": "assistant",
        "content": answer,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "routing_skills": routing.get("skills", []),
        "routing_reasoning": routing.get("reasoning", ""),
    }
    history.append(assistant_entry)
    
    save_conversation_history(conversation_id, history)


def get_context_summary(conversation_id: str, last_n: int = 3) -> str:
    """Get summary of recent conversation for context injection."""
    history = load_conversation_history(conversation_id)
    
    if not history:
        return ""
    
    recent = history[-last_n:]
    summary_lines = []
    
    for entry in recent:
        summary_lines.append(f"Q: {entry.get('question', '')}")
        answer = entry.get('answer', '')
        # Truncate long answers
        if len(answer) > 200:
            answer = answer[:200] + "..."
        summary_lines.append(f"A: {answer}")
    
    return "\n".join(summary_lines)
