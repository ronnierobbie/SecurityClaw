---
schedule_interval_seconds: null
skill: RAGQuerier
description: >
  Searches stored baseline knowledge (via RAG) to answer user questions
  about network behavior, traffic patterns, and system activity.
  Data-agnostic—analyzes whatever baselines have been generated.
---

# RAG Querier

## Purpose

This skill **searches both stored baselines and raw data** to answer user questions.

It does NOT generate baselines. Instead, it performs a dual search:
1. **Baseline Knowledge**: Searches stored RAG baselines for pattern information
2. **Observed Data**: Searches recent raw logs for actual recordings of activity

This provides both "what is normal" and "what actually happened" context.

## Input

Receives a user question via `context["parameters"]["question"]`.

Examples:
- "Is there traffic to 8.8.8.8?"
- "What are the normal protocols in this network?"
- "What ports are typically used?"

## Process

1. **Embed the question**: Convert the user question into a vector using the LLM
2. **Search RAG**: Retrieve similar baseline documents (what is normal)
3. **Search raw logs**: Query logs for records matching keywords from the question (what happened)
4. **Combine context**: Format both baseline and observed data for analysis
5. **Analyze results**: Use the LLM to extract an answer from combined context
6. **Return findings**: Structured answer with confidence and source breakdown

## Output

Returns a dict:
```json
{
  "status": "ok",
  "findings": {
    "question": "user question",
    "answer": "answer based on baselines and observed data",
    "rag_sources": 5,
    "log_records": 23,
    "confidence": 0.85,
    "summary": {
      "baseline_insights": 5,
      "raw_observations": 23
    }
  }
}
```

## Data Agnostic

This skill works with any baseline data:
- Network baselines (IPs, ports, protocols)
- Endpoint baselines (processes, users, connections)
- Application baselines (DNS, HTTP, custom)
- Any other metric-based baselines

The skill simply retrieves what exists and answers questions about it.

## Relationship to Other Skills

- **network_baseliner**: *Creates* baselines → stores in RAG *(doesn't answer)*
- **rag_querier**: *Searches* baselines → answers questions *(this skill)*
- **anomaly_watcher**: Detects deviations from baselines
- **threat_analyst**: Analyzes findings in context of baselines

## When to Invoke

Answer questions like:
- "What's normal traffic for this network?"
- "Have we seen traffic to this IP before?"
- "What protocols are common?"
- "Are these ports unusual?"
- "Show me the baseline for this sensor"

## Data Extraction Rules

When analyzing logs and baselines to answer questions, follow these rules:

### 1. Extract Exact Values
- Copy timestamps, IP addresses, ports, and protocols directly from the data
- Don't paraphrase or abstract—show actual values from the records
- Example: "Traffic to 192.168.0.16 port 1194 at 14:32:51 UTC" (not "various traffic patterns")

### 2. Quote All Matching Records
- List EVERY record that matches the search criteria
- For each record, show: @timestamp, source IP, dest IP, port, protocol, bytes, packets
- Group records by similarity if there are many

### 3. Handle Timezone Conversions
- If user asks for PST, convert UTC timestamps (UTC-8, or UTC-7 during DST)
- Show both original UTC and converted time
- Example: "2026-02-13T14:32:51 UTC = 06:32:51 PST"

### 4. Include Counts & Statistics
- Provide exact counts: "5 records", not "multiple records"
- Show totals: "1024 bytes total across 2 packets"
- Never say "multiple" or "several" when you can give exact numbers

### 5. Field Documentation First
- If data includes field_documentation from the baseliner, use it to identify available fields
- This tells you what fields exist and what they mean
- Helps parse records correctly

### 6. Never Say "Not Specified" When Data is Available
- If data is in the records, extract it
- Only say data is unavailable if it's truly missing from all records
- Before saying "unavailable", check every record shown

### 7. Be Specific About Uncertainty
- Don't say "The timestamp is not available" if @timestamp exists in records
- Say "The @timestamp field shows..." (with actual values)
- Only claim ambiguity if there's genuine inconsistency in the data

### 8. Prioritize Data Over Baselines
- When both baselines and raw logs exist, prefer specific data from logs
- Baselines show "what's normal"
- Logs show "what actually happened"
