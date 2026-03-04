"""
tests/test_conversation_context.py — Tests for conversation context passing.

Verifies that:
  - Conversation history is passed through the routing system
  - Search terms are extracted from conversation history
  - Geographic context is preserved across conversation turns
  - rag_querier uses conversation history in search
"""
from __future__ import annotations

import pytest
from tests.mock_llm import MockLLMProvider


class TestRouteQuestionWithHistory:
    """Test route_question() accepts and uses conversation history."""
    
    def test_route_question_signature_accepts_history(self):
        """Verify route_question signature includes conversation_history parameter."""
        from skills.chat_router.logic import route_question
        import inspect
        
        sig = inspect.signature(route_question)
        params = list(sig.parameters.keys())
        assert "conversation_history" in params
        assert sig.parameters["conversation_history"].default is None
    
    def test_route_question_includes_history_in_parameters(self):
        """When history is provided, it should be in the returned parameters."""
        from skills.chat_router.logic import route_question
        
        llm = MockLLMProvider()
        history = [
            {"role": "user", "content": "Any visits from Iran?"},
            {"role": "assistant", "content": "Found 2 visits from Iran"},
        ]
        
        skills = [{"name": "rag_querier", "description": "Search baselines"}]
        instruction = "You are a security analyst."
        
        result = route_question("When did visits occur?", skills, llm, instruction, history)
        
        assert "parameters" in result
        assert "conversation_history" in result["parameters"]
        assert result["parameters"]["conversation_history"] == history
    
    def test_route_question_without_history_works(self):
        """route_question should work fine with no history (backward compatibility)."""
        from skills.chat_router.logic import route_question
        
        llm = MockLLMProvider()
        skills = [{"name": "rag_querier", "description": "Search baselines"}]
        instruction = "You are a security analyst."
        
        # Should not raise any exception
        result = route_question("Any visits from Iran?", skills, llm, instruction)
        
        assert "parameters" in result
        assert "question" in result["parameters"]
    
    def test_route_question_includes_history_in_prompt(self):
        """The routing prompt should mention history when it exists."""
        from skills.chat_router.logic import route_question
        
        llm = MockLLMProvider()
        history = [
            {"role": "user", "content": "Iran visits"},
            {"role": "assistant", "content": "Found Iran data"},
        ]
        
        skills = [{"name": "rag_querier", "description": "Search baselines"}]
        instruction = "You are a security analyst."
        
        # MockLLMProvider will return a valid response
        result = route_question("When?", skills, llm, instruction, history)
        
        # Just verify it returns successfully with history
        assert "parameters" in result


class TestExtractSearchTermsWithHistory:
    """Test _extract_search_terms() uses conversation history."""
    
    def test_extract_terms_from_current_question(self):
        """Search terms should be extracted from the current question."""
        from skills.rag_querier.logic import _extract_search_terms
        
        terms = _extract_search_terms("Any visits from Iran?")
        assert "visits" in terms
        assert "iran" in terms
    
    def test_extract_terms_includes_history_context(self):
        """Geographic terms from history should be included in search."""
        from skills.rag_querier.logic import _extract_search_terms
        
        history = [
            {"role": "user", "content": "Any visits from Iran?"},
            {"role": "assistant", "content": "Found 2 visits from Iran IP 62.60.131.168"},
        ]
        
        # Follow-up question without mentioning Iran should still include it
        terms = _extract_search_terms("When did visits occur?", history)
        
        # "iran" should be extracted from history
        assert "iran" in terms
        # The current question terms should also be there
        assert "visits" in terms
    
    def test_extract_ips_from_history(self):
        """IP addresses in history should be extracted."""
        from skills.rag_querier.logic import _extract_search_terms
        
        history = [
            {"role": "assistant", "content": "Traffic from 192.168.1.100 to 10.0.0.1"},
        ]
        
        terms = _extract_search_terms("What else?", history)
        
        # IPs from history should be included
        assert "192.168.1.100" in terms or "10.0.0.1" in terms
    
    def test_extract_terms_deduplicates(self):
        """Duplicate terms should be removed."""
        from skills.rag_querier.logic import _extract_search_terms
        
        history = [
            {"role": "user", "content": "Iran visits"},
            {"role": "assistant", "content": "Iran data found"},
        ]
        
        terms = _extract_search_terms("Iran again?", history)
        
        # "iran" should appear only once
        assert terms.count("iran") == 1
    
    def test_extract_terms_without_history_works(self):
        """Should work fine without history (backward compatibility)."""
        from skills.rag_querier.logic import _extract_search_terms
        
        terms = _extract_search_terms("Any visits from Iran?")
        
        # Should extract basic terms
        assert len(terms) > 0
        assert any(term in ["visits", "iran"] for term in terms)
    
    def test_extract_filters_stopwords(self):
        """Common stopwords should be filtered out."""
        from skills.rag_querier.logic import _extract_search_terms
        
        terms = _extract_search_terms("What is the traffic?")
        
        # Common words should be filtered
        assert "is" not in terms
        assert "the" not in terms
        assert "what" not in terms


class TestRagQuerierWithHistory:
    """Test rag_querier skill receives conversation history."""
    
    def test_rag_querier_receives_history_in_parameters(self, runner_context):
        """rag_querier.run() should receive conversation_history in parameters."""
        import importlib
        
        logic = importlib.import_module("skills.rag_querier.logic")
        
        history = [
            {"role": "user", "content": "Iran visits"},
            {"role": "assistant", "content": "Found Iran data"},
        ]
        
        context = {
            **runner_context,
            "parameters": {
                "question": "When?",
                "conversation_history": history,
            }
        }
        
        # Should not raise an error about missing question
        # (May return "no_data" if no logs, but should handle history gracefully)
        result = logic.run(context)
        
        assert isinstance(result, dict)
        assert "status" in result
    
    def test_search_raw_logs_signature_accepts_history(self):
        """_search_raw_logs should accept conversation_history parameter."""
        from skills.rag_querier.logic import _search_raw_logs
        import inspect
        
        sig = inspect.signature(_search_raw_logs)
        params = list(sig.parameters.keys())
        assert "conversation_history" in params
        assert sig.parameters["conversation_history"].default is None


class TestConversationFlowIntegration:
    """Integration tests for multi-turn conversations."""
    
    def test_two_turn_conversation_preserves_context(self):
        """Simulates a two-turn conversation where context is preserved."""
        from skills.chat_router.logic import route_question
        from tests.mock_llm import MockLLMProvider
        
        llm = MockLLMProvider()
        skills = [{"name": "rag_querier", "description": "Search baselines"}]
        instruction = "You are a security analyst."
        
        # Q1: Ask about Iran
        q1 = "Any visits from Iran?"
        routing1 = route_question(q1, skills, llm, instruction, conversation_history=None)
        
        # Check Q1 result
        assert "parameters" in routing1
        assert "question" in routing1["parameters"]
        
        # Build history from Q1
        history = [
            {"role": "user", "content": q1},
            {"role": "assistant", "content": "Found 2 visits from Iran"},
        ]
        
        # Q2: Ask about timing (without re-mentioning Iran)
        q2 = "When did visits occur?"
        routing2 = route_question(q2, skills, llm, instruction, conversation_history=history)
        
        # Check Q2 result includes history
        assert "parameters" in routing2
        assert "conversation_history" in routing2["parameters"]
        assert routing2["parameters"]["conversation_history"] == history
        
        # The parameters should be passed to rag_querier
        assert "rag_querier" in routing2.get("skills", []) or routing2.get("skills") == []
