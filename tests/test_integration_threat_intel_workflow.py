"""
tests/test_integration_threat_intel_workflow.py — End-to-end threat intel workflow
"""
from __future__ import annotations

import pytest
from unittest.mock import Mock, patch


class TestThreatIntelWorkflow:
    """Integration tests for complete threat intelligence workflow."""

    def test_conversation_history_to_threat_intel_complete_flow(self):
        """Complete workflow: history -> extract IP -> query APIs -> format response."""
        from skills.threat_analyst.logic import run, _analyze_finding, _enrich_with_reputation
        
        # Simulate conversation history with an IP mentioned
        conversation_history = [
            {
                "role": "user",
                "content": "The suspicious IP address 62.60.131.168 connected from Iran"
            },
            {
                "role": "assistant",
                "content": "I found network flows to that IP on port 1194"
            },
            {
                "role": "user",
                "content": "can you pull threat intel on this ip?"  # No IP in this message
            }
        ]
        
        # Mock context
        mock_db = Mock()
        mock_llm = Mock()
        mock_llm.chat.return_value = '{"verdict": "TRUE_THREAT", "confidence": 85}'
        context = {
            "db": mock_db,
            "llm": mock_llm,
            "memory": None,
            "config": Mock(),
            "parameters": {"question": "can you pull threat intel on this ip?"},
            "conversation_history": conversation_history
        }
        
        with patch("core.rag_engine.RAGEngine") as mock_rag_class:
            mock_rag = Mock()
            mock_rag.build_context_string.return_value = "Baseline: normal traffic"
            mock_rag_class.return_value = mock_rag
            
            with patch("core.reputation_intel.get_ip_reputation") as mock_get_ip:
                mock_get_ip.return_value = {
                    "ip": "62.60.131.168",
                    "abuseipdb": {"abuse_score": 75, "reports": 42},
                    "alienvault": {"reputation": "malicious", "pulses": 5},
                    "virustotal": {"malicious": 3},
                    "combined_risk": "HIGH",
                    "queries": ["abuseipdb", "alienvault", "virustotal"]
                }
                
                # Run threat_analyst
                result = run(context)
                
                # Verify the IP was found and queried
                assert mock_get_ip.called
                mock_get_ip.assert_called_with("62.60.131.168")
                
                # Verify verdict was generated
                assert result["status"] == "ok"
                assert len(result["verdicts"]) > 0

    def test_knn_search_falls_back_to_keyword_search(self):
        """When KNN search fails, system falls back to keyword search."""
        from core.rag_engine import RAGEngine
        
        mock_db = Mock()
        # KNN fails with NMSLIB error
        mock_db.knn_search.side_effect = Exception(
            "Engine [NMSLIB] does not support filters"
        )
        # Keyword search succeeds
        mock_db.search.return_value = [
            {
                "text": "Normal baseline includes HTTP on port 80",
                "category": "network_baseline",
                "source": "documentation"
            }
        ]
        
        mock_llm = Mock()
        mock_llm.embed.return_value = [0.1, 0.2, 0.3]
        
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        
        # Request with category filter
        results = rag.retrieve("Network baseline", category="network_baseline")
        
        # Should still get results from fallback search
        assert len(results) > 0
        assert results[0]["text"] == "Normal baseline includes HTTP on port 80"
        
        # Both searches should have been attempted
        assert mock_db.knn_search.called
        assert mock_db.search.called

    def test_threat_intel_with_multiple_ips_in_history(self):
        """threat_analyst handles multiple IPs in conversation history."""
        from skills.threat_analyst.logic import _enrich_with_reputation
        
        conversation_history = [
            {"role": "user", "content": "Traffic from 62.60.131.168 and 192.168.0.1"},
            {"role": "user", "content": "Get threat intel"}  # No IPs here
        ]
        
        with patch("core.reputation_intel.get_ip_reputation") as mock_intel:
            # Mock different risks for different IPs
            def get_intel_side_effect(ip):
                if ip == "62.60.131.168":
                    return {
                        "ip": ip,
                        "abuseipdb": {"abuse_score": 75},
                        "combined_risk": "HIGH",
                        "queries": ["abuseipdb"]
                    }
                elif ip == "192.168.0.1":
                    return {
                        "ip": ip,
                        "abuseipdb": {"abuse_score": 0},
                        "combined_risk": "LOW",
                        "queries": ["abuseipdb"]
                    }
            
            mock_intel.side_effect = get_intel_side_effect
            
            # Question has no IP, should extract both from history
            result_string, queried_apis = _enrich_with_reputation("Get threat intel", conversation_history)
            
            # Should have queried both IPs
            assert mock_intel.call_count == 2
            
            # Result should mention both IPs
            assert "62.60.131.168" in result_string
            assert "192.168.0.1" in result_string
            
            # Should track which APIs were queried
            assert "abuseipdb" in queried_apis

    def test_reputation_data_formatted_for_llm(self):
        """Reputation data should be properly formatted for LLM consumption."""
        from skills.threat_analyst.logic import _enrich_with_reputation
        
        with patch("core.reputation_intel.get_ip_reputation") as mock_intel:
            mock_intel.return_value = {
                "ip": "8.8.8.8",
                "abuseipdb": {
                    "abuse_score": 0,
                    "reports": 0,
                    "is_whitelisted": True
                },
                "alienvault": {
                    "reputation": "clean",
                    "pulses": 0,
                    "tags": []
                },
                "virustotal": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 71
                },
                "combined_risk": "LOW",
                "queries": ["abuseipdb", "alienvault", "virustotal"]
            }
            
            result_string, queried_apis = _enrich_with_reputation("What about 8.8.8.8?")
            
            # Result should be readable string for LLM
            assert isinstance(result_string, str)
            assert "8.8.8.8" in result_string
            assert "AbuseIPDB" in result_string
            assert "AlienVault" in result_string
            # VirusTotal is only shown if malicious > 0 (optimization)
            # For 8.8.8.8 it's not shown since no malicious detections
            assert "LOW" in result_string  # Risk level should be visible
            assert "abuseipdb" in queried_apis
            assert "alienvault" in queried_apis
            assert "virustotal" in queried_apis

    def test_no_ips_in_question_or_history(self):
        """When no IPs found anywhere, enrichment returns graceful message."""
        from skills.threat_analyst.logic import _enrich_with_reputation
        
        history = [
            {"role": "user", "content": "What is normal baseline traffic?"}
        ]
        
        with patch("core.reputation_intel.get_ip_reputation"):
            # Question and history have no IPs
            result_string, queried_apis = _enrich_with_reputation(
                "Can you explain the baseline?",
                history
            )
            
            # Should return graceful message, not error
            assert isinstance(result_string, str)
            assert "No external reputation data" in result_string or "no IPs" in result_string.lower()
            assert queried_apis == []  # No APIs queried

    def test_threat_analyst_prefers_question_ips_over_history(self):
        """If question has IP, don't search history (avoid stale context)."""
        from skills.threat_analyst.logic import _enrich_with_reputation
        
        history = [
            {"role": "user", "content": "Old IP: 1.2.3.4"}
        ]
        
        with patch("core.reputation_intel.get_ip_reputation") as mock_intel:
            mock_intel.return_value = {
                "ip": "8.8.8.8",
                "combined_risk": "LOW",
                "queries": ["abuseipdb"]
            }
            
            # Question has explicit IP - should use that
            result = _enrich_with_reputation("Check 8.8.8.8", history)
            
            # Should only query the question's IP, not history's
            mock_intel.assert_called_once_with("8.8.8.8")
