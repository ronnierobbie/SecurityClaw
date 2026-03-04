"""
tests/test_knn_search_fix.py — Tests for KNN search filter compatibility
"""
from __future__ import annotations

import pytest
from unittest.mock import Mock, MagicMock


class TestKNNSearchWithFilters:
    """Test that KNN search handles filters correctly for NMSLIB compatibility."""

    def test_knn_search_without_filters(self):
        """KNN search without filters should use simple KNN query."""
        from core.db_connector import OpenSearchConnector
        
        # Mock the OpenSearch client
        mock_client = Mock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "text": "Found document",
                            "category": "network_baseline"
                        },
                        "_score": 0.95
                    }
                ]
            }
        }
        
        connector = OpenSearchConnector(client=mock_client)
        result = connector.knn_search(
            index="test-index",
            vector=[0.1, 0.2, 0.3],
            k=5
        )
        
        # Verify search was called
        assert mock_client.search.called
        
        # Check the query structure
        call_args = mock_client.search.call_args
        body = call_args[1]["body"]
        
        # Should have simple KNN query
        assert "query" in body
        assert "knn" in body["query"]
        assert "embedding" in body["query"]["knn"]
        assert body["query"]["knn"]["embedding"]["k"] == 5
        
        # Verify result
        assert len(result) == 1
        assert result[0]["text"] == "Found document"

    def test_knn_search_with_filters(self):
        """KNN search with filters should use bool query with must and filter."""
        from core.db_connector import OpenSearchConnector
        
        # Mock the OpenSearch client
        mock_client = Mock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "text": "Baseline context",
                            "category": "network_baseline"
                        },
                        "_score": 0.88
                    }
                ]
            }
        }
        
        connector = OpenSearchConnector(client=mock_client)
        result = connector.knn_search(
            index="test-index",
            vector=[0.1, 0.2, 0.3],
            k=5,
            filters={"term": {"category": "network_baseline"}}
        )
        
        # Verify search was called
        assert mock_client.search.called
        
        # Check the query structure for filter-aware query
        call_args = mock_client.search.call_args
        body = call_args[1]["body"]
        query = body["query"]
        
        # Should have bool query with must (KNN) and filter
        assert "bool" in query
        assert "must" in query["bool"]
        assert "filter" in query["bool"]
        
        # KNN should be in the must clause
        assert "knn" in query["bool"]["must"]
        assert "embedding" in query["bool"]["must"]["knn"]
        
        # Filter should be at the bool level
        assert query["bool"]["filter"] == {"term": {"category": "network_baseline"}}
        
        # Verify result
        assert len(result) == 1
        assert result[0]["category"] == "network_baseline"

    def test_knn_search_error_handling(self):
        """KNN search should handle errors gracefully and return empty list."""
        from core.db_connector import OpenSearchConnector
        
        # Mock the OpenSearch client to raise an exception
        mock_client = Mock()
        mock_client.search.side_effect = Exception("Search failed")
        
        connector = OpenSearchConnector(client=mock_client)
        result = connector.knn_search(
            index="test-index",
            vector=[0.1, 0.2, 0.3],
            k=5,
            filters={"term": {"status": "active"}}
        )
        
        # Should return empty list on error
        assert result == []

    def test_knn_search_filter_structure_for_nmslib(self):
        """KNN search filter structure should be compatible with NMSLIB."""
        from core.db_connector import OpenSearchConnector
        
        mock_client = Mock()
        mock_client.search.return_value = {"hits": {"hits": []}}
        
        connector = OpenSearchConnector(client=mock_client)
        
        # Test with category filter (common case)
        connector.knn_search(
            index="vectors",
            vector=[0.1, 0.2],
            k=3,
            filters={"term": {"category": "field_documentation"}}
        )
        
        # Capture the query sent
        call_args = mock_client.search.call_args
        body = call_args[1]["body"]
        query = body["query"]
        
        # Verify the filter is at the bool level (NMSLIB compatible)
        assert "bool" in query
        assert "must" in query["bool"]
        assert query["bool"]["must"]["knn"]["embedding"]["vector"] == [0.1, 0.2]
        assert query["bool"]["filter"]["term"]["category"] == "field_documentation"
        
        # KNN should NOT have filter inside it (NMSLIB incompatible)
        knn_embedding = query["bool"]["must"]["knn"]["embedding"]
        assert "filter" not in knn_embedding


class TestRAGEngineWithKNNFix:
    """Test that RAG engine works correctly with fixed KNN search."""

    def test_rag_retrieve_with_category_filter(self):
        """RAG retrieve should work with category filters via fixed KNN."""
        from core.rag_engine import RAGEngine
        
        mock_db = Mock()
        mock_db.knn_search.return_value = [
            {
                "text": "Network baseline includes port 443",
                "source": "baseline",
                "category": "network_baseline"
            }
        ]
        
        mock_llm = Mock()
        mock_llm.embed.return_value = [0.1, 0.2, 0.3]
        
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        
        # Retrieve with category filter
        results = rag.retrieve("baseline information", category="network_baseline")
        
        # Verify knn_search was called with filters
        assert mock_db.knn_search.called
        call_args = mock_db.knn_search.call_args
        assert call_args[1]["filters"] == {"term": {"category": "network_baseline"}}
        
        # Verify results
        assert len(results) == 1
        assert results[0]["category"] == "network_baseline"

    def test_rag_build_context_uses_fixed_knn(self):
        """RAG build_context_string should use KNN with proper filter structure."""
        from core.rag_engine import RAGEngine
        
        mock_db = Mock()
        mock_db.knn_search.return_value = [
            {
                "text": "Port 80 is standard for HTTP",
                "category": "network_baseline",
                "source": "documentation"
            },
            {
                "text": "Port 443 is standard for HTTPS",
                "category": "network_baseline",
                "source": "documentation"
            }
        ]
        
        mock_llm = Mock()
        mock_llm.embed.return_value = [0.1, 0.2]
        
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        context = rag.build_context_string("What ports are normal?", category="network_baseline")
        
        # Verify results were formatted
        assert "Port 80" in context
        assert "Port 443" in context
        assert "network_baseline" in context
