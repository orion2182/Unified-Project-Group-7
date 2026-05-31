"""Tests for Unified-PDP MCP Server."""

import pytest
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestDecisionEngine:
    """Test Intelligent Decision Engine."""

    def test_analyze_target(self):
        """Test target analysis."""
        from mcp_server.agents.decision_engine import IntelligentDecisionEngine

        engine = IntelligentDecisionEngine()
        result = engine.analyze_target("https://api.example.com", "quick")

        assert result["target"] == "https://api.example.com"
        assert "recommendations" in result
        assert len(result["recommendations"]) > 0

    def test_select_tools(self):
        """Test tool selection."""
        from mcp_server.agents.decision_engine import IntelligentDecisionEngine

        engine = IntelligentDecisionEngine()
        tools = engine.select_tools("https://api.example.com", max_tools=5)

        assert len(tools) <= 5
        assert all(hasattr(t, "tool_name") for t in tools)

    def test_optimize_parameters(self):
        """Test parameter optimization."""
        from mcp_server.agents.decision_engine import IntelligentDecisionEngine

        engine = IntelligentDecisionEngine()
        result = engine.optimize_parameters("nmap", "https://target.com", {})

        assert result["status"] == "optimized"
        assert "params" in result

    def test_suggest_attack_chain(self):
        """Test attack chain suggestion."""
        from mcp_server.agents.decision_engine import IntelligentDecisionEngine

        engine = IntelligentDecisionEngine()
        chains = engine.suggest_attack_chain("https://target.com", "full")

        assert len(chains) > 0
        assert "name" in chains[0]
        assert "steps" in chains[0]


class TestCache:
    """Test Smart Cache."""

    def test_cache_set_get(self):
        """Test basic cache operations."""
        from mcp_server.cache.cache_manager import SmartCache

        cache = SmartCache(max_entries=100, max_size_mb=10)
        cache.set("test_key", {"data": "test_value"}, ttl=60)
        result = cache.get("test_key")

        assert result == {"data": "test_value"}

    def test_cache_miss(self):
        """Test cache miss."""
        from mcp_server.cache.cache_manager import SmartCache

        cache = SmartCache()
        result = cache.get("nonexistent_key")

        assert result is None

    def test_cache_delete(self):
        """Test cache deletion."""
        from mcp_server.cache.cache_manager import SmartCache

        cache = SmartCache()
        cache.set("delete_me", "value")
        cache.delete("delete_me")
        result = cache.get("delete_me")

        assert result is None

    def test_cache_clear(self):
        """Test cache clear."""
        from mcp_server.cache.cache_manager import SmartCache

        cache = SmartCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()

        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_cache_stats(self):
        """Test cache statistics."""
        from mcp_server.cache.cache_manager import SmartCache

        cache = SmartCache()
        cache.get("miss1")
        cache.get("miss2")
        cache.set("hit1", "value")
        cache.get("hit1")

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 2


class TestAgents:
    """Test AI Agents."""

    def test_base_agent_init(self):
        """Test base agent initialization."""
        from mcp_server.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            async def execute(self, **kwargs):
                pass

            def get_capabilities(self):
                return ["test"]

        agent = TestAgent("test_agent", "Test agent")
        assert agent.name == "test_agent"
        assert agent.description == "Test agent"
        assert agent.execution_count == 0

    def test_agent_status(self):
        """Test agent status method."""
        from mcp_server.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            async def execute(self, **kwargs):
                pass

            def get_capabilities(self):
                return ["test"]

        agent = TestAgent("test_agent", "Test agent")
        status = agent.get_status()

        assert "name" in status
        assert "execution_count" in status
        assert "avg_execution_time" in status


class TestMCPTools:
    """Test MCP tool functions."""

    def test_health_check(self):
        """Test health check tool."""
        # Import would require full setup
        # This is a placeholder for integration tests
        pass

    def test_version(self):
        """Test version output."""
        # Placeholder
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
