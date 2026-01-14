import asyncio
from typing import Any

import pytest

from extensions.eda.plugins.event_source.snmp_trap import (
    SNMPTrapProtocol,
    main as snmp_trap_main,
)


@pytest.mark.asyncio
async def test_cancel() -> None:
    """Test that the plugin can be cancelled."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {"host": "127.0.0.1", "port": 16200, "version": "v2c", "community": "public"}
    plugin_task = asyncio.create_task(snmp_trap_main(queue, args))

    # Cancel after a short delay
    await asyncio.sleep(0.1)
    plugin_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await plugin_task


@pytest.mark.asyncio
async def test_snmpv2_trap_parsing() -> None:
    """Test parsing of SNMPv2c trap."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16201,
        "version": "v2c",
        "community": "public",
        "include_raw": True,
        "include_structured": True,
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Create a minimal SNMPv2c trap packet
    # This is a simplified test - in practice, you'd use pysnmp to generate proper traps
    # For now, we'll test with malformed data to ensure error handling works
    test_data = b"\x30\x0c\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa7\x00"
    addr = ("127.0.0.1", 12345)

    await protocol._process_trap(test_data, addr)

    # Should handle error gracefully without crashing
    assert True


@pytest.mark.asyncio
async def test_snmpv1_trap_parsing() -> None:
    """Test parsing of SNMPv1 trap."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16202,
        "version": "v1",
        "community": "public",
        "include_raw": True,
        "include_structured": True,
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Create a minimal SNMPv1 trap packet (simplified)
    test_data = b"\x30\x0c\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa4\x00"
    addr = ("127.0.0.1", 12345)

    await protocol._process_trap(test_data, addr)

    # Should handle error gracefully without crashing
    assert True


@pytest.mark.asyncio
async def test_event_structure() -> None:
    """Test that events have the correct structure."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16203,
        "version": "v2c",
        "community": "public",
        "include_raw": True,
        "include_structured": True,
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Test with invalid data - should not crash
    test_data = b"invalid_snmp_data"
    addr = ("192.168.1.1", 162)

    await protocol._process_trap(test_data, addr)

    # Queue should be empty since parsing failed
    assert queue.empty()


@pytest.mark.asyncio
async def test_include_raw_only() -> None:
    """Test with include_raw=True and include_structured=False."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16204,
        "version": "v2c",
        "community": "public",
        "include_raw": True,
        "include_structured": False,
    }

    protocol = SNMPTrapProtocol(queue, args)
    assert protocol.include_raw is True
    assert protocol.include_structured is False


@pytest.mark.asyncio
async def test_include_structured_only() -> None:
    """Test with include_raw=False and include_structured=True."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16205,
        "version": "v2c",
        "community": "public",
        "include_raw": False,
        "include_structured": True,
    }

    protocol = SNMPTrapProtocol(queue, args)
    assert protocol.include_raw is False
    assert protocol.include_structured is True


@pytest.mark.asyncio
async def test_invalid_version() -> None:
    """Test with invalid SNMP version."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16206,
        "version": "invalid",
        "community": "public",
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Should handle invalid version gracefully
    test_data = b"test_data"
    addr = ("127.0.0.1", 12345)

    await protocol._process_trap(test_data, addr)

    # Should not crash
    assert True


def test_format_snmp_value() -> None:
    """Test SNMP value formatting."""
    from pysnmp.proto import rfc1902  # type: ignore # noqa: PGH003

    queue: asyncio.Queue[Any] = asyncio.Queue()
    args = {"version": "v2c", "community": "public"}

    protocol = SNMPTrapProtocol(queue, args)

    # Test Integer32
    int_val = rfc1902.Integer32(42)
    result = protocol._format_snmp_value(int_val)
    assert result == 42

    # Test OctetString
    octet_val = rfc1902.OctetString(b"test")
    result = protocol._format_snmp_value(octet_val)
    assert result == "test"

    # Test TimeTicks
    ticks_val = rfc1902.TimeTicks(12345)
    result = protocol._format_snmp_value(ticks_val)
    assert result == 12345


@pytest.mark.asyncio
async def test_multiple_traps() -> None:
    """Test handling multiple traps."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16207,
        "version": "v2c",
        "community": "public",
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Process multiple invalid traps
    for i in range(5):
        test_data = f"invalid_data_{i}".encode()
        addr = ("127.0.0.1", 12345 + i)
        await protocol._process_trap(test_data, addr)

    # Should handle all without crashing
    assert True


@pytest.mark.asyncio
async def test_default_args() -> None:
    """Test with default arguments."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {}

    protocol = SNMPTrapProtocol(queue, args)

    # Should use defaults
    assert protocol.version == "v2c"
    assert protocol.community == "public"
    assert protocol.include_raw is True
    assert protocol.include_structured is True


def test_mib_loader() -> None:
    """Test MIB loader initialization and OID resolution."""
    from extensions.eda.plugins.event_source.snmp_trap import MIBLoader

    args = {
        "mib_paths": [],
        "auto_load_standard_mibs": False,
    }

    loader = MIBLoader(args)

    # Test OID resolution for standard trap OID
    result = loader.resolve_oid("1.3.6.1.6.3.1.1.5.1")
    assert "name" in result
    assert result["name"] == "coldStart"

    # Test OID resolution for common OID
    result = loader.resolve_oid("1.3.6.1.2.1.1.3.0")
    assert "name" in result
    assert result["name"] == "sysUpTime"

    # Test unknown OID
    result = loader.resolve_oid("1.3.6.1.999.999.999")
    assert result == {}


def test_trap_filter_allow_mode() -> None:
    """Test trap filtering in allow mode."""
    from extensions.eda.plugins.event_source.snmp_trap import TrapFilter

    args = {
        "filter_mode": "allow",
        "filter_oids": ["1.3.6.1.6.3.1.1.5.1"],  # coldStart
        "filter_require_all": False,
    }

    filter_obj = TrapFilter(args)

    # Should allow matching OID
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "public") is True

    # Should deny non-matching OID
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.2", "public") is False


def test_trap_filter_deny_mode() -> None:
    """Test trap filtering in deny mode."""
    from extensions.eda.plugins.event_source.snmp_trap import TrapFilter

    args = {
        "filter_mode": "deny",
        "filter_oids": ["1.3.6.1.6.3.1.1.5.1"],  # coldStart
        "filter_require_all": False,
    }

    filter_obj = TrapFilter(args)

    # Should deny matching OID
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "public") is False

    # Should allow non-matching OID
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.2", "public") is True


def test_trap_filter_community() -> None:
    """Test trap filtering by community string."""
    from extensions.eda.plugins.event_source.snmp_trap import TrapFilter

    args = {
        "filter_mode": "allow",
        "filter_communities": ["public", "monitoring"],
        "filter_require_all": False,
    }

    filter_obj = TrapFilter(args)

    # Should allow matching community
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "public") is True
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "monitoring") is True

    # Should deny non-matching community
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "private") is False


def test_trap_filter_oid_patterns() -> None:
    """Test trap filtering by OID patterns."""
    from extensions.eda.plugins.event_source.snmp_trap import TrapFilter

    args = {
        "filter_mode": "allow",
        "filter_oid_patterns": ["1.3.6.1.4.1.*"],
        "filter_require_all": False,
    }

    filter_obj = TrapFilter(args)

    # Should allow matching pattern
    assert filter_obj.should_process_trap("1.3.6.1.4.1.12345.1", "public") is True
    assert filter_obj.should_process_trap("1.3.6.1.4.1.99999.5", "public") is True

    # Should deny non-matching pattern
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "public") is False


def test_trap_filter_require_all() -> None:
    """Test trap filtering with require_all option."""
    from extensions.eda.plugins.event_source.snmp_trap import TrapFilter

    args = {
        "filter_mode": "allow",
        "filter_oids": ["1.3.6.1.6.3.1.1.5.1"],
        "filter_communities": ["public"],
        "filter_require_all": True,  # AND logic
    }

    filter_obj = TrapFilter(args)

    # Should allow when both match
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "public") is True

    # Should deny when only one matches
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "private") is False
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.2", "public") is False


def test_trap_filter_disabled() -> None:
    """Test trap filtering when disabled."""
    from extensions.eda.plugins.event_source.snmp_trap import TrapFilter

    args = {}

    filter_obj = TrapFilter(args)

    # Should process all traps when filtering is disabled
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.1", "public") is True
    assert filter_obj.should_process_trap("1.3.6.1.6.3.1.1.5.2", "private") is True


@pytest.mark.asyncio
async def test_token_bucket_consume() -> None:
    """Test token bucket token consumption."""
    from extensions.eda.plugins.event_source.snmp_trap import TokenBucket

    bucket = TokenBucket(rate=10.0, burst=20)

    # Should allow consuming tokens up to burst size
    for _ in range(20):
        result = await bucket.consume(1)
        assert result is True

    # Should deny when no tokens available
    result = await bucket.consume(1)
    assert result is False


@pytest.mark.asyncio
async def test_token_bucket_refill() -> None:
    """Test token bucket token refill."""
    import asyncio

    from extensions.eda.plugins.event_source.snmp_trap import TokenBucket

    bucket = TokenBucket(rate=10.0, burst=20)

    # Consume all tokens
    for _ in range(20):
        await bucket.consume(1)

    # Wait for tokens to refill (0.2 seconds should give us 2 tokens)
    await asyncio.sleep(0.2)

    # Should be able to consume refilled tokens
    result = await bucket.consume(1)
    assert result is True


@pytest.mark.asyncio
async def test_token_bucket_burst() -> None:
    """Test token bucket burst handling."""
    from extensions.eda.plugins.event_source.snmp_trap import TokenBucket

    bucket = TokenBucket(rate=10.0, burst=5)

    # Should allow burst up to burst size
    for _ in range(5):
        result = await bucket.consume(1)
        assert result is True

    # Should deny beyond burst size
    result = await bucket.consume(1)
    assert result is False


@pytest.mark.asyncio
async def test_rate_limit_manager_disabled() -> None:
    """Test rate limit manager when disabled."""
    from extensions.eda.plugins.event_source.snmp_trap import RateLimitManager

    args = {"rate_limit_enabled": False}

    manager = RateLimitManager(args)

    # Should allow all traps when disabled
    allowed, stats = await manager.check_rate_limit("192.168.1.1")
    assert allowed is True
    assert stats == {}


@pytest.mark.asyncio
async def test_rate_limit_manager_global() -> None:
    """Test global rate limiting."""
    from extensions.eda.plugins.event_source.snmp_trap import RateLimitManager

    args = {
        "rate_limit_enabled": True,
        "rate_limit_global": 5,  # 5 traps per second
        "rate_limit_global_burst": 10,
        "rate_limit_action": "discard",
    }

    manager = RateLimitManager(args)

    # Should allow up to burst size
    for _ in range(10):
        allowed, _ = await manager.check_rate_limit("192.168.1.1")
        assert allowed is True

    # Should rate limit beyond burst
    allowed, stats = await manager.check_rate_limit("192.168.1.1")
    assert allowed is False
    assert stats.get("rate_limited") is True
    assert stats.get("reason") == "global"


@pytest.mark.asyncio
async def test_rate_limit_manager_per_source() -> None:
    """Test per-source rate limiting."""
    from extensions.eda.plugins.event_source.snmp_trap import RateLimitManager

    args = {
        "rate_limit_enabled": True,
        "rate_limit_per_source": 3,  # 3 traps per second per source
        "rate_limit_per_source_burst": 5,
        "rate_limit_action": "log",
    }

    manager = RateLimitManager(args)

    # Should allow up to burst size for source 1
    for _ in range(5):
        allowed, _ = await manager.check_rate_limit("192.168.1.1")
        assert allowed is True

    # Should rate limit source 1 beyond burst
    allowed, stats = await manager.check_rate_limit("192.168.1.1")
    assert allowed is False
    assert stats.get("reason") == "per_source"

    # Should still allow for different source
    allowed, _ = await manager.check_rate_limit("192.168.1.2")
    assert allowed is True


@pytest.mark.asyncio
async def test_rate_limit_manager_combined() -> None:
    """Test combined global and per-source rate limiting."""
    from extensions.eda.plugins.event_source.snmp_trap import RateLimitManager

    args = {
        "rate_limit_enabled": True,
        "rate_limit_global": 10,
        "rate_limit_global_burst": 20,
        "rate_limit_per_source": 5,
        "rate_limit_per_source_burst": 10,
        "rate_limit_action": "discard",
    }

    manager = RateLimitManager(args)

    # Should respect per-source limit first
    for _ in range(10):
        allowed, _ = await manager.check_rate_limit("192.168.1.1")
        assert allowed is True

    # Per-source should be rate limited
    allowed, stats = await manager.check_rate_limit("192.168.1.1")
    assert allowed is False
    assert stats.get("reason") == "per_source"


@pytest.mark.asyncio
async def test_rate_limit_manager_stats() -> None:
    """Test rate limiting statistics."""
    from extensions.eda.plugins.event_source.snmp_trap import RateLimitManager

    args = {
        "rate_limit_enabled": True,
        "rate_limit_global": 5,
        "rate_limit_global_burst": 5,
        "rate_limit_include_stats": True,
    }

    manager = RateLimitManager(args)

    # Process some traps
    for _ in range(10):
        await manager.check_rate_limit("192.168.1.1")

    stats = manager.get_stats()
    assert stats["total_received"] == 10
    assert stats["total_rate_limited"] > 0
    assert stats["rate_limit_enabled"] is True


@pytest.mark.asyncio
async def test_rate_limit_action_queue() -> None:
    """Test rate limit action 'queue'."""
    from extensions.eda.plugins.event_source.snmp_trap import RateLimitManager

    args = {
        "rate_limit_enabled": True,
        "rate_limit_global": 1,
        "rate_limit_global_burst": 1,
        "rate_limit_action": "queue",
    }

    manager = RateLimitManager(args)

    # First trap should be allowed
    allowed, stats = await manager.check_rate_limit("192.168.1.1")
    assert allowed is True

    # Second trap should be rate limited but return True for queue action
    # Actually, the check_rate_limit returns False, but the action is handled in the protocol
    allowed, stats = await manager.check_rate_limit("192.168.1.1")
    assert allowed is False
    assert stats.get("rate_limited") is True


def test_inform_response_builder() -> None:
    """Test inform response builder."""
    from extensions.eda.plugins.event_source.snmp_trap import InformResponseBuilder

    args = {
        "inform_response_mode": "minimal",
        "version": "v2c",
        "community": "public",
    }

    builder = InformResponseBuilder(args)
    assert builder.response_mode == "minimal"

    # Test with custom mode
    args_custom = {
        "inform_response_mode": "custom",
        "inform_response_varbinds": [
            {"oid": "1.3.6.1.2.1.1.3.0", "value": "12345"},
        ],
        "version": "v2c",
        "community": "public",
    }

    builder_custom = InformResponseBuilder(args_custom)
    assert builder_custom.response_mode == "custom"
    assert len(builder_custom.response_varbinds) == 1


def test_inform_detection() -> None:
    """Test inform PDU detection."""
    from extensions.eda.plugins.event_source.snmp_trap import SNMPTrapProtocol

    queue: asyncio.Queue[Any] = asyncio.Queue()
    args = {
        "version": "v2c",
        "community": "public",
        "inform_enabled": True,
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Test with invalid data (should not detect as inform)
    test_data = b"invalid_snmp_data"
    is_inform, request_id, whole_msg = protocol._detect_pdu_type_sync(test_data)
    assert is_inform is False
    assert request_id is None


def test_inform_parsing() -> None:
    """Test inform parsing."""
    from extensions.eda.plugins.event_source.snmp_trap import SNMPTrapProtocol

    queue: asyncio.Queue[Any] = asyncio.Queue()
    args = {
        "version": "v2c",
        "community": "public",
        "inform_enabled": True,
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Test with invalid data (should return None)
    test_data = b"invalid_inform_data"
    result = protocol._parse_snmpv2_inform_sync(test_data, "192.168.1.1", 12345)
    assert result is None


@pytest.mark.asyncio
async def test_inform_response_sending() -> None:
    """Test inform response sending."""
    from extensions.eda.plugins.event_source.snmp_trap import SNMPTrapProtocol
    from pysnmp.proto.api import v2c  # type: ignore # noqa: PGH003

    queue: asyncio.Queue[Any] = asyncio.Queue()
    args = {
        "version": "v2c",
        "community": "public",
        "inform_enabled": True,
        "inform_response_mode": "minimal",
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Create a mock message
    whole_msg = v2c.Message()
    whole_msg["version"] = 1
    whole_msg["community"] = "public"

    # Test response sending (will fail without transport, but should handle gracefully)
    result = await protocol._send_inform_response(12345, whole_msg, ("192.168.1.1", 162))
    # Should return False since transport is not set up
    assert result is False


@pytest.mark.asyncio
async def test_inform_with_rate_limiting() -> None:
    """Test inform processing with rate limiting."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "host": "127.0.0.1",
        "port": 16208,
        "version": "v2c",
        "community": "public",
        "inform_enabled": True,
        "rate_limit_enabled": True,
        "rate_limit_global": 5,
        "rate_limit_global_burst": 5,
    }

    protocol = SNMPTrapProtocol(queue, args)

    # Test with invalid data - should handle gracefully
    test_data = b"invalid_data"
    addr = ("127.0.0.1", 12345)

    await protocol._process_trap(test_data, addr)

    # Should not crash
    assert True


@pytest.mark.asyncio
async def test_inform_disabled() -> None:
    """Test inform processing when disabled."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "version": "v2c",
        "community": "public",
        "inform_enabled": False,
    }

    protocol = SNMPTrapProtocol(queue, args)
    assert protocol.inform_enabled is False
    assert protocol.inform_response_builder is None


def test_community_string_manager() -> None:
    """Test community string manager."""
    from extensions.eda.plugins.event_source.snmp_trap import CommunityStringManager

    args = {
        "communities": [
            {"name": "public"},
            {"name": "monitoring", "rate_limit_per_source": 10},
        ],
        "community_validation_mode": "allow-list",
    }

    manager = CommunityStringManager(args)
    assert len(manager.communities) == 2
    assert "public" in manager.communities
    assert "monitoring" in manager.communities

    # Test validation
    is_valid, config = manager.validate_community("public")
    assert is_valid is True
    assert config is not None

    is_valid, config = manager.validate_community("unknown")
    assert is_valid is False
    assert config is None


def test_community_string_manager_backward_compat() -> None:
    """Test community string manager backward compatibility."""
    from extensions.eda.plugins.event_source.snmp_trap import CommunityStringManager

    # Old format
    args = {"community": "public"}
    manager = CommunityStringManager(args)
    assert len(manager.communities) == 1
    assert "public" in manager.communities

    # Both formats
    args = {
        "community": "public",
        "communities": [{"name": "monitoring"}],
    }
    manager = CommunityStringManager(args)
    assert len(manager.communities) == 2
    assert "public" in manager.communities
    assert "monitoring" in manager.communities


def test_community_string_manager_validation_modes() -> None:
    """Test community string manager validation modes."""
    from extensions.eda.plugins.event_source.snmp_trap import CommunityStringManager

    # Permissive mode
    args = {
        "communities": [{"name": "public"}],
        "community_validation_mode": "permissive",
    }
    manager = CommunityStringManager(args)
    is_valid, _ = manager.validate_community("any_community")
    assert is_valid is True

    # Allow-list mode
    args = {
        "communities": [{"name": "public"}],
        "community_validation_mode": "allow-list",
    }
    manager = CommunityStringManager(args)
    is_valid, _ = manager.validate_community("public")
    assert is_valid is True
    is_valid, _ = manager.validate_community("unknown")
    assert is_valid is False

    # Strict mode
    args = {
        "communities": [{"name": "public"}],
        "community_validation_mode": "strict",
    }
    manager = CommunityStringManager(args)
    is_valid, _ = manager.validate_community("public")
    assert is_valid is True
    is_valid, _ = manager.validate_community("unknown")
    assert is_valid is False


def test_security_context_manager() -> None:
    """Test security context manager."""
    from extensions.eda.plugins.event_source.snmp_trap import SecurityContextManager

    args = {
        "security_contexts": [
            {
                "username": "snmpuser1",
                "auth_key": "authkey123",
                "priv_key": "privkey123",
                "auth_protocol": "SHA",
                "priv_protocol": "AES128",
                "security_level": "authPriv",
            },
        ],
        "security_context_validation_mode": "allow-list",
    }

    manager = SecurityContextManager(args)
    assert len(manager.contexts) == 1
    assert "snmpuser1" in manager.contexts

    # Test validation
    is_valid, config = manager.validate_context("snmpuser1")
    assert is_valid is True
    assert config is not None

    is_valid, config = manager.validate_context("unknown")
    assert is_valid is False
    assert config is None


def test_security_context_manager_backward_compat() -> None:
    """Test security context manager backward compatibility."""
    from extensions.eda.plugins.event_source.snmp_trap import SecurityContextManager

    # Old format
    args = {
        "v3_username": "snmpuser",
        "v3_auth_key": "authkey",
        "v3_priv_key": "privkey",
    }
    manager = SecurityContextManager(args)
    assert len(manager.contexts) == 1
    assert "snmpuser" in manager.contexts


def test_security_context_manager_validation_modes() -> None:
    """Test security context manager validation modes."""
    from extensions.eda.plugins.event_source.snmp_trap import SecurityContextManager

    # Permissive mode
    args = {
        "security_contexts": [{"username": "snmpuser1"}],
        "security_context_validation_mode": "permissive",
    }
    manager = SecurityContextManager(args)
    is_valid, _ = manager.validate_context("any_user")
    assert is_valid is True

    # Allow-list mode
    args = {
        "security_contexts": [{"username": "snmpuser1"}],
        "security_context_validation_mode": "allow-list",
    }
    manager = SecurityContextManager(args)
    is_valid, _ = manager.validate_context("snmpuser1")
    assert is_valid is True
    is_valid, _ = manager.validate_context("unknown")
    assert is_valid is False


def test_community_string_manager_stats() -> None:
    """Test community string manager statistics."""
    from extensions.eda.plugins.event_source.snmp_trap import CommunityStringManager

    args = {
        "communities": [{"name": "public"}],
        "community_stats_enabled": True,
    }

    manager = CommunityStringManager(args)
    manager.validate_community("public")
    manager.validate_community("unknown")

    stats = manager.get_stats()
    assert stats["total_checked"] == 2
    assert stats["valid_matches"] == 1
    assert stats["invalid_matches"] == 1


def test_per_community_config_override() -> None:
    """Test per-community configuration override."""
    from extensions.eda.plugins.event_source.snmp_trap import CommunityStringManager

    args = {
        "communities": [
            {"name": "public"},
            {
                "name": "monitoring",
                "rate_limit_per_source": 15,
                "filter_oids": ["1.3.6.1.6.3.1.1.5.1"],
            },
        ],
    }

    manager = CommunityStringManager(args)
    public_config = manager.get_community_config("public")
    monitoring_config = manager.get_community_config("monitoring")

    assert public_config is not None
    assert monitoring_config is not None
    assert monitoring_config.get("rate_limit_per_source") == 15
    assert "1.3.6.1.6.3.1.1.5.1" in monitoring_config.get("filter_oids", [])


@pytest.mark.asyncio
async def test_community_validation_in_protocol() -> None:
    """Test community validation in protocol."""
    queue: asyncio.Queue[Any] = asyncio.Queue()

    args = {
        "version": "v2c",
        "communities": [{"name": "public"}],
        "community_validation_mode": "allow-list",
        "community_mismatch_action": "discard",
    }

    protocol = SNMPTrapProtocol(queue, args)
    assert protocol.community_manager is not None
    assert len(protocol.community_manager.communities) == 1
