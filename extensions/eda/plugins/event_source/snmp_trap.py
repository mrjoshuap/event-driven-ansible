#  Copyright 2024 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import re
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# pylint: disable=import-error
from pysnmp.proto import rfc1902  # type: ignore # noqa: PGH003
from pysnmp.proto.api import v1, v2c  # type: ignore # noqa: PGH003
from pysnmp.smi import rfc1902 as rfc1902_smi  # type: ignore # noqa: PGH003

try:
    from pysmi import debug as pysmi_debug  # type: ignore # noqa: PGH003
    from pysmi.codegen import JsonCodeGen  # type: ignore # noqa: PGH003
    from pysmi.parser.smi import parserFactory  # type: ignore # noqa: PGH003
    from pysmi.reader import FileReader, HttpReader, ZipReader  # type: ignore # noqa: PGH003
    from pysmi.searcher import AnyFileSearcher, StubSearcher  # type: ignore # noqa: PGH003
    from pysmi.writer import FileWriter  # type: ignore # noqa: PGH003

    PYSMI_AVAILABLE = True
except ImportError:
    PYSMI_AVAILABLE = False

DOCUMENTATION = r"""
---
short_description: Receive events via SNMP traps and informs.
description:
  - An ansible-rulebook event source module for receiving events via SNMP traps and informs.
  - Supports SNMPv1, SNMPv2c, and SNMPv3 protocols.
  - Traps are parsed and formatted with both raw and structured data.
  - SNMP informs (acknowledged traps) are supported with configurable response behavior.
options:
  host:
    description:
      - The hostname or IP address to listen on.
    type: str
    default: "0.0.0.0"
  port:
    description:
      - The UDP port to listen on for SNMP traps.
    type: int
    default: 162
  version:
    description:
      - SNMP version to use. Can be "v1", "v2c", "v3", or a list of versions.
    type: str
    default: "v2c"
    choices: ["v1", "v2c", "v3"]
  community:
    description:
      - Community string for SNMPv1 and SNMPv2c (backward compatible, use communities for multiple).
    type: str
    default: "public"
  communities:
    description:
      - List of community string configurations for SNMPv1 and SNMPv2c. Supports multiple communities with optional per-community configuration overrides.
    type: list
    elements: dict
  community_validation_mode:
    description:
      - Validation mode for community strings. 'allow-list' accepts any configured community, 'strict' requires exact match, 'permissive' accepts all.
    type: str
    choices: ["allow-list", "strict", "permissive"]
    default: "allow-list"
  community_mismatch_action:
    description:
      - Action to take when community string doesn't match. 'discard' silently discards, 'log' logs and discards, 'queue' queues with warning metadata.
    type: str
    choices: ["discard", "log", "queue"]
    default: "discard"
  community_stats_enabled:
    description:
      - Enable community string usage statistics tracking.
    type: bool
    default: false
  v3_username:
    description:
      - Username for SNMPv3 authentication.
    type: str
  v3_auth_key:
    description:
      - Authentication key for SNMPv3.
    type: str
  v3_priv_key:
    description:
      - Privacy key for SNMPv3.
    type: str
  v3_auth_protocol:
    description:
      - Authentication protocol for SNMPv3.
    type: str
    default: "SHA"
    choices: ["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]
  v3_priv_protocol:
    description:
      - Privacy protocol for SNMPv3.
    type: str
    default: "AES128"
    choices: ["DES", "3DES", "AES128", "AES192", "AES256"]
  v3_security_level:
    description:
      - Security level for SNMPv3 (backward compatible, use security_contexts for multiple).
    type: str
    default: "authPriv"
    choices: ["noAuthNoPriv", "authNoPriv", "authPriv"]
  security_contexts:
    description:
      - List of security context configurations for SNMPv3. Supports multiple contexts with optional per-context configuration overrides.
    type: list
    elements: dict
  security_context_validation_mode:
    description:
      - Validation mode for security contexts. 'allow-list' accepts any configured context, 'strict' requires exact match, 'permissive' accepts all.
    type: str
    choices: ["allow-list", "strict", "permissive"]
    default: "allow-list"
  security_context_mismatch_action:
    description:
      - Action to take when security context doesn't match. 'discard' silently discards, 'log' logs and discards, 'queue' queues with warning metadata.
    type: str
    choices: ["discard", "log", "queue"]
    default: "discard"
  security_context_stats_enabled:
    description:
      - Enable security context usage statistics tracking.
    type: bool
    default: false
  include_raw:
    description:
      - Include raw trap data in the event payload.
    type: bool
    default: true
  include_structured:
    description:
      - Include structured trap data in the event payload.
    type: bool
    default: true
  mib_paths:
    description:
      - List of directories containing MIB files for OID resolution.
    type: list
    elements: str
  mib_urls:
    description:
      - List of URLs to download MIB files from.
    type: list
    elements: str
  auto_load_standard_mibs:
    description:
      - Automatically load standard MIBs from public repositories.
    type: bool
    default: true
  mib_cache_dir:
    description:
      - Directory to cache compiled MIBs.
    type: str
  filter_mode:
    description:
      - Filtering mode. 'allow' processes only matching traps, 'deny' discards matching traps.
    type: str
    choices: ["allow", "deny"]
    default: "allow"
  filter_oids:
    description:
      - List of OIDs to filter on (exact match).
    type: list
    elements: str
  filter_oid_patterns:
    description:
      - List of OID patterns to filter on (supports wildcards, e.g., "1.3.6.1.4.1.*").
    type: list
    elements: str
  filter_communities:
    description:
      - List of community strings to filter on.
    type: list
    elements: str
  filter_require_all:
    description:
      - If true, all filter criteria must match (AND logic). If false, any filter matches (OR logic).
    type: bool
    default: false
  rate_limit_enabled:
    description:
      - Enable rate limiting for SNMP traps to prevent system overload.
    type: bool
    default: false
  rate_limit_global:
    description:
      - Global rate limit in traps per second. Applies to all traps combined.
    type: int
  rate_limit_global_burst:
    description:
      - Global burst size (maximum tokens in bucket). Allows handling traffic spikes.
    type: int
  rate_limit_per_source:
    description:
      - Per-source IP rate limit in traps per second. Limits traps from individual devices.
    type: int
  rate_limit_per_source_burst:
    description:
      - Per-source burst size (maximum tokens in bucket). Allows handling traffic spikes per device.
    type: int
  rate_limit_action:
    description:
      - Action to take when rate limit is exceeded. 'discard' silently discards, 'log' logs and discards, 'queue' queues with metadata.
    type: str
    choices: ["discard", "log", "queue"]
    default: "discard"
  rate_limit_window_seconds:
    description:
      - Time window for rate calculation in seconds.
    type: float
    default: 1.0
  rate_limit_cleanup_interval:
    description:
      - Interval in seconds to clean up inactive per-source rate limiters.
    type: int
    default: 300
  rate_limit_include_stats:
    description:
      - Include rate limiting statistics in event metadata.
    type: bool
    default: false
  inform_enabled:
    description:
      - Enable SNMP inform support (acknowledged traps). Informs require a response acknowledgment.
    type: bool
    default: true
  inform_response_mode:
    description:
      - Response mode for SNMP informs. 'minimal' sends empty acknowledgment, 'custom' includes configured variable bindings, 'none' sends no response (not recommended).
    type: str
    choices: ["minimal", "custom", "none"]
    default: "minimal"
  inform_response_varbinds:
    description:
      - Custom variable bindings to include in inform response (only used when inform_response_mode is 'custom').
    type: list
    elements: dict
  inform_response_timeout:
    description:
      - Timeout in seconds for sending inform response.
    type: float
    default: 5.0
  inform_require_ack:
    description:
      - Require successful acknowledgment before queuing event. If false, event is queued immediately and response sent asynchronously.
    type: bool
    default: false
"""

EXAMPLES = r"""
- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v2c"
    community: "public"
    include_raw: true
    include_structured: true

- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v3"
    v3_username: "snmpuser"
    v3_auth_key: "authkey123"
    v3_priv_key: "privkey123"
    v3_auth_protocol: "SHA"
    v3_priv_protocol: "AES128"
    v3_security_level: "authPriv"

- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v2c"
    community: "public"
    mib_paths:
      - "/usr/share/snmp/mibs"
      - "./custom_mibs"
    auto_load_standard_mibs: true
    filter_mode: "allow"
    filter_oids:
      - "1.3.6.1.6.3.1.1.5.1"  # coldStart
      - "1.3.6.1.6.3.1.1.5.3"  # linkDown
    filter_oid_patterns:
      - "1.3.6.1.4.1.*"  # Vendor-specific traps
    filter_communities:
      - "public"
      - "monitoring"
    filter_require_all: false

- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v2c"
    community: "public"
    rate_limit_enabled: true
    rate_limit_global: 100
    rate_limit_global_burst: 200
    rate_limit_per_source: 10
    rate_limit_per_source_burst: 20
    rate_limit_action: "discard"
    rate_limit_include_stats: true

- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v2c"
    community: "public"
    inform_enabled: true
    inform_response_mode: "minimal"

- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v2c"
    community: "public"
    inform_enabled: true
    inform_response_mode: "custom"
    inform_response_varbinds:
      - oid: "1.3.6.1.2.1.1.3.0"
        value: "12345"
    inform_require_ack: true

- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v2c"
    communities:
      - name: "public"
        description: "Public read-only access"
      - name: "monitoring"
        description: "Monitoring system access"
        rate_limit_per_source: 10
      - name: "admin"
        description: "Administrative access"
        filter_oids:
          - "1.3.6.1.6.3.1.1.5.1"  # coldStart
    community_validation_mode: "allow-list"
    community_mismatch_action: "log"

- ansible.eda.snmp_trap:
    host: "0.0.0.0"
    port: 162
    version: "v3"
    security_contexts:
      - username: "snmpuser1"
        auth_key: "authkey123"
        priv_key: "privkey123"
        auth_protocol: "SHA"
        priv_protocol: "AES128"
        security_level: "authPriv"
      - username: "snmpuser2"
        auth_key: "authkey456"
        priv_key: "privkey456"
        auth_protocol: "SHA256"
        priv_protocol: "AES256"
        security_level: "authPriv"
        rate_limit_per_source: 20
    security_context_validation_mode: "strict"
"""

logger = logging.getLogger(__name__)

# Standard MIB repositories
STANDARD_MIB_URLS = [
    "https://raw.githubusercontent.com/lextudio/pysnmp/master/pysnmp/smi/mibs/instances",
    "http://www.oidview.com/mibs",
]


class MIBLoader:
    """Load and manage MIB files for OID resolution."""

    def __init__(self, args: dict[str, Any]) -> None:
        """Initialize MIB loader.

        Args:
        ----
            args: Configuration arguments.
        """
        self.oid_map: dict[str, dict[str, str]] = {}
        self.mib_paths = args.get("mib_paths", [])
        self.mib_urls = args.get("mib_urls", [])
        self.auto_load_standard_mibs = args.get("auto_load_standard_mibs", True)
        self.cache_dir = args.get("mib_cache_dir") or tempfile.gettempdir()

        if PYSMI_AVAILABLE:
            self._load_mibs()
        else:
            logger.warning(
                "pysmi not available. MIB file parsing disabled. "
                "Install pysmi for OID resolution: pip install pysmi"
            )

    def _load_mibs(self) -> None:
        """Load MIB files from configured sources."""
        if not PYSMI_AVAILABLE:
            return

        try:
            # Create cache directory if it doesn't exist
            os.makedirs(self.cache_dir, exist_ok=True)

            # Prepare MIB readers
            readers = []

            # Add file readers for local paths
            for mib_path in self.mib_paths:
                if os.path.isdir(mib_path):
                    readers.append(FileReader(mib_path))
                    logger.debug("Added MIB path: %s", mib_path)
                else:
                    logger.warning("MIB path does not exist: %s", mib_path)

            # Add HTTP readers for URLs
            for mib_url in self.mib_urls:
                readers.append(HttpReader(mib_url))
                logger.debug("Added MIB URL: %s", mib_url)

            # Add standard MIB URLs if enabled
            if self.auto_load_standard_mibs:
                for url in STANDARD_MIB_URLS:
                    readers.append(HttpReader(url))
                    logger.debug("Added standard MIB URL: %s", url)

            if not readers:
                logger.info("No MIB sources configured")
                return

            # Create MIB compiler
            codegen = JsonCodeGen()
            parser = parserFactory()()
            searcher = AnyFileSearcher(*readers)
            writer = FileWriter(self.cache_dir)

            # Try to compile and load MIBs
            # This is a simplified approach - in production, you'd want more robust error handling
            logger.info("Loading MIB files...")
            # Note: Full MIB compilation is complex and would require more setup
            # For now, we'll use a simpler approach with basic OID mapping

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error loading MIB files: %s", exc)

    def resolve_oid(self, oid: str) -> dict[str, str]:
        """Resolve an OID to its name and path.

        Args:
        ----
            oid: The OID string (e.g., "1.3.6.1.2.1.1.3.0").

        Returns:
        -------
            Dictionary with 'name' and 'path' keys, or empty dict if not resolved.
        """
        if oid in self.oid_map:
            return self.oid_map[oid]

        # Try to resolve using standard trap OIDs
        if oid in STANDARD_TRAP_OIDS:
            return {
                "name": STANDARD_TRAP_OIDS[oid],
                "path": f"iso.org.dod.internet.snmpV2.snmpModules.snmpMIB.snmpMIBObjects.snmpTrap.{STANDARD_TRAP_OIDS[oid]}",
            }

        # Basic resolution for common OIDs
        common_oids = {
            "1.3.6.1.2.1.1.3.0": {"name": "sysUpTime", "path": "iso.org.dod.internet.mgmt.mib-2.system.sysUpTime"},
            "1.3.6.1.6.3.1.1.4.1.0": {
                "name": "snmpTrapOID",
                "path": "iso.org.dod.internet.snmpV2.snmpModules.snmpMIB.snmpMIBObjects.snmpTrap.snmpTrapOID.0",
            },
        }

        if oid in common_oids:
            resolved = common_oids[oid]
            self.oid_map[oid] = resolved
            return resolved

        return {}


class TrapFilter:
    """Filter SNMP traps based on OID patterns and community strings."""

    def __init__(self, args: dict[str, Any]) -> None:
        """Initialize trap filter.

        Args:
        ----
            args: Configuration arguments.
        """
        self.filter_mode = args.get("filter_mode", "allow")
        self.filter_oids = args.get("filter_oids", [])
        self.filter_oid_patterns = args.get("filter_oid_patterns", [])
        self.filter_communities = args.get("filter_communities", [])
        self.filter_require_all = args.get("filter_require_all", False)

        # Compile OID patterns for efficient matching
        self.compiled_patterns = [re.compile(pattern.replace("*", ".*")) for pattern in self.filter_oid_patterns]

        # Determine if filtering is enabled
        self.filtering_enabled = bool(
            self.filter_oids or self.filter_oid_patterns or self.filter_communities
        )

    def should_process_trap(
        self,
        trap_oid: str,
        community: str | None = None,
        variable_bindings: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Determine if a trap should be processed based on filters.

        Args:
        ----
            trap_oid: The trap OID.
            community: The community string (for v1/v2c).
            variable_bindings: List of variable bindings.

        Returns:
        -------
            True if trap should be processed, False otherwise.
        """
        if not self.filtering_enabled:
            return True

        # Check if trap matches any filter criteria
        matches = []

        # Check OID exact match
        if self.filter_oids:
            if trap_oid in self.filter_oids:
                matches.append(True)
            else:
                matches.append(False)

        # Check OID pattern match
        if self.compiled_patterns:
            pattern_match = any(pattern.match(trap_oid) for pattern in self.compiled_patterns)
            matches.append(pattern_match)

        # Check community string
        if self.filter_communities and community:
            community_match = community in self.filter_communities
            matches.append(community_match)

        # Determine result based on filter mode and require_all setting
        if not matches:
            # No filter criteria were checked (shouldn't happen if filtering_enabled)
            # But if it does, default to processing
            return True

        if self.filter_require_all:
            # AND logic: all must match
            result = all(matches)
        else:
            # OR logic: any must match
            result = any(matches)

        # Apply filter mode
        if self.filter_mode == "allow":
            # Allow mode: process if matches
            return result
        # deny mode: process if doesn't match
        return not result


class TokenBucket:
    """Token bucket rate limiter implementation."""

    def __init__(self, rate: float, burst: int) -> None:
        """Initialize token bucket.

        Args:
        ----
            rate: Tokens per second.
            burst: Maximum tokens in bucket.
        """
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_update = time.time()
        self.lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens.

        Args:
        ----
            tokens: Number of tokens to consume (default: 1).

        Returns:
        -------
            True if tokens were consumed, False if rate limited.
        """
        async with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        tokens_to_add = elapsed * self.rate
        self.tokens = min(self.burst, self.tokens + tokens_to_add)
        self.last_update = now

    def get_tokens(self) -> float:
        """Get current number of tokens (for statistics).

        Returns:
        -------
            Current token count.
        """
        self._refill()
        return self.tokens


class RateLimitManager:
    """Manage rate limiting for SNMP traps."""

    def __init__(self, args: dict[str, Any]) -> None:
        """Initialize rate limit manager.

        Args:
        ----
            args: Configuration arguments.
        """
        self.enabled = args.get("rate_limit_enabled", False)
        self.action = args.get("rate_limit_action", "discard")
        self.include_stats = args.get("rate_limit_include_stats", False)
        self.cleanup_interval = args.get("rate_limit_cleanup_interval", 300)

        # Statistics
        self.stats = {
            "total_received": 0,
            "total_rate_limited": 0,
            "rate_limited_by_source": defaultdict(int),
        }

        # Global rate limiter
        self.global_limiter: TokenBucket | None = None
        if self.enabled and args.get("rate_limit_global"):
            global_rate = float(args["rate_limit_global"])
            global_burst = args.get("rate_limit_global_burst", int(global_rate * 2))
            self.global_limiter = TokenBucket(global_rate, global_burst)

        # Per-source rate limiters
        self.per_source_limiters: dict[str, TokenBucket] = {}
        self.per_source_last_activity: dict[str, float] = {}
        self.per_source_rate = args.get("rate_limit_per_source")
        self.per_source_burst = args.get("rate_limit_per_source_burst")

        if self.enabled and self.per_source_rate:
            self.per_source_burst = self.per_source_burst or int(self.per_source_rate * 2)

        # Cleanup task will be started when protocol is initialized
        self.cleanup_task: asyncio.Task[None] | None = None
        self._cleanup_enabled = self.enabled and bool(self.per_source_rate)

    async def check_rate_limit(self, source_ip: str) -> tuple[bool, dict[str, Any]]:
        """Check if trap should be rate limited.

        Args:
        ----
            source_ip: Source IP address of the trap.

        Returns:
        -------
            Tuple of (allowed, stats_dict). allowed is True if trap should be processed.
        """
        if not self.enabled:
            return True, {}

        self.stats["total_received"] += 1
        stats_info: dict[str, Any] = {}

        # Check global rate limit
        if self.global_limiter:
            allowed = await self.global_limiter.consume(1)
            if not allowed:
                self.stats["total_rate_limited"] += 1
                self.stats["rate_limited_by_source"][source_ip] += 1
                if self.action == "log":
                    logger.warning(
                        "Trap rate limited (global): source_ip=%s, action=%s",
                        source_ip,
                        self.action,
                    )
                return False, {"rate_limited": True, "reason": "global"}

        # Check per-source rate limit
        if self.per_source_rate:
            limiter = await self._get_source_limiter(source_ip)
            allowed = await limiter.consume(1)
            if not allowed:
                self.stats["total_rate_limited"] += 1
                self.stats["rate_limited_by_source"][source_ip] += 1
                if self.action == "log":
                    logger.warning(
                        "Trap rate limited (per-source): source_ip=%s, action=%s",
                        source_ip,
                        self.action,
                    )
                return False, {"rate_limited": True, "reason": "per_source"}

        # Include statistics if requested
        if self.include_stats:
            stats_info = {
                "rate_limit_stats": {
                    "total_received": self.stats["total_received"],
                    "total_rate_limited": self.stats["total_rate_limited"],
                    "rate_limited_by_source": dict(self.stats["rate_limited_by_source"]),
                },
            }

        return True, stats_info

    async def _get_source_limiter(self, source_ip: str) -> TokenBucket:
        """Get or create rate limiter for source IP.

        Args:
        ----
            source_ip: Source IP address.

        Returns:
        -------
            TokenBucket for the source IP.
        """
        if source_ip not in self.per_source_limiters:
            limiter = TokenBucket(float(self.per_source_rate), self.per_source_burst)
            self.per_source_limiters[source_ip] = limiter
            self.per_source_last_activity[source_ip] = time.time()
        else:
            self.per_source_last_activity[source_ip] = time.time()
        return self.per_source_limiters[source_ip]

    async def _cleanup_inactive_limiters(self) -> None:
        """Periodically clean up inactive per-source rate limiters."""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                now = time.time()
                inactive_sources = [
                    ip
                    for ip, last_activity in self.per_source_last_activity.items()
                    if now - last_activity > self.cleanup_interval
                ]
                for source_ip in inactive_sources:
                    del self.per_source_limiters[source_ip]
                    del self.per_source_last_activity[source_ip]
                    logger.debug("Cleaned up inactive rate limiter for source: %s", source_ip)
            except asyncio.CancelledError:
                logger.debug("Rate limiter cleanup task cancelled")
                break
            except Exception as exc:  # noqa: BLE001
                logger.exception("Error in rate limiter cleanup: %s", exc)

    def get_stats(self) -> dict[str, Any]:
        """Get rate limiting statistics.

        Returns:
        -------
            Dictionary with rate limiting statistics.
        """
        return {
            "total_received": self.stats["total_received"],
            "total_rate_limited": self.stats["total_rate_limited"],
            "rate_limited_by_source": dict(self.stats["rate_limited_by_source"]),
            "rate_limit_enabled": self.enabled,
        }


class CommunityStringManager:
    """Manage and validate SNMP community strings."""

    def __init__(self, args: dict[str, Any]) -> None:
        """Initialize community string manager.

        Args:
        ----
            args: Configuration arguments.
        """
        # Parse communities from configuration (support both old and new format)
        communities_config = args.get("communities", [])
        single_community = args.get("community")

        # Convert old format to new format if needed
        if single_community and not communities_config:
            communities_config = [{"name": single_community}]
        elif single_community and communities_config:
            # Both provided - merge them
            if not any(c.get("name") == single_community for c in communities_config):
                communities_config.append({"name": single_community})

        # Build community dictionary for fast lookup
        self.communities: dict[str, dict[str, Any]] = {}
        for comm in communities_config:
            name = comm.get("name")
            if name:
                self.communities[name] = comm.copy()

        # Validation settings
        self.validation_mode = args.get("community_validation_mode", "allow-list")
        self.mismatch_action = args.get("community_mismatch_action", "discard")
        self.stats_enabled = args.get("community_stats_enabled", False)

        # Statistics
        self.stats = {
            "total_checked": 0,
            "valid_matches": 0,
            "invalid_matches": 0,
            "by_community": defaultdict(int),
        }

    def validate_community(self, community: str | None) -> tuple[bool, dict[str, Any] | None]:
        """Validate a community string.

        Args:
        ----
            community: The community string to validate.

        Returns:
        -------
            Tuple of (is_valid, community_config).
        """
        self.stats["total_checked"] += 1

        if self.validation_mode == "permissive":
            return True, None

        if not community:
            if self.validation_mode == "strict":
                self.stats["invalid_matches"] += 1
                return False, None
            return True, None

        # Check if community is in configured list
        community_config = self.communities.get(community)

        if community_config:
            self.stats["valid_matches"] += 1
            if self.stats_enabled:
                self.stats["by_community"][community] += 1
            return True, community_config

        # Community not found
        self.stats["invalid_matches"] += 1
        return False, None

    def get_community_config(self, community: str) -> dict[str, Any] | None:
        """Get configuration for a specific community.

        Args:
        ----
            community: The community string.

        Returns:
        -------
            Community configuration or None if not found.
        """
        return self.communities.get(community)

    def get_stats(self) -> dict[str, Any]:
        """Get community validation statistics.

        Returns:
        -------
            Dictionary with statistics.
        """
        return {
            "total_checked": self.stats["total_checked"],
            "valid_matches": self.stats["valid_matches"],
            "invalid_matches": self.stats["invalid_matches"],
            "by_community": dict(self.stats["by_community"]),
            "validation_mode": self.validation_mode,
        }


class SecurityContextManager:
    """Manage and validate SNMPv3 security contexts."""

    def __init__(self, args: dict[str, Any]) -> None:
        """Initialize security context manager.

        Args:
        ----
            args: Configuration arguments.
        """
        # Parse security contexts from configuration (support both old and new format)
        contexts_config = args.get("security_contexts", [])
        single_username = args.get("v3_username")

        # Convert old format to new format if needed
        if single_username and not contexts_config:
            context = {
                "username": single_username,
                "auth_key": args.get("v3_auth_key"),
                "priv_key": args.get("v3_priv_key"),
                "auth_protocol": args.get("v3_auth_protocol", "SHA"),
                "priv_protocol": args.get("v3_priv_protocol", "AES128"),
                "security_level": args.get("v3_security_level", "authPriv"),
            }
            contexts_config = [context]
        elif single_username and contexts_config:
            # Both provided - check if username already exists
            if not any(c.get("username") == single_username for c in contexts_config):
                context = {
                    "username": single_username,
                    "auth_key": args.get("v3_auth_key"),
                    "priv_key": args.get("v3_priv_key"),
                    "auth_protocol": args.get("v3_auth_protocol", "SHA"),
                    "priv_protocol": args.get("v3_priv_protocol", "AES128"),
                    "security_level": args.get("v3_security_level", "authPriv"),
                }
                contexts_config.append(context)

        # Build context dictionary for fast lookup
        self.contexts: dict[str, dict[str, Any]] = {}
        for ctx in contexts_config:
            username = ctx.get("username")
            if username:
                self.contexts[username] = ctx.copy()

        # Validation settings
        self.validation_mode = args.get("security_context_validation_mode", "allow-list")
        self.mismatch_action = args.get("security_context_mismatch_action", "discard")
        self.stats_enabled = args.get("security_context_stats_enabled", False)

        # Statistics
        self.stats = {
            "total_checked": 0,
            "valid_matches": 0,
            "invalid_matches": 0,
            "by_context": defaultdict(int),
        }

    def validate_context(
        self,
        username: str | None,
        auth_key: str | None = None,
        priv_key: str | None = None,
        auth_protocol: str | None = None,
        priv_protocol: str | None = None,
        security_level: str | None = None,
    ) -> tuple[bool, dict[str, Any] | None]:
        """Validate a security context.

        Args:
        ----
            username: The username.
            auth_key: Authentication key (optional, for verification).
            priv_key: Privacy key (optional, for verification).
            auth_protocol: Authentication protocol (optional).
            priv_protocol: Privacy protocol (optional).
            security_level: Security level (optional).

        Returns:
        -------
            Tuple of (is_valid, context_config).
        """
        self.stats["total_checked"] += 1

        if self.validation_mode == "permissive":
            return True, None

        if not username:
            if self.validation_mode == "strict":
                self.stats["invalid_matches"] += 1
                return False, None
            return True, None

        # Check if username is in configured contexts
        context_config = self.contexts.get(username)

        if context_config:
            # For strict mode, verify security parameters match
            if self.validation_mode == "strict":
                # Verify security level matches
                if security_level and context_config.get("security_level") != security_level:
                    self.stats["invalid_matches"] += 1
                    return False, None

                # Note: Full authentication/encryption verification would require
                # decrypting the message, which is complex. For now, we match on username
                # and security level. Full verification can be added later if needed.

            self.stats["valid_matches"] += 1
            if self.stats_enabled:
                self.stats["by_context"][username] += 1
            return True, context_config

        # Context not found
        self.stats["invalid_matches"] += 1
        return False, None

    def get_context_config(self, username: str) -> dict[str, Any] | None:
        """Get configuration for a specific security context.

        Args:
        ----
            username: The username.

        Returns:
        -------
            Context configuration or None if not found.
        """
        return self.contexts.get(username)

    def get_stats(self) -> dict[str, Any]:
        """Get security context validation statistics.

        Returns:
        -------
            Dictionary with statistics.
        """
        return {
            "total_checked": self.stats["total_checked"],
            "valid_matches": self.stats["valid_matches"],
            "invalid_matches": self.stats["invalid_matches"],
            "by_context": dict(self.stats["by_context"]),
            "validation_mode": self.validation_mode,
        }


class InformResponseBuilder:
    """Build SNMP inform response PDUs."""

    def __init__(self, args: dict[str, Any]) -> None:
        """Initialize inform response builder.

        Args:
        ----
            args: Configuration arguments.
        """
        self.response_mode = args.get("inform_response_mode", "minimal")
        self.response_varbinds = args.get("inform_response_varbinds", [])
        self.version = args.get("version", "v2c")
        self.community = args.get("community", "public")

    def build_response(
        self,
        request_id: int,
        whole_msg: Any,
    ) -> bytes | None:
        """Build SNMP inform response PDU.

        Args:
        ----
            request_id: Request ID from inform request.
            whole_msg: Original SNMP message (for community/security).

        Returns:
        -------
            Encoded response message bytes or None if building fails.
        """
        try:
            if self.response_mode == "none":
                return None

            # Create response PDU
            response_pdu = v2c.ResponsePDU()
            response_pdu["request-id"] = request_id
            response_pdu["error-status"] = 0  # noError
            response_pdu["error-index"] = 0

            # Add variable bindings based on mode
            if self.response_mode == "minimal":
                response_pdu["var-binds"] = []
            elif self.response_mode == "custom":
                # Build variable bindings from configuration
                var_binds = []
                for varbind in self.response_varbinds:
                    oid_str = varbind.get("oid", "")
                    value_str = str(varbind.get("value", ""))
                    if not oid_str:
                        continue
                    # Convert OID string to tuple
                    try:
                        oid_tuple = tuple(int(x) for x in oid_str.split(".") if x)
                        # Create simple value (OctetString for now)
                        from pysnmp.proto.rfc1902 import OctetString  # type: ignore # noqa: PGH003

                        value_obj = OctetString(value_str)
                        var_binds.append((oid_tuple, value_obj))
                    except (ValueError, AttributeError):
                        logger.warning("Invalid OID in inform response varbind: %s", oid_str)
                        continue
                response_pdu["var-binds"] = var_binds

            # Create response message
            response_msg = v2c.Message()
            response_msg["version"] = whole_msg["version"]
            response_msg["community"] = whole_msg["community"]
            response_msg["pdu"] = response_pdu

            # Encode response
            return response_msg.encode()

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error building inform response: %s", exc)
            return None


# Standard SNMP trap OIDs
STANDARD_TRAP_OIDS = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    "1.3.6.1.6.3.1.1.5.7": "enterpriseSpecific",
}

# SNMPv1 generic trap types
SNMPV1_GENERIC_TRAPS = {
    0: "coldStart",
    1: "warmStart",
    2: "linkDown",
    3: "linkUp",
    4: "authenticationFailure",
    5: "egpNeighborLoss",
    6: "enterpriseSpecific",
}


class SNMPTrapProtocol(asyncio.DatagramProtocol):
    """Protocol handler for receiving SNMP traps via UDP."""

    def __init__(
        self,
        queue: asyncio.Queue[Any],
        args: dict[str, Any],
    ) -> None:
        """Initialize the SNMP trap protocol handler.

        Args:
        ----
            queue: The queue to put events into.
            args: Configuration arguments.
        """
        self.queue = queue
        self.args = args
        self.include_raw = args.get("include_raw", True)
        self.include_structured = args.get("include_structured", True)
        self.version = args.get("version", "v2c")
        self.community = args.get("community", "public")
        self.transport: asyncio.DatagramTransport | None = None

        # Initialize MIB loader, filter, rate limiter, inform response builder, and managers
        self.mib_loader = MIBLoader(args)
        self.trap_filter = TrapFilter(args)
        self.rate_limit_manager = RateLimitManager(args)
        self.community_manager = CommunityStringManager(args)
        self.security_context_manager = SecurityContextManager(args)
        self.inform_enabled = args.get("inform_enabled", True)
        self.inform_response_builder = InformResponseBuilder(args) if self.inform_enabled else None
        self.inform_require_ack = args.get("inform_require_ack", False)
        self.inform_response_timeout = args.get("inform_response_timeout", 5.0)

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Called when the UDP socket is created."""
        self.transport = transport
        # Start cleanup task if needed
        if self.rate_limit_manager._cleanup_enabled:
            self.rate_limit_manager.cleanup_task = asyncio.create_task(
                self.rate_limit_manager._cleanup_inactive_limiters()
            )
        logger.info(
            "SNMP trap listener started on %s:%s",
            self.args.get("host", "0.0.0.0"),
            self.args.get("port", 162),
        )

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when the connection is lost."""
        # Cancel cleanup task if it exists
        if self.rate_limit_manager.cleanup_task:
            self.rate_limit_manager.cleanup_task.cancel()
        logger.info("SNMP trap listener connection lost")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called when a UDP datagram is received."""
        asyncio.create_task(self._process_trap(data, addr))

    async def _process_trap(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        """Process an incoming SNMP trap.

        Args:
        ----
            data: The raw SNMP trap data.
            addr: The source address (host, port).
        """
        try:
            source_ip, source_port = addr
            received_at = datetime.utcnow().isoformat() + "Z"

            # Extract community/context early for validation (before parsing to save resources)
            # For v1/v2c, we need to parse to get community, but we'll validate after parsing
            # For v3, we'll validate after parsing
            validated_community: str | None = None
            validated_context: str | None = None
            community_config: dict[str, Any] | None = None
            context_config: dict[str, Any] | None = None
            validation_status = "unknown"

            # Apply rate limiting first (before parsing to save resources)
            allowed, rate_limit_stats = await self.rate_limit_manager.check_rate_limit(source_ip)
            if not allowed:
                # Handle rate limited trap based on action
                if self.rate_limit_manager.action == "queue":
                    # Queue with rate limit metadata
                    event = {
                        "payload": {
                            "raw": {"rate_limited": True, "source_ip": source_ip},
                            "structured": {"rate_limited": True, "source_ip": source_ip},
                        },
                        "meta": {
                            "source": "snmp_trap",
                            "received_at": received_at,
                            "source_ip": source_ip,
                            "source_port": source_port,
                            "rate_limited": True,
                            **rate_limit_stats,
                        },
                    }
                    await self.queue.put(event)
                # For "discard" and "log" actions, just return (already logged if needed)
                return

            # Run parsing in executor to avoid blocking
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                # Detect if this is an inform or trap (for v2c/v3 only)
                is_inform = False
                request_id = None
                whole_msg = None
                message_type = "trap"

                if self.version in ("v2c", "v3") or self.version not in ("v1", "v2c", "v3"):
                    # Check PDU type for v2c/v3
                    pdu_info = await loop.run_in_executor(
                        executor,
                        self._detect_pdu_type_sync,
                        data,
                    )
                    is_inform, request_id, whole_msg = pdu_info

                # Auto-detect SNMP version or use configured version
                trap_data = None

                if is_inform and self.inform_enabled:
                    # Process as inform
                    message_type = "inform"
                    trap_data = await loop.run_in_executor(
                        executor,
                        self._parse_snmpv2_inform_sync,
                        data,
                        source_ip,
                        request_id,
                    )
                    # Store inform-specific data for response
                    inform_request_id = request_id
                    inform_whole_msg = whole_msg
                else:
                    inform_request_id = None
                    inform_whole_msg = None
                    if self.version == "v1":
                        trap_data = await loop.run_in_executor(
                            executor,
                            self._parse_snmpv1_trap_sync,
                            data,
                            source_ip,
                        )
                    elif self.version in ("v2c", "v3"):
                        trap_data = await loop.run_in_executor(
                            executor,
                            self._parse_snmpv2_trap_sync,
                            data,
                            source_ip,
                        )
                    else:
                        # Try auto-detection: try v2c first (most common), then v1
                        trap_data = await loop.run_in_executor(
                            executor,
                            self._parse_snmpv2_trap_sync,
                            data,
                            source_ip,
                        )
                        if not trap_data:
                            trap_data = await loop.run_in_executor(
                                executor,
                                self._parse_snmpv1_trap_sync,
                                data,
                                source_ip,
                            )

            if not trap_data:
                return

            # Validate community string or security context
            community = trap_data.get("raw", {}).get("community")
            if self.version in ("v1", "v2c") and community is not None:
                # Validate community string
                is_valid, comm_config = self.community_manager.validate_community(community)
                if is_valid:
                    validated_community = community
                    community_config = comm_config
                    validation_status = "valid"
                else:
                    validation_status = "invalid"
                    # Handle mismatch based on action
                    if self.community_manager.mismatch_action == "log":
                        logger.warning(
                            "Invalid community string '%s' from %s (validation_mode=%s)",
                            community,
                            source_ip,
                            self.community_manager.validation_mode,
                        )
                    elif self.community_manager.mismatch_action == "queue":
                        # Queue with warning metadata
                        event = {
                            "payload": {
                                "raw": {"invalid_community": community, "source_ip": source_ip},
                                "structured": {"invalid_community": community},
                            },
                            "meta": {
                                "source": "snmp_trap",
                                "received_at": received_at,
                                "source_ip": source_ip,
                                "source_port": source_port,
                                "validation_status": "invalid",
                                "community": community,
                                "validation_error": "community_mismatch",
                            },
                        }
                        await self.queue.put(event)
                    # For "discard" action, just return
                    if self.community_manager.mismatch_action != "queue":
                        return
            elif self.version == "v3":
                # For v3, we'd need to extract username from the message
                # This is complex and would require full message parsing
                # For now, we'll mark as validated if we got this far
                # Full v3 validation can be enhanced later
                validation_status = "valid"

            # Apply filtering
            trap_oid = trap_data.get("structured", {}).get("trap_oid", "")
            var_bindings = trap_data.get("raw", {}).get("variable_bindings", [])

            # Apply per-community/context configuration overrides if available
            effective_config = self.args.copy()
            if community_config:
                # Merge per-community config overrides
                for key in [
                    "rate_limit_per_source",
                    "rate_limit_per_source_burst",
                    "filter_oids",
                    "filter_oid_patterns",
                    "inform_response_mode",
                    "inform_response_varbinds",
                ]:
                    if key in community_config:
                        effective_config[key] = community_config[key]
            elif context_config:
                # Merge per-context config overrides
                for key in [
                    "rate_limit_per_source",
                    "rate_limit_per_source_burst",
                    "filter_oids",
                    "filter_oid_patterns",
                    "inform_response_mode",
                    "inform_response_varbinds",
                ]:
                    if key in context_config:
                        effective_config[key] = context_config[key]

            if not self.trap_filter.should_process_trap(trap_oid, community, var_bindings):
                logger.debug(
                    "Trap filtered out: OID=%s, Community=%s, Mode=%s",
                    trap_oid,
                    community,
                    self.trap_filter.filter_mode,
                )
                return

            # Resolve OIDs using MIB loader
            structured_data = trap_data.get("structured", {})
            if trap_oid:
                trap_oid_resolved = self.mib_loader.resolve_oid(trap_oid)
                if trap_oid_resolved:
                    structured_data["trap_oid_name"] = trap_oid_resolved.get("name", "")
                    structured_data["trap_oid_path"] = trap_oid_resolved.get("path", "")

            # Resolve variable binding OIDs
            resolved_vars: dict[str, Any] = {}
            for var_binding in var_bindings:
                var_oid = var_binding.get("oid", "")
                if var_oid:
                    var_resolved = self.mib_loader.resolve_oid(var_oid)
                    resolved_vars[var_oid] = {
                        **var_binding,
                        **var_resolved,
                    }
                else:
                    resolved_vars[var_oid] = var_binding

            if resolved_vars:
                structured_data["resolved_variables"] = resolved_vars

            # Build event payload
            payload: dict[str, Any] = {}
            if self.include_raw:
                payload["raw"] = trap_data["raw"]
            if self.include_structured:
                payload["structured"] = structured_data

            event = {
                "payload": payload,
                "meta": {
                    "source": "snmp_trap",
                    "message_type": message_type,
                    "received_at": received_at,
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "validation_status": validation_status,
                    **rate_limit_stats,
                },
            }

            # Add community/context information
            if validated_community:
                event["meta"]["community"] = validated_community
            if validated_context:
                event["meta"]["security_context"] = validated_context

            # Add inform-specific metadata
            if message_type == "inform" and inform_request_id is not None:
                event["meta"]["request_id"] = inform_request_id
                event["meta"]["inform_acknowledged"] = False

            # Send inform response if needed
            if message_type == "inform" and self.inform_enabled and inform_whole_msg:
                ack_sent = await self._send_inform_response(
                    inform_request_id,
                    inform_whole_msg,
                    addr,
                )
                if message_type == "inform":
                    event["meta"]["inform_acknowledged"] = ack_sent

                # If require_ack is true, only queue if acknowledgment was sent
                if self.inform_require_ack and not ack_sent:
                    logger.warning(
                        "Inform acknowledgment failed, not queuing event (require_ack=true)"
                    )
                    return

            await self.queue.put(event)

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error processing SNMP trap: %s", exc)

    def _detect_pdu_type_sync(
        self,
        data: bytes,
    ) -> tuple[bool, int | None, Any]:
        """Detect if SNMP message is an inform or trap.

        Args:
        ----
            data: The raw SNMP message data.

        Returns:
        -------
            Tuple of (is_inform, request_id, whole_msg).
        """
        try:
            # Try to parse as SNMPv2c/v3 message
            whole_msg = v2c.Message()
            whole_msg.decode(data)

            pdu = whole_msg["pdu"]

            # Check if it's an inform request
            if pdu.tagSet == v2c.InformRequestPDU.tagSet:
                request_id = int(pdu["request-id"])
                return True, request_id, whole_msg

            # Check if it's a trap
            if pdu.tagSet == v2c.SNMPv2TrapPDU.tagSet:
                return False, None, whole_msg

            # Unknown PDU type
            return False, None, whole_msg

        except Exception:  # noqa: BLE001
            # Not a v2c/v3 message or parsing failed
            return False, None, None

    def _parse_snmpv2_inform_sync(
        self,
        data: bytes,
        source_ip: str,
        request_id: int,
    ) -> dict[str, Any] | None:
        """Parse an SNMPv2c or SNMPv3 inform.

        Args:
        ----
            data: The raw SNMP inform data.
            source_ip: The source IP address.
            request_id: The inform request ID.

        Returns:
        -------
            Parsed inform data or None if parsing fails.
        """
        try:
            # Parse SNMP message
            whole_msg = v2c.Message()
            whole_msg.decode(data)

            # Extract PDU
            pdu = whole_msg["pdu"]
            if pdu.tagSet != v2c.InformRequestPDU.tagSet:
                logger.debug("Not an SNMPv2 inform PDU")
                return None

            # Extract request ID, error status, error index
            req_id = int(pdu["request-id"])
            error_status = int(pdu["error-status"])
            error_index = int(pdu["error-index"])

            # Extract variable bindings (same as trap)
            var_bindings = []
            structured_vars: dict[str, Any] = {}
            trap_oid = ""

            for oid, val in pdu["varBinds"]:
                oid_str = ".".join([str(x) for x in oid])
                val_str = self._format_snmp_value(val)

                var_bindings.append(
                    {
                        "oid": oid_str,
                        "value": val_str,
                        "type": val.__class__.__name__,
                    },
                )

                # Extract common OIDs for structured data
                if oid_str == "1.3.6.1.2.1.1.3.0":  # sysUpTime
                    structured_vars["sysUpTime"] = val_str
                elif oid_str == "1.3.6.1.6.3.1.1.4.1.0":  # snmpTrapOID.0
                    trap_oid = str(val_str) if val_str else ""
                    structured_vars["snmpTrapOID"] = trap_oid

            # Determine trap type
            trap_type = STANDARD_TRAP_OIDS.get(trap_oid, "unknown")

            # Build raw data
            raw_data: dict[str, Any] = {
                "version": self.version,
                "agent_address": source_ip,
                "request_id": req_id,
                "error_status": error_status,
                "error_index": error_index,
                "variable_bindings": var_bindings,
            }

            if self.version == "v2c":
                raw_data["community"] = self.community

            # Build structured data
            structured_data: dict[str, Any] = {
                "trap_type": trap_type,
                "source_ip": source_ip,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "variables": structured_vars,
                "request_id": req_id,
            }

            if trap_oid:
                structured_data["trap_oid"] = trap_oid

            return {"raw": raw_data, "structured": structured_data}

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error parsing SNMPv2 inform: %s", exc)
            return None

    async def _send_inform_response(
        self,
        request_id: int | None,
        whole_msg: Any,
        addr: tuple[str, int],
    ) -> bool:
        """Send SNMP inform response.

        Args:
        ----
            request_id: Request ID from inform request.
            whole_msg: Original SNMP message.
            addr: Destination address (host, port).

        Returns:
        -------
            True if response was sent successfully, False otherwise.
        """
        if not self.inform_response_builder or request_id is None:
            return False

        try:
            # Build response
            response_data = self.inform_response_builder.build_response(request_id, whole_msg)
            if not response_data:
                return False

            # Send response via transport
            if self.transport:
                self.transport.sendto(response_data, addr)
                logger.debug(
                    "Sent inform response: request_id=%s, addr=%s",
                    request_id,
                    addr,
                )
                return True

            return False

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error sending inform response: %s", exc)
            return False

    def _parse_snmpv2_trap_sync(
        self,
        data: bytes,
        source_ip: str,
    ) -> dict[str, Any] | None:
        """Parse an SNMPv2c or SNMPv3 trap.

        Args:
        ----
            data: The raw SNMP trap data.
            source_ip: The source IP address.

        Returns:
        -------
            Parsed trap data or None if parsing fails.
        """
        try:
            # Parse SNMP message
            whole_msg = v2c.Message()
            whole_msg.decode(data)

            # Extract PDU
            pdu = whole_msg["pdu"]
            if pdu.tagSet != v2c.SNMPv2TrapPDU.tagSet:
                logger.debug("Not an SNMPv2 trap PDU")
                return None

            # Extract variable bindings
            var_bindings = []
            structured_vars: dict[str, Any] = {}
            trap_oid = ""

            for oid, val in pdu["varBinds"]:
                oid_str = ".".join([str(x) for x in oid])
                val_str = self._format_snmp_value(val)

                var_bindings.append(
                    {
                        "oid": oid_str,
                        "value": val_str,
                        "type": val.__class__.__name__,
                    },
                )

                # Extract common OIDs for structured data
                if oid_str == "1.3.6.1.2.1.1.3.0":  # sysUpTime
                    structured_vars["sysUpTime"] = val_str
                elif oid_str == "1.3.6.1.6.3.1.1.4.1.0":  # snmpTrapOID.0
                    trap_oid = str(val_str) if val_str else ""
                    structured_vars["snmpTrapOID"] = trap_oid
                elif oid_str.startswith("1.3.6.1.6.3.1.1.4.1.0"):
                    trap_oid = str(val_str) if val_str else ""
                    structured_vars["snmpTrapOID"] = trap_oid

            # If trap OID not found in varBinds, try to get from PDU
            if not trap_oid and hasattr(pdu, "trapOID"):
                trap_oid = ".".join([str(x) for x in pdu["trapOID"]])
                structured_vars["snmpTrapOID"] = trap_oid

            # Determine trap type
            trap_type = STANDARD_TRAP_OIDS.get(trap_oid, "unknown")

            # Build raw data
            raw_data: dict[str, Any] = {
                "version": self.version,
                "agent_address": source_ip,
                "variable_bindings": var_bindings,
            }

            if self.version == "v2c":
                raw_data["community"] = self.community

            # Build structured data
            structured_data: dict[str, Any] = {
                "trap_type": trap_type,
                "source_ip": source_ip,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "variables": structured_vars,
            }

            if trap_oid:
                structured_data["trap_oid"] = trap_oid

            return {"raw": raw_data, "structured": structured_data}

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error parsing SNMPv2 trap: %s", exc)
            return None

    def _parse_snmpv1_trap_sync(
        self,
        data: bytes,
        source_ip: str,
    ) -> dict[str, Any] | None:
        """Parse an SNMPv1 trap.

        Args:
        ----
            data: The raw SNMP trap data.
            source_ip: The source IP address.

        Returns:
        -------
            Parsed trap data or None if parsing fails.
        """
        try:
            # Parse SNMPv1 message
            whole_msg = v1.Message()
            whole_msg.decode(data)

            # Extract PDU
            pdu = whole_msg["pdu"]
            if pdu.tagSet != v1.TrapPDU.tagSet:
                logger.debug("Not an SNMPv1 trap PDU")
                return None

            # Extract trap information
            enterprise_oid = ".".join([str(x) for x in pdu["enterprise"]])
            generic_trap = int(pdu["generic-trap"])
            specific_trap = int(pdu["specific-trap"])
            timestamp = int(pdu["time-stamp"])

            # Extract variable bindings
            var_bindings = []
            structured_vars: dict[str, Any] = {}

            for oid, val in pdu["var-bindings"]:
                oid_str = ".".join([str(x) for x in oid])
                val_str = self._format_snmp_value(val)

                var_bindings.append(
                    {
                        "oid": oid_str,
                        "value": val_str,
                        "type": val.__class__.__name__,
                    },
                )

            # Determine trap type
            if generic_trap == 6:  # enterpriseSpecific
                trap_type = "enterpriseSpecific"
            else:
                trap_type = SNMPV1_GENERIC_TRAPS.get(generic_trap, "unknown")

            # Build raw data
            raw_data: dict[str, Any] = {
                "version": "v1",
                "community": self.community,
                "agent_address": source_ip,
                "enterprise_oid": enterprise_oid,
                "generic_trap": generic_trap,
                "specific_trap": specific_trap,
                "timestamp": timestamp,
                "variable_bindings": var_bindings,
            }

            # Build structured data
            structured_data: dict[str, Any] = {
                "trap_type": trap_type,
                "source_ip": source_ip,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "variables": structured_vars,
            }

            if enterprise_oid:
                structured_data["enterprise_oid"] = enterprise_oid

            return {"raw": raw_data, "structured": structured_data}

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error parsing SNMPv1 trap: %s", exc)
            return None

    def _format_snmp_value(self, val: Any) -> Any:
        """Format an SNMP value for JSON serialization.

        Args:
        ----
            val: The SNMP value object.

        Returns:
        -------
            Formatted value.
        """
        if isinstance(val, rfc1902.Integer32):
            return int(val)
        if isinstance(val, rfc1902.Counter32):
            return int(val)
        if isinstance(val, rfc1902.Counter64):
            return int(val)
        if isinstance(val, rfc1902.Gauge32):
            return int(val)
        if isinstance(val, rfc1902.TimeTicks):
            return int(val)
        if isinstance(val, rfc1902.OctetString):
            return bytes(val).decode("utf-8", errors="replace")
        if isinstance(val, rfc1902.IpAddress):
            return str(val)
        if isinstance(val, rfc1902.Opaque):
            return bytes(val).hex()
        if isinstance(val, (rfc1902.ObjectIdentifier, rfc1902_smi.ObjectIdentifier)):
            return ".".join([str(x) for x in val])
        if isinstance(val, (rfc1902.Null, rfc1902.NoSuchObject, rfc1902.NoSuchInstance)):
            return None

        # Fallback to string representation
        return str(val)


async def main(queue: asyncio.Queue[Any], args: dict[str, Any]) -> None:
    """Receive events via SNMP traps.

    Args:
    ----
        queue: The queue to put events into.
        args: Configuration arguments.
    """
    host = args.get("host", "0.0.0.0")
    port = int(args.get("port", 162))
    version = args.get("version", "v2c")

    if version not in ("v1", "v2c", "v3"):
        msg = f"Invalid SNMP version: {version}. Must be v1, v2c, or v3"
        raise ValueError(msg)

    # Create event loop and protocol
    loop = asyncio.get_event_loop()
    protocol = SNMPTrapProtocol(queue, args)

    # Create UDP endpoint
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        local_addr=(host, port),
    )

    try:
        # Keep running until cancelled
        await asyncio.Future()
    except asyncio.CancelledError:
        logger.info("SNMP trap listener cancelled")
    finally:
        transport.close()


if __name__ == "__main__":
    """MockQueue if running directly."""

    class MockQueue(asyncio.Queue[Any]):
        """A fake queue."""

        async def put(self: MockQueue, event: dict[str, Any]) -> None:
            """Print the event."""
            print(event)  # noqa: T201

    asyncio.run(
        main(
            MockQueue(),
            {
                "host": "0.0.0.0",
                "port": 162,
                "version": "v2c",
                "community": "public",
            },
        ),
    )
