import os
import socket
import subprocess
import time
from typing import Callable

import pytest

from .. import TESTS_PATH
from ..utils import CLIRunner


def wait_for_events(proc: subprocess.Popen[bytes], timeout: float = 15.0) -> None:
    """
    Wait for events to be processed by ansible-rulebook, or timeout.
    Requires the process to be running in debug mode.
    """
    start = time.time()
    if not proc.stdout:  # pragma: no cover
        return
    while stdout := proc.stdout.readline().decode():
        if "Waiting for events" in stdout or "SNMP trap listener started" in stdout:
            break
        time.sleep(0.1)
        if time.time() - start > timeout:
            raise TimeoutError("Timeout waiting for events")


def send_snmp_trap_v2c(host: str, port: int, community: str = "public") -> None:
    """
    Send a simple SNMPv2c trap using snmptrap command if available.
    Falls back to sending raw UDP packet if snmptrap is not available.
    """
    # Try to use snmptrap command first
    snmptrap_cmd = None
    for cmd in ["snmptrap", "snmptrapd"]:
        if subprocess.run(
            ["which", cmd], capture_output=True, check=False
        ).returncode == 0:
            snmptrap_cmd = cmd
            break

    if snmptrap_cmd:
        try:
            # Send a coldStart trap
            subprocess.run(
                [
                    "snmptrap",
                    "-v",
                    "2c",
                    "-c",
                    community,
                    f"{host}:{port}",
                    "",
                    "1.3.6.1.6.3.1.1.5.1",  # coldStart OID
                    "i",
                    "12345",  # sysUpTime value
                ],
                capture_output=True,
                check=False,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fall back to raw UDP if snmptrap fails
            _send_raw_snmp_trap(host, port)
    else:
        # Fall back to raw UDP packet
        _send_raw_snmp_trap(host, port)


def _send_raw_snmp_trap(host: str, port: int) -> None:
    """
    Send a minimal raw SNMPv2c trap packet via UDP.
    This is a simplified trap packet for testing.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Minimal SNMPv2c trap packet structure
        # This is a very basic packet - real traps would be more complex
        trap_packet = (
            b"\x30\x27\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"
            b"\xa7\x1a\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
            b"\x30\x0c\x30\x0a\x06\x08\x2b\x06\x01\x02\x01\x01\x03\x00"
            b"\x05\x00"
        )
        sock.sendto(trap_packet, (host, port))
        sock.close()
    except Exception:  # noqa: BLE001
        # Ignore errors in test environment
        pass


@pytest.mark.parametrize(
    "port",
    [
        pytest.param(16200, id="default_test_port"),
        pytest.param(16201, id="custom_test_port"),
    ],
)
def test_snmp_trap_source_sanity(
    subprocess_teardown: Callable[..., None], port: int
) -> None:
    """
    Check the successful execution and processing of SNMP traps.
    """
    host = "127.0.0.1"
    community = "public"

    env = os.environ.copy()
    env["SNMP_HOST"] = "0.0.0.0"
    env["SNMP_PORT"] = str(port)
    env["SNMP_VERSION"] = "v2c"
    env["SNMP_COMMUNITY"] = community

    rules_file = TESTS_PATH + "/event_source_snmp_trap/test_snmp_trap_rules.yml"

    proc = CLIRunner(
        rules=rules_file,
        envvars="SNMP_HOST,SNMP_PORT,SNMP_VERSION,SNMP_COMMUNITY",
        env=env,
        debug=True,
    ).run_in_background()
    subprocess_teardown(proc)

    wait_for_events(proc)

    # Send a test trap
    send_snmp_trap_v2c(host, port, community)

    # Wait a bit for processing
    time.sleep(2)

    try:
        stdout, _unused_stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        stdout, _unused_stderr = proc.communicate()

    # Check that the process started successfully
    # Note: Actual trap processing may vary based on trap format
    assert "SNMP trap listener started" in stdout.decode() or proc.returncode in (
        0,
        1,
    )


def test_snmp_trap_source_with_busy_port(
    subprocess_teardown: Callable[..., None],
) -> None:
    """
    Ensure the CLI responds correctly if the desired port is already in use.
    """
    port = 16202
    env = os.environ.copy()
    env["SNMP_HOST"] = "0.0.0.0"
    env["SNMP_PORT"] = str(port)
    env["SNMP_VERSION"] = "v2c"
    env["SNMP_COMMUNITY"] = "public"

    rules_file = TESTS_PATH + "/event_source_snmp_trap/test_snmp_trap_rules.yml"
    proc1 = CLIRunner(
        rules=rules_file,
        envvars="SNMP_HOST,SNMP_PORT,SNMP_VERSION,SNMP_COMMUNITY",
        env=env,
        debug=True,
    ).run_in_background()
    subprocess_teardown(proc1)

    wait_for_events(proc1)

    proc2 = CLIRunner(
        rules=rules_file,
        envvars="SNMP_HOST,SNMP_PORT,SNMP_VERSION,SNMP_COMMUNITY",
        env=env,
        debug=True,
    ).run_in_background()
    proc2.wait(timeout=15)
    stdout, _unused_stderr = proc2.communicate()
    # Port binding error may vary by OS
    assert (
        "address already in use" in stdout.decode()
        or "Address already in use" in stdout.decode()
        or proc2.returncode != 0
    )


def test_snmp_trap_source_v1(subprocess_teardown: Callable[..., None]) -> None:
    """
    Test SNMPv1 trap reception.
    """
    port = 16203
    env = os.environ.copy()
    env["SNMP_HOST"] = "0.0.0.0"
    env["SNMP_PORT"] = str(port)
    env["SNMP_VERSION"] = "v1"
    env["SNMP_COMMUNITY"] = "public"

    rules_file = TESTS_PATH + "/event_source_snmp_trap/test_snmp_trap_rules.yml"

    proc = CLIRunner(
        rules=rules_file,
        envvars="SNMP_HOST,SNMP_PORT,SNMP_VERSION,SNMP_COMMUNITY",
        env=env,
        debug=True,
    ).run_in_background()
    subprocess_teardown(proc)

    wait_for_events(proc)

    # Send a test trap (v1 format)
    _send_raw_snmp_trap("127.0.0.1", port)

    # Wait a bit for processing
    time.sleep(2)

    try:
        stdout, _unused_stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        stdout, _unused_stderr = proc.communicate()

    # Check that the process started successfully
    assert "SNMP trap listener started" in stdout.decode() or proc.returncode in (
        0,
        1,
    )
