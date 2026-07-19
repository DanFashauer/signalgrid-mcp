"""Hardware identity and OS information."""

from __future__ import annotations

import getpass
from typing import Any

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.runner import run_json, text


def collect_identity() -> dict[str, Any]:
    r = run_json(["system_profiler", "SPHardwareDataType", "-json"])
    if not r["ok"]:
        return {"error": r["error"]}
    try:
        blob = r["data"]["SPHardwareDataType"][0]
    except (KeyError, IndexError, TypeError) as e:
        return {"error": f"unexpected system_profiler shape: {e}"}
    return {
        "model_name": blob.get("machine_name"),
        "model_identifier": blob.get("machine_model"),
        "chip": blob.get("chip_type") or blob.get("cpu_type"),
        "serial_number": blob.get("serial_number"),
        "hardware_uuid": blob.get("platform_UUID"),
        "provisioning_udid": blob.get("provisioning_UDID"),
        "memory": blob.get("physical_memory"),
        "activation_lock": blob.get("activation_lock_status"),
    }


def collect_os() -> dict[str, Any]:
    return {
        "product_name": text(["sw_vers", "-productName"]),
        "product_version": text(["sw_vers", "-productVersion"]),
        "build_version": text(["sw_vers", "-buildVersion"]),
        "kernel": text(["uname", "-v"]),
        "computer_name": text(["scutil", "--get", "ComputerName"]),
        "local_hostname": text(["scutil", "--get", "LocalHostName"]),
        "uptime": text(["uptime"]),
        "console_user": text(["stat", "-f", "%Su", "/dev/console"]),
        "process_user": getpass.getuser(),
    }


@mcp.tool(name="signalgrid_device_identity", annotations=READ_ONLY)
def signalgrid_device_identity() -> dict[str, Any]:
    """Hardware identity: serial number, model, hardware UUID, chip, activation lock.

    The stable anchor for a device trust record. Serial number + hardware UUID
    uniquely identify the physical machine across OS reinstalls.

    Returns:
        dict with keys: model_name, model_identifier, chip, serial_number,
        hardware_uuid, provisioning_udid, memory, activation_lock — or
        {"error": str} if system_profiler could not run.
    """
    return collect_identity()


@mcp.tool(name="signalgrid_os_info", annotations=READ_ONLY)
def signalgrid_os_info() -> dict[str, Any]:
    """macOS product/build version, kernel, hostnames, uptime, and current users.

    Use to establish OS patch level (compare product_version against Apple's
    latest release) and which user is on the console.

    Returns:
        dict with keys: product_name, product_version, build_version, kernel,
        computer_name, local_hostname, uptime, console_user, process_user.
        Individual values read "unavailable"/error text when a probe fails.
    """
    return collect_os()
