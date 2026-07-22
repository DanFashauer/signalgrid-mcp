"""Removable media / USB inventory — the data-egress channel on the endpoint.

Manufacturing and shared-device endpoint management calls out USB control to
prevent data leaks. This read-only tool inventories what is physically connected
over USB and flags MASS-STORAGE devices — the removable-storage channel a user
could copy data onto or run code from. It reads `system_profiler SPUSBDataType`;
it changes nothing and enforces nothing (that is a management tool's job) — it
reports the fact so the SignalGrid fabric can decide.

Fail-safe: if the USB tree could not be read, `available` is False (NOT "nothing
connected"); a device whose class can't be determined is 'other', never assumed
harmless storage-wise.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat, name_filter, paginate, render_page
from signalgrid_mcp.runner import run_json


def _walk(items: Any):
    """Yield every node in the SPUSBDataType tree (devices nest under _items)."""
    if not isinstance(items, list):
        return
    for node in items:
        if not isinstance(node, dict):
            continue
        yield node
        yield from _walk(node.get("_items"))


def parse_usb(data: Any) -> dict[str, Any]:
    """Parse `system_profiler SPUSBDataType -json`'s value. Fail-safe: a shape we
    don't recognize yields available=False (unknown), never an empty 'nothing
    connected'."""
    if not isinstance(data, list):
        return {"available": False, "device_count": None, "mass_storage_count": None, "mass_storage_connected": None, "devices": [], "_note": "unrecognized SPUSBDataType shape"}

    devices: list[dict[str, Any]] = []
    for node in _walk(data):
        name = node.get("_name")
        vendor = node.get("manufacturer") or node.get("vendor_id")
        media = node.get("Media")
        has_media = isinstance(media, list) and len(media) > 0
        # Skip the synthetic bus/root-hub controllers — BUT never skip a node that
        # actually presents storage (compute has_media first, so a Media-bearing
        # device is never dropped just because it also carries a controller key).
        if ("host_controller" in node or "pci_device" in node) and not has_media:
            continue
        # A real device has a vendor id/name or presents storage media. A bare hub
        # with nothing identifying is skipped.
        if not (has_media or vendor):
            continue
        volumes: list[str] = []
        if has_media:
            for m in media:
                if not isinstance(m, dict):
                    continue
                vols = m.get("volumes")
                for vol in vols if isinstance(vols, list) else []:
                    if isinstance(vol, dict) and vol.get("_name"):
                        volumes.append(vol["_name"])
        devices.append({
            "name": name,
            "vendor": node.get("manufacturer"),
            "serial": node.get("serial_num"),
            # Mass storage = a data-egress channel. Anything else is 'other' — we do
            # NOT try to prove it's a harmless HID, we just don't flag it as storage.
            "kind": "mass_storage" if has_media else "other",
            "volumes": volumes,
        })

    mass = [d for d in devices if d["kind"] == "mass_storage"]
    return {
        "available": True,
        "device_count": len(devices),
        "mass_storage_count": len(mass),
        "mass_storage_connected": len(mass) > 0,
        "devices": devices,
        "_note": (
            "mass_storage_connected=true means a removable-storage data-egress "
            "channel is physically present; 'other' devices are not classified as "
            "storage (not proven harmless). available=false means the USB tree "
            "could not be read — never 'nothing connected'."
        ),
    }


def collect_removable_media() -> dict[str, Any]:
    r = run_json(["system_profiler", "SPUSBDataType", "-json"], timeout=60)
    if not r.get("ok"):
        return {"available": False, "device_count": None, "mass_storage_count": None, "mass_storage_connected": None, "devices": [], "_note": r.get("error") or "system_profiler failed"}
    d = r.get("data")
    tree = d.get("SPUSBDataType") if isinstance(d, dict) else None
    return parse_usb(tree)


@mcp.tool(name="signalgrid_removable_media", annotations=READ_ONLY)
def signalgrid_removable_media(
    name_contains: Annotated[str | None, Field(description="Case-insensitive filter on device name/vendor.")] = None,
    limit: Annotated[int, Field(ge=1, le=500, description="Max devices to return.")] = 100,
    offset: Annotated[int, Field(ge=0, description="Pagination offset.")] = 0,
    response_format: ResponseFormat = ResponseFormat.MARKDOWN,
) -> Any:
    """Connected USB / removable-media devices, flagging MASS-STORAGE — the
    data-egress channel a shared or plant-floor device manager cares about.
    Read-only; needs no elevation.

    `mass_storage_connected: true` means removable storage is physically present.
    `available: false` means the USB tree could not be read (never "nothing
    connected"). SignalGrid reports this; it does not block the device.

    Returns:
        dict with available (bool), device_count, mass_storage_count,
        mass_storage_connected (bool | None), and devices[] each with name,
        vendor, serial, kind (mass_storage | other), volumes.
    """
    data = collect_removable_media()
    devs = data.get("devices") or []
    devs = name_filter(devs, name_contains, "name", "vendor")
    page = paginate(devs, limit, offset)
    if response_format == ResponseFormat.JSON:
        return {
            "available": data.get("available"),
            "device_count": data.get("device_count"),
            "mass_storage_count": data.get("mass_storage_count"),
            "mass_storage_connected": data.get("mass_storage_connected"),
            "devices": page["items"],
            "total": page["total"],
            "has_more": page["has_more"],
            "next_offset": page["next_offset"],
            "_note": data.get("_note"),
        }
    title = (
        f"Removable media (available={data.get('available')}, "
        f"{data.get('device_count')} USB devices, "
        f"{data.get('mass_storage_count')} mass-storage, "
        f"connected={data.get('mass_storage_connected')})"
    )
    return render_page(page, response_format, title,
                       [("name", "Device"), ("vendor", "Vendor"), ("kind", "Kind"), ("serial", "Serial")],
                       note=data.get("_note"))
