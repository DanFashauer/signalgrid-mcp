"""Code signature and notarization inspection."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.runner import run, text


def _verify(path: str) -> str:
    """Signature validity for `path`, keyed on the EXIT CODE.

    `codesign --verify --deep --strict` is SILENT on success — exit 0, no stdout, no
    stderr — so `text()` returned its "unavailable" fallback and EVERY validly-signed
    app read as if the check could not run (the field's whole job, "valid on disk", was
    unreachable). Map it explicitly: exit 0 -> valid, nonzero -> the specific failure
    on stderr, couldn't-run-at-all -> unavailable.
    """
    r = run(["codesign", "--verify", "--deep", "--strict", path])
    if "error" in r:
        return f"unavailable: {r['error']}"
    if r["ok"]:
        return r["stdout"] or r["stderr"] or "valid on disk"
    return r["stderr"] or r["stdout"] or f"invalid (exit {r['exit_code']})"


@mcp.tool(name="signalgrid_codesign_inspect", annotations=READ_ONLY)
def signalgrid_codesign_inspect(
    path: Annotated[
        str,
        Field(
            description=(
                "Absolute path to an .app bundle or Mach-O binary, e.g. "
                "'/Applications/Safari.app' or '/usr/local/bin/some-tool'"
            ),
            min_length=2,
            max_length=1024,
            pattern=r"^/[^\x00\n]*$",
        ),
    ],
) -> dict[str, Any]:
    """Inspect the code signature, signature validity, and Gatekeeper assessment
    of a bundle or binary on this Mac.

    Use to answer "is this app properly signed and notarized, and by whom?".
    Reads only; never executes the target.

    Args:
        path: Absolute path to the .app or binary to inspect.

    Returns:
        dict with keys:
        - path: the inspected path
        - signature: `codesign -dv --verbose=4` output (authority chain,
          team identifier, hashes)
        - verify: `codesign --verify --deep --strict` result ("valid on disk"
          style output, or the specific failure)
        - assessment: `spctl --assess --verbose=4` Gatekeeper verdict
          (accepted/rejected and the source, e.g. "Notarized Developer ID")

        A missing path yields codesign/spctl error text in those fields rather
        than an exception.
    """
    return {
        "path": path,
        "signature": text(["codesign", "-dv", "--verbose=4", path]),
        "verify": _verify(path),
        "assessment": text(["spctl", "--assess", "--verbose=4", path]),
    }
