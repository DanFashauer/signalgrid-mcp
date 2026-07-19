"""Code signature and notarization inspection."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.runner import text


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
        "verify": text(["codesign", "--verify", "--deep", "--strict", path]),
        "assessment": text(["spctl", "--assess", "--verbose=4", path]),
    }
