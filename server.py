"""Back-compat entry point. The server now lives in src/signalgrid_mcp/.

Kept so existing client configs pointing at `python server.py` keep working.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from signalgrid_mcp.server import main  # noqa: E402

if __name__ == "__main__":
    main()
