"""Package entry point. Used by `python -m findevil`.

Kept tiny on purpose: running `python -m findevil.server` would cause
Python to execute server.py twice (once as __main__, again as the
findevil.server module when tool modules import from it), producing
two separate FastMCP instances and losing half the tool registrations.
This shim imports findevil.server as a normal module so every
@mcp.tool() decorator registers on the same instance.
"""

from findevil.server import mcp

if __name__ == "__main__":
    mcp.run()
