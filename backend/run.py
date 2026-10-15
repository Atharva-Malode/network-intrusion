"""
Backend launcher — run this instead of the `uvicorn` CLI on Windows.

Why: under a flood the server opens many concurrent sockets. Windows' default
asyncio SelectorEventLoop wraps select(), which has a hard 512-descriptor limit,
so the event loop crashes with:

    ValueError: too many file descriptors in select()

uvicorn forces that SelectorEventLoop whenever it runs a subprocess (i.e. with
--reload or --workers > 1). This launcher pins the Proactor event loop (IOCP,
no 512 limit) and runs a single in-process worker with reload OFF, so the
backend survives heavy traffic. Loops back to the same app either way.

Run:  uv run python run.py       (from backend/)
Env overrides: BACKEND_HOST (default 127.0.0.1), BACKEND_PORT (default 8000).
"""
from __future__ import annotations

import asyncio
import os
import sys

# Pin IOCP on Windows BEFORE uvicorn starts — removes the select() 512 limit.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import uvicorn  # noqa: E402  (import after the policy is set)

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=os.environ.get("BACKEND_HOST", "127.0.0.1"),
        port=int(os.environ.get("BACKEND_PORT", "8000")),
        reload=False,   # a reload subprocess would re-pin the 512-limited loop
        workers=1,      # single process -> Proactor loop is used on Windows
    )
