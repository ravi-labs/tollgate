#!/usr/bin/env python3
"""Entrypoint for the full safety demo."""

from __future__ import annotations

import asyncio

from full_safety_demo_core import run_full_safety_demo


if __name__ == "__main__":
    asyncio.run(run_full_safety_demo())
