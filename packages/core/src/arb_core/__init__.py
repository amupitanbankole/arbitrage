"""Shared foundation for the arbitrage platform.

This package is deliberately framework-agnostic: it contains no FastAPI, no
CCXT and no exchange-specific knowledge. Anything that lives here must be safe
to import from the API, from every worker, and from the test-suite.

Layering rule (enforced by review and by ``ruff`` first-party import sorting):

    apps/api, apps/worker  ->  packages/core
    packages/core          ->  (nothing else in the monorepo)
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
