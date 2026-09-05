"""Persistence package: ORM models, repositories and migrations.

Both the API and every worker depend on this package, so neither tier has to
import the other to reach the database. See ``README.md`` for the rationale.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
