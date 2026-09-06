"""`docs/STATUS.md` is part of the API contract, so it is tested like one.

The status document tells the next phase's frontend developer which endpoints
exist, which error codes they must handle, and what each one means. A document
that drifts from the code is worse than no document: it is read once, believed,
and then coded against. Two directions of drift matter and both are silent.

* The document names something the code does not have — an endpoint that was
  renamed, a code that was retyped from memory (``CSRF_INVALID`` for
  ``CSRF_FAILED``), a status that changed. A client written against the document
  branches on a string that never arrives.
* The code raises something the document does not mention. A client with no
  branch for it shows the user a generic failure at the exact moment a specific
  one was the whole point — "your account is locked" versus "sign-in failed".

Both are checked here against the running application's own OpenAPI schema and
against the error classes the authentication layer actually imports, so neither
list is maintained by hand a second time.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from arb_core import errors as error_module
from arb_core.errors import AppError, ErrorCode, http_status_for

if TYPE_CHECKING:
    from collections.abc import Iterator

    from fastapi import FastAPI

_STATUS_DOC = Path(__file__).resolve().parents[2] / "docs" / "STATUS.md"

#: The modules whose imports define the authentication error surface. Anything an
#: endpoint, dependency or service can raise has to be imported by one of these.
_AUTH_SURFACE_MODULES = (
    "apps/api/src/arb_api/api/v1/auth.py",
    "apps/api/src/arb_api/api/dependencies.py",
    "apps/api/src/arb_api/services/auth_service.py",
    "apps/api/src/arb_api/services/session_service.py",
    "apps/api/src/arb_api/services/mfa_service.py",
    "apps/api/src/arb_api/services/password_service.py",
)

_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

#: One backticked ``METHOD /path`` cell, and nothing else in that cell. Rows whose
#: first cell lists several paths (``GET /openapi.json``, ``/docs``, ``/redoc``)
#: deliberately do not match: they describe a group, not a route.
_ENDPOINT_ROW = re.compile(r"^\|\s*`(" + "|".join(_METHODS) + r") (/\S+)`\s*\|", re.M)

#: A row of the error-code table: ``| `CODE` | 401 | ...``.
_ERROR_ROW = re.compile(r"^\|\s*`([A-Z_]+)`\s*\|\s*(\d{3})\s*\|", re.M)


@pytest.fixture(scope="module")
def status_document() -> str:
    """The rendered status document, as committed."""
    assert _STATUS_DOC.is_file(), f"expected the status document at {_STATUS_DOC}"
    return _STATUS_DOC.read_text()


@pytest.fixture
def openapi_paths(app: Any) -> dict[str, set[str]]:
    """What the application advertises it serves, as ``{path: {METHOD, ...}}``.

    Taken from the OpenAPI schema rather than from ``app.routes``: this FastAPI
    version collapses included routers into opaque wrapper objects, so walking the
    router tree would mean depending on its internals — and a documentation test
    that breaks when a dependency is upgraded stops being read.

    One served path is absent by design and is handled by ``_SCHEMA_EXCLUDED``.
    """
    built: FastAPI = app
    schema: dict[str, Any] = built.openapi()
    return {
        path: {method.upper() for method in operations}
        for path, operations in schema["paths"].items()
    }


#: Served but deliberately kept out of the OpenAPI schema, so that scraping it is
#: not advertised. Each entry must be *documented* as excluded — a path missing
#: from the schema for no stated reason is a path nobody can find. Whether it is
#: actually served is asserted by `tests/security/test_endpoint_security.py`.
_SCHEMA_EXCLUDED: Final[frozenset[tuple[str, str]]] = frozenset({("GET", "/metrics")})


def _documented_endpoints(document: str) -> Iterator[tuple[str, str]]:
    yield from _ENDPOINT_ROW.findall(document)


def _documented_errors(document: str) -> dict[str, int]:
    return {code: int(status) for code, status in _ERROR_ROW.findall(document)}


def _error_code_by_class_name() -> dict[str, ErrorCode]:
    """Every ``AppError`` subclass in the taxonomy, by the name it is imported under."""
    codes: dict[str, ErrorCode] = {}
    for name, member in vars(error_module).items():
        if (
            isinstance(member, type)
            and issubclass(member, AppError)
            and member is not AppError
            and isinstance(getattr(member, "code", None), ErrorCode)
        ):
            codes[name] = member.code
    return codes


def _imported_error_classes(module_path: Path) -> set[str]:
    """Names imported from ``arb_core.errors`` by one module, via its AST.

    Parsed rather than grepped, so a mention in a docstring or a comment does not
    claim an error the module cannot raise.
    """
    tree = ast.parse(module_path.read_text(), filename=str(module_path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "arb_core.errors":
            imported.update(alias.name for alias in node.names)
    return imported


class TestDocumentedEndpointsExist:
    """The endpoint tables must describe routes the application serves."""

    def test_the_tables_are_not_empty(self, status_document: str) -> None:
        """A regex that matches nothing would pass every test below."""
        assert len(list(_documented_endpoints(status_document))) >= 25

    def test_every_documented_route_is_served(
        self, status_document: str, openapi_paths: dict[str, set[str]]
    ) -> None:
        missing: list[str] = []
        for method, path in _documented_endpoints(status_document):
            if (method, path) in _SCHEMA_EXCLUDED:
                continue
            methods = openapi_paths.get(path)
            if methods is None:
                missing.append(f"{method} {path} (no such path)")
            elif method not in methods:
                missing.append(f"{method} {path} (serves {', '.join(sorted(methods))})")
        assert missing == [], (
            "docs/STATUS.md advertises routes the application does not serve: " + "; ".join(missing)
        )

    def test_the_whole_authentication_surface_is_documented(
        self, status_document: str, openapi_paths: dict[str, set[str]]
    ) -> None:
        """The reverse direction: no served auth route may be missing from the doc."""
        served = {
            (method, path)
            for path, methods in openapi_paths.items()
            if path.startswith("/api/v1/auth")
            for method in methods - {"HEAD", "OPTIONS"}
        }
        # Without this the test passes vacuously if the prefix ever changes.
        assert len(served) == 19, f"expected 19 authentication routes, saw {len(served)}"

        undocumented = sorted(served - set(_documented_endpoints(status_document)))
        assert undocumented == [], (
            "these authentication routes are served but not in docs/STATUS.md, so a "
            "client reading the document does not know they exist: "
            + ", ".join(f"{method} {path}" for method, path in undocumented)
        )

    def test_every_schema_excluded_path_says_so_in_the_document(
        self, status_document: str, openapi_paths: dict[str, set[str]]
    ) -> None:
        """An exclusion is a decision, and the decision has to be written down."""
        for method, path in sorted(_SCHEMA_EXCLUDED):
            assert path not in openapi_paths, f"{path} is in the schema; drop it from the exception"
            row = next(
                (line for line in status_document.splitlines() if f"`{method} {path}`" in line),
                None,
            )
            assert row is not None, f"{method} {path} is served but not documented at all"
            assert "OpenAPI" in row, (
                f"{method} {path} is absent from the OpenAPI schema, and its documented "
                "row does not say so — a reader would look for it there and not find it"
            )


class TestDocumentedErrorCodes:
    """The error-code table must be the real taxonomy, with the real statuses."""

    def test_the_table_is_not_empty(self, status_document: str) -> None:
        assert len(_documented_errors(status_document)) >= 15

    def test_every_documented_code_exists(self, status_document: str) -> None:
        real = {code.value for code in ErrorCode}
        invented = sorted(set(_documented_errors(status_document)) - real)
        assert invented == [], (
            "docs/STATUS.md documents error codes that do not exist, which is how a "
            f"client ends up branching on a string that never arrives: {invented}"
        )

    def test_every_documented_status_matches_the_code(self, status_document: str) -> None:
        wrong = [
            f"{code}: documented {status}, raised as {http_status_for(ErrorCode(code))}"
            for code, status in sorted(_documented_errors(status_document).items())
            if status != http_status_for(ErrorCode(code))
        ]
        assert wrong == [], (
            "docs/STATUS.md states the wrong HTTP status for these codes: " + "; ".join(wrong)
        )

    def test_every_code_the_auth_surface_raises_is_documented(self, status_document: str) -> None:
        """A client with no branch for a code shows a generic failure instead."""
        documented = set(_documented_errors(status_document))
        codes = _error_code_by_class_name()
        root = _STATUS_DOC.parents[1]

        raisable: dict[str, set[str]] = {}
        for relative in _AUTH_SURFACE_MODULES:
            module = root / relative
            assert module.is_file(), f"{relative} moved; update _AUTH_SURFACE_MODULES"
            for name in _imported_error_classes(module):
                code = codes.get(name)
                if code is not None:
                    raisable.setdefault(code.value, set()).add(relative.split("/")[-1])

        undocumented = sorted(set(raisable) - documented)
        assert undocumented == [], (
            "the authentication surface can raise these codes but docs/STATUS.md does "
            "not list them, so a client cannot distinguish them: "
            + "; ".join(
                f"{code} (from {', '.join(sorted(raisable[code]))})" for code in undocumented
            )
        )
