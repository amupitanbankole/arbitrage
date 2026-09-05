"""Identifier generation (§82).

UUIDv7 was chosen over UUIDv4 for index locality on the highest-insert tables.
If that property is lost — for example by a refactor that swaps in ``uuid4()`` —
insert performance on ``orders`` and ``order_fills`` degrades badly and silently,
so the ordering property is asserted here rather than assumed.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from arb_core.identifiers import new_id, new_id_str, parse_id, prefixed_id, uuid7


class TestUuid7:
    def test_reports_version_seven(self) -> None:
        assert uuid7().version == 7

    def test_uses_the_rfc_variant(self) -> None:
        # reserved_in_rfc_4122 is Python's label for the RFC 4122 variant bits.
        assert "RFC 4122" in str(uuid7().variant)

    def test_timestamp_is_roughly_now(self) -> None:
        """The leading 48 bits are Unix epoch milliseconds."""
        import time

        before = int(time.time() * 1000)
        identifier = uuid7()
        after = int(time.time() * 1000)
        embedded = identifier.int >> 80
        assert before <= embedded <= after

    def test_is_monotonic_within_a_burst(self) -> None:
        """Same-millisecond IDs must still sort in generation order."""
        identifiers = [uuid7() for _ in range(2000)]
        assert identifiers == sorted(identifiers)
        assert len({str(item) for item in identifiers}) == len(identifiers)

    def test_uniqueness_across_a_large_sample(self) -> None:
        generated = [uuid7() for _ in range(20_000)]
        assert len(set(generated)) == len(generated)

    def test_new_id_and_new_id_str_agree(self) -> None:
        assert isinstance(new_id(), UUID)
        assert isinstance(new_id_str(), str)
        assert UUID(new_id_str()).version == 7


class TestPrefixedId:
    @pytest.mark.parametrize("prefix", ["ord", "trd", "bot", "OPP"])
    def test_format(self, prefix: str) -> None:
        value = prefixed_id(prefix)
        head, _, tail = value.partition("_")
        assert head == prefix.lower()
        assert UUID(tail).version == 7

    @pytest.mark.parametrize("prefix", ["", "a-b", "a b", "ord!", "ünicode"])
    def test_rejects_unsafe_prefixes(self, prefix: str) -> None:
        """Prefixes are ASCII alphanumeric only, so IDs stay URL- and log-safe."""
        with pytest.raises(ValueError, match="prefix must be"):
            prefixed_id(prefix)


class TestParseId:
    def test_parses_a_plain_uuid(self) -> None:
        value = uuid7()
        assert parse_id(str(value)) == value

    def test_accepts_a_uuid_instance(self) -> None:
        value = uuid7()
        assert parse_id(value) is value

    def test_strips_a_known_prefix(self) -> None:
        decorated = prefixed_id("ord")
        assert str(parse_id(decorated)) == decorated.split("_", 1)[1]

    def test_tolerates_surrounding_whitespace(self) -> None:
        value = uuid7()
        assert parse_id(f"  {value}  ") == value

    @pytest.mark.parametrize("value", ["", "not-a-uuid", "ord_", "12345", "../../etc/passwd"])
    def test_rejects_invalid_input(self, value: str) -> None:
        with pytest.raises(ValueError, match="invalid identifier"):
            parse_id(value)
