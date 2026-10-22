"""Mutation regression tests for the optional NR-4 source drift guard."""

from __future__ import annotations

from dev.verification import nr4_observation_edges as guard


def test_current_checked_sources_have_expected_shape() -> None:
    assert guard.scan(guard.read_sources()) == []


def test_missing_error_fallback_fails_closed() -> None:
    sources = guard.read_sources()
    original = sources[guard.TLS]
    assert '_ => "Broker failed closed."' in original
    sources[guard.TLS] = original.replace(
        '_ => "Broker failed closed."', '_ => "some private text"', 1
    )
    assert any('bounded-error-taxonomy' in problem for problem in guard.scan(sources))


def test_removed_guest_frame_conversion_is_detected() -> None:
    sources = guard.read_sources()
    sources[guard.TLS] = sources[guard.TLS].replace(
        'json::capture(&value)', 'json::capture(&raw_provider_response)', 1
    )
    assert any('answer-conversion' in problem for problem in guard.scan(sources))


def test_skipped_public_write_flush_is_detected() -> None:
    sources = guard.read_sources()
    sources[guard.TLS] = sources[guard.TLS].replace(
        '.and_then(|_| self.0.flush())', '.and_then(|_| Ok(()))', 1
    )
    assert any('guest-frame-single-writer' in problem for problem in guard.scan(sources))


def test_framing_before_authentication_is_detected() -> None:
    sources = guard.read_sources()
    content = sources[guard.TLS]
    expected = 'VerifiedPeer::from_connection(&connection)'
    assert expected in content
    # Deliberately move the verification call out of the observed serve region.
    sources[guard.TLS] = content.replace(expected, 'VerifiedPeer::unverified(&connection)', 1)
    assert any('guest-auth-before-public-framing' in problem for problem in guard.scan(sources))


def test_unsafe_return_of_provider_error_detected_as_source_drift() -> None:
    sources = guard.read_sources()
    sources[guard.TLS] = sources[guard.TLS].replace(
        'Error::OutcomeUnknown =>', 'Error::ProviderDebug =>', 1
    )
    assert any('bounded-error-taxonomy' in problem for problem in guard.scan(sources))


def test_native_source_guard_not_a_semantic_certification() -> None:
    # Inserting a new side effect between existing anchors can evade a
    # source-shape scan. Recording this counterexample keeps the gate honest.
    sources = guard.read_sources()
    source = sources[guard.TLS]
    sources[guard.TLS] = source.replace(
        'json::capture(&value)', 'json::capture(&value) /* unreviewed side effect */', 1
    )
    assert guard.scan(sources) == []
