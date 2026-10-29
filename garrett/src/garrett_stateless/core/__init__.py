"""The ``garrett-stateless-v1`` protocol, module for module as the Rust crate
``garrett-stateless-core`` that Aeneas extracts and the Lean proofs cover:

* :mod:`.stateless` and :mod:`.stateless_token` (with :mod:`.encoding`):
  surrogate claims, issuance, renewal, the token codec and opening;
* :mod:`.stateless_login` and :mod:`.stateless_mailbox`: the optional OAuth
  login;
* :mod:`.stateless_policy` and :mod:`.stateless_proxy`: operation
  authorization and the proxy's request decision;
* :mod:`.proxy_http`: the strict HTTP/1.1 subset, the exact upstream encoder
  and response release (the Rust ``proxy_http`` with its small leaves).

Every function is a function of its arguments: no I/O, clock, randomness or
cryptography (those are the protocols :class:`.stateless_token.KeyMaterial`
and :class:`.stateless_token.StateKey`, and arguments such as ``now`` and
``nonce``). This Python reference is tested against the same vectors as the
Rust crate; it is not proved.
"""
