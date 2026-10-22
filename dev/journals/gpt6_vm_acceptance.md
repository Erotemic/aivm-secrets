## 2026-10-21 20:40 -0400

Implemented a separate, opt-in OUT-2 native operator/VM fixture and documented its
limits. The real client makes its key inside the VM; public CSR travels to the
native authority, while the provider credential, broker and HTTPS provider stay
under a new private `/tmp` host workspace. An SSH remote Unix-socket forward
carries only the existing mTLS protocol and deliberately does not change
firewall rules or forward an SSH agent. A new random synthetic credential is
created per run so the value is not present in source material attached to the
VM. The fixture fails closed when AIVM has no exact matching VM, SSH identity
or reachable KVM guest, or when forwarding cannot be created with private
socket permissions.

This is the first live VM experiment, not an accepted result: the test has not
been run on the maintainer's actual `aivm-2404` at the time this entry was
written. Initial success and error-path checks are portable only. Future work
must address forbidden egress to a reachable test endpoint, identity rejection,
real adapter lifecycle, and broad host filesystem/sink inventory. Do not
mistake an SSH transport or a handful of negative file probes for a formal
isolation guarantee.
