"""P2 provider independence: a second, differently shaped HTTPS service.

The same generic native manifest path (no provider-specific Rust) serves a
package-registry-shaped API with x-api-key authentication, nested selection
and pagination. Synthetic credential only; the provider is a local TLS
service that records exactly what it received.
"""

import subprocess

import pytest

from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory
from tests.test_rust_invoke import client_config, invoke

HOST = "registry.example.net"


def registry_policy(directory, server=None):
    result = dict(
        schema=2,
        adapter="https",
        service="packages",
        host=HOST,
        authentication="x-api-key",
        credential_source=dict(kind="file", path=str(directory / "credential")),
        lifetime_seconds=300,
        max_requests=50,
        max_body_bytes=100,
        operations=[
            dict(name="package.view", effect="read", method="GET",
                 path="/api/packages/{name}", parameters={"name": ["alpha", "beta"]}),
            dict(name="release.list", effect="read", method="GET",
                 path="/api/packages/{name}/releases",
                 parameters={"name": ["alpha", "beta"], "page": {"min": 1, "max": 5}},
                 query={"page": "{page}"},
                 page={"size": 3, "at": ["releases"], "parameter": "page"}),
        ],
    )
    if server is not None:
        result["egress"] = dict(
            address="127.0.0.1", port=server.port, ca_file=str(server.files["ca"])
        )
    return result


def registry_disclosure():
    text = lambda *at: {"at": list(at), "type": "text"}
    return {
        "package.view": {
            "name": text("name"),
            "latest": text("latest", "version"),
            "downloads": {"at": ["stats", "downloads"], "type": "integer"},
        },
        "release.list": {
            "releases": {"at": ["releases"], "type": "array", "max_items": 3,
                         "items": {"at": [], "type": "object",
                                   "fields": {"version": text("version")}}},
        },
    }


@pytest.fixture
def registry(tmp_path):
    with TLSService(provider_directory(tmp_path), host=HOST) as provider:
        provider.routes[("GET", "/api/packages/alpha")] = {
            "name": "alpha",
            "latest": {"version": "2.1.0", "yanked_by": "maintainer@example.org"},
            "stats": {"downloads": 1234, "private_score": 0.93},
            "owner_token_echo": TOKEN,
        }
        provider.routes[("GET", "/api/packages/alpha/releases?page=2")] = {
            "releases": [{"version": v, "sha": "private"} for v in ("1.0", "1.1", "2.0")],
            "internal": TOKEN,
        }
        p = registry_policy(tmp_path, provider)
        with ManifestCase(tmp_path, provider, p, releases=registry_disclosure(),
                          authentication="x-api-key") as case:
            yield provider, case


def test_second_service_selected_read_uses_its_own_authentication(registry):
    provider, case = registry
    reply = invoke(client_config(case), "package.view", "--arguments", '{"name":"alpha"}')
    assert reply == {"version": 1, "ok": True,
                     "result": {"downloads": 1234, "latest": "2.1.0", "name": "alpha"}}
    [sent] = provider.seen()
    assert (sent["method"], sent["target"]) == ("GET", "/api/packages/alpha")
    assert sent["headers"]["x-api-key"] == TOKEN
    assert "authorization" not in sent["headers"]
    assert TOKEN.encode() not in codec.dumps(reply)


def test_second_service_pagination_metadata_is_the_declassified_row_count(registry):
    provider, case = registry
    reply = invoke(client_config(case), "release.list",
                   "--arguments", '{"name":"alpha","page":2}')
    assert reply == {
        "version": 1, "ok": True,
        "meta": {"pagination": {"page": 2, "per_page": 3, "possibly_more": True}},
        "result": {"releases": [{"version": "1.0"}, {"version": "1.1"}, {"version": "2.0"}]},
    }
    [sent] = provider.seen()
    assert sent["target"] == "/api/packages/alpha/releases?page=2"
    assert TOKEN.encode() not in codec.dumps(reply)


@pytest.mark.parametrize("operation,arguments", [
    ("package.view", '{"name":"gamma"}'),
    ("release.list", '{"name":"alpha","page":9}'),
    ("package.delete", '{"name":"alpha"}'),
])
def test_second_service_out_of_scope_requests_never_reach_the_provider(
    registry, operation, arguments
):
    provider, case = registry
    done = subprocess.run([*client_config(case), "invoke", operation, "--arguments", arguments],
                          capture_output=True, timeout=15)
    assert done.returncode != 0 or not codec.loads(done.stdout)["ok"]
    assert TOKEN.encode() not in done.stdout + done.stderr
    assert provider.seen() == []
