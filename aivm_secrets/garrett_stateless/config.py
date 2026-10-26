"""Configuration files (spec sections 11 and 12), accepted exactly as the
Rust crate accepts them. Relative paths resolve against the file's directory."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import encoding as enc
from .files import read_public
from .token import ClaimCopy

PROVIDER_SCHEMA = 'garrett-stateless-v1/provider'
BROKER_SCHEMA = 'garrett-stateless-v1/broker'
PROXY_SCHEMA = 'garrett-stateless-v1/proxy'


class ConfigError(ValueError):
    pass


class _Fields:
    def __init__(self, value: Any, what: str, base: Path, required: set[str], optional: set[str]):
        if not isinstance(value, dict):
            raise ConfigError(f'{what} is not an object')
        missing = required - set(value)
        unknown = set(value) - required - optional
        if missing:
            raise ConfigError(f'{what}: {sorted(missing)[0]} missing')
        if unknown:
            raise ConfigError(f'{what}: unknown member {sorted(unknown)[0]}')
        self.map, self.what, self.base = value, what, base

    def present(self, name: str) -> Any:
        value = self.map.get(name)
        return None if value is None else value

    def string(self, name: str) -> str:
        value = self.present(name)
        if not isinstance(value, str):
            raise ConfigError(f'{self.what}: {name} must be a string')
        return value

    def optional_string(self, name: str) -> str | None:
        return None if self.present(name) is None else self.string(name)

    def checked(self, name: str, valid) -> str:
        value = self.string(name)
        if not valid(value):
            raise ConfigError(f'{self.what}: invalid {name}')
        return value

    def int(self, name: str, default: int, low: int, high: int) -> int:
        value = self.present(name)
        if value is None:
            value = default
        if type(value) is not int:
            raise ConfigError(f'{self.what}: {name} must be an integer')
        if not low <= value <= high:
            raise ConfigError(f'{self.what}: {name} must be in {low}..={high}')
        return value

    def path(self, name: str) -> Path:
        return self.base / self.string(name)

    def optional_path(self, name: str) -> Path | None:
        text = self.optional_string(name)
        return None if text is None else self.base / text

    def strings(self, name: str) -> list[str]:
        value = self.present(name)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f'{self.what}: {name} must be an array of strings')
        return list(value)


def _load(path: Path, schema: str) -> tuple[dict, Path]:
    path = Path(path)
    try:
        value = enc.parse(read_public(path, 1 << 20), 1 << 20, 16)
    except enc.JsonError:
        raise ConfigError(f'{path}: not strict JSON') from None
    if not isinstance(value, dict) or value.get('schema') != schema:
        raise ConfigError(f'{path}: schema must be {schema}')
    return value, path.parent


def _host_ok(host: str) -> bool:
    return bool(host) and all(c.isascii() and (c.isalnum() or c in '.-') for c in host)


@dataclass(frozen=True)
class HttpsUrl:
    host: str
    port: int
    path: str

    @classmethod
    def parse(cls, text: str) -> 'HttpsUrl':
        if not text.startswith('https://'):
            raise ConfigError('endpoint must be https')
        rest = text[len('https://'):]
        if any(c in rest for c in '?#@ '):
            raise ConfigError('endpoint must not have a query, fragment or user')
        authority, slash, path = rest.partition('/')
        path = '/' + path if slash else '/'
        host, colon, port = authority.rpartition(':')
        if not colon:
            host, port = authority, '443'
        if not port.isdigit() or not 0 <= int(port) <= 65535:
            raise ConfigError('bad port')
        if not _host_ok(host):
            raise ConfigError('bad host')
        return cls(host.lower(), int(port), path)

    def authority(self) -> str:
        return self.host if self.port == 443 else f'{self.host}:{self.port}'

    def url(self) -> str:
        return f'https://{self.authority()}{self.path}'


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    authorization_url: HttpsUrl
    token_url: HttpsUrl
    client_id: str
    scopes: tuple[str, ...]
    default_scope: str
    token_address: str | None = None
    token_ca_file: Path | None = None
    client_secret_file: Path | None = None
    issuer: str | None = None
    copy_claims: ClaimCopy = field(default_factory=ClaimCopy)

    @classmethod
    def load(cls, path: Path) -> 'ProviderConfig':
        value, base = _load(path, PROVIDER_SCHEMA)
        f = _Fields(value, 'provider', base,
                    {'authorization_url', 'client_id', 'default_scope', 'name', 'schema', 'scopes', 'token_url'},
                    {'client_secret_file', 'copy_claims', 'issuer', 'token_address', 'token_ca_file'})
        scopes = f.strings('scopes')
        if len(scopes) > 64 or not all(s and ' ' not in s and enc.is_scope(s) for s in scopes):
            raise ConfigError('provider: invalid scopes')
        copy = f.present('copy_claims')
        if copy is None:
            copy_claims = ClaimCopy('access')
        elif copy == 'all':
            copy_claims = ClaimCopy('all')
        elif isinstance(copy, list):
            copy_claims = ClaimCopy(f.strings('copy_claims'))
        else:
            raise ConfigError('provider: copy_claims must be null, "all" or a list of names')
        issuer = f.optional_string('issuer')
        if issuer is not None and not enc.is_text(issuer):
            raise ConfigError('provider: invalid issuer')
        provider = cls(
            name=f.checked('name', enc.is_provider),
            authorization_url=HttpsUrl.parse(f.string('authorization_url')),
            token_url=HttpsUrl.parse(f.string('token_url')),
            client_id=f.checked('client_id', enc.is_text),
            scopes=tuple(scopes), default_scope=f.string('default_scope'),
            token_address=f.optional_string('token_address'), token_ca_file=f.optional_path('token_ca_file'),
            client_secret_file=f.optional_path('client_secret_file'), issuer=issuer, copy_claims=copy_claims,
        )
        provider.requested_scope(None)
        return provider

    def requested_scope(self, requested: str | None) -> str:
        scope = self.default_scope if requested is None else requested
        if not enc.is_scope(scope) or not all(s in self.scopes for s in scope.split(' ') if s):
            raise ConfigError('invalid_scope')
        return scope


@dataclass(frozen=True)
class BrokerConfig:
    issuer: str
    audience: str
    replica: str
    agent_listen: str
    browser_listen: str
    public_url: HttpsUrl
    certificate: Path
    private_key: Path
    agent_ca: Path
    keys: Path
    providers: tuple[ProviderConfig, ...]
    max_lifetime: int = 3600
    max_renew: int = 604800
    login_ttl: int = 600

    @classmethod
    def load(cls, path: Path) -> 'BrokerConfig':
        value, base = _load(path, BROKER_SCHEMA)
        f = _Fields(value, 'broker', base,
                    {'agent_ca', 'agent_listen', 'audience', 'browser_listen', 'certificate', 'issuer', 'keys',
                     'private_key', 'providers', 'public_url', 'replica', 'schema'},
                    {'login_ttl', 'max_lifetime', 'max_renew'})
        public_url = HttpsUrl.parse(f.string('public_url'))
        if not public_url.path.endswith('/'):
            raise ConfigError('broker: public_url must end with /')
        providers = tuple(ProviderConfig.load(base / p) for p in f.strings('providers'))
        if not 1 <= len(providers) <= 16:
            raise ConfigError('broker: between 1 and 16 providers')
        if len({p.name for p in providers}) != len(providers):
            raise ConfigError('broker: duplicate provider names')
        return cls(
            issuer=f.checked('issuer', enc.is_text), audience=f.checked('audience', enc.is_text),
            replica=f.checked('replica', enc.is_kid), agent_listen=f.string('agent_listen'),
            browser_listen=f.string('browser_listen'), public_url=public_url,
            certificate=f.path('certificate'), private_key=f.path('private_key'), agent_ca=f.path('agent_ca'),
            keys=f.path('keys'), providers=providers,
            max_lifetime=f.int('max_lifetime', 3600, 1, 86400), max_renew=f.int('max_renew', 604800, 0, 2592000),
            login_ttl=f.int('login_ttl', 600, 1, 600),
        )


@dataclass(frozen=True)
class RouteConfig:
    provider: str
    host: str
    address: str
    port: int
    authentication: str
    ca_file: Path | None
    deny: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ProxyConfig:
    listen: str
    authority: str
    certificate: Path
    private_key: Path
    client_ca: Path
    keys: Path
    audiences: tuple[str, ...]
    routes: tuple[RouteConfig, ...]
    max_lifetime: int = 3600
    skew: int = 60
    request_limit: int = 1 << 20
    audit: Path | None = None

    @classmethod
    def load(cls, path: Path) -> 'ProxyConfig':
        value, base = _load(path, PROXY_SCHEMA)
        f = _Fields(value, 'proxy', base,
                    {'audiences', 'authority', 'certificate', 'client_ca', 'keys', 'listen', 'private_key',
                     'routes', 'schema'},
                    {'audit', 'max_lifetime', 'request_limit', 'skew'})
        audiences = f.strings('audiences')
        if not 1 <= len(audiences) <= 16 or not all(enc.is_text(a) for a in audiences):
            raise ConfigError('proxy: invalid audiences')
        items = f.present('routes')
        if not isinstance(items, list):
            raise ConfigError('proxy: routes must be an array')
        routes = tuple(_route(item, base) for item in items)
        if not 1 <= len(routes) <= 16:
            raise ConfigError('proxy: between 1 and 16 routes')
        if len({r.provider for r in routes}) != len(routes):
            raise ConfigError('proxy: duplicate route providers')
        authority = f.string('authority').lower()
        if not authority or not all(c.isascii() and (c.isalnum() or c in '.-:') for c in authority):
            raise ConfigError('proxy: invalid authority')
        return cls(
            listen=f.string('listen'), authority=authority, certificate=f.path('certificate'),
            private_key=f.path('private_key'), client_ca=f.path('client_ca'), keys=f.path('keys'),
            audiences=tuple(audiences), routes=routes, max_lifetime=f.int('max_lifetime', 3600, 1, 86400),
            skew=f.int('skew', 60, 0, 300), request_limit=f.int('request_limit', 1 << 20, 1, 16 << 20),
            audit=f.optional_path('audit'),
        )


def _route(value: Any, base: Path) -> RouteConfig:
    f = _Fields(value, 'route', base, {'authentication', 'host', 'provider'}, {'address', 'ca_file', 'deny', 'port'})
    host = f.string('host').lower()
    if not _host_ok(host):
        raise ConfigError('route: invalid host')
    authentication = f.string('authentication')
    if authentication not in ('bearer', 'api-key'):
        raise ConfigError('route: authentication must be bearer or api-key')
    deny = []
    for rule in f.present('deny') or []:
        r = _Fields(rule, 'deny rule', base, {'path'}, {'method'})
        path = r.string('path')
        if not path.startswith('/'):
            raise ConfigError('deny rule: path must start with /')
        deny.append((r.optional_string('method') or '', path))
    return RouteConfig(
        provider=f.checked('provider', enc.is_provider), host=host,
        address=f.optional_string('address') or host, port=f.int('port', 443, 1, 65535),
        authentication=authentication, ca_file=f.optional_path('ca_file'), deny=tuple(deny),
    )
