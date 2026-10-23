"""EDIT HERE: how a provider attempt's bytes are pinned to the captured route."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

X = (-5.25, -1.75, 1.75, 5.25)
Y = 1.63


def _k(route, channel, writer, provider):
    return (Knowledge('route', (X[0], -0.95), route, 3.3, 2.75),
            Knowledge('channel', (X[1], -0.95), channel, 3.3, 2.75),
            Knowledge('writer', (X[2], -0.95), writer, 3.3, 2.75),
            Knowledge('provider', (X[3], -0.95), provider, 3.3, 2.75))


PLAN = Diagram(
    key='proof_send',
    title='Which bytes can reach the provider',
    kicker='exchange_send_writes_route_body: every exchange that reaches send writes its own route-encoded request.',
    nodes=(
        Node('route', 'Captured route', 'ScopedRequest context', (X[0], Y), 2.6, 1.12, 'policy'),
        Node('channel', 'Core channel', 'channel_work + provider_io', (X[1], Y), 2.6, 1.12, 'proved'),
        Node('writer', 'Native writer', 'write_all / flush', (X[2], Y), 2.6, 1.12, 'assumed'),
        Node('provider', 'Provider', 'authenticated TLS peer', (X[3], Y), 2.6, 1.12, 'provider'),
    ),
    links=(
        Link('encode', 'route', 'channel', 'encode, then connect', ((X[0]+1.31, 1.63), (X[1]-1.31, 1.63)), 'proved', label_xy=(-3.5, 2.3)),
        Link('submit', 'channel', 'writer', 'exact bytes, once', ((X[1]+1.31, 1.63), (X[2]-1.31, 1.63)), 'proved', label_xy=(0, 2.3)),
        Link('deliver', 'writer', 'provider', 'TLS records', ((X[2]+1.31, 1.63), (X[3]-1.31, 1.63)), 'assumed', label_xy=(3.5, 2.3)),
    ),
    beats=(
        Beat('setup', 'Setup encodes the request for the captured route before connecting.',
             nodes=('route', 'channel', 'writer', 'provider'), links=('encode',), packet='encode',
             packet_label='request_body(route)', status='implemented',
             knowledge=_k(('host, port, method,', 'path fixed by host'),
                          ('fresh channel', 'attempted = false', 'body = encoded request'),
                          ('connected stream', 'no bytes written'),
                          ('handshake only',))),
        Beat('gate', 'The send gate needs current admission and an acknowledged audit record.',
             focus=('channel',), status='implemented',
             knowledge=_k(('unchanged',),
                          ('begin_send(phase)', 'current stamp checked', 'audit acknowledged'),
                          ('still nothing sent',),
                          ('waiting',))),
        Beat('submit', 'Channel::submit hands exactly the body bytes to write_all, once.',
             links=('submit', 'deliver'), packet='submit', packet_label='encoded request',
             status='implemented',
             knowledge=_k(('unchanged',),
                          ('attempted = true', 'ready only after flush'),
                          ('write_all(body bytes)', 'flush'),
                          ('one authorized request',))),
        Beat('replay', 'A spent channel refuses another submit; no second write is attempted.',
             focus=('channel',), status='implemented',
             knowledge=_k(('unchanged',),
                          ('replay -> refused', 'no writer callback'),
                          ('not called again',),
                          ('nothing new',))),
        Beat('trusted', 'Assumed: native code makes no other write of credential bytes.',
             focus=('writer',), status='assumed',
             knowledge=_k(('—',),
                          ('proved up to the', 'writer callback'),
                          ('NATIVE-SINK-01', 'RUST-HTTPS-01'),
                          ('TLS delivery is', 'a library contract'))),
    ),
    footer='write_all may accept a prefix and then fail; that is an attempt, never a silent retry.',
)
