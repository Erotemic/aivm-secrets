"""EDIT HERE: where the credential goes in the credential-substitution proxy."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

X = (-5.25, -1.75, 1.75, 5.25)
Y = 1.63


def _k(guest, parser, encoder, provider):
    return (Knowledge('guest', (X[0], -0.95), guest, 3.3, 2.75),
            Knowledge('parser', (X[1], -0.95), parser, 3.3, 2.75),
            Knowledge('encoder', (X[2], -0.95), encoder, 3.3, 2.75),
            Knowledge('provider', (X[3], -0.95), provider, 3.3, 2.75))


PLAN = Diagram(
    key='proof_proxy',
    title='Where the proxy puts the credential',
    kicker='encode_upstream_contract: prefix (request only) ++ one verified auth line ++ suffix (request only).',
    nodes=(
        Node('guest', 'Guest tool', 'curl / gh via HTTPS_PROXY', (X[0], Y), 2.6, 1.12, 'guest'),
        Node('parser', 'Strict parser', 'parse_request', (X[1], Y), 2.6, 1.12, 'assumed'),
        Node('encoder', 'Upstream encoder', 'encode_upstream', (X[2], Y), 2.6, 1.12, 'proved'),
        Node('provider', 'Configured origin', 'pinned address, CA', (X[3], Y), 2.6, 1.12, 'provider'),
    ),
    links=(
        Link('send', 'guest', 'parser', 'any request bytes', ((X[0]+1.31, Y), (X[1]-1.31, Y)), 'guest', label_xy=(-3.5, 2.3)),
        Link('accept', 'parser', 'encoder', 'accepted request', ((X[1]+1.31, Y), (X[2]-1.31, Y)), 'assumed', label_xy=(0, 2.3)),
        Link('write', 'encoder', 'provider', 'canonical bytes', ((X[2]+1.31, Y), (X[3]-1.31, Y)), 'proved', label_xy=(3.5, 2.3)),
    ),
    beats=(
        Beat('input', 'The guest sends whatever it likes, with a placeholder credential.',
             nodes=('guest', 'parser', 'encoder', 'provider'), links=('send',), packet='send',
             packet_label='Authorization: placeholder', status='implemented',
             knowledge=_k(('Authorization: x', 'Cookie: y', 'X-Trace: t'),
                          ('strict subset', 'or refuse'),
                          ('waiting',),
                          ('nothing yet',))),
        Beat('filter', 'Fourteen field names are dropped, in order: every credential-bearing one.',
             focus=('encoder',), status='implemented',
             knowledge=_k(('unchanged',),
                          ('fields parsed', '(tested, not proved)'),
                          ('dropped_eq', 'forwarded_drops', 'X-Trace kept'),
                          ('nothing yet',))),
        Beat('encode', 'The secret enters exactly once: one verified line after every guest field.',
             links=('accept', 'write'), packet='write', packet_label='prefix + auth + suffix',
             status='implemented',
             knowledge=_k(('never sees', 'the secret'),
                          ('accepted',),
                          ('UpstreamPrefix(request)', 'Authorization: Bearer S', 'UpstreamSuffix(request)'),
                          ('one request',))),
        Beat('refuse', 'A deny-listed request or bad credential writes nothing at all.',
             focus=('encoder',), status='implemented',
             knowledge=_k(('POST /v1/tokens',),
                          ('accepted',),
                          ('refused', 'buffer unchanged'),
                          ('nothing sent',))),
        Beat('framing', 'The encoder re-checks every line itself: no CR or LF from the guest.',
             focus=('encoder',), status='implemented',
             knowledge=_k(('X-Evil: a\\r\\nAuth..',),
                          ('should refuse', '(not relied on)'),
                          ('clean_fields', 'check_target', 'refused otherwise'),
                          ('one line per field',))),
        Beat('reflect', 'A response carrying the credential is refused; released bytes never contain it.',
             focus=('provider', 'encoder'), status='implemented',
             knowledge=_k(('gets the response', 'or a fixed 502'),
                          ('—',),
                          ('reflects_spec', 'unwrapped_spec (no CR/LF)', 'guest_response_contract',
                           'raw form always listed'),
                          ('echoes S?', '-> refused'))),
        Beat('limits', 'Not confinement: the guest still has the credential\'s full authority.',
             focus=('provider',), status='assumed',
             knowledge=_k(('can mint new', 'credentials'),
                          ('framing not', 'relied on'),
                          ('proved',),
                          ('PROXY-AUTHORITY-01', 'PROXY-REFLECT-01', 'PROXY-PARSE-01'))),
    ),
    footer='Use named operations or constrained-http for broad credentials; this profile is for narrow ones.',
)
