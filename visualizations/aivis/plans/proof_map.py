"""EDIT HERE: which code each stage of one native read runs, proved or trusted."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

X = (-5.25, -1.75, 1.75, 5.25)
Y = 1.63


def _k(guest, core, native, provider):
    return (Knowledge('guest', (X[0], -0.95), guest, 3.3, 2.75),
            Knowledge('core', (X[1], -0.95), core, 3.3, 2.75),
            Knowledge('native', (X[2], -0.95), native, 3.3, 2.75),
            Knowledge('provider', (X[3], -0.95), provider, 3.3, 2.75))


PLAN = Diagram(
    key='proof_map',
    title='Proved code and trusted code in one read',
    kicker='Green: Aeneas-extracted Rust with Lean proofs. Amber: what those proofs trust (native code, the provider).',
    nodes=(
        Node('guest', 'Guest agent', 'untrusted requests', (X[0], Y), 2.6, 1.12, 'guest'),
        Node('core', 'Extracted core', 'Rust proved in Lean', (X[1], Y), 2.6, 1.12, 'proved'),
        Node('native', 'Native adapters', 'trusted Rust + std/TLS', (X[2], Y), 2.6, 1.12, 'assumed'),
        Node('provider', 'Provider API', 'HTTPS service', (X[3], Y), 2.6, 1.12, 'provider'),
    ),
    links=(
        Link('ask', 'guest', 'core', 'request', ((X[0]+1.31, 1.85), (X[1]-1.31, 1.85)), 'guest', label_xy=(-3.5, 2.3)),
        Link('emit', 'core', 'native', 'channel bytes', ((X[1]+1.31, 1.85), (X[2]-1.31, 1.85)), 'proved', label_xy=(0, 2.3)),
        Link('wire', 'native', 'provider', 'TLS write', ((X[2]+1.31, 1.85), (X[3]-1.31, 1.85)), 'assumed', label_xy=(3.5, 2.3)),
        Link('reply', 'provider', 'native', 'response', ((X[3]-1.31, 1.4), (X[2]+1.31, 1.4)), 'provider', label_xy=(3.5, 0.95)),
        Link('parsed', 'native', 'core', 'status + document', ((X[2]-1.31, 1.4), (X[1]+1.31, 1.4)), 'assumed', label_xy=(0, 0.95)),
        Link('frame', 'core', 'guest', 'one frame', ((X[1]-1.31, 1.4), (X[0]+1.31, 1.4)), 'proved', label_xy=(-3.5, 0.95)),
    ),
    beats=(
        Beat('admit', 'Admission is the extracted manifest::authorize over host state and the request.',
             nodes=('guest', 'core', 'native', 'provider'), links=('ask',), packet='ask',
             packet_label='typed request', status='implemented',
             knowledge=_k(('chooses operation', 'and arguments'),
                          ('manifest::authorize', 'current admission', 'ScopedRequest context'),
                          ('clock samples', 'lease callbacks', '(RUST-CLOCK-01)'),
                          ('not contacted yet',))),
        Beat('send', 'The core builds the channel and calls Channel::submit after its send gate.',
             links=('emit', 'wire'), packet='emit', packet_label='encoded request',
             status='implemented',
             knowledge=_k(('waits',),
                          ('channel_work::Submitting', 'begin_send gate', 'Channel::submit once'),
                          ('request_body wrapper', 'TCP/TLS connect', 'write_all, flush'),
                          ('receives exactly the', 'route-encoded request'))),
        Beat('respond', 'The core classifies the status; native code parses the body.',
             links=('reply', 'parsed'), packet='parsed', packet_label='status + document',
             status='assumed',
             knowledge=_k(('waits',),
                          ('provider_status::parse', 'manifest status class', 'response gate token'),
                          ('HTTP framing', 'serde_json parse', '(RUST-JSON-01)'),
                          ('any response,', 'possibly hostile'))),
        Beat('release', 'Projection, metadata, assembly, both reflection checks and the frame are extracted.',
             links=('frame',), packet='frame', packet_label='checked JSON line',
             status='implemented',
             knowledge=_k(('selected fields', 'or one fixed denial'),
                          ('selected_release::select', 'reflection checks', 'public_error frames'),
                          ('Reply::Released glue', '(NATIVE-GLUE-01)'),
                          ('sees nothing back',))),
        Beat('control', 'describe and renounce are decided in the core too, and never reach the provider.',
             links=('ask', 'frame'), packet='frame', packet_label='fixed reply shape',
             status='implemented',
             knowledge=_k(('describe / renounce',),
                          ('control::control', 'control_paths', 'revoked_record_exact'),
                          ('revoke, audit record,', 'deactivate callbacks', '(CONTROL-NATIVE-01)'),
                          ('not contacted',))),
        Beat('trust', 'What the proofs still trust is named and on the assumption roadmap.',
             focus=('native',), status='assumed',
             knowledge=_k(('—',),
                          ('Charon/Aeneas + Lean', '(RUST-COMPILER-01)'),
                          ('no other credential', 'write (NATIVE-SINK-01)', 'TLS/OS (RUST-HTTPS-01)'),
                          ('honours read-only', 'semantics (SPEC-02)'))),
    ),
    footer='Assumption IDs refer to docs/planning/aivm-secrets-assumption-roadmap.md. Not a whole-service proof.',
)
