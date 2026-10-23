"""EDIT HERE: the exact-write gate in front of the production controller."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

X = (-5.25, -1.75, 1.75, 5.25)
Y = 1.63


def _k(guest, approval, gate, provider):
    return (Knowledge('guest', (X[0], -0.95), guest, 3.3, 2.75),
            Knowledge('approval', (X[1], -0.95), approval, 3.3, 2.75),
            Knowledge('gate', (X[2], -0.95), gate, 3.3, 2.75),
            Knowledge('provider', (X[3], -0.95), provider, 3.3, 2.75))


PLAN = Diagram(
    key='proof_write_gate',
    title='When a write may run',
    kicker='production_write_has_approval_and_authorized_attempts: no Allowed decision, no controller.',
    nodes=(
        Node('guest', 'Guest request', 'named write + args', (X[0], Y), 2.6, 1.12, 'guest'),
        Node('approval', 'Approval decision', 'approval::consume', (X[1], Y), 2.6, 1.12, 'proved'),
        Node('gate', 'Write gate', 'write_gate::run_approved', (X[2], Y), 2.6, 1.12, 'proved'),
        Node('provider', 'Controller + provider', 'run_current', (X[3], Y), 2.6, 1.12, 'provider'),
    ),
    links=(
        Link('ask', 'guest', 'approval', 'request digest', ((X[0]+1.31, Y), (X[1]-1.31, Y)), 'guest', label_xy=(-3.5, 2.3)),
        Link('decide', 'approval', 'gate', 'Allowed / Denied / Required', ((X[1]+1.31, Y), (X[2]-1.31, Y)), 'proved', label_xy=(0, 2.3)),
        Link('run', 'gate', 'provider', 'only on Allowed', ((X[2]+1.31, Y), (X[3]-1.31, Y)), 'proved', label_xy=(3.5, 2.3)),
    ),
    beats=(
        Beat('approve', 'In approve mode a write needs a matching, unexpired host approval.',
             nodes=('guest', 'approval', 'gate', 'provider'), links=('ask', 'decide'), packet='decide',
             packet_label='Allowed', status='implemented',
             knowledge=_k(('POST comment #23',), ('digest matches', 'not expired', 'slot consumed'),
                          ('waiting',), ('nothing yet',))),
        Beat('run', 'Only an Allowed decision reaches the controller; attempts stay authorized and audited.',
             links=('run',), packet='run', packet_label='one write', status='implemented',
             knowledge=_k(('—',), ('slot now empty',), ('Ran(result)',),
                          ('authorized, audited,', 'bound, not retried'))),
        Beat('refuse', 'Denied or Required returns at once: no dispatch, no provider attempt.',
             focus=('gate',), status='implemented',
             knowledge=_k(('same request again',), ('Required (spent)',), ('Required', 'controller untouched'),
                          ('nothing sent',))),
        Beat('limits', 'Assumed: the session passes this request\'s own decision; provider write semantics.',
             focus=('approval',), status='assumed',
             knowledge=_k(('—',), ('APPROVAL-RUST-01',), ('proved',), ('COORD-RUST-01',))),
    ),
    footer='The gate is the session\'s only call of the production controller.',
)
