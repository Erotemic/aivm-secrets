"""EDIT HERE: the constrained-http profile run inside the guest (HP-6)."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

X = (-5.25, -1.75, 1.75, 5.25)
Y = 1.63


def _k(tool, translator, bridge, provider):
    return (Knowledge('tool', (X[0], -0.95), tool, 3.3, 2.75),
            Knowledge('translator', (X[1], -0.95), translator, 3.3, 2.75),
            Knowledge('bridge', (X[2], -0.95), bridge, 3.3, 2.75),
            Knowledge('provider', (X[3], -0.95), provider, 3.3, 2.75))


PLAN = Diagram(
    key='proof_constrained',
    title='Ordinary HTTPS as named operations',
    kicker='translate_round_trip: a target is accepted only if the host encoder writes it back exactly.',
    nodes=(
        Node('tool', 'Guest tool', 'curl / gh via HTTPS_PROXY', (X[0], Y), 2.6, 1.12, 'guest'),
        Node('translator', 'Translator', 'in the guest, no credential', (X[1], Y), 2.6, 1.12, 'guest'),
        Node('bridge', 'Host bridge', 'authorizes named ops', (X[2], Y), 2.6, 1.12, 'proved'),
        Node('provider', 'Provider', 'pinned HTTPS service', (X[3], Y), 2.6, 1.12, 'provider'),
    ),
    links=(
        Link('request', 'tool', 'translator', 'GET /repos/o/r/pulls/7', ((X[0]+1.31, Y), (X[1]-1.31, Y)), 'guest', label_xy=(-3.5, 2.3)),
        Link('invoke', 'translator', 'bridge', 'pr.diff {pr: 7}', ((X[1]+1.31, Y), (X[2]-1.31, Y)), 'guest', label_xy=(0, 2.3)),
        Link('send', 'bridge', 'provider', 'fill_target bytes', ((X[2]+1.31, Y), (X[3]-1.31, Y)), 'proved', label_xy=(3.5, 2.3)),
    ),
    beats=(
        Beat('request', 'A stock tool sends an ordinary request; it holds only a placeholder.',
             nodes=('tool', 'translator', 'bridge', 'provider'), links=('request',), packet='request',
             packet_label='Authorization: placeholder', status='implemented',
             knowledge=_k(('a placeholder', 'proxy token'),
                          ('route copy', '(public policy)'),
                          ('the credential',),
                          ('nothing yet',))),
        Beat('translate', 'The translator keeps arguments only if the host encoder rewrites the same target.',
             focus=('translator',), status='implemented',
             knowledge=_k(('waits',),
                          ('route_match::translate', 'translate_round_trip', 'else: unsupported'),
                          ('—',),
                          ('nothing yet',))),
        Beat('invoke', 'It asks the bridge for the named operation, like any guest tool.',
             links=('invoke',), packet='invoke', packet_label='operation + arguments', status='implemented',
             knowledge=_k(('waits',),
                          ('garrett-client invoke', 'arguments on stdin'),
                          ('authorizes on its', 'own policy'),
                          ('nothing yet',))),
        Beat('send', 'The host sends the operation; every byte of the target is the proved encoder output.',
             links=('send',), packet='send', packet_label='GET /repos/o/r/pulls/7', status='implemented',
             knowledge=_k(('waits',),
                          ('—',),
                          ('fill_target_exact', 'fill_target_safe', 'NR theorems'),
                          ('sees the real', 'credential once'))),
        Beat('tampered', 'A tampered route copy can only ask for another operation; the host still refuses.',
             focus=('bridge',), status='implemented',
             knowledge=_k(('gets a refusal',),
                          ('asks for gamma', '(not in host policy)'),
                          ('denies', '(host policy)'),
                          ('not contacted',))),
    ),
    footer='The guest gets the operation\'s disclosure, never the full provider response or the credential.',
)
