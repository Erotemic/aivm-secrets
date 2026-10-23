"""EDIT HERE: what a successful read frame is, and what a denial frame is."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

X = (-5.25, -1.75, 1.75, 5.25)
Y = 1.63


def _k(document, release, checks, guest):
    return (Knowledge('document', (X[0], -0.95), document, 3.3, 2.75),
            Knowledge('release', (X[1], -0.95), release, 3.3, 2.75),
            Knowledge('checks', (X[2], -0.95), checks, 3.3, 2.75),
            Knowledge('guest', (X[3], -0.95), guest, 3.3, 2.75))


PLAN = Diagram(
    key='proof_release',
    title='What the guest receives',
    kicker='production_read_frame and denial_frame_exact: the frame is a checked encoding or one of 17 fixed lines.',
    nodes=(
        Node('document', 'Provider document', 'parsed response', (X[0], Y), 2.6, 1.12, 'provider'),
        Node('release', 'Extracted release', 'selected_release', (X[1], Y), 2.6, 1.12, 'proved'),
        Node('checks', 'Reflection checks', 'decoded text + bytes', (X[2], Y), 2.6, 1.12, 'proved'),
        Node('guest', 'Guest frame', 'one JSON line', (X[3], Y), 2.6, 1.12, 'guest'),
    ),
    links=(
        Link('select', 'document', 'release', 'project_fields', ((X[0]+1.31, 1.63), (X[1]-1.31, 1.63)), 'proved', label_xy=(-3.5, 2.3)),
        Link('check', 'release', 'checks', 'assembled reply', ((X[1]+1.31, 1.63), (X[2]-1.31, 1.63)), 'proved', label_xy=(0, 2.3)),
        Link('emit', 'checks', 'guest', 'bytes + newline', ((X[2]+1.31, 1.63), (X[3]-1.31, 1.63)), 'proved', label_xy=(3.5, 2.3)),
    ),
    beats=(
        Beat('select', 'Only host-schema paths are projected; everything else is left behind.',
             nodes=('document', 'release', 'checks', 'guest'), links=('select',), packet='select',
             packet_label='selected fields', status='implemented',
             knowledge=_k(('selected paths', 'unselected fields', 'maybe credential echo'),
                          ('host schema fields', 'pagination metadata', '{meta?,ok,result,version}'),
                          ('waiting',), ('nothing yet',))),
        Beat('check', 'Both checks run on the exact reply that will be released.',
             links=('check',), packet='check', packet_label='assembled reply', status='implemented',
             knowledge=_k(('unchanged',),
                          ('reply handed over', 'by value'),
                          ('no decoded key/string', 'contains the credential', 'nor do the bytes'),
                          ('nothing yet',))),
        Beat('emit', 'The frame is exactly the checked encoding plus one newline.',
             links=('emit',), packet='emit', packet_label='JSON line', status='implemented',
             knowledge=_k(('unchanged',), ('done',),
                          ('bytes passed',),
                          ('selected data', 'credential-free bytes', 'for any document'))),
        Beat('deny', 'Any refusal becomes one of 17 fixed lines that depend only on the error class.',
             focus=('guest',), status='implemented',
             knowledge=_k(('irrelevant to', 'the denial bytes'),
                          ('Err(class)',),
                          ('public_error table',),
                          ('{"error":{"code":..,', '"message":..},', '"ok":false,"version":1}'))),
    ),
    footer='A selected field can still be harmful content; the proof is about credentials and unselected data.',
)
