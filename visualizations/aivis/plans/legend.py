"""EDIT HERE: plain/signed/encrypted/host-private visual vocabulary."""
from aivis.diagram import Beat, Diagram, Node

PLAN = Diagram(
    key='legend',
    title='How to read the drawings',
    kicker='A box shows what is stored or sent. A border tells you how it is protected.',
    nodes=(
        Node('plain','Readable','Anyone holding it may read it',(-5.04,0.25),2.50,1.48,'neutral'),
        Node('signed','Signed','Readable; tampering can be detected',(-1.68,0.25),2.50,1.48,'policy'),
        Node('encrypted','Encrypted','Ciphertext to parties without the key',(1.68,0.25),2.50,1.48,'guest'),
        Node('private','Host-only','Key or secret kept in host storage',(5.04,0.25),2.50,1.48,'secret'),
    ),
    links=(),
    beats=(
        Beat('plain','Readable is not the same as authorized.',nodes=('plain',),focus=('plain',)),
        Beat('signed','A signature protects authenticity, not secrecy.',nodes=('signed',),focus=('signed',)),
        Beat('encrypted','Encrypted data may be carried without being readable.',nodes=('encrypted',),focus=('encrypted',)),
        Beat('private','Host-only means controlled by the host; that still depends on OS isolation.',nodes=('private',),focus=('private',),status='assumed'),
    ),
    footer='A nested box is an explanatory cross-section; it does not imply plaintext is exposed.',
)
