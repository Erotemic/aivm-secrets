"""EDIT HERE: same public reply text, two different hidden credentials."""
from aivis.diagram import Beat, Diagram, Link, Node

PLAN=Diagram(
    key='reflection',
    title='What if GitHub sends the secret back?',
    kicker='Two runs with identical requested text, but different hidden bearer tokens.',
    nodes=(
        Node('token_a','Host credential A','TOKEN_A (not sent to guest)',(-5.05,1.22),2.90,1.15,'secret'),
        Node('body_a','Provider text','contains TOKEN_A',(-0.35,1.22),3.10,1.15,'provider'),
        Node('denied','Guest sees','denied: no content',(4.75,1.22),3.02,1.15,'secret'),
        Node('token_b','Host credential B','TOKEN_B (not sent to guest)',(-5.05,-1.15),2.90,1.15,'secret'),
        Node('body_b','Same provider text','still contains TOKEN_A',(-0.35,-1.15),3.10,1.15,'provider'),
        Node('allowed','Guest sees','allowed text',(4.75,-1.15),3.02,1.15,'guest'),
    ),
    links=(
        Link('a1','token_a','body_a','compared locally',((-3.58,1.22),(-1.94,1.22)),'policy',label_xy=(-2.75,1.65)),
        Link('a2','body_a','denied','literal match',((1.23,1.22),(3.21,1.22)),'secret',label_xy=(2.22,1.65)),
        Link('b1','token_b','body_b','compared locally',((-3.58,-1.15),(-1.94,-1.15)),'policy',label_xy=(-2.72,-0.71)),
        Link('b2','body_b','allowed','no literal match',((1.23,-1.15),(3.21,-1.15)),'guest',label_xy=(2.18,-0.71)),
    ),
    beats=(
        Beat('match','If selected text literally contains the host credential, the broker denies it.',
             nodes=('token_a','body_a','denied'),links=('a1','a2'),focus=('denied',),status='implemented'),
        Beat('different','With a different credential, the same text can be allowed.',
             nodes=('token_b','body_b','allowed'),links=('b1','b2'),focus=('allowed',),status='implemented'),
        Beat('observable','The guest can see allow vs deny. A proof must not pretend that bit is hidden.',
             focus=('denied','allowed'),status='open'),
    ),
    footer='Literal reflection guard is in code. Whether the denial itself reveals a useful secret is threat-model dependent.',
)
