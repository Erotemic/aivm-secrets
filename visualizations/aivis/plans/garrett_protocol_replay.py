"""Distinguish network access to an honest proxy from proxy compromise."""
from aivis.diagram import Beat, Diagram, Link, Node
from aivis.plans.garrett_protocol_helpers import knowledge

PLAN=Diagram(
    key='gp_replay',title='Garrett / stolen surrogate',
    kicker='Attacker has S and network access. The honest proxy still rejects certificate B.',
    nodes=(
        Node('agent','Agent A','Holds S + skA',(-4.68,1.82),3.02,1.08,'guest',icon='sandbox'),
        Node('attacker','Attacker B','Copied S, not skA',(0,1.82),3.02,1.08,'secret',icon='host'),
        Node('proxy','Honest proxy','Enforces cert binding',(4.68,1.82),3.02,1.08,'broker',icon='host'),
    ),
    links=(
        Link('steal','agent','attacker','S copied',((-3.17,1.82),(-1.51,1.82)),'secret',label_xy=(-2.35,2.24)),
        Link('replay','attacker','proxy','S + cert B',((1.51,1.82),(3.17,1.82)),'secret',label_xy=(2.35,2.24)),
    ),
    beats=(
        Beat('copy','An attacker tricks an agent into disclosing surrogate S (but not its private key skA).',
             nodes=('agent','attacker','proxy'),links=('steal',),packet='steal',packet_label='stolen S',
             knowledge=knowledge(['S + skA','cert A'],['Stolen S','No skA','Can reach proxy'],
                                 ['Kseal + pkIssuer','Requires valid mTLS'],names=('agent','attacker','proxy')),status='explainer'),
        Beat('submit','The attacker submits S over an authenticated TLS connection as client B.',
             links=('replay',),packet='replay',packet_label='S, mTLS cert B',
             knowledge=knowledge(['Still holds skA'],['Stolen S','skB + cert B','No skA'],
                                 ['S has cnf(cert A)','Actual TLS peer is B'],names=('agent','attacker','proxy')),status='explainer'),
        Beat('deny','Signed cnf says A, TLS peer is B; the honest proxy rejects before decrypting.',
             focus=('proxy',),
             knowledge=knowledge(['No credential disclosed'],['Cannot use S as B'],
                                 ['cert B != cnf(cert A)','Reject BEFORE unsealing','No upstream request'],
                                 names=('agent','attacker','proxy')),status='explainer'),
    ),
    footer='mTLS stops stolen-surrogate replay through an honest proxy, assuming skA was not also compromised.',
)
