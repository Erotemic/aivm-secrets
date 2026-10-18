"""A copied surrogate is useless without the victim's authenticated identity."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

L=(-4.82,-0.93); M=(0,-0.93); R=(4.82,-0.93)
def holdings(attacker, bridge, victim):
    return (Knowledge('attacker',L,tuple(attacker),3.76,2.72),
            Knowledge('bridge',M,tuple(bridge),3.76,2.72),
            Knowledge('victim',R,tuple(victim),3.76,2.72))

PLAN=Diagram(
    key='garrett_stolen',title='Garrett 4 / copying is not enough',
    kicker='Two certificates. One copied token. The identities must agree.',
    nodes=(
        Node('attacker','Other sandbox','Different client key',(-4.82,1.63),2.68,1.10,'guest',icon='sandbox'),
        Node('bridge','Host TLS bridge','Compares peer to claim',(0,1.63),2.68,1.10,'broker',icon='host'),
        Node('victim','Original client','Cert A and its private key',(4.82,1.63),2.68,1.10,'policy',icon='certificate'),
    ),
    links=(
        Link('copy','victim','attacker','copied surrogate',((3.47,1.31),(3.07,0.99),(-3.06,0.99),(-3.47,1.31)),
             'guest',dashed=True,label_xy=(0,0.79)),
        Link('attempt','attacker','bridge','cert B + token for A',((-3.47,1.63),(-1.35,1.63)),
             'guest',label_xy=(-2.43,2.08)),
        Link('denial','bridge','attacker','denied',((-1.35,1.3),(-3.47,1.3)),
             'secret',label_xy=(-2.42,0.91)),
    ),
    beats=(
        Beat('start','The original client has a surrogate bound to certificate A.',
             nodes=('attacker','bridge','victim'),
             knowledge=holdings(['certificate B','private signing key B'],
                                ['registry: cert A and cert B','host issuer keys'],
                                ['certificate A','private signing key A','surrogate bound to A']),status='implemented'),
        Beat('copy','An adversary copies the surrogate bytes; it does not get client A\'s private key.',
             links=('copy',),packet='copy',packet_label='copy of token A',
             knowledge=holdings(['copied surrogate A','private key B, not A'],
                                ['enrollment records'],
                                ['surrogate A','private signing key A']),status='assumed'),
        Beat('attempt','The copy is presented on a TLS connection authenticated by certificate B.',
             links=('attempt',),packet='attempt',packet_label='token A + cert B',
             knowledge=holdings(['token A','can sign only as B'],
                                ['actual TLS peer B','surrogate claim A'],
                                ['original client key A']),status='implemented'),
        Beat('reject','The thumbprints differ. Reject before unsealing or credential use.',
             focus=('bridge',),
             knowledge=holdings(['denial (no bearer)','still has copied token'],
                                ['peer B != token binding A','no inner unseal','no provider dispatch'],
                                ['private key A remains here']),status='implemented'),
        Beat('report','The bridge returns denial; ciphertext possession alone is not permission.',
             links=('denial',),packet='denial',packet_label='denied',
             knowledge=holdings(['denied','no host credential'],
                                ['identity mismatch','host credential unaffected'],
                                ['surrogate A still valid for A']),status='implemented'),
    ),
    footer='Assumes the attacker cannot authenticate as A or invoke A\'s signing oracle. Not a statement about host compromise.',
)
