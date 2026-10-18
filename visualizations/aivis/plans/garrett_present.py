"""Garrett surrogate presentation: TLS peer binding before unsealing."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

L=(-4.82,-0.93); M=(0,-0.93); R=(4.82,-0.93)
def holdings(client, bridge, broker):
    return (Knowledge('client',L,tuple(client),3.76,2.72),
            Knowledge('bridge',M,tuple(bridge),3.76,2.72),
            Knowledge('broker',R,tuple(broker),3.76,2.72))

PLAN=Diagram(
    key='garrett_present',title='Garrett 3 / present and open',
    kicker='The client signs the TLS handshake. The surrogate must match that peer.',
    nodes=(
        Node('client','Agent sandbox','TLS client cert + surrogate',(-4.82,1.63),2.68,1.10,'guest',icon='sandbox'),
        Node('bridge','Host TLS bridge','Checks actual peer', (0,1.63),2.68,1.10,'broker',icon='host'),
        Node('broker','Host broker','Authorized credential use',(4.82,1.63),2.68,1.10,'policy',icon='vault'),
    ),
    links=(
        Link('present','client','bridge','TLS + surrogate',((-3.47,1.63),(-1.35,1.63)),
             'guest',label_xy=(-2.41,2.08)),
        Link('open','bridge','broker','bound inner capability',((1.35,1.63),(3.47,1.63)),
             'broker',label_xy=(2.45,2.08)),
        Link('reply','broker','client','public reply',((3.47,1.15),(3.1,0.94),(-3.05,0.94),(-3.47,1.15)),
             'guest',label_xy=(0,0.83)),
    ),
    beats=(
        Beat('peer','The client proves control of its enrolled signing key during TLS.',
             nodes=('client','bridge','broker'),
             knowledge=holdings(['client private key','public certificate','opaque surrogate'],
                                ['TLS peer identity','current enrollment registry'],
                                ['provider credential','host inner-capability keys']),status='implemented'),
        Beat('present','The client sends the surrogate on that authenticated connection.',
             links=('present',),packet='present',packet_label='surrogate',
             knowledge=holdings(['surrogate and request','no bearer token'],
                                ['actual TLS peer thumbprint','signed encrypted surrogate'],
                                ['credential on host']),status='implemented'),
        Beat('verify','The bridge checks signature, issuer, audience, subject, thumbprint, epoch and time.',
             focus=('bridge',),
             knowledge=holdings(['no opened payload'],
                                ['verified outer claims','matched certificate','current epoch + expiry'],
                                ['still has credential']),status='implemented'),
        Beat('unseal','Only after these checks may host cryptography reveal the nested capability.',
             focus=('bridge',),
             knowledge=holdings(['surrogate is still opaque'],
                                ['host-opens outer AES-GCM','retrieves inner aivs1'],
                                ['inner authorization','provider token remains host-only']),status='implemented'),
        Beat('authorize','The broker independently checks the inner grant before using a provider token.',
             links=('open',),packet='open',packet_label='inner cap (host)',
             knowledge=holdings(['operation request','no credential'],
                                ['authenticated peer','opened inner capability'],
                                ['grant + operation checks','audit before provider send','provider token']),status='implemented'),
        Beat('return','Only an approved public result can travel back to the agent.',
             links=('reply',),packet='reply',packet_label='selected result',
             knowledge=holdings(['approved public result','still no bearer'],
                                ['authenticated request','result gate'],
                                ['provider response','output projection','provider token still on host']),status='idealized'),
    ),
    footer='The proof covers extracted opening/credential-use decisions under adapter contracts; full Rust I/O refinement is open.',
)
