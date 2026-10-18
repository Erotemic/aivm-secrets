"""Garrett surrogate issuance: two independently protected envelopes.

The provider token is in the host inner aivs1 capability, not issued as raw
credential bytes. Outer JWT has readable claims and signed ciphertext.
"""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

LEFT=(-4.82,-0.93); MID=(0,-0.93); RIGHT=(4.82,-0.93)
def holdings(host, issuer, client):
    return (Knowledge('host',LEFT,tuple(host),3.76,2.72),
            Knowledge('issuer',MID,tuple(issuer),3.76,2.72),
            Knowledge('client',RIGHT,tuple(client),3.76,2.72))

PLAN=Diagram(
    key='garrett_issue',title='Garrett 2 / issue a surrogate',
    kicker='Bind the capability to an enrolled certificate, then encrypt and sign.',
    nodes=(
        Node('host','Credential host','Inner aivs1 capability',(-4.82,1.63),2.68,1.10,'broker',icon='vault'),
        Node('issuer','Host issuer','Grant + sealed envelope',(0,1.63),2.68,1.10,'policy',icon='authority'),
        Node('client','Enrolled client','Carries only surrogate',(4.82,1.63),2.68,1.10,'guest',icon='sandbox'),
    ),
    links=(
        Link('inner','host','issuer','host-protected aivs1',((-3.47,1.63),(-1.35,1.63)),
             'broker',label_xy=(-2.40,2.08)),
        Link('token','issuer','client','signed + encrypted',((1.35,1.63),(3.47,1.63)),
             'policy',label_xy=(2.42,2.08)),
    ),
    beats=(
        Beat('host_secret','The host holds the GitHub credential. The agent never receives these bytes.',
             nodes=('host','issuer','client'),
             knowledge=holdings(['provider bearer token','aivs1 encryption key','allowed provider scope'],
                                ['issuer signing key','outer encryption key','enrollment registry'],
                                ['client cert + private key','no GitHub credential']),status='implemented'),
        Beat('inner','The host wraps credential material in a host-encrypted aivs1 capability.',
             links=('inner',),packet='inner',packet_label='opaque aivs1',
             knowledge=holdings(['credential (host only)','encrypted inner capability'],
                                ['opaque inner capability','issuer keys'],
                                ['client certificate only']),status='implemented'),
        Beat('claims','The issuer chooses subject, certificate thumbprint, epoch and validity window.',
             focus=('issuer',),
             knowledge=holdings(['inner capability','provider credential'],
                                ['enrolled subject','certificate thumbprint','epoch + expiry','bounded operation grant'],
                                ['certificate + signer','no inner plaintext']),status='implemented'),
        Beat('outer','The issuer encrypts the inner capability, then signs the outer surrogate.',
             focus=('issuer',),
             knowledge=holdings(['credential stays on host'],
                                ['signed surrogate','AES-GCM ciphertext','readable public claims'],
                                ['no provider credential']),status='implemented'),
        Beat('deliver','The guest can carry the surrogate; it cannot open either protected payload.',
             links=('token',),packet='token',packet_label='surrogate (opaque)',
             knowledge=holdings(['credential still on host','issuer/outer keys remain private'],
                                ['signed + encrypted surrogate','certificate binding'],
                                ['signed surrogate','client signing key + cert','no GitHub bearer']),status='implemented'),
    ),
    footer='Inner aivs1 and outer surrogate are different wrappers. Crypto/key custody are trusted adapter/environment boundaries.',
)
