"""EDIT HERE: encrypted nested surrogate, showing contents as an X-ray.

The agent sees *ciphertext*, not the labels inside the encrypted layers.
Refs: docs/verified-garrett.md and aivm-secrets/identity/token.py.
"""
from aivis.diagram import Beat, Diagram, Layer, Link, Node, Package

SURROGATE=Layer('surrogate','Signed surrogate (JWT)','public claims + signature · Ed25519','signed',
    Layer('outer_cipher','AES-GCM encrypted payload','opaque to the guest · bound to a TLS certificate','encrypted',
        Layer('inner_cap','aivs1 capability','host-protected, carried as opaque bytes','sealed',
            Layer('bearer','Provider credential','illustrated contents; never guest-readable','private'))))

PLAN=Diagram(
    key='packaging',
    title='What is inside the surrogate?',
    kicker='X-ray view for explanation — this is not what the guest can decrypt.',
    nodes=(
        Node('issuer','Host issuer','Creates signed + sealed token',(-5.57,1.57),2.10,1.05,'broker'),
        Node('guest','Agent / guest','Carries opaque surrogate',(5.57,1.57),2.10,1.05,'guest'),
    ),
    links=(
        Link('issue','issuer','guest','signed encrypted token',((-4.51,1.57),(-4.05,2.37),(4.05,2.37),(4.51,1.57)),
             'policy',label_xy=(0,2.52)),
    ),
    packages=(Package('token', (0,-0.29),5.65,4.50,SURROGATE),),
    beats=(
        Beat('signed','The outer surrogate is signed. Its visible claims are not secret.',
             nodes=('issuer','guest'),packages=('token',),layer_focus='surrogate',status='implemented'),
        Beat('ciphertext','Inside it is AES-GCM ciphertext. Only the host can open this layer.',
             layer_focus='outer_cipher',status='implemented'),
        Beat('nested','The encrypted value carries an inner aivs1 capability.',
             layer_focus='inner_cap',status='implemented'),
        Beat('secret','The provider credential is protected again inside that inner capability.',
             layer_focus='bearer',status='implemented'),
        Beat('carried','The guest carries the surrogate but cannot read the encrypted credential.',
             links=('issue',),packet='issue',packet_label='signed surrogate',
             layer_focus='outer_cipher',status='assumed'),
    ),
    footer='Exact crypto format is source-specific. Isolation and issuer-key custody remain environmental assumptions.',
)
