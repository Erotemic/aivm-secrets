"""Garrett certificate enrollment: the private key stays with the client.

Edit nodes, beats and knowledge here. The operator/authority approves a CSR;
a mere name in a CSR is not authority to enroll.
"""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

LEFT=(-4.82,-0.94); MIDDLE=(0,-0.94); RIGHT=(4.82,-0.94)

def holdings(client, authority, registry):
    return (Knowledge('client', LEFT, tuple(client), 3.76, 2.72),
            Knowledge('authority', MIDDLE, tuple(authority), 3.76, 2.72),
            Knowledge('registry', RIGHT, tuple(registry), 3.76, 2.72))

PLAN=Diagram(
    key='garrett_enroll',
    title='Garrett 1 / enroll the client',
    kicker='The client proves control of a key; the host approves its identity.',
    nodes=(
        Node('client','Client / sandbox','Software key or TPM',(-4.82,1.63),2.68,1.10,'guest',icon='sandbox'),
        Node('authority','Host authority','Issues client certificate',(0,1.63),2.68,1.10,'policy',icon='authority'),
        Node('registry','Enrollment registry','Current cert + epoch',(4.82,1.63),2.68,1.10,'broker',icon='certificate'),
    ),
    links=(
        Link('csr','client','authority','CSR + proof of key',((-3.47,1.83),(-1.35,1.83)),
             'guest',label_xy=(-2.4,2.22)),
        Link('certificate','authority','client','signed client cert',((-1.35,1.31),(-3.47,1.31)),
             'policy',label_xy=(-2.42,0.96)),
        Link('registration','authority','registry','record cert + epoch',((1.35,1.63),(3.47,1.63)),
             'broker',label_xy=(2.44,2.05)),
    ),
    beats=(
        Beat('key','The client makes or uses a private key. The host does not receive its private bytes.',
             nodes=('client','authority','registry'),
             knowledge=holdings(['private signing key','public key','no provider credential'],
                                ['CA signing key','approval policy','current epoch'],
                                ['existing enrollments']),status='implemented'),
        Beat('csr','The public key travels in a CSR. A CSR is not permission to enroll.',
             links=('csr',),packet='csr',packet_label='CSR (public key)',
             knowledge=holdings(['private key stays here','CSR public key'],
                                ['CSR public key','proposed subject','approval still required'],
                                ['existing enrollments']),status='implemented'),
        Beat('approve','An operator-approved fingerprint or verified TPM evidence determines whether to sign.',
             focus=('authority',),
             knowledge=holdings(['private key','proof of key control'],
                                ['approved fingerprint OR','TPM attestation evidence','trusted subject binding'],
                                ['no unapproved entry']),status='implemented'),
        Beat('record','The authority signs a client cert and records its current enrollment epoch.',
             links=('registration',),packet='registration',packet_label='cert + epoch',
             knowledge=holdings(['private key','waiting for certificate'],
                                ['CA key remains on host','signed client certificate'],
                                ['certificate thumbprint','subject + epoch','current active state']),status='implemented'),
        Beat('deliver','The client receives its certificate, not the host CA key or GitHub credential.',
             links=('certificate',),packet='certificate',packet_label='public cert',
             knowledge=holdings(['private key','client certificate','can attempt client TLS'],
                                ['CA private key','issuer keys','enrollment decision'],
                                ['certificate thumbprint','subject + epoch']),status='implemented'),
    ),
    footer='Software-key and TPM-backed enrollment are distinct modes. Host approval and key/VM isolation are assumed operationally.',
)
