"""Token issuance through browser login and broker signing."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node


def view(idp, broker, agent):
    return (Knowledge('idp',(-4.68,-0.80),tuple(idp),3.86,2.63),
            Knowledge('broker',(0,-0.80),tuple(broker),3.86,2.63),
            Knowledge('agent',(4.68,-0.80),tuple(agent),3.86,2.63))

PLAN = Diagram(
    key='gp_issue',title='Garrett / issuance',
    kicker='The human authorizes a credential; the agent gets a signed encrypted substitute.',
    nodes=(
        Node('browser','Human browser','Interactive login',(-5.33,1.76),2.04,1.06,'neutral',icon='host'),
        Node('idp','Identity provider','OAuth example',(-1.81,1.76),2.28,1.06,'provider',icon='identity'),
        Node('broker','Trusted broker','Receives, seals, signs',(1.81,1.76),2.28,1.06,'broker',icon='vault'),
        Node('agent','AI agent','Receives surrogate',(5.33,1.76),2.04,1.06,'guest',icon='sandbox'),
    ),
    links=(
        Link('auth','browser','idp','login / consent',((-4.31,1.76),(-2.95,1.76)),'neutral',label_xy=(-3.65,2.17)),
        Link('receive','idp','broker','real token T',((-0.67,1.76),(0.67,1.76)),'secret',label_xy=(0,2.17)),
        Link('present_cert','agent','broker','mTLS cert A',((5.33,1.23),(5.33,0.83),(1.81,0.83),(1.81,1.23)),'guest',label_xy=(3.55,0.95)),
        Link('issue','broker','agent','surrogate S',((2.95,1.76),(4.31,1.76)),'policy',label_xy=(3.62,2.17)),
    ),
    beats=(
        Beat('request','The agent requests a credential and proves its certificate identity to the broker.',
             nodes=('browser','idp','broker','agent'),links=('present_cert',),
             packet='present_cert',packet_label='cert A / mTLS',
             knowledge=view(['Waiting for human login'],['Kseal + signing key','Authenticated agent cert A'],['skAgent + certAgent','No real token']),status='explainer'),
        Beat('login','The user authenticates through the browser. The identity provider handles the real login.',
             links=('auth',),packet='auth',packet_label='human login',
             knowledge=view(['User consent','Token issuance pending'],['Authenticated agent cert A'],['No real token']),status='explainer'),
        Beat('credential','The provider delivers real credential T to the trusted broker, not to the agent.',
             links=('receive',),packet='receive',packet_label='real token T',
             knowledge=view(['Provider issued T'],['Plaintext T (temporary)','Kseal, skIssuer, cert A'],['No plaintext T']),status='explainer'),
        Beat('encrypt','The broker uses Kseal to encrypt T; the ciphertext goes in the JWT payload as enc.',
             focus=('broker',),
             knowledge=view(['Issued token T'],['AES-GCM: enc = Enc(Kseal,T)','Readable JWT claims + enc','cert A thumbprint in cnf'],['No plaintext T']),status='explainer'),
        Beat('sign','The broker signs the complete JWT with skIssuer. Signing is not encryption.',
             focus=('broker',),
             knowledge=view(['Provider may keep its own state'],['Sign(header.payload)','No per-surrogate record created','T not retained by protocol'],['No plaintext T']),status='explainer'),
        Beat('deliver','The agent keeps S = signed JWT with encrypted T. The broker needs no token database.',
             links=('issue',),packet='issue',packet_label='S',
             knowledge=view(['Provider issued T'],['Kseal + skIssuer','No stored T -> S mapping'],['skAgent + certificate A','Surrogate S, not T','Cannot decrypt enc']),status='explainer'),
    ),
    footer='OAuth is Garrett\'s example, not a requirement of the surrogate mechanism. Token acquisition may differ.',
)
