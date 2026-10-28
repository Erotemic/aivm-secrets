"""The trust boundary and the shared-key compromise counterexample."""
from aivis.diagram import Beat, Diagram, Link, Node
from aivis.plans.garrett_protocol_helpers import knowledge

PLAN=Diagram(
    key='gp_compromise',title='Garrett / what mTLS cannot stop',
    kicker='Full trusted-proxy compromise is different from reaching an honest proxy over the network.',
    nodes=(
        Node('attacker','Attacker','Captured surrogate S',(-4.68,1.84),3.01,1.10,'secret',icon='host'),
        Node('proxy','Compromised proxy','Exposes Kseal or T',(0,1.84),3.01,1.10,'open',icon='host'),
        Node('api','Provider API','Accepts underlying T',(4.68,1.84),3.01,1.10,'provider',icon='cloud'),
    ),
    links=(
        Link('stolen_key','proxy','attacker','Kseal stolen',((-1.51,1.84),(-3.17,1.84)),'secret',label_xy=(-2.34,2.24)),
        Link('direct','attacker','api','T can be used directly',((-4.68,1.29),(-4.68,0.87),(4.68,0.87),(4.68,1.29)),
             'secret',label_xy=(0,0.96)),
    ),
    beats=(
        Beat('trust','The proxy has Kseal and temporarily sees T. It is inside the trusted computing base.',
             nodes=('attacker','proxy','api'),
             knowledge=knowledge(['Surrogate S only'],['Kseal (sealing key)','Plaintext T during requests','Honest mTLS checks'],
                                 ['Expects real token T'],names=('attacker','proxy','api')),status='explainer'),
        Beat('compromise','Full proxy compromise can disclose Kseal or plaintext T. mTLS cannot prevent this.',
             links=('stolen_key',),packet='stolen_key',packet_label='stolen Kseal',
             knowledge=knowledge(['Captured S + stolen Kseal','Can decrypt Enc(Kseal,T)'],
                                 ['Key custody breached','No honest-check guarantee'],['Provider still trusts real T'],
                                 names=('attacker','proxy','api')),status='explainer'),
        Beat('direct','The attacker can recover T offline and use it directly while the provider accepts T.',
             links=('direct',),packet='direct',packet_label='Bearer T',
             knowledge=knowledge(['Recovered plaintext T','No agent cert needed'],
                                 ['Compromised process','No credential DB to dump'],
                                 ['Accepts T per provider rules'],names=('attacker','proxy','api')),status='explainer'),
    ),
    footer='Statelessness limits stored credential aggregation, not what an attacker with Kseal + captured S can recover.',
)
