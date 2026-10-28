"""No per-surrogate state: replicated brokers and proxies using startup keys."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

PLAN=Diagram(
    key='gp_replicas',title='Garrett / no token database',
    kicker='Replicas need compatible keys and policy, not a shared surrogate-to-token table.',
    nodes=(
        Node('startup','Startup provisioner','Injects key material',(0,1.96),3.15,1.10,'policy',icon='key'),
        Node('brokers','Broker replicas A, B','Independent issuers',(-4.66,0.34),3.18,1.05,'broker',icon='vault'),
        Node('proxies','Proxy replicas A, B','Independent readers',(4.66,0.34),3.18,1.05,'broker',icon='host'),
    ),
    links=(
        Link('broker_keys','startup','brokers','skIssuer + Kseal',((-1.58,1.96),(-4.66,1.96),(-4.66,0.87)),
             'policy',label_xy=(-3.34,2.33)),
        Link('proxy_keys','startup','proxies','pkIssuer + Kseal',((1.58,1.96),(4.66,1.96),(4.66,0.87)),
             'policy',label_xy=(3.38,2.33)),
    ),
    beats=(
        Beat('inject','The operator provides compatible cryptographic keys to independent processes at startup.',
             nodes=('startup','brokers','proxies'),links=('broker_keys','proxy_keys'),
             knowledge=(Knowledge('brokers',(-3.14,-1.54),('Each has skIssuer + Kseal','No token database','No per-token decryption keys'),5.42,1.85),
                        Knowledge('proxies',(3.14,-1.54),('Each has pkIssuer + Kseal','No token database','No per-token lookup on request'),5.42,1.85)),status='explainer'),
        Beat('independent','Any proxy with the right keys can open any valid, appropriately bound surrogate.',
             focus=('proxies',),
             knowledge=(Knowledge('brokers',(-3.14,-1.54),('Broker A issues self-contained S','Broker B can issue new S','Neither persists S -> T records'),5.42,1.85),
                        Knowledge('proxies',(3.14,-1.54),('Proxy A verifies + opens S','Proxy B can verify + open S','Both check authenticated peer'),5.42,1.85)),status='explainer'),
        Beat('scale','Start additional replicas: no distributed credential database or token registry is required.',
             focus=('brokers','proxies'),
             knowledge=(Knowledge('brokers',(-3.14,-1.54),('Compatible keys and config','No durable credential state','Fresh replicas issue surrogates'),5.42,1.85),
                        Knowledge('proxies',(3.14,-1.54),('Compatible keys and config','No credential record retrieval','Fresh replicas accept valid S'),5.42,1.85)),status='explainer'),
    ),
    footer='Startup key provisioning/rotation and TLS security remain operational needs; no DB != no trusted keys.',
)
