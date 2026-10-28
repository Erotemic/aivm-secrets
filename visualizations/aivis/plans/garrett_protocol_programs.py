"""The six independently running programs in Garrett's example.

Program placement is deliberately stable across the following close-ups.
The browser handles the human login UI; it is not the token issuer.
"""
from aivis.diagram import Beat, Diagram, Link, Node

PLAN = Diagram(
    key='gp_programs',
    title='Garrett / the programs',
    kicker='Six distinct processes; the broker and proxy are trusted services.',
    nodes=(
        Node('browser', 'Browser', 'Human signs in', (-4.75, 1.93), 2.38, 1.04, 'neutral', icon='host'),
        Node('idp', 'Identity provider', 'Issues real token T', (0, 1.93), 2.55, 1.04, 'provider', icon='identity'),
        Node('broker', 'Broker', 'Seals and signs', (4.75, 1.93), 2.38, 1.04, 'broker', icon='vault'),
        Node('agent', 'AI agent', 'Stores surrogate S', (-4.75, 0.19), 2.38, 1.04, 'guest', icon='sandbox'),
        Node('proxy', 'Trusted proxy', 'Checks, opens, relays', (0, 0.19), 2.55, 1.04, 'broker', icon='host'),
        Node('api', 'Provider API', 'Accepts real T', (4.75, 0.19), 2.38, 1.04, 'provider', icon='cloud'),
    ),
    links=(
        Link('login', 'browser', 'idp', 'Human login', ((-3.56,1.93),(-1.28,1.93)), 'neutral', label_xy=(-2.45,2.37)),
        Link('oauth', 'idp', 'broker', 'real T', ((1.28,1.93),(3.56,1.93)), 'secret', label_xy=(2.39,2.37)),
        Link('deliver', 'broker', 'agent', 'signed surrogate S', ((4.75,1.41),(4.75,0.97),(-4.75,0.97),(-4.75,0.71)), 'policy', label_xy=(0,1.11)),
        Link('present', 'agent', 'proxy', 'mTLS + S', ((-3.56,0.19),(-1.28,0.19)), 'guest', label_xy=(-2.44,-0.20)),
        Link('egress', 'proxy', 'api', 'real T', ((1.28,0.19),(3.56,0.19)), 'secret', label_xy=(2.42,-0.20)),
    ),
    beats=(
        Beat('actors', 'The browser, identity provider, broker, agent, proxy and API are separate programs.',
             nodes=('browser','idp','broker','agent','proxy','api'), status='explainer'),
        Beat('login', 'The human signs in; the identity provider issues real credential T to the broker.',
             links=('login','oauth'), packet='oauth',packet_label='real token T',status='explainer'),
        Beat('surrogate', 'The broker signs a surrogate S containing an encrypted T; the agent stores S.',
             links=('deliver',),packet='deliver',packet_label='surrogate S',status='explainer'),
        Beat('use', 'The agent authenticates to the proxy and presents S, never the plaintext T.',
             links=('present',),packet='present',packet_label='S + mTLS',status='explainer'),
        Beat('relay', 'The proxy decrypts T and sends it to the provider API over its own connection.',
             links=('egress',),packet='egress',packet_label='real token T',status='explainer'),
    ),
    footer='Network arrows show protocol messages; each box is a distinct role, not a shared memory space.',
)
