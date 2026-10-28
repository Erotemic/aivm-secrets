"""Accurate X-ray of the actual stateless v1 signed JWT.

The compact JWS header/payload/signature are readable; only `enc` is AEAD
ciphertext. Layers represent conceptual *containment*, not nested encryption.
"""
from aivis.diagram import Beat, Diagram, Layer, Link, Node, Package

TOKEN = Layer(
    'jwt', 'S = header.payload.signature',
    'Signed by broker skIssuer; not encrypted as a whole', 'signed',
    Layer(
        'claims', 'JWT payload: readable JSON',
        'iss, aud, prv, exp, cnf(cert A), enc, ...', 'plain',
        Layer(
            'enc', 'enc field: AES-256-GCM',
            'nonce || ciphertext || auth tag; only Kseal opens it', 'encrypted',
            Layer(
                'real_token', 'T = provider credential',
                'X-RAY ONLY: not readable to the agent', 'private',
            ),
        ),
    ),
)

PLAN = Diagram(
    key='gp_packet',title='Garrett / unpack the surrogate',
    kicker='Exploded X-ray of a signed JWT: only the enc field is encrypted.',
    nodes=(
        Node('broker','Broker','Signs and encrypts',(-5.66,1.45),2.04,1.05,'broker',icon='vault'),
        Node('agent','Agent','Can inspect claims',(5.66,1.45),2.04,1.05,'guest',icon='sandbox'),
    ),
    links=(
        Link('give','broker','agent','signed JWT S',((-4.64,1.45),(-4.23,2.47),(4.23,2.47),(4.64,1.45)),
             'policy',label_xy=(0,2.51)),
    ),
    packages=(Package('S',(0,-0.18),6.15,4.12,TOKEN),),
    beats=(
        Beat('outer','The surrogate is a signed JWT. Signature verification detects tampering; it does not hide claims.',
             nodes=('broker','agent'),packages=('S',),layer_focus='jwt',status='explainer'),
        Beat('visible','The agent can decode header and payload: public claims include cnf, provider, audience and expiry.',
             layer_focus='claims',status='explainer'),
        Beat('ciphertext','The enc claim contains AES-GCM ciphertext with nonce and tag; its plaintext is not visible.',
             layer_focus='enc',status='explainer'),
        Beat('xray','An X-ray reveals the original token T *inside enc*. The agent cannot make this reveal.',
             layer_focus='real_token',status='explainer'),
        Beat('carry','The agent carries the entire signed JWT S; it has neither Kseal nor the original T.',
             links=('give',),packet='give',packet_label='S (header.payload.sig)',
             layer_focus='enc',status='explainer'),
    ),
    footer='In v1, AEAD associated data binds enc to JWT header and all other claims; enc is not the entire JWT.',
)
