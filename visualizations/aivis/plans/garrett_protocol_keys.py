"""The custody table: who has which exact cryptographic key and token."""
from aivis.diagram import Beat, Diagram, Node
from aivis.plans.garrett_protocol_helpers import knowledge

PLAN = Diagram(
    key='gp_keys',title='Garrett / who holds each key?',
    kicker='Agent authentication key != broker signing key != shared token sealing key.',
    nodes=(
        Node('broker','Broker process','Issues surrogate S',(-4.68,1.83),2.95,1.07,'broker',icon='vault'),
        Node('agent','Agent process','Carries surrogate S',(0,1.83),2.95,1.07,'guest',icon='sandbox'),
        Node('proxy','Proxy process','Uses real token T',(4.68,1.83),2.95,1.07,'broker',icon='host'),
    ),
    links=(),
    beats=(
        Beat('initial','At startup, the broker and proxy receive their cryptographic keys; the agent has a separate mTLS key.',
             nodes=('broker','agent','proxy'),
             knowledge=knowledge(
                 ['Kseal (encrypt + decrypt)','skIssuer (JWT signing)','login-state key (broker only)','No credential database'],
                 ['skAgent (mTLS private key)','certAgent (public cert)','No Kseal or skIssuer','No real provider token T'],
                 ['Kseal (decrypt)','pkIssuer (JWT verification)','Trusted TLS peer certificate','No credential database'],
                 names=('broker','agent','proxy')),status='explainer'),
        Beat('issuance','During issuance, the broker temporarily sees T. It gives the agent only signed surrogate S.',
             focus=('broker','agent'),
             knowledge=knowledge(
                 ['Kseal, skIssuer','Temporarily holds real T','Encrypts T inside S','Does not retain T by design'],
                 ['skAgent + certAgent','S: signed JWT with Enc(Kseal,T)','No Kseal','Cannot read real T'],
                 ['Kseal, pkIssuer','No per-surrogate lookup','No T until an agent request'],
                 names=('broker','agent','proxy')),status='explainer'),
        Beat('proxy','On a normal proxy request, the proxy recovers T with Kseal, independent of skAgent.',
             focus=('proxy',),
             knowledge=knowledge(
                 ['Kseal + skIssuer','No token-record store'],
                 ['skAgent + certAgent','Surrogate S','Never receives plaintext T'],
                 ['Kseal + pkIssuer','Verifies cert binding','Decrypts T transiently','Uses T toward provider'],
                 names=('broker','agent','proxy')),status='explainer'),
    ),
    footer='Kseal is shared by broker and proxy. mTLS controls honest proxy use; it is not an AES decryption share.',
)
