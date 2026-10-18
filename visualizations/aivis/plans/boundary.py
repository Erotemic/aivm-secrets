"""EDIT HERE: the exact knowledge snapshot after each communication step."""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

G=(-4.84,-0.89); H=(0,-0.89); P=(4.84,-0.89)
def k(guest,host,provider):
    return (Knowledge('guest',G,tuple(guest),width=3.78,height=2.76),
            Knowledge('host',H,tuple(host),width=3.78,height=2.76),
            Knowledge('provider',P,tuple(provider),width=3.78,height=2.76))

PLAN=Diagram(
    key='boundary',
    title='Who knows what?',
    kicker='Information does not disappear from the sender when a copy is sent.',
    nodes=(
        Node('guest','Agent / guest','Untrusted process',(-4.84,1.72),2.63,1.06,'guest'),
        Node('host','Host broker','Trusted credential holder',(0,1.72),2.75,1.06,'broker'),
        Node('provider','GitHub API','Remote service',(4.84,1.72),2.56,1.06,'provider'),
    ),
    links=(
        Link('intent','guest','host','typed operation',((-3.51,1.72),(-1.39,1.72)),'guest',label_xy=(-2.48,2.15)),
        Link('outbound','host','provider','authenticated HTTPS',((1.39,1.72),(3.55,1.72)),'broker',label_xy=(2.48,2.15)),
        Link('incoming','provider','host','raw result',((3.55,1.20),(3.30,1.20),(3.30,0.92),(1.39,0.92),(1.39,1.20)),'provider',label_xy=(2.42,0.70)),
        Link('release','host','guest','selected reply',((-1.39,1.20),(-3.51,1.20)),'guest',label_xy=(-2.48,0.94)),
    ),
    beats=(
        Beat('start','Before the request, the agent has no GitHub bearer token.',nodes=('guest','host','provider'),
             knowledge=k(['goal: inspect PR','bound surrogate','client identity (mTLS)'],
                         ['provider bearer credential','grant, policy, keys','audit file'],
                         ['API data','account permissions']),status='assumed'),
        Beat('ask','The agent sends a request and its bound surrogate, not the bearer token.',
             links=('intent',),packet='intent',packet_label='pr.diff + surrogate',
             knowledge=k(['goal: inspect PR','bound surrogate','client identity'],
                         ['credential','grant + policy','incoming request'],
                         ['API data']),status='implemented'),
        Beat('send','The broker applies the credential to an approved provider request.',
             links=('outbound',),packet='outbound',packet_label='Authorization: Bearer …',
             knowledge=k(['goal, surrogate','no bearer token from broker'],
                         ['credential','approved endpoint','outgoing request'],
                         ['API data','bearer token on HTTPS request']),status='implemented'),
        Beat('return','The broker sees the full response; the agent gets only the selected result.',
             links=('incoming','release'),packet='release',packet_label='filtered diff',
             knowledge=k(['surrogate','selected diff text','no raw API response'],
                         ['credential','raw provider response','filtered result + audit'],
                         ['API data','authenticated request','reply it sent']),status='idealized'),
    ),
    footer='This is the intended boundary for one broker session. Host/guest network isolation is a deployment assumption.',
)
