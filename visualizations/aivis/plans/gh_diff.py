"""EDIT HERE: illustrative, narrowly-scoped gh PR-diff walk-through.

One read-only request, using the TauCetiProject/TauCeti PR 13861 W1/W2
fixture. Not a claim of arbitrary GitHub CLI compatibility.
"""
from aivis.diagram import Beat, Diagram, Knowledge, Link, Node

G=(-4.84,-0.86); H=(0,-0.86); P=(4.84,-0.86)
def k(guest,host,provider):
    return (Knowledge('agent',G,tuple(guest),width=3.76,height=2.79),
            Knowledge('broker',H,tuple(host),width=3.76,height=2.79),
            Knowledge('github',P,tuple(provider),width=3.76,height=2.79))

PLAN=Diagram(
    key='gh_diff',
    title='Agent runs gh pr diff 13861',
    kicker='One idealized read-only command · TauCetiProject/TauCeti',
    nodes=(
        Node('agent','Agent / gh alias','Guest-side syntax',(-4.84,1.77),2.63,1.06,'guest'),
        Node('broker','Rust broker','Narrow native operations',(0,1.77),2.81,1.06,'broker'),
        Node('github','GitHub API','HTTPS provider',(4.84,1.77),2.63,1.06,'provider'),
    ),
    links=(
        Link('op','agent','broker','pr.diff + repo + PR',((-3.51,1.77),(-1.43,1.77)),
             'guest',label_xy=(-2.48,2.19)),
        Link('send','broker','github','approved URL, bearer',((1.43,1.77),(3.51,1.77)),
             'broker',label_xy=(2.48,2.19)),
        Link('provider_return','github','broker','raw diff',((3.51,1.23),(3.27,1.23),(3.27,0.92),
                 (1.43,0.92),(1.43,1.23)),'provider',label_xy=(2.46,0.70)),
        Link('reply','broker','agent','selected text',((-1.43,1.23),(-3.51,1.23)),
             'guest',label_xy=(-2.46,0.93)),
    ),
    beats=(
        Beat('command','The agent asks to read one PR diff: gh pr diff 13861 -R TauCetiProject/TauCeti.',
             nodes=('agent','broker','github'),
             knowledge=k(['command + repository','bound surrogate','no bearer token'],
                         ['policy: pr.diff','PR 13861 allowed','provider bearer token'],
                         ['PR contents','authenticated API']),status='idealized'),
        Beat('translate','A narrow gh-compatible client maps the command to typed pr.diff arguments.',
             links=('op',),packet='op',packet_label='pr.diff {repo, pr}',
             knowledge=k(['typed request','surrogate','no bearer'],
                         ['pr.diff','repo + PR fields','credential stored here'],
                         ['PR contents']),status='implemented'),
        Beat('check','The broker checks the grant, repo/PR scope, and host-selected request rule.',
             focus=('broker',),knowledge=k(['requested pr.diff','may get denial'],
                         ['current grant checked','manifest picks endpoint','only read operation'],
                         ['PR contents']),status='implemented'),
        Beat('preflight','When required, host-selected metadata is checked before the main effect.',
             links=('send','provider_return'),packet='send',packet_label='GET PR metadata',
             knowledge=k(['still has no bearer'],
                         ['head/repo/PR facts','reject mismatched PR','credential'],
                         ['sees bearer + preflight','returns metadata']),status='implemented'),
        Beat('audit','The broker records dispatch intent and rechecks the grant.',
             focus=('broker',),knowledge=k(['requested operation','no audit file access'],
                         ['audit intent recorded','fresh grant required','credential'],
                         ['no diff request yet']),status='implemented'),
        Beat('provider','The broker makes the fixed HTTPS request with its own credential.',
             packet='send',packet_label='GET approved .diff',
             knowledge=k(['still no bearer'],
                         ['credential used here','approved GitHub URL','audit intent'],
                         ['authenticated request','diff content']),status='implemented'),
        Beat('raw','GitHub sends the raw response to the host, not directly to the agent.',
             packet='provider_return',packet_label='raw diff body',
             knowledge=k(['still waiting for reply'],
                         ['raw .diff body','credential + policy','response checks'],
                         ['diff it sent','authenticated request']),status='implemented'),
        Beat('release','The broker checks the reply and sends only the allowed diff text.',
             links=('reply',),packet='reply',packet_label='selected diff',
             knowledge=k(['approved diff text','command result','not the bearer'],
                         ['raw response','released text','audit outcome'],
                         ['request + raw response']),status='idealized'),
    ),
    footer='W2 native gh read-only subset exists; this sequence is illustrative, not unrestricted gh or verified native I/O.',
)
