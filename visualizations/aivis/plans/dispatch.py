"""EDIT HERE: authorization, preflight and audit in the host before sending."""
from aivis.diagram import Beat, Diagram, Link, Node

PLAN=Diagram(
    key='dispatch',
    title='What happens before GitHub sees a request?',
    kicker='The agent chooses an intent; the host chooses the actual effect.',
    nodes=(
        Node('intent','Requested action','pr.diff / PR 13861',(-5.28,1.19),2.29,1.10,'guest'),
        Node('grant','Grant','repo · operation · expiry',(-2.47,1.19),2.29,1.10,'policy'),
        Node('manifest','Host rule','fixed method + URL',(0.33,1.19),2.29,1.10,'policy'),
        Node('facts','Provider facts','required PR metadata',(3.15,1.19),2.29,1.10,'broker'),
        Node('denied','Stop','no authorized send',(-4.17,-1.14),2.29,1.10,'secret'),
        Node('audit','Audit intent','must succeed first',(0.63,-1.14),2.35,1.10,'broker'),
        Node('https','HTTPS send','host attaches token',(4.71,-1.14),2.38,1.10,'provider'),
    ),
    links=(
        Link('a','intent','grant','',((-4.12,1.19),(-3.64,1.19)),'guest'),
        Link('b','grant','manifest','',((-1.31,1.19),(-0.83,1.19)),'policy'),
        Link('c','manifest','facts','',((1.49,1.19),(1.98,1.19)),'policy'),
        Link('deny','grant','denied','rejected',((-2.47,0.63),(-2.47,-0.40),(-4.17,-0.58)),'secret',label_xy=(-3.65,-0.25)),
        Link('audit','facts','audit','',((3.15,0.63),(3.15,-0.10),(0.63,-0.57)),'broker'),
        Link('send','audit','https','new grant check',((1.83,-1.14),(3.50,-1.14)),'broker',label_xy=(2.66,-0.86)),
    ),
    beats=(
        Beat('intent','The command is not authority. The broker checks a current grant.',
             nodes=('intent','grant'),links=('a',),focus=('grant',),status='implemented'),
        Beat('route','The manifest decides which method, path and limits are allowed.',
             nodes=('manifest','denied'),links=('b','deny'),focus=('manifest',),status='implemented'),
        Beat('facts','The broker may inspect upstream metadata and reject mismatches.',
             nodes=('facts',),links=('c',),focus=('facts',),status='implemented'),
        Beat('audit','No acknowledged audit intent means no credentialed dispatch.',
             nodes=('audit',),links=('audit',),focus=('audit',),status='implemented'),
        Beat('send','The broker rechecks the grant immediately before sending to the fixed endpoint.',
             nodes=('https',),links=('send',),packet='send',packet_label='approved request',status='implemented'),
    ),
    footer='The Rust controllers are source-linked to Lean; W6 still needs complete concrete network/audit correspondence.',
)
