#!/usr/bin/env python3
"""Generate a Thunderbird-style 'Local Folders' directory with tricky messages
(encodings, HTML-only, inline images, multi-MB attachments, 200 recipients,
forwarded messages, deleted/flagged/unread states, malformed mail, a
3000-message folder, nested subfolders, an empty folder, and accented folder names in UTF-8,
NFD, Latin-1 and IMAP modified UTF-7 encodings)."""
import os, sys, random, email.utils, time
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.message import MIMEMessage
from email import encoders
from email.header import Header

if len(sys.argv) != 2:
    sys.exit('usage: make_test_mail.py OUTPUT_DIR   (creates OUTPUT_DIR/"Local Folders")')
base = sys.argv[1]
root = os.path.join(base, 'Local Folders')
import shutil
shutil.rmtree(root, ignore_errors=True); os.makedirs(root)
random.seed(1)

def envelope(ts): return 'From - ' + time.strftime('%a %b %d %H:%M:%S %Y', time.gmtime(ts)) + '\n'

def write_mbox(path, msgs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        for ts, m, status in msgs:
            data = m if isinstance(m, bytes) else m.as_bytes(policy=m.policy.clone(linesep='\n')) if hasattr(m,'policy') else m.as_bytes()
            f.write(envelope(ts).encode())
            f.write(f'X-Mozilla-Status: {status:04x}\nX-Mozilla-Status2: 00000000\n'.encode())
            f.write(data)
            if not data.endswith(b'\n'): f.write(b'\n')
            f.write(b'\n')
    open(path + '.msf', 'w').write('// fake index')

T = 1700000000
def simple(i, subj, body, frm='Alice Example <alice@example.com>', to='Bob <bob@example.org>'):
    m = EmailMessage()
    m['From'] = frm; m['To'] = to; m['Subject'] = subj
    m['Date'] = email.utils.formatdate(T + i*3600); m['Message-ID'] = f'<msg{i}@example.com>'
    m.set_content(body)
    return m

inbox = []
# 1 plain text, read
inbox.append((T, simple(1, 'Plain text message', 'Hello Bob,\n\nThis is plain text.\nFrom the desk of Alice.\n'), 0x0001))
# 2 UTF-8 / Japanese subject, unread + flagged, body with ">From" escape
m = simple(2, 'Grüße – 日本語の件名 ✓', 'Ünïcödé body ✓\n>From here on, escaped line.\n')
m['Cc'] = '"Zoë Ünlü" <zoe@example.net>, carol@example.com'
inbox.append((T+1, m, 0x0004))
# 3 HTML only, iso-8859-1
m = MIMEText('<html><head><meta charset="iso-8859-1"><style>p{}</style></head><body><p>Caf\xe9 &amp; cr\xe8me<br>line2</p></body></html>', 'html', 'iso-8859-1')
m['From']='shop@example.com'; m['To']='bob@example.org'; m['Subject']='=?iso-8859-1?q?Caf=E9_offer?='; m['Date']=email.utils.formatdate(T+3)
inbox.append((T+2, m, 0x0001))
# 4 multipart/alternative + PDF attachment + RFC2231 filename + inline image
outer = MIMEMultipart('mixed')
outer['From']='Dave <dave@example.com>'; outer['To']='bob@example.org, Eve <eve@example.com>'; outer['Bcc']='secret@example.com'
outer['Subject']='Re: Fwd: Report with attachments'; outer['Date']=email.utils.formatdate(T+4); outer['X-Priority']='1 (Highest)'
rel = MIMEMultipart('related'); alt = MIMEMultipart('alternative')
alt.attach(MIMEText('Plain version of the report', 'plain', 'utf-8'))
alt.attach(MIMEText('<html><body><h1>Report</h1><img src="cid:logo123@x"></body></html>', 'html', 'utf-8'))
rel.attach(alt)
img = MIMEImage(bytes(range(256))*20, 'png'); img.add_header('Content-ID','<logo123@x>'); img.add_header('Content-Disposition','inline')
rel.attach(img); outer.attach(rel)
pdf = MIMEBase('application','pdf'); pdf.set_payload(b'%PDF-1.4 fake ' + os.urandom(5000)); encoders.encode_base64(pdf)
pdf.add_header('Content-Disposition','attachment', filename=('utf-8','','Résumé 2024.pdf')); outer.attach(pdf)
inbox.append((T+3, outer, 0x0001))
# 5 large attachments: 3 MB (XBLOCK) and 10 MB (XXBLOCK)
outer = MIMEMultipart('mixed'); outer['From']='big@example.com'; outer['To']='bob@example.org'; outer['Subject']='Big files'; outer['Date']=email.utils.formatdate(T+5)
outer.attach(MIMEText('see attached','plain'))
global BIG3, BIG10
BIG3 = os.urandom(3*1024*1024); BIG10 = os.urandom(10*1024*1024)
for name, data in [('three.bin', BIG3), ('ten.bin', BIG10)]:
    a = MIMEBase('application','octet-stream'); a.set_payload(data); encoders.encode_base64(a); a.add_header('Content-Disposition','attachment',filename=name); outer.attach(a)
inbox.append((T+4, outer, 0x0001))
open(os.path.join(base,'big3.bin'),'wb').write(BIG3); open(os.path.join(base,'big10.bin'),'wb').write(BIG10)
# 6 forwarded message/rfc822
outer = MIMEMultipart('mixed'); outer['From']='fwd@example.com'; outer['To']='bob@example.org'; outer['Subject']='Fwd: inner'; outer['Date']=email.utils.formatdate(T+6)
outer.attach(MIMEText('forwarding','plain')); outer.attach(MIMEMessage(simple(99,'The inner message','inner body')))
inbox.append((T+5, outer, 0x0001))
# 7 deleted (expunged) message -> skipped by default
inbox.append((T+6, simple(7,'I was deleted','gone'), 0x0009))
# 8 200 recipients (recipient table row matrix > 3580 bytes -> subnode) & huge body (> heap)
m = simple(8, 'Mass mail '+'x'*300, 'Body line\n'*5000, to=', '.join(f'"User {k}" <user{k}@example.com>' for k in range(200)))
inbox.append((T+7, m, 0x0000))
# 9 no Date header, no From
m = EmailMessage(); m['Subject']='No date'; m.set_content('date comes from envelope'); inbox.append((T+8, m, 0))
# 10 garbage
inbox.append((T+9, b'this is not\n a valid header block\x00\xff\n\nbody\n', 0))
# 11 group syntax / bare address
m = simple(11, 'Group', 'g', to='Team: a@x.com, b@y.com;')
inbox.append((T+10, m, 1))
write_mbox(f'{root}/Inbox', inbox)

write_mbox(f'{root}/Inbox.sbd/Projects', [(T, simple(20+i, f'Project note {i}', f'note {i}'), 1) for i in range(5)])
write_mbox(f'{root}/Inbox.sbd/Projects.sbd/Archive 2019', [(T, simple(30+i, f'Archived {i}', 'old'), 1) for i in range(3)])
write_mbox(f'{root}/Sent', [(T, simple(40, 'Sent thing', 'sent'), 1)])
write_mbox(f'{root}/Trash', [(T, simple(41, 'Trashed thing', 'trash'), 1)])
open(f'{root}/Drafts','w').close(); open(f'{root}/Drafts.msf','w').write('x')
# Big folder: 3000 messages -> multi-level BTH and row-matrix subnode
write_mbox(f'{root}/Bulk', [(T+i, simple(1000+i, f'Bulk message number {i} ' + 'ü'*(i%40), f'bulk body {i}\n'*(i%20+1)), 1 if i%3 else 0) for i in range(3000)])
# Accented folder names in every on-disk encoding Thunderbird profiles can have
import unicodedata
def raw_mbox(name_bytes, subject):
    path = os.path.join(root.encode(), name_bytes)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'wb').write(b'From - Mon Jan 01 00:00:00 2024\nFrom: Fran\xe7ois <f@exemple.fr>\nSubject: R\xe9union ' + subject + b'\n\nCorps du message \xe9t\xe9\n\n')
    open(path + b'.msf', 'wb').close()
raw_mbox('Éléments envoyés'.encode(), b'utf8')                                   # UTF-8 (NFC)
raw_mbox(unicodedata.normalize('NFD', 'Reçus été').encode(), b'nfd')             # macOS-style NFD
raw_mbox('Société Générale'.encode('latin-1'), b'latin1')                        # legacy 8-bit name
raw_mbox('Archivé'.encode('latin-1') + b'.sbd/Factures', b'latin1 parent')       # child of 8-bit .sbd
raw_mbox(b'Envoy&AOk-s', b'imap utf7')                                           # IMAP modified UTF-7
raw_mbox(b'R&D', b'literal ampersand')                                           # must stay "R&D"
open(f'{root}/msgFilterRules.dat','w').write('version="9"')
open(f'{root}/filterlog.html','w').write('<html></html>')
print("Created", root, "(big3.bin / big10.bin hold the expected large attachment contents)")
