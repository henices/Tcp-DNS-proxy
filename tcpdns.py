#! /usr/bin/python
# -*- coding: utf-8 -*-
# cody by zhouzhenster@gmail.com
#
# Change log:
#
# 2011-10-23, use SocketServer to run a multithread udp server
# 2012-04-16, add more public dns servers support tcp dns query
# 2013-05-14, merge code from linkerlin, add gevent support
# 2013-06-24, add lru cache support
# 2013-08-13, add ipv6 support


#  8.8.8.8                 Google
#  8.8.4.4                 Google
#  156.154.70.1            Dnsadvantage
#  156.154.71.1            Dnsadvantage
#  208.67.222.222          OpenDNS
#  208.67.220.220          OpenDNS
#  198.153.192.1           Norton
#  198.153.194.1           Norton
#  2001:4860:4860::8888    Google ipv6
#  2001:4860:4860::8844    Google ipv6

import os, sys
import socket
import struct
import threading
import SocketServer
import traceback
import random
import optparse
try:
    import gevent
    from gevent import monkey
except:
    print "Install gevent will save a lot of CPU time"
else:
    monkey.patch_all()

NAME = 'TCP DNS PROXY'
VERSION = '1.0'

DHOSTS = ['156.154.70.1',
         '8.8.8.8',
         '8.8.4.4',
         '156.154.71.1',
         '208.67.222.222',
         '208.67.220.220',
         #'198.153.192.1',
         #'198.153.194.1',
         '74.207.247.4',
         '209.244.0.3',
         '8.26.56.26'
         ]

DHOSTS_V6 = ['2001:4860:4860::8888',
             '2001:4860:4860::8844']

DPORT = 53                # default dns port 53
TIMEOUT = 20              # set timeout 5 second
VERBOSE = 0               # display level
IPV6 = 0


#-------------------------------------------------------------
# Hexdump Cool :)
# default width 16
#--------------------------------------------------------------
def hexdump( src, width=16 ):
    FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    result=[]
    for i in xrange(0, len(src), width):
        s = src[i:i+width]
        hexa = ' '.join(["%02X"%ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%04X   %s   %s\n" % (i, hexa, printable))
    return ''.join(result)


#---------------------------------------------------------------
# bytetodomain
# 03www06google02cn00 => www.google.cn
#--------------------------------------------------------------
def bytetodomain(s):
    domain = ''
    i = 0
    length = struct.unpack('!B', s[0:1])[0]

    while length != 0 :
        i += 1
        domain += s[i:i+length]
        i += length
        length = struct.unpack('!B', s[i:i+1])[0]
        if length != 0 :
            domain += '.'

    return domain

#--------------------------------------------------
# tcp dns request
#---------------------------------------------------
from pylru import lrudecorator
@lrudecorator(100)
def QueryDNS(server, port, querydata):
    # length
    Buflen = struct.pack('!h', len(querydata))
    sendbuf = Buflen + querydata
    data=None
    try:
        af = socket.AF_INET6 if int(IPV6) > 0 else socket.AF_INET
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT) # set socket timeout
        s.connect((server, int(port)))
        s.send(sendbuf)
        data = s.recv(2048)
    except Exception, e:
        print '[ERROR] QueryDNS: %s' %  e.message
    finally:
        if s: s.close()
        return data


#----------------------------------------------------
# show dns packet information
#----------------------------------------------------
def show_info(data, direction):
    try:
        from dns import message as m
    except ImportError:
        print "Install dnspython module will give you more response infomation."
    else:
        if direction == 0:
            print "query:\n\t", "\n\t".join(str(m.from_wire(data)).split("\n"))
            print "\n================"
        elif direction == 1:
            print "response:\n\t","\n\t".join(str(m.from_wire(data)).split("\n"))
            print "\n================"

#-----------------------------------------------------
# send udp dns respones back to client program
#----------------------------------------------------
def transfer(querydata, addr, server):
    if not querydata: return

    domain = bytetodomain(querydata[12:-4])
    qtype = struct.unpack('!h', querydata[-4:-2])[0]
    print 'domain:%s, qtype:%x, thread:%d' % \
         (domain, qtype, threading.activeCount())
    sys.stdout.flush()
    response=None

    SERVERS = DHOSTS_V6 if int(IPV6) > 0 else DHOSTS
    for i in range(len(SERVERS)):
        DHOST = SERVERS[i]
        response = QueryDNS(DHOST, DPORT, querydata)
        if response:
            # udp dns packet no length
            server.sendto(response[2:], addr)
            if int(VERBOSE) > 0:
                show_info(querydata, 0)
                show_info(response[2:], 1)
            break
    if response is None:
        print "[ERROR] Tried many times and failed to resolve %s" % domain


class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, s, t):
        af = socket.AF_INET6 if int(IPV6) > 0 else socket.AF_INET
        self.address_family = af
        SocketServer.UDPServer.__init__(self, s, t)

class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    # much faster rebinding
    allow_reuse_address = True

    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        addr = self.client_address
        transfer(data, addr, socket)

#------------------------------------------------------
# main entry
#------------------------------------------------------
if __name__ == "__main__":
    print '>> %s, version %s' % (NAME, VERSION)
    print '>> Please wait program init....'
    print '>> Init finished!'
    print '>> Now you can set dns server to 127.0.0.1 (::1)'

    parser = optparse.OptionParser()
    parser.add_option("-v", dest="verbose", default="0", help="Verbosity level, 0-2, default is 0")
    parser.add_option("-e", "--ipv6", dest="ipv6", default="0", help="Use ipv6 Dns query, default is ipv4")
    options, _ = parser.parse_args()
    VERBOSE = options.verbose
    IPV6 = options.ipv6

    server_addr = '::1' if int(IPV6) > 0 else '127.0.0.1'
    server = ThreadedUDPServer((server_addr, 53), ThreadedUDPRequestHandler)
    # on my ubuntu uid is 1000, change it
    # comment out below line on windows platform
    #os.setuid(1000)

    server.serve_forever()
    server.shutdown()

