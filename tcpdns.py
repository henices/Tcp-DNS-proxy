#! /usr/bin/python
# -*- coding: utf-8 -*-
# cody by zhouzhenster@gmail.com

# ver: 0.2 update 2011-10-23
#           use SocketServer to run a multithread udp server
# update:
# 2012-04-16, add more public dns servers support tcp dns query
# 2013-05-14  merge code from linkerlin, add gevent support
# 2013-06-24  add lru cache support
# 2013-08-14  add option to disable cache


#  8.8.8.8        google
#  8.8.4.4        google
#  156.154.70.1   Dnsadvantage
#  156.154.71.1   Dnsadvantage
#  208.67.222.222 OpenDNS
#  208.67.220.220 OpenDNS
#  198.153.192.1  Norton
#  198.153.194.1  Norton

import os, sys
import socket
import struct
import threading
import SocketServer
import traceback
import random
import optparse
from pylru import lrucache

try:
    import gevent
    from gevent import monkey
except:
    print "Install gevent will save a lot of CPU time\n"
else:
    monkey.patch_all()

DHOSTS = ['8.8.8.8',
         '8.8.4.4',
         '156.154.70.1',
         '156.154.71.1',
         '208.67.222.222',
         '208.67.220.220',
         #'198.153.192.1',
         #'198.153.194.1',
         '74.207.247.4',
         '209.244.0.3',
         '8.26.56.26'
         ]

DPORT = 53
TIMEOUT = 20
LRUCACHE = None


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
def QueryDNS(server, port, querydata):
    # length
    Buflen = struct.pack('!h', len(querydata))
    sendbuf = Buflen + querydata
    data=None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT) # set socket timeout
        s.connect((server, int(port)))
        s.send(sendbuf)
        data = s.recv(2048)
    except Exception, e:
        print '[ERROR] QueryDNS: %s' %  e.message
    finally:
        if s: s.close()
        return data

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
    t_id = querydata[:2]
    key = querydata[2:].encode('hex')

    if LRUCACHE is not None:
        try:
            response = LRUCACHE[key]
            server.sendto(t_id + response[4:], addr)
        except KeyError:
            pass

    if response is not None:
        return

    for i in range(len(DHOSTS)):
        DHOST = DHOSTS[i]
        response = QueryDNS(DHOST, DPORT, querydata)

        if response is None:
            continue

        if LRUCACHE is not None:
            LRUCACHE[key] = response

        # udp dns packet no length
        server.sendto(response[2:], addr)
        break

    if response is None:
        print "[ERROR] Tried many times and failed to resolve %s" % domain

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, s, t):
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

    parser = optparse.OptionParser()
    parser.add_option("-c", "--cached", action="store_true", dest="cache", default=False, help="Enable LRU cache")
    options, _ = parser.parse_args()
    CACHE = options.cache

    if CACHE:
        LRUCACHE = lrucache(100)

    print '>> Please wait program init....'
    print '>> Init finished!'
    print '>> Now you can set dns server to 127.0.0.1'

    server = ThreadedUDPServer(('127.0.0.1', 53), ThreadedUDPRequestHandler)

    server.serve_forever()
    server.shutdown()

