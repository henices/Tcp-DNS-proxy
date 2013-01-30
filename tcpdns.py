#! /usr/bin/python
# -*- coding: utf-8 -*-
# cody by zhouzhenster@gmail.com

# ver: 0.2 update 2011-10-23
#           use SocketServer to run a multithread udp server
# update:
# 2012-04-16, add more public dns servers support tcp dns query
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

DHOSTS = ['156.154.70.1', # remote dns server address list
         '8.8.8.8',
         '8.8.4.4',
         '156.154.71.1',
         #'208.67.222.222',
         #'208.67.220.220',
         #'198.153.192.1',
         #'198.153.194.1',
         #'74.207.247.4',
         #'209.244.0.3',
         #'8.26.56.26'
         ]
DPORT = 53                # default dns port 53
TIMEOUT = 20              # set timeout 5 second


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
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT) # set socket timeout
        s.connect((server, int(port)))
        s.send(sendbuf)
        data = s.recv(2048)
    except:
        print traceback.print_exc(sys.stdout)
        if s: s.close()
        return
      
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
    choose = random.sample(xrange(len(DHOSTS)), 1)[0]
    DHOST = DHOSTS[choose]
    response = QueryDNS(DHOST, DPORT, querydata)
    if response:
        # udp dns packet no length
        server.sendto(response[2:], addr)
    return

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
    print '>> Please wait program init....'
    print '>> Init finished!'
    print '>> Now you can set dns server to 127.0.0.1'

    server = ThreadedUDPServer(('127.0.0.1', 53), ThreadedUDPRequestHandler)
    # on my ubuntu uid is 1000, change it 
    # comment out below line on windows platform
    #os.setuid(1000)

    server.serve_forever()
    server.shutdown()

