#! /usr/bin/python
# -*- coding: utf-8 -*-
# cody by zhouzhenster@gmail.com

#
# Change log:
#
# 2011-10-23  use SocketServer to run a multithread udp server
# 2012-04-16  add more public dns servers support tcp dns query
# 2013-05-14  merge code from @linkerlin, add gevent support
# 2013-06-24  add lru cache support
# 2013-08-14  add option to disable cache
# 2014-01-04  add option "servers", "timeout" @jinxingxing
# 2014-04-04  support daemon process on unix like platform
# 2014-05-27  support udp dns server on non-standard port
# 2014-07-08  use json config file
# 2014-07-09  support private host

#  8.8.8.8        google
#  8.8.4.4        google
#  156.154.70.1   Dnsadvantage
#  156.154.71.1   Dnsadvantage
#  208.67.222.222 OpenDNS
#  208.67.220.220 OpenDNS
#  198.153.192.1  Norton
#  198.153.194.1  Norton

try:
    from gevent import monkey
    from gevent.server import DatagramServer
except:
    print "*** Install gevent will save a lot of CPU time\n"
# else:
#    monkey.patch_all()


import os
import sys
import socket
import struct
import threading
import SocketServer
import argparse
import json
import re
from fnmatch import fnmatch
import third_party
from pylru import lrucache


cfg = {}
LRUCACHE = None
DNS_SERVERS = None

def hexdump(src, width=16):
    """ hexdump, default width 16
    """
    FILTER = ''.join(
        [(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    result = []
    for i in xrange(0, len(src), width):
        s = src[i:i + width]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%04X   %s   %s\n" % (i, hexa, printable))
    return ''.join(result)


def bytetodomain(s):
    """bytetodomain

    03www06google02cn00 => www.google.cn
    """
    domain = ''
    i = 0
    length = struct.unpack('!B', s[0:1])[0]

    while length != 0:
        i += 1
        domain += s[i:i + length]
        i += length
        length = struct.unpack('!B', s[i:i + 1])[0]
        if length != 0:
            domain += '.'

    return domain


def QueryDNS(server, port, querydata):
    """tcp dns request

    Args:
        server: remote tcp dns server
        port: remote tcp dns port
        querydata: udp dns request packet data

    Returns:
        tcp dns response data
    """

    if cfg['udp_mode']:
        sendbuf = querydata
    else:
        # length
        Buflen = struct.pack('!h', len(querydata))
        sendbuf = Buflen + querydata

    data = None
    try:
        if not cfg['udp_mode']:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # set socket timeout
        s.settimeout(cfg['socket_timeout'])
        s.connect((server, int(port)))
        s.send(sendbuf)
        data = s.recv(2048)
    except Exception as e:
        print '[ERROR] QueryDNS: %s' % e.message
    finally:
        if s:
            s.close()
        return data


def private_dns_response(data):
    ret = None

    TID = data[0:2]
    Questions = data[4:6]
    AnswerRRs = data[6:8]
    AuthorityRRs = data[8:10]
    AdditionalRRs = data[10:12]

    q_domain = bytetodomain(data[12:-4])
    qtype = struct.unpack('!h', data[-4:-2])[0]
    print 'domain:%s, qtype:%x' % (q_domain, qtype)
    sys.stdout.flush()

    if qtype != 0x0001:
        return None

    if Questions != '\x00\x01' or AnswerRRs != '\x00\x00' or \
        AuthorityRRs != '\x00\x00' or AdditionalRRs != '\x00\x00':
            return None

    items = cfg['private_host'].items()

    for domain, ip in items:
        if fnmatch(q_domain, domain):
            ret = TID
            ret += '\x81\x80'
            ret += '\x00\x01'
            ret += '\x00\x01'
            ret += '\x00\x00'
            ret += '\x00\x00'
            ret += data[12:]
            ret += '\xc0\x0c'
            ret += '\x00\x01'
            ret += '\x00\x01'
            ret += '\x00\x00\xff\xff'
            ret += '\x00\x04'
            ret +=  socket.inet_aton(ip)

    return ret


def check_dns_packet(data):

    if cfg['udp_mode']:
        Flags = data[2:4]
    else:
        Flags = data[4:6]

    Reply_code = struct.unpack('>h', Flags)[0] & 0x000F
    return Reply_code == 0


def transfer(querydata, addr, server):
    """send udp dns respones back to client program

    Args:
        querydata: udp dns request data
        addr: udp dns client address
        server: udp dns server socket

    Returns:
        None
    """

    if len(querydata) < 12:
        return

    response = None
    t_id = querydata[:2]
    key = querydata[2:].encode('hex')

    response = private_dns_response(querydata)
    if response:
        server.sendto(response, addr)
        return

    if LRUCACHE and  key in LRUCACHE:
        response = LRUCACHE[key]
        if cfg['udp_mode']:
            server.sendto(t_id + response[2:], addr)
        else:
            server.sendto(t_id + response[4:], addr)

        return

    for item in DNS_SERVERS:
        ip, port = item.split(':')

        response = QueryDNS(ip, port, querydata)
        if response is None:
            continue

        if LRUCACHE is not None and check_dns_packet(response):
            LRUCACHE[key] = response

        if cfg['udp_mode']:
            server.sendto(response, addr)
        else:
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


class GeventUDPServer(DatagramServer):

    def handle(self, data, address):
        transfer(data, address, self.socket)


def thread_main():
    server = ThreadedUDPServer(('127.0.0.1', 53), ThreadedUDPRequestHandler)
    server.serve_forever()
    server.shutdown()


def gevent_main():
    GeventUDPServer('127.0.0.1:53').serve_forever()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='TCP DNS Proxy')
    parser.add_argument('-f', dest='config_json', type=argparse.FileType('r'),
            required=True, help='Json config file')
    args = parser.parse_args()

    cfg = json.load(args.config_json)

    server = thread_main

    if cfg['use_gevent']:
        server = gevent_main

    if cfg['udp_mode']:
        DNS_SERVERS = cfg['udp_dns_server']
    else:
        DNS_SERVERS = cfg['tcp_dns_server']

    if cfg['enable_lru_cache']:
        LRUCACHE = lrucache(cfg['lru_cache_size'])

    print '>> TCP DNS Proxy, https://github.com/henices/Tcp-DNS-proxy'
    print '>> DNS Servers:\n%s' % ('\n'.join(DNS_SERVERS))
    print '>> Query Timeout: %f' % (cfg['socket_timeout'])
    print '>> Enable Cache: %r' % (cfg['enable_lru_cache'])
    print '>> Now you can set dns server to 127.0.0.1'

    if cfg['daemon_process']:
        if os.name == 'nt':
            raise Exception("Windows doesn't support daemon process")
        else:
            try:
                import daemon
                print '>>> Run code in daemon process'
            except ImportError:
                print '*** Please install python-daemon'

    try:
        with daemon.DaemonContext(detach_process=True):
            server()
    except:
        server()
