#!/usr/bin/env python
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
# 2015-01-14  support dns server auto switch

#  8.8.8.8        google
#  8.8.4.4        google
#  156.154.70.1   Dnsadvantage
#  156.154.71.1   Dnsadvantage
#  208.67.222.222 OpenDNS
#  208.67.220.220 OpenDNS
#  198.153.192.1  Norton
#  198.153.194.1  Norton

import gevent
import os
import socket
import struct
import SocketServer
import argparse
import json
import time
from fnmatch import fnmatch
import logging
import third_party
from pylru import lrucache
import ctypes
import sys

cfg = {}
LRUCACHE = None
DNS_SERVERS = None
FAST_SERVERS = None
SPEED = {}
DATA = {'err_counter': 0, 'speed_test': False}
UDPMODE = False
PIDFILE = '/tmp/tcpdns.pid'


def cfg_logging(dbg_level):
    """ logging format
    """
    logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s',
                        level=dbg_level)

def hexdump(src, width=16):
    """ hexdump, default width 16
    """
    FILTER = ''.join(
        [(x < 0x7f and x > 0x1f) and chr(x) or '.' for x in range(256)])
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

def dnsping(ip, port):
    buff =  "\x00\x1d\xb2\x5f\x01\x00\x00\x01"
    buff += "\x00\x00\x00\x00\x00\x00\x07\x74"
    buff += "\x77\x69\x74\x74\x65\x72\x03\x63"
    buff += "\x6f\x6d\x00\x00\x01\x00\x01"

    cost = 100
    begin = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(cfg['socket_timeout'])
        s.connect((ip, int(port)))
        s.send(buff)
        s.recv(2048)
    except Exception as e:
        logging.error('%s:%s, %s' % (ip, port, str(e)))
    else:
        cost = time.time() - begin

    key = '%s:%d' % (ip, int(port))
    if key not in SPEED:
        SPEED[key] = []

    SPEED[key].append(cost)

def TestSpeed():
    global DNS_SERVERS
    global FAST_SERVERS
    global DATA

    DATA['speed_test'] = True

    if cfg['udp_mode']:
        servers = cfg['udp_dns_server']
    else:
        servers = cfg['tcp_dns_server']

    logging.info('Testing dns server speed ...')
    jobs = []
    for i in xrange(0, 6):
        for s in servers:
            ip, port = s.split(':')
            jobs.append(gevent.spawn(dnsping, ip, port))

    gevent.joinall(jobs)

    cost = {}
    for k, v in SPEED.items():
        cost[k] = sum(v)

    d = sorted(cost, key=cost.get)
    FAST_SERVERS = d[:3]
    DNS_SERVERS = FAST_SERVERS

    DATA['err_counter'] = 0
    DATA['speed_test'] = False

def QueryDNS(server, port, querydata):
    """tcp dns request

    Args:
        server: remote tcp dns server
        port: remote tcp dns port
        querydata: udp dns request packet data

    Returns:
        tcp dns response data
    """

    global DATA

    if DATA['err_counter'] >= 10 and not DATA['speed_test']:
        TestSpeed()

    # length
    Buflen = struct.pack('!h', len(querydata))
    sendbuf = UDPMODE and querydata or Buflen + querydata

    data = None
    try:
        protocol = UDPMODE and socket.SOCK_DGRAM or socket.SOCK_STREAM
        s = socket.socket(socket.AF_INET, protocol)

        # set socket timeout
        s.settimeout(cfg['socket_timeout'])
        s.connect((server, int(port)))
        s.send(sendbuf)
        data = s.recv(2048)
    except Exception as e:
        DATA['err_counter'] += 1
        logging.error('Server %s: %s' % (server, str(e)))
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
    q_type = struct.unpack('!h', data[-4:-2])[0]

    logging.debug('domain:%s, qtype:%x' % (q_domain, q_type))

    try:
        if q_type != 0x0001:
            return

        if Questions != '\x00\x01' or AnswerRRs != '\x00\x00' or \
            AuthorityRRs != '\x00\x00' or AdditionalRRs != '\x00\x00':
                return

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
    finally:
        return (q_type, q_domain, ret)


def check_dns_packet(data, q_type):

    global UDPMODE

    test_ipv4 = False
    test_ipv6 = False

    if len(data) < 12:
        return False

    Flags = UDPMODE and data[2:4] or data[4:6]

    Reply_code = struct.unpack('>h', Flags)[0] & 0x000F

    # TODO: need more check
    if Reply_code == 3:
        return True

    if q_type == 0x0001:

        ipv4_len = data[-6:-4]
        ipv4_answer_class = data[-12:-10]
        ipv4_answer_type = data[-14:-12]

        test_ipv4 = (ipv4_len == '\x00\x04' and \
                     ipv4_answer_class == '\x00\x01' and \
                     ipv4_answer_type == '\x00\x01')

        if not test_ipv4:

            ipv6_len = data[-18:-16]
            ipv6_answer_class = data[-24:-22]
            ipv6_answer_type =data[-26:-24]

            test_ipv6 = (ipv6_len == '\x00\x10' and \
                         ipv6_answer_class == '\x00\x01' and \
                         ipv6_answer_type == '\x00\x1c')

        if not (test_ipv4 or test_ipv6):
            return False

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
    global UDPMODE

    if len(querydata) < 12:
        return

    response = None
    t_id = querydata[:2]
    key = querydata[2:].encode('hex')

    q_type, q_domain, response = private_dns_response(querydata)
    if response:
        server.sendto(response, addr)
        return

    UDPMODE = cfg['udp_mode']
    if FAST_SERVERS:
        DNS_SERVERS = FAST_SERVERS
    else:
        DNS_SERVERS = \
                UDPMODE and cfg['udp_dns_server'] or cfg['tcp_dns_server']

    if cfg['internal_dns_server'] and cfg['internal_domain']:
        for item in cfg['internal_domain']:
            if fnmatch(q_domain, item):
                UDPMODE = True
                DNS_SERVERS = cfg['internal_dns_server']

    if LRUCACHE and  key in LRUCACHE:
        response = LRUCACHE[key]
        sendbuf = UDPMODE and response[2:] or response[4:]
        server.sendto(t_id + sendbuf, addr)

        return

    for item in DNS_SERVERS:
        ip, port = item.split(':')

        logging.debug("server: %s port:%s" % (ip, port))
        response = QueryDNS(ip, port, querydata)
        if response is None or not check_dns_packet(response, q_type):
            continue

        if LRUCACHE is not None:
            LRUCACHE[key] = response

        sendbuf = UDPMODE and response or response[2:]
        server.sendto(sendbuf, addr)

        break

    if response is None:
        logging.error('Tried many times and failed to resolve %s' % q_domain)


def HideCMD():
    whnd = ctypes.windll.kernel32.GetConsoleWindow()
    if whnd != 0:
        ctypes.windll.user32.ShowWindow(whnd, 0)
        ctypes.windll.kernel32.CloseHandle(whnd)



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


from daemon import Daemon
class RunDaemon(Daemon):

    def run(self):
        thread_main(cfg)

def StopDaemon():
    RunDaemon(PIDFILE).stop()

def thread_main(cfg):
    server = ThreadedUDPServer((cfg["host"], cfg["port"]), ThreadedUDPRequestHandler)
    server.serve_forever()
    server.shutdown()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP DNS Proxy')
    parser.add_argument('-f', dest='config_json', type=argparse.FileType('r'),
            required=False, help='Json config file')
    parser.add_argument('-d', dest='dbg_level', action='store_true',
            required=False, default=False, help='Print debug message')
    parser.add_argument('-s', dest="stop_daemon", action='store_true',
            required=False, default=False, help='Stop tcp dns proxy daemon')
    args = parser.parse_args()

    if args.stop_daemon:
        StopDaemon()
        sys.exit(0)

    if args.dbg_level:
        cfg_logging(logging.DEBUG)
    else:
        cfg_logging(logging.INFO)

    try:
        cfg = json.load(args.config_json)
    except:
        logging.error('Loading json config file error [!!]')
        sys.exit(1)

    if not cfg.has_key("host"):
        cfg["host"] = "0.0.0.0"

    if not cfg.has_key("port"):
        cfg["port"] = 53

    if cfg['udp_mode']:
        DNS_SERVERS = cfg['udp_dns_server']
    else:
        DNS_SERVERS = cfg['tcp_dns_server']

    if cfg['enable_lru_cache']:
        LRUCACHE = lrucache(cfg['lru_cache_size'])

    logging.info('TCP DNS Proxy, https://github.com/henices/Tcp-DNS-proxy')
    logging.info('DNS Servers:\n%s' % DNS_SERVERS)
    logging.info('Query Timeout: %f' % (cfg['socket_timeout']))
    logging.info('Enable Cache: %r' % (cfg['enable_lru_cache']))
    logging.info('Enable Switch: %r' % (cfg['enable_server_switch']))

    if cfg['speed_test']:
        TestSpeed()

    logging.info(
            'Now you can set dns server to %s:%s' % (cfg["host"], cfg["port"]))

    if cfg['daemon_process']:
        if os.name == 'nt':
            HideCMD()
            thread_main(cfg)
        else:
            d = RunDaemon(PIDFILE)
            d.start()
    else:
        thread_main(cfg)
