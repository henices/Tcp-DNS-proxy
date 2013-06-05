#! /usr/bin/python
# -*- coding: utf-8 -*-
# cody by linker.lin@me.com

import socket
from bg_worker import bgworker
from connection import Connection


TIMEOUT = 3
# a connection pool
class ConnectionPool(object):
    def __init__(self, ttl=1):
        self.conn_pool = {}
        self.inuse_conn = {}

    def getConnection(self, ip, port, socket_type=socket.SOCK_STREAM, socket_family=socket.AF_INET, timeout=TIMEOUT):
        #print "conn_pool",self.conn_pool
        conn_key = (socket_family, socket_type, ip, port, timeout)
        if conn_key in self.conn_pool:
            conn = self.conn_pool[conn_key]
            if not conn.isTimeout():
                del self.conn_pool[conn_key]
                self.inuse_conn[conn] = conn_key
                #print "conn_pool",self.conn_pool
                return conn
            elif conn.isTimeout():
                #print conn, "timeout"
                del self.conn_pool[conn_key]
        conn = Connection(conn_key)
        self.inuse_conn[conn] = conn_key
        #print self.conn_pool
        return conn

    def releaseConnection(self, conn):
        #print "inuse_conn",self.inuse_conn
        if conn in self.inuse_conn:
            conn_key = self.inuse_conn[conn]
            if not conn.isTimeout():
                self.conn_pool[conn_key] = conn
            else:
                def f():
                    self.conn_pool[conn_key] = Connection(conn.getKey())
                bgworker.post(lambda :f())
                #print conn, "timeout"
                pass
            del self.inuse_conn[conn]
        else:
            print "Error", "release a unknown connection.", conn
        #print "inuse_conn",self.inuse_conn





main_conn_pool = ConnectionPool(100)
if __name__ == "__main__":
    for i in range(100):
        c = main_conn_pool.getConnection('8.8.8.8', 53)
        main_conn_pool.releaseConnection(c)
        c = main_conn_pool.getConnection('8.8.8.8', 53)
        main_conn_pool.releaseConnection(c)
