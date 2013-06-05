#! /usr/bin/python
# -*- coding: utf-8 -*-
# cody by linker.lin@me.com

import socket
from bg_worker import bgworker
import time


class Connection(object):
    def __init__(self, conn_key):
        self.key = conn_key
        self.timestamp = time.time()
        self.timeout = conn_key[4]
        self.s = self._createSocket(self.key)


    def isTimeout(self):
        return self.timestamp + self.timeout < time.time()

    def getKey(self):
        return self.key

    def getSokcet(self):
        return self.s

    def _createSocket(self, conn_key):
        #print "create a new connection:", conn_key
        socket_family = conn_key[0]
        socket_type = conn_key[1]
        ip = conn_key[2]
        port = conn_key[3]
        timeout = conn_key[4]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout) # set socket timeout
        s.connect((ip, int(port)))
        return s

if __name__ == "__main__":
    c = Connection((socket.AF_INET,socket.AF_INET,'8.8.8.8', 53,10))
    print c.isTimeout()