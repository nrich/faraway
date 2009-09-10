#!/usr/bin/python

import socket
import simplejson
import time
import httplib
import urllib
import sys

class Client:
    def __init__(self, Host='127.0.0.1', Port=None, SSL=0):
	if Port == None:
	    if SSL:
		conclass = httplib.HTTPSConnection
		Port = 9096
	    else:
		conclass = httplib.HTTPConnection
		Port = 9095

	hoststr = '%s:%d' % (Host, Port)

	self.conn = conclass(hoststr)

    def __getattr__(self, name):
	return lambda data={}: self.call_remote(name, data)

    def call_remote(self, action, data):
        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Accept": "text/plain"
        }

	obj = {
	    'timestamp': int(time.time()),
	    'data': data,
	}

	obj['checksum'] = 1

        self.conn.request("POST", '/' + action, simplejson.dumps(obj), headers)
        res = self.conn.getresponse()

	response = simplejson.loads(res.read())
	return response
