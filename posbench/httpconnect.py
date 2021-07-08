# -*- encoding=utf8 -*-

"""
description: http协议
author: baorb
"""

import sys
import httplib
import logging

if sys.version < '2.7':
    import myLib.myhttplib as httplib
try:
    import ssl
except ImportError:
    logging.warning('import ssl module error')
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    logging.warning('create unverified https context except')
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context


class MyHTTPConnection:
    def __init__(self, host, port=None, timeout=80):
        self.timeout = timeout
        self.connection = None
        self.host = host.split(',')[0]
        self.port = port

    def create_connection(self):
        self.connection = httplib.HTTPConnection('{}:{}'.format(self.host, self.port), timeout=self.timeout)
        logging.debug('create connection to host: ' + self.host)

    def close_connection(self):
        if not self.connection:
            return
        try:
            self.connection.close()
        except Exception, data:
            logging.error('Caught [%s], when close a connection' % data)
            # 此处暂不抛异常
            pass
        finally:
            self.connection = None

    def connect_connection(self):
        self.connection.connect()


def compare_version(v1, v2):
    v1 = v1.split('.')
    v2 = v2.split('.')
    try:
        for i in range(0, len(v1)):
            if len(v2) < i + 1:
                return 1
            elif int(v1[i]) < int(v2[i]):
                return -1
            elif int(v1[i]) > int(v2[i]):
                return 1
    except:
        return -1
    if len(v2) > len(v1):
        return -1
    return 0