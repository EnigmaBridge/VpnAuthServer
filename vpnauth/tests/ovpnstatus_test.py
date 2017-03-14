#!/usr/bin/env python
# -*- coding: utf-8 -*-

from vpnauth.ovpnstatus import *
import unittest
import datetime

__author__ = 'dusanklinec'


test1 = """OpenVPN CLIENT LIST
Updated,Tue Mar 14 11:54:08 2017
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
tester@gmail.com/default,200.10.20.30:51264,935376,4331157,Tue Mar 14 11:32:25 2017
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,tester@gmail.com/default,200.10.20.30:51264,Tue Mar 14 11:54:07 2017
GLOBAL STATS
Max bcast/mcast queue length,0
END"""

test2 = """OpenVPN CLIENT LIST
Updated,Tue Mar 14 11:54:08 2017
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
GLOBAL STATS
Max bcast/mcast queue length,0
END"""


class OvpnStatusParserTest(unittest.TestCase):
    """Simple test"""

    def __init__(self, *args, **kwargs):
        super(OvpnStatusParserTest, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test1(self):
        parser = OvpnStatusParser(status_data=test1)
        parser.process()

        # Simple parser test
        self.assertEqual(len(parser.clients), 1)
        self.assertEqual(len(parser.routes), 1)

        key = 'tester@gmail.com/default'
        self.assertTrue(key in parser.clients)
        self.assertTrue(key in parser.routes)

        cl = parser.clients[key]
        rt = parser.routes[key]
        self.assertEqual(cl.bytes_sent, 4331157)
        self.assertTrue(isinstance(cl.connected_since, datetime.datetime))

        self.assertEqual(rt.local_addr, '10.8.0.2')
        self.assertTrue(isinstance(rt.last_ref, datetime.datetime))

    def test2(self):
        parser = OvpnStatusParser(status_data=test2)
        parser.process()

        # Simple parser test
        self.assertEqual(len(parser.clients), 0)
        self.assertEqual(len(parser.routes), 0)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


