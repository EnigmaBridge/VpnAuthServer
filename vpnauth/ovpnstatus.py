#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
OpenVPN status file parser
"""

import os
import logging
from dateutil.parser import parse


logger = logging.getLogger(__name__)


class OvpnClient(object):
    """
    OpenVPN client from the status file
    """
    def __init__(self, cname=None, addr=None, bytes_recv=None, bytes_sent=None, connected_since=None, *args, **kwargs):
        self.cname = cname
        self.addr = addr
        self.bytes_recv = bytes_recv
        self.bytes_sent = bytes_sent
        self.connected_since = connected_since

    def __repr__(self):
        return 'OvpnClient(cname=%r, addr=%r, bytes_recv=%r, bytes_sent=%r, connected_since=%r)' \
               % (self.cname, self.addr, self.bytes_recv, self.bytes_sent, self.connected_since)


class OvpnRoute(object):
    """
    OpenVpn route from the status file
    """
    def __init__(self, local_addr=None, cname=None, remote_addr=None, last_ref=None, *args, **kwargs):
        self.local_addr = local_addr
        self.cname = cname
        self.remote_addr = remote_addr
        self.last_ref = last_ref

    def __repr__(self):
        return 'OvpnRoute(local_addr=%r, cname=%r, remote_addr=%r, last_ref=%r)' \
               % (self.local_addr, self.cname, self.remote_addr, self.last_ref)


class OvpnStatusParser(object):
    """
    Parses ovpn status file
    """

    def __init__(self, status_file=None, status_data=None):
        self.status_file = status_file
        self.status_data = status_data
        self.clients = {}
        self.routes = {}

    def load_file(self):
        """
        Loads file content
        :return:
        """
        if self.status_data is not None:
            return self.status_data

        if not os.path.exists(self.status_file):
            return None

        with open(self.status_file, 'r') as fh:
            return fh.read()

    def try_parse_date(self, date_str):
        """
        Tries to parse datetime string to datetime
        :param str:
        :return:
        """
        try:
            return parse(date_str)
        except Exception as e:
            logger.info('Date parsing failed [%s]: %s' % (date_str, e))
            return date_str

    def process(self):
        """
        Parses the file
        :return:
        """
        data = self.load_file()
        if data is None:
            return

        lines = data.split('\n')
        if len(lines) == 0:
            return

        line_cnt = len(lines)
        line_idx = 0
        insection_idx = 0

        self.clients = {}
        self.routes = {}

        section = lines[0].upper()
        while section != 'END' and line_idx + 1 < line_cnt:
            line_idx += 1
            insection_idx += 1
            line = lines[line_idx].strip()

            if line == '':
                continue

            if section == 'OPENVPN CLIENT LIST':
                if insection_idx <= 2:
                    continue

                if ',' not in line:
                    section = line.upper()
                    insection_idx = 0
                    continue

                parts = line.split(',')

                # Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
                client = OvpnClient(cname=parts[0], addr=parts[1], bytes_recv=int(parts[2]), bytes_sent=int(parts[3]),
                                    connected_since=self.try_parse_date(parts[4]))
                self.clients[client.cname] = client
                continue

            if section == 'ROUTING TABLE':
                if insection_idx == 1:
                    continue

                if ',' not in line:
                    section = line.upper()
                    insection_idx = 0
                    continue

                parts = line.split(',')

                # Virtual Address,Common Name,Real Address,Last Ref
                route = OvpnRoute(local_addr=parts[0], cname=parts[1], remote_addr=parts[2],
                                  last_ref=self.try_parse_date(parts[3]))
                self.routes[route.cname] = route


