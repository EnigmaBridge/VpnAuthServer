#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Notifier part of the script
"""

from core import Core
from config import Config

import threading
import pid
import time
import os
import sys
import util
import requests
import argparse
import logging
import coloredlogs
import traceback
import collections
import server


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class Notifier(object):
    """
    Main notifier object
    """

    def __init__(self, *args, **kwargs):
        self.core = Core()
        self.args = None
        self.config = None
        self.last_result = None

    def return_code(self, code=0):
        self.last_result = code
        return code

    def build_payload(self):
        """
        Builds payload by extracting information from env vars
        :return:
        """
        def add_payload(payload, key, env_key=None):
            if env_key is None:
                env_key = key
            if env_key in os.environ:
                payload[key] = os.environ[env_key]

        payload = collections.OrderedDict()
        payload['time'] = time.time()

        add_payload(payload, 'dev_type')
        add_payload(payload, 'dev')
        add_payload(payload, 'cname', 'common_name')
        add_payload(payload, 'username', 'common_name')

        add_payload(payload, 'local_ip', 'ifconfig_pool_remote_ip')
        add_payload(payload, 'remote_ip', 'trusted_ip')
        add_payload(payload, 'remote_port', 'trusted_port')
        add_payload(payload, 'proto', 'proto_1')

        add_payload(payload, 'duration', 'time_duration')
        add_payload(payload, 'bytes_sent', 'bytes_sent')
        add_payload(payload, 'bytes_recv', 'bytes_received')
        payload['aux'] = dict(os.environ)
        return payload

    def work(self):
        """
        Main entry
        :return:
        """
        if self.args.ebstall:
            self.config = Config.from_file('/etc/enigma/config.json')
            self.config.mysql_db = self.config.vpnauth_db
            self.config.mysql_password = self.config.vpnauth_password
            self.config.mysql_user = 'vpnauth'

        else:
            self.config = Core.read_configuration()
            if self.config is None or not self.config.has_nonempty_config():
                sys.stderr.write('Configuration is empty: %s\nCreating default one... (fill in access credentials)\n'
                                 % Core.get_config_file_path())

                Core.write_configuration(Config.default_config())
                return self.return_code(1)

        base_url = 'http://127.0.0.1:%d/api/v1.0/' % server.Server.HTTP_PORT
        url = base_url
        evt = self.args.event

        if evt == 'connected':
            url += 'onConnected'

        elif evt == 'disconnected':
            url += 'onDisconnected'

        elif evt == 'up':
            url += 'onUp'

        elif evt == 'down':
            url += 'onDown'

        else:
            logger.error('Unknown event: ')
            return

        data = self.build_payload()
        js = collections.OrderedDict()
        js['evt'] = evt
        js['time'] = time.time()
        js['data'] = util.protect_payload(data, config=self.config)

        try:
            res = requests.post(url, json=js)
            res.raise_for_status()
            res_json = res.json()

        except Exception as e:
            logger.info('Exception in calling %s : %s' % (url, e))
            logger.debug(traceback.format_exc())

        sys.exit(0)

    def app_main(self):
        """
        Argument parsing & startup
        :return:
        """
        # Parse our argument list
        parser = argparse.ArgumentParser(description='EnigmaBridge VPN Auth server notifier')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='enables debug mode')

        parser.add_argument('--verbose', dest='verbose', action='store_const', const=True,
                            help='enables verbose mode')

        parser.add_argument('--event', dest='event',
                            help='notify event')

        parser.add_argument('--ebstall', dest='ebstall', default=False, action='store_const', const=True,
                            help='ebstall compatible mode - uses enigma configuration')

        parser.add_argument('args', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Further arguments (e.g., config file)')

        self.args = parser.parse_args()
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
    """
    Main server starter
    :return:
    """
    app = Notifier()
    app.app_main()


if __name__ == '__main__':
    main()

