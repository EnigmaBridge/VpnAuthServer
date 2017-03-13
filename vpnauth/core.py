#!/usr/bin/env python
# -*- coding: utf-8 -*-

from config import Config
import os.path
import pid
import util
from datetime import datetime


CONFIG_DIR = '/etc/enigma-vpnauth'
CONFIG_FILE = 'config.json'


class Core(object):
    """
    Pidlock + configuration
    """
    def __init__(self, *args, **kwargs):
        """Init the core functions"""
        self.pidlock = pid.PidFile(pidname='enigma-vpnauth.pid', piddir='/var/run')
        self.pidlock_created = False

    def pidlock_create(self):
        """
        Creates a new pidlock if it was not yet created
        :return:
        """
        if not self.pidlock_created:
            self.pidlock.create()
            self.pidlock_created = True

    def pidlock_check(self):
        """
        Checks if the current process owns the pidlock
        :return: True if the current process owns the pidlock
        """
        return self.pidlock.check()

    def pidlock_get_pid(self):
        """
        Returns pid of the process holding pidlock, None if there is none.
        :return:
        """
        filename = self.pidlock.filename
        if filename and os.path.isfile(filename):
            try:
                with open(filename, "r") as fh:
                    fh.seek(0)
                    pid = int(fh.read().strip())
                    return pid
            except:
                pass

        return None

    @staticmethod
    def get_config_file_path():
        """Returns basic configuration file"""
        return os.path.join(CONFIG_DIR, CONFIG_FILE)

    @staticmethod
    def config_file_exists():
        conf_name = Core.get_config_file_path()
        return os.path.exists(conf_name) and os.path.isfile(conf_name)

    @staticmethod
    def is_configuration_nonempty(config):
        return config is not None and config.has_nonempty_config()

    @staticmethod
    def read_configuration():
        if not Core.config_file_exists():
            return None

        conf_name = Core.get_config_file_path()
        return Config.from_file(conf_name)

    @staticmethod
    def write_configuration(cfg):
        util.make_or_verify_dir(CONFIG_DIR, mode=0o755)

        conf_name = Core.get_config_file_path()
        with os.fdopen(os.open(conf_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as config_file:
            config_file.write('// \n')
            config_file.write('// Config file generated: %s\n' % datetime.now().strftime("%Y-%m-%d %H:%M"))
            config_file.write('// \n')
            config_file.write(cfg.to_string() + "\n\n")
        return conf_name
