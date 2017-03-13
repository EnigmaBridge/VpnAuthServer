#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Server part of the script
"""

from daemon import Daemon
from core import Core
from config import Config

import threading
import pid
import time
import os
import sys
import argparse
from threading import Lock as Lock
from threading import RLock as RLock
import logging
import coloredlogs
import traceback


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class AppDeamon(Daemon):
    """
    Daemon wrapper
    """
    def __init__(self, *args, **kwargs):
        Daemon.__init__(self, *args, **kwargs)
        self.app = kwargs.get('app')

    def run(self, *args, **kwargs):
        self.app.work()


class Server(object):
    """
    Main server object
    """

    def __init__(self, *args, **kwargs):
        self.core = Core()
        self.args = None
        self.config = None

        self.logdir = '/var/log/enigma-vpnauth'
        self.piddir = '/var/run'

        self.daemon = None
        self.running = True
        self.run_thread = None
        self.stop_event = threading.Event()

        self.last_result = None

        self.db = None
        self.queue_thread = None
        self.queue_lock = RLock()

    def check_pid(self, retry=True):
        """
        Check the PID lock ownership
        :param retry:
        :return:
        """
        first_retry = True
        attempt_ctr = 0
        while first_retry or retry:
            try:
                first_retry = False
                attempt_ctr += 1

                self.core.pidlock_create()
                if attempt_ctr > 1:
                    print('\nPID lock acquired')
                return True

            except pid.PidFileAlreadyRunningError as e:
                return True

            except pid.PidFileError as e:
                pidnum = self.core.pidlock_get_pid()
                print('\nError: CLI already running in exclusive mode by PID: %d' % pidnum)

                if self.args.pidlock >= 0 and attempt_ctr > self.args.pidlock:
                    return False

                print('Next check will be performed in few seconds. Waiting...')
                time.sleep(3)
        pass

    def return_code(self, code=0):
        self.last_result = code
        return code

    def start_daemon(self):
        """
        Starts daemon mode
        :return:
        """
        self.daemon = AppDeamon('/var/run/enigma-vpnauth-server.pid',
                                stderr=os.path.join(self.logdir, "stderr.log"),
                                stdout=os.path.join(self.logdir, "stdout.log"),
                                app=self)
        self.daemon.start()

    def work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('Scanning thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:


            contacted = set([])
            maxid = self.config.maxid if self.config.maxid is not None else 0L

            while not self.stop_event.is_set():
                # do simple search, later, here will be policy from the rule
                # https://dev.twitter.com/rest/reference/get/search/tweets

                # For each rule do the query & take the action
                for rule_idx, rule in enumerate(self.rules):
                    try:
                        self.current_rule = rule_idx
                        res = self.read_all_new_tweets(q=rule.q, rule=rule, since_id=rule.since_id,
                                                       contacted=contacted, process_tweet=self.rule_process)
                        since_id, max_id, contacted = res
                        rule.since_id = since_id

                    except Exception as e:
                        traceback.print_exc()
                        logger.error('Exception: %s' % e)

                    finally:
                        self.rule_update()
                        self.flush_audit()

                    if self.stop_event.is_set():
                        break

                self.current_rule = None
                Core.write_configuration(self.config)

                # sleep time - interruptible.
                sleep_time = 20 if self.args.fast else self.args.sleep
                self.interruptible_sleep(sleep_time)

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception: %s' % e)
            logger.error(e)

        finally:
            self.rule_update()
            self.flush_audit()

        logger.info('Work loop terminated')

    def work_loop(self):
        """
        Process configuration, initialize connections, databases, start threads.
        :return:
        """
        self.config = Core.read_configuration()
        if self.config is None or not self.config.has_nonempty_config():
            sys.stderr.write('Configuration is empty: %s\nCreating default one... (fill in access credentials)\n'
                             % Core.get_config_file_path())

            Core.write_configuration(Config.default_config())
            return self.return_code(1)

        # load rules.
        rule_ok = self.rule_load()
        if not rule_ok:
            logger.info('Starting without rules file - manual mode')
            self.cmdloop()
            return

        if not self.check_root() or not self.check_pid():
            return self.return_code(1)

        # DB init
        self.init_db()

        # Resume state from monitoring files if we have any
        self.state_resume()
        self.follow_history_resume()

        # Kick off twitter - for initial load
        self.twitter_login_if_needed()

        # Sub threads
        self.follow_thread = threading.Thread(target=self.follow_main, args=())
        self.follow_thread.start()

        # Daemon vs. run mode.
        if self.args.daemon:
            self.start_daemon()

        elif self.args.direct:
            self.work()

        else:
            # start thread with work method.
            self.run_thread = threading.Thread(target=self.work, args=())
            self.run_thread.start()

            # work locally
            logger.info('Main thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
            self.cmdloop()

    def app_main(self):
        """
        Argument parsing & startup
        :return:
        """
        # Parse our argument list
        parser = argparse.ArgumentParser(description='EnigmaBridge VPN Auth server')
        parser.add_argument('-l', '--pid-lock', dest='pidlock', type=int, default=-1,
                            help='number of attempts for pidlock acquire')
        parser.add_argument('--debug', dest='debug', action='store_const', const=True,
                            help='enables debug mode')
        parser.add_argument('--verbose', dest='verbose', action='store_const', const=True,
                            help='enables verbose mode')

        parser.add_argument('-d', '--daemon', dest='daemon', default=False, action='store_const', const=True,
                            help='Runs in daemon mode')

        self.args = parser.parse_args(args=args_src[1:])
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work_loop()


def main():
    """
    Main server starter
    :return:
    """
    app = Server()
    app.app_main()


if __name__ == '__main__':
    main()

