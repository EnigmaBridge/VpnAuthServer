#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Server part of the script
"""

from daemon import Daemon
from core import Core
from config import Config
from dbutil import MySQL, VpnUserSessions, VpnUserState

import threading
import pid
import time
import os
import sys
import util
import argparse
import calendar
from threading import Lock as Lock
from threading import RLock as RLock
import logging
import coloredlogs
import traceback
import collections
import BaseHTTPServer
from flask import Flask, jsonify, request, abort
from datetime import datetime, timedelta
import sqlalchemy as salch


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
    HTTP_PORT = 32080
    HTTPS_PORT = 32443

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

        self.flask = Flask(__name__)
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

    def init_log(self):
        """
        Initializes logging
        :return:
        """
        util.make_or_verify_dir(self.logdir)

    def init_db(self):
        """
        Initializes the database
        :return:
        """
        self.db = MySQL(config=self.config)
        self.db.init_db()

    #
    # REST interface
    #

    def init_rest(self):
        """
        Initializes rest server
        TODO: auth for dump, up, down - encrypt time token.
        :return:
        """
        @self.flask.route('/api/v1.0/dump', methods=['GET'])
        def rest_dump():
            return self.on_dump(request)

        @self.flask.route('/api/v1.0/verify', methods=['GET'])
        def rest_verify():
            return jsonify({'result': False})   # TODO: implement verification

        @self.flask.route('/api/v1.0/onConnected', methods=['GET', 'POST'])
        def client_connected():
            return self.on_client_change(request, True)

        @self.flask.route('/api/v1.0/onDisconnected', methods=['GET', 'POST'])
        def client_disconnected():
            return self.on_client_change(request, False)

        @self.flask.route('/api/v1.0/onUp', methods=['GET', 'POST'])
        def on_up():
            return self.on_server_state_change(request, up=True)

        @self.flask.route('/api/v1.0/onDown', methods=['GET', 'POST'])
        def on_down():
            return self.on_server_state_change(request, up=False)

    def on_dump(self, request):
        """
        Dump state config
        :return:
        """
        s = self.db.get_session()
        states = s.query(VpnUserState).all()

        res = {}
        for state in states:
            obj = collections.OrderedDict()
            obj['username'] = state.username
            obj['cname'] = state.cname
            obj['connected'] = state.connected

            obj['date_updated'] = calendar.timegm(state.date_updated.timetuple())
            obj['date_connected'] = calendar.timegm(state.date_connected.timetuple())

            obj['client_local_ip'] = state.client_local_ip
            obj['client_remote_ip'] = state.client_remote_ip
            obj['client_remote_port'] = state.client_remote_port
            obj['proto'] = state.proto
            obj['bytes_sent'] = state.bytes_sent
            obj['bytes_recv'] = state.bytes_recv
            res[state.cname] = obj

        return jsonify({'result': True, 'data': res})

    def on_server_state_change(self, request, up=True):
        """
        On server state change
        :param request:
        :param up:
        :return:
        """
        s = self.db.get_session()
        try:
            self.disconnect_all(s)
            s.commit()

        except Exception as e:
            logger.warning('Exception in disconnecting users %s' % e)
            logger.warning(traceback.format_exc())

        finally:
            util.silent_close(s)

        return jsonify({'result': True})

    def on_client_change(self, request, on_connected=True):
        """
        Called on client change
        :return:
        """
        logger.info('Req: %s' % request)
        if not request.json or 'data' not in request.json:
            logger.warning('Invalid request')
            abort(400)

        data = request.json['data']
        js = util.unprotect_payload(data, self.config)

        s = self.db.get_session()
        try:
            self.store_user_state(js, s, on_connected=on_connected)
            if not on_connected:
                self.store_user_session(js, s)

            s.commit()

        except Exception as e:
            logger.warning('Exception in storing user change %s' % e)
            logger.warning(traceback.format_exc())

        finally:
            util.silent_close(s)

        return jsonify({'result': True})

    #
    # DB Update
    #

    def disconnect_all(self, s):
        """
        Disconnects all users
        :param s: session
        :return:
        """
        stmt = salch.update(VpnUserState).values({
            'connected': 0
        })
        self.db.get_engine().execute(stmt)

    def store_user_state(self, user, s, on_connected=True):
        """
        Stores username to the database.
        :param user:
        :param s: session
        :param on_connected:
        :return:
        """
        try:
            db_user = s.query(VpnUserState).filter(VpnUserState.cname == user['cname']).one_or_none()
            new_one = True

            if db_user is None:
                db_user = VpnUserState()
                db_user.cname = user['cname']
                db_user.username = user['username']
            else:
                new_one = False

            db_user.date_updated = salch.func.now()
            db_user.connected = 1 if on_connected else 0
            db_user.proto = user['proto']
            db_user.client_local_ip = user['local_ip']
            db_user.client_remote_ip = user['remote_ip']
            db_user.client_remote_port = user['remote_port']

            if on_connected:
                db_user.bytes_sent = 0
                db_user.bytes_recv = 0
                # db_user.duration = 0
                db_user.date_connected = salch.func.now()

            else:
                db_user.bytes_sent = user['bytes_sent']
                db_user.bytes_recv = user['bytes_recv']
                # db_user.duration = user['duration']
                db_user.date_connected = None

            if new_one:
                s.add(db_user)
            else:
                s.merge(db_user)
            return 0

        except Exception as e:
            traceback.print_exc()
            logger.warning('User query problem: %s' % e)
            return 1

    def store_user_session(self, user, s):
        """
        Stores a new user session to DB
        :param user:
        :param s:
        :return:
        """
        try:
            db_user = VpnUserSessions()
            db_user.cname = user['cname']
            db_user.username = user['username']

            duration = int(user['duration'])
            disconnected = datetime.now()
            db_user.date_disconnected = disconnected
            db_user.date_connected = disconnected - timedelta(seconds=duration)

            db_user.proto = user['proto']
            db_user.client_local_ip = user['local_ip']
            db_user.client_remote_ip = user['remote_ip']
            db_user.client_remote_port = user['remote_port']

            db_user.bytes_sent = int(user['bytes_sent'])
            db_user.bytes_recv = int(user['bytes_recv'])
            db_user.duration = duration
            s.add(db_user)

            return 0

        except Exception as e:
            traceback.print_exc()
            logger.warning('User stat save problem: %s' % e)
            return 1

    #
    # Server
    #

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

    def shutdown_server(self):
        """
        Shutdown flask server
        :return:
        """
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()

    def work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('REST thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            r = self.flask.run(debug=self.args.server_debug, port=self.HTTP_PORT)
            logger.info('Terminating flask: %s' % r)

        except Exception as e:
            logger.error('Exception: %s' % e)
            logger.error(traceback.format_exc())
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

        if self.args.server_debug and self.args.daemon:
            # Server debug causes flask to restart the whole daemon (due to server reloading on code change)
            logger.error('Server debug and deamon are mutually exclusive')
            raise ValueError('Invalid start arguments')

        # Init
        self.init_log()
        self.init_db()
        self.init_rest()

        # Sub threads
        # self.queue_thread = threading.Thread(target=self.follow_main, args=())
        # self.follow_thread.start()

        # Daemon vs. run mode.
        if self.args.daemon:
            logger.info('Starting daemon')
            self.start_daemon()

        else:
            # if not self.check_pid():
            #     return self.return_code(1)
            self.work()

    def app_main(self):
        """
        Argument parsing & startup
        :return:
        """
        # Parse our argument list
        parser = argparse.ArgumentParser(description='EnigmaBridge VPN Auth server')

        parser.add_argument('-l', '--pid-lock', dest='pidlock', type=int, default=-1,
                            help='number of attempts for pidlock acquire')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='enables debug mode')

        parser.add_argument('--server-debug', dest='server_debug', default=False, action='store_const', const=True,
                            help='enables server debug mode')

        parser.add_argument('--verbose', dest='verbose', action='store_const', const=True,
                            help='enables verbose mode')

        parser.add_argument('-d', '--daemon', dest='daemon', default=False, action='store_const', const=True,
                            help='Runs in daemon mode')

        self.args = parser.parse_args()
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

