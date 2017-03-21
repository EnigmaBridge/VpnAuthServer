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
import json
import argparse
import calendar
from threading import RLock as RLock
import logging
import coloredlogs
import traceback
import collections
from flask import Flask, jsonify, request, abort
from datetime import datetime, timedelta
from ovpnstatus import OvpnClient, OvpnRoute, OvpnStatusParser
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

        self.status_file = '/etc/openvpn/openvpn-status.log'
        self.logdir = '/var/log/enigma-vpnauth'
        self.piddir = '/var/run'

        self.daemon = None
        self.running = True
        self.run_thread = None
        self.stop_event = threading.Event()

        self.last_result = None

        self.flask = Flask(__name__)
        self.db = None
        self.disconnected_cache = {}  # cname -> disconnected event time

        self.status_thread = None
        self.status_thread_lock = RLock()
        self.status_last_check = 0
        self.status_check_time = 5

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

    def init_config(self):
        """
        Initializes configuration
        :return:
        """
        if self.args.ebstall:
            self.config = Config.from_file('/etc/enigma/config.json')
            self.config.mysql_db = self.config.vpnauth_db
            self.config.mysql_password = self.config.vpnauth_db_password
            self.config.mysql_user = 'vpnauth'
            return

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

        @self.flask.route('/api/v1.0/stats', methods=['GET'])
        def rest_stats():
            return self.on_stats(request)

        @self.flask.route('/api/v1.0/verify', methods=['GET', 'POST'])
        def rest_verify():
            return self.on_verify(request)

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

    def process_payload(self, request):
        """
        Decrypts payload, fails request in case of a problem
        :param request:
        :return:
        """
        if not request.json or 'data' not in request.json:
            logger.warning('Invalid request')
            abort(400)

        data = request.json['data']
        js = util.unprotect_payload(data, self.config)

        if time.time() - js['time'] > 60:
            logger.warning('Client change update too old')
            abort(403)
        return js

    def vpn_user_to_obj(self, user):
        """
        Converts Db User state to the object.
        Used in building REST responses.
        :param user:
        :return:
        """
        obj = collections.OrderedDict()
        obj['cname'] = user.cname
        obj['connected'] = user.connected

        obj['date_updated'] = calendar.timegm(user.date_updated.timetuple())
        obj['date_connected'] = calendar.timegm(user.date_connected.timetuple())

        obj['client_local_ip'] = user.client_local_ip
        obj['client_remote_ip'] = user.client_remote_ip
        obj['client_remote_port'] = user.client_remote_port
        obj['proto'] = user.proto
        obj['bytes_sent'] = user.bytes_sent
        obj['bytes_recv'] = user.bytes_recv
        return obj

    def on_stats(self, request):
        """
        Returns stats for daily, monthly use
        :return:
        """
        res = self.build_stats()
        return jsonify({'result': True, 'data': res})

    def on_verify(self, request):
        """
        Verify request for ip, username.
        :param request:
        :return:
        """
        ip = request.args.get('ip')
        user = request.args.get('user')

        if ip is None and user is None:
            abort(400)
        if user is not None:
            if '%' in user:
                abort(403)

        # User is optional, can be the email only.
        # IP, user, or both.
        db_user = None
        s = self.db.get_session()
        try:
            stmt = s.query(VpnUserState)
            if ip is not None:
                stmt = stmt.filter(VpnUserState.client_local_ip == ip)
            if user is not None:
                cname_prefix = user + '/'
                stmt = stmt.filter(VpnUserState.cname.startswith(cname_prefix))

            db_user = stmt.one_or_none()

        except Exception as e:
            logger.warning('Exception in user verification %s' % e)
            logger.warning(traceback.format_exc())

        finally:
            util.silent_close(s)

        if db_user is None:
            return jsonify({'result': False})
        else:
            res = collections.OrderedDict()
            res['result'] = True
            res['user'] = self.vpn_user_to_obj(db_user)
            return jsonify(res)

    def on_dump(self, request):
        """
        Dump state config
        :return:
        """
        self.process_payload(request)
        s = self.db.get_session()
        states = s.query(VpnUserState).all()

        res = {}
        for state in states:
            obj = self.vpn_user_to_obj(state)
            res[state.cname] = obj

        util.silent_close(s)
        return jsonify({'result': True, 'data': res})

    def on_server_state_change(self, request, up=True):
        """
        On server state change
        :param request:
        :param up:
        :return:
        """
        self.process_payload(request)
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
        js = self.process_payload(request)
        s = self.db.get_session()
        try:
            if not self.is_valid_cname(js['cname']):
                logger.warning('Invalid cname: %s' % js['cname'])
                return jsonify({'result': False})

            if on_connected:
                self.disconnected_cache[js['cname']] = 0
            else:
                self.disconnected_cache[js['cname']] = time.time()

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

    def build_stats(self, add_meta=False):
        """
        Builds stats object
        :return:
        """
        s = self.db.get_session()

        # Fetch current stats of connected clients, will be added to aggregate stats
        connected_clients = s.query(VpnUserState).all()
        connected_map = {x.cname: x for x in connected_clients}

        # Aggregate calls on sessions
        current_time = datetime.utcnow()
        month_start = current_time - timedelta(days=current_time.day, hours=current_time.hour,
                                               minutes=current_time.minute, seconds=current_time.second)
        week_ago = current_time - timedelta(days=7)
        day_start = current_time - timedelta(hours=current_time.hour, minutes=current_time.minute,
                                             seconds=current_time.second)

        last_month = self.aggregated_sessions(s, month_start).all()
        last_week = self.aggregated_sessions(s, week_ago).all()
        last_day = self.aggregated_sessions(s, day_start).all()

        users = set([x.cname for x in connected_clients] + [x.cname for x in last_month])
        users = sorted(list(users))

        stats_base = {}  # increment for connected=1
        for user in users:
            stats_base[user] = 0, 0
        for cl in connected_clients:
            if cl.connected == 1:
                stats_base[cl.cname] = cl.bytes_sent, cl.bytes_recv

        map_day, map_week, map_month = self.aggregation_maps(users, last_day, last_week, last_month)
        res = collections.OrderedDict()
        for user in users:
            obj = collections.OrderedDict()
            if add_meta and user in connected_map:
                user_db = connected_map[user]
                obj['cname'] = user_db.cname
                obj['email'] = util.get_user_from_cname(user_db.cname)
                obj['local_ip'] = user_db.client_local_ip
                obj['remote_ip'] = user_db.client_remote_ip
                obj['remote_port'] = int(user_db.client_remote_port)
                obj['connected'] = int(user_db.connected)
                obj['date_updated'] = calendar.timegm(user_db.date_updated.timetuple()) \
                    if user_db.date_updated is not None else None
                obj['date_connected'] = calendar.timegm(user_db.date_connected.timetuple()) \
                    if user_db.date_connected is not None else None

            obj['cur'] = {
                'sent': int(stats_base[user][0]),
                'recv': int(stats_base[user][1]),
            }

            obj['day'] = {
                'sent': int(stats_base[user][0] + map_day[user][0]),
                'recv': int(stats_base[user][1] + map_day[user][1]),
            }

            obj['last7d'] = {
                'sent': int(stats_base[user][0] + map_week[user][0]),
                'recv': int(stats_base[user][1] + map_week[user][1]),
            }

            obj['month'] = {
                'sent': int(stats_base[user][0] + map_month[user][0]),
                'recv': int(stats_base[user][1] + map_month[user][1]),
            }

            res[user] = obj
        util.silent_close(s)
        return res

    def session_from_state(self, state):
        """
        Converts state view to the session record
        :param VpnUserState state:
        :return:
        """
        db_user = VpnUserSessions()
        db_user.cname = state.cname

        connected_time = calendar.timegm(state.date_connected.timetuple())
        duration = time.time() - connected_time

        disconnected = datetime.now()
        db_user.date_disconnected = disconnected
        db_user.date_connected = disconnected - timedelta(seconds=duration)

        db_user.proto = state.proto
        db_user.client_local_ip = state.client_local_ip
        db_user.client_remote_ip = state.client_remote_ip
        db_user.client_remote_port = state.client_remote_port

        db_user.bytes_sent = state.bytes_sent
        db_user.bytes_recv = state.bytes_recv
        db_user.duration = duration
        return db_user

    def is_the_same_connection(self, state_db, cl):
        """
        Returns true if state representation of the user connection is the same as mentioned in the status file.
        :param VpnUserState state_db: VPN user state - DB
        :param OvpnClient cl: client info from VPN state file
        :return:
        """
        # IP check, should be the same remote socket
        if cl.addr != ('%s:%s' % (state_db.client_remote_ip, state_db.client_remote_port)):
            return False

        # Bytes stats check. Status file has to be greater or equal
        if state_db.bytes_sent > cl.bytes_sent or state_db.bytes_recv > cl.bytes_recv:
            return False

        # Check connection time, tolerance 5 minutes.
        connected_db_utc = calendar.timegm(state_db.date_connected.timetuple())
        connected_stat_utc = util.unix_time(cl.connected_since)
        time_diff = abs(connected_db_utc - connected_stat_utc)
        if time_diff > 60*5:
            return False

        return True

    def is_valid_cname(self, cname):
        """
        Returns false if cname is invalid
        :param cname:
        :return:
        """
        return cname is not None and cname != '' and len(cname) > 0 and cname.lower() != 'undef'

    def sync_with_status(self):
        """
        Synchronizes all users with the status file. Disconnects users not mentioned in the status file.
        Executed on auth server start
        :return:
        """
        # Load status file. If user has same remote socket and times, do not store new sessions.
        status_file = self.load_status()

        s = self.db.get_session()
        try:
            states = s.query(VpnUserState).all()
            for state in states:
                if state.connected != 1:
                    continue

                # check connected user w.r.t. status file.
                # If status file signalizes user is still connected and he has the same remote
                # socket (ip:port) it is highly probable it is exactly same connection as
                # remote port usually changes randomly with each connection.
                # To improve this detection there are further conditions: bytes sent, received should be larger or
                # equal to those in status file.
                # Also connected_from time in status file should be maximally 60 seconds longer.
                still_same_connection = False
                cl = None

                cname = state.cname
                if cname in status_file.clients:
                    cl = status_file.clients[cname]
                    still_same_connection = self.is_the_same_connection(state, cl)

                if not still_same_connection:
                    session = self.session_from_state(state)
                    session.record_type = 1  # Mark we created this record artificially
                    s.add(session)

                state.date_updated = salch.func.now()
                if cl is None:
                    state.connected = 0
                    state.bytes_recv = 0
                    state.bytes_sent = 0
                    state.date_connected = None
                else:
                    state.connected = 1
                    state.bytes_recv = cl.bytes_recv
                    state.bytes_sent = cl.bytes_sent
                    state.date_connected = cl.connected_since

            s.commit()

        except Exception as e:
            logger.warning('Exception in disconnecting users %s' % e)
            logger.warning(traceback.format_exc())

        finally:
            util.silent_close(s)

    def aggregated_sessions(self, s, delta):
        """
        Builds aggregation query for sessions.
        :param delta:
        :return:
        """
        qry = s.query(
            VpnUserSessions.cname,
            salch.func.sum(VpnUserSessions.bytes_sent).label("sum_bytes_sent"),
            salch.func.sum(VpnUserSessions.bytes_recv).label("sum_bytes_recv"))

        qry = qry.filter(salch.or_(
            VpnUserSessions.date_connected >= delta,
            VpnUserSessions.date_disconnected >= delta))

        qry = qry.group_by(VpnUserSessions.cname)
        return qry

    def aggregation_maps(self, users, *args):
        """
        Creates maps cname -> (sent, recv)
        :param users:
        :param args:
        :return:
        """
        res = []
        for idx, aggregation in enumerate(args):
            res.append({})
            aggmap = {x.cname: x for x in aggregation}
            for user in users:
                if user not in aggmap:
                    res[idx][user] = 0, 0
                else:
                    res[idx][user] = aggmap[user].sum_bytes_sent, aggmap[user].sum_bytes_recv
        return res

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
                db_user.date_connected = salch.func.now()

            else:
                db_user.bytes_sent = user['bytes_sent']
                db_user.bytes_recv = user['bytes_recv']
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

    def store_user_from_file(self, client, route, s):
        """
        Stores user vpn auth state from vpn status file.
        User is always considered connected, otherwise it won't be in the status file.

        :param client:
        :param route:
        :return:
        """
        try:
            db_user = s.query(VpnUserState).filter(VpnUserState.cname == client.cname).one_or_none()
            new_one = True

            if db_user is None:
                db_user = VpnUserState()
                db_user.cname = client.cname
                db_user.date_connected = salch.func.now()

            else:
                new_one = False
                if db_user.connected == 0:
                    db_user.date_connected = salch.func.now()

            db_user.date_updated = salch.func.now()
            db_user.connected = 1
            db_user.bytes_sent = client.bytes_sent
            db_user.bytes_recv = client.bytes_recv

            if route is not None:
                db_user.client_local_ip = route.local_addr

            try:
                addr, port = client.addr.rsplit(':', 1)
                db_user.client_remote_ip = addr
                db_user.client_remote_port = port

            except Exception as e:
                logger.info('Addr parse fail [%s]: %s' % (client.addr, e))

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
    # Status monitoring
    #

    def status_main(self):
        """
        Status file monitoring
        :return:
        """
        logger.info('Status thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            while not self.stop_event.is_set():
                try:
                    time.sleep(0.2)
                    cur_time = time.time()
                    if self.status_last_check + self.status_check_time > cur_time:
                        continue

                    self.update_state_from_file()
                    self.status_last_check = cur_time

                    self.status_dump_json()

                except Exception as e:
                    logger.error('Exception in status processing: %s' % e)
                    logger.debug(traceback.format_exc())

        except Exception as e:
            logger.error('Exception: %s' % e)
            logger.debug(traceback.format_exc())

        logger.info('Status loop terminated')

    def load_status(self):
        """
        Loads status file
        :return: parser
        """
        parser = OvpnStatusParser(status_file=self.status_file)
        parser.process()
        return parser

    def update_state_from_file(self):
        """
        Updates auth state from state file.
        :return:
        """
        results = self.load_status()
        for cname in results.clients:
            if not self.is_valid_cname(cname):
                logger.warning('state file - CNAME user invalid: %s' % cname)
                continue

            cl = results.clients[cname]
            rt = results.routes[cname] if cname in results.routes else None

            # If user was recently disconnected, to not update with connected obsolete state
            if cname in self.disconnected_cache:
                if time.time() - self.disconnected_cache[cname] < 60:
                    continue

            s = self.db.get_session()
            try:
                self.store_user_from_file(client=cl, route=rt, s=s)
                s.commit()

            except Exception as e:
                logger.warning('Exception in storing user state %s' % e)
                logger.warning(traceback.format_exc())

            finally:
                util.silent_close(s)

    def status_dump_json(self):
        """
        Dumps stats with file consumption to json
        :return:
        """
        try:
            if self.args.dump_stats_file is None:
                return

            folder = self.args.dump_stats_file.rsplit('/', 1)[0]
            if not os.path.exists(folder):
                logger.info('Stat folder does not exist: %s' % folder)

            res = self.build_stats(add_meta=True)
            js = collections.OrderedDict()
            js['generated'] = time.time()
            js['users'] = res
            util.flush_file(json.dumps(js, indent=2), filepath=self.args.dump_stats_file)

        except Exception as e:
            logger.error('Exception in file generation: %s' % e)
            logger.debug(traceback.format_exc())

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

    def terminating(self):
        """
        Set state to terminating
        :return:
        """
        self.running = False
        self.stop_event.set()

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

        self.terminating()
        logger.info('Work loop terminated')

    def work_loop(self):
        """
        Process configuration, initialize connections, databases, start threads.
        :return:
        """
        # Init
        self.init_config()
        self.init_log()
        self.init_db()
        self.init_rest()

        # Disconnect all users
        self.sync_with_status()

        # Sub threads
        self.status_thread = threading.Thread(target=self.status_main, args=())
        self.status_thread.setDaemon(True)
        self.status_thread.start()

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

        parser.add_argument('--ebstall', dest='ebstall', default=False, action='store_const', const=True,
                            help='ebstall compatible mode - uses enigma configuration')

        parser.add_argument('--dump-stats', dest='dump_stats_file', default=None,
                            help='Dumping stats to a file')

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

