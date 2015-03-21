import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from tornado.options import define, options

import os
import sys
import base64
import datetime
import sqlite3
import hmac, random
from hashlib import md5, sha224, sha256, sha512

import http.client
import socket
import xmlrpc.client

define('port', type=int, default=8888, help='run on the given port')
define('addr', type=str, default='localhost', help='run on the given address')
define('debug', type=bool, default=False, help='running in debug mode')
define('servicename', type=str, default='shadowsocks',
       help='shadowsocks\'s service name in supervisor')
define('cookie_secret', type=str, default=None,
       help='You must specify the cookie_secret option. It should be a long, '
            'random sequence of bytes to be used as the HMAC secret for the '
            'signature.\n'
            'You can create this HMAC string with --hmac option.')
define('hmac', type=None, default=False, help='create a HMAC string')


class BaseHandler(tornado.web.RequestHandler):
    def initialize(self):
        self.conn = sqlite3.connect('ssweb.db')
        self.conn.execute(
            'CREATE TABLE IF NOT EXISTS users ( '
            '    id INTEGER PRIMARY KEY AUTOINCREMENT, '
            '    username NOT NULL UNIQUE, '
            '    password NOT NULL)')

    @property
    def config(self):
        return self.application.config

    def get_current_user(self):
        return self.get_secure_cookie('_t')


class LoginHandler(BaseHandler):
    def initialize(self):
        if self.request.method == 'GET':
            self.first_time_login = True
        else:
            self.first_time_login = False
        BaseHandler.initialize(self)

    def get(self):
        if not self.get_current_user():
            self.render('login.html', message=None,
                    next=self.get_argument('next', '/'))
            return
        self.redirect('/')

    def post(self):
        username = self.get_argument('username')
        password = sha256(self.get_argument('password')
                    .encode('utf8')).hexdigest()

        self.conn.row_factory = sqlite3.Row
        cur = self.conn.cursor()
        cur.execute('SELECT username, password FROM users '
                    'WHERE username=? AND password=?', (username, password))
        row = cur.fetchone()
        if row:
            self.set_secure_cookie('_t', self.get_argument('username'))
            self.redirect(self.get_argument('next', '/'))
            return

        cur.execute('SELECT COUNT(*) AS count FROM users')
        row = cur.fetchone()
        if (row['count'] == 0 and self.get_argument('password')
                                  == config['password'].decode('utf8')):
            # Create account by password in the config file,
            #   while first time login
            password = sha256(config['password']).hexdigest()
            cur.execute(
                'INSERT INTO users (username, password) VALUES(?, ?)',
                (username, password))
            self.conn.commit()
            self.set_secure_cookie('_t', self.get_argument('username'))
            self.redirect(self.get_argument('next', '/'))
            return

        self.render('login.html', message='login error',
                next=self.get_argument('next', '/'))


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect('/')


class RootHandler(BaseHandler):
    def get(self):
        self.redirect('/dashboard')


class DashboardHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        # TODO: It's currently support Python 3 only.
        #       Add python 2 support ASAP.
        msg = SupervisorController().get_info()
        self.render('dashboard.html', msg=msg)


class ConfigHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        items = []
        if not self.config["port_password"]:
            _config = {
                "server": self.config["server"],
                "port": self.config["server_port"],
                "password": self.config["password"].decode("utf-8"),
                "method": self.config["method"]
            }
            constr = "%s:%s@%s:%s" % (_config["method"], _config["password"],
                _config["server"], _config["port"])
            b64str = base64.b64encode(constr.encode("utf-8")).decode("utf-8")
            items += [(_config, constr, b64str)]
        else:
            for port, password in self.config["port_password"].items():
                _config = {
                    "server": self.config["server"],
                    "port": port,
                    "password": password.decode("utf-8"),
                    "method": self.config["method"]
                }
                constr = "%s:%s@%s:%s" % (_config["method"],
                    _config["password"], _config["server"], _config["port"])
                b64str = base64.b64encode(constr.encode("utf-8")).decode("utf-8")
                items += [(_config, constr, b64str)]
        self.render("config.html", items=items)


class PlaneConfigHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        items = []
        if not self.config["port_password"]:
            _config = {
                "server": self.config["server"],
                "port": self.config["server_port"],
                "password": self.config["password"].decode("utf-8"),
                "method": self.config["method"]
            }
            constr = "%s:%s@%s:%s" % (_config["method"], _config["password"],
                _config["server"], _config["port"])
            b64str = base64.b64encode(constr.encode("utf-8")).decode("utf-8")
            items += [(_config, constr, b64str)]
        else:
            for port, password in self.config["port_password"].items():
                _config = {
                    "server": self.config["server"],
                    "port": port,
                    "password": password.decode("utf-8"),
                    "method": self.config["method"]
                }
                constr = "%s:%s@%s:%s" % (_config["method"],
                    _config["password"], _config["server"], _config["port"])
                b64str = base64.b64encode(constr.encode("utf-8")).decode("utf-8")
                items += [(_config, constr, b64str)]
        from pprint import pformat
        self.write('<pre>%s</pre>' % pformat(items))


class ControlHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('control.html')


class ControlStartHandler(BaseHandler):
    def get(self):
        m = SupervisorController().start()
        self.redirect('/control')


class ControlStopHandler(BaseHandler):
    def get(self):
        m = SupervisorController().stop()
        self.redirect('/control')


class ControlRestartHandler(BaseHandler):
    def get(self):
        m = SupervisorController().restart()
        self.redirect('/control')


class SupervisorController(object):
    def __init__(self):

        class UnixStreamHTTPConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(self.host)

        class UnixStreamTransport(xmlrpc.client.Transport, object):
            def __init__(self, socket_path):
                self.socket_path = socket_path
                super(UnixStreamTransport, self).__init__()

            def make_connection(self, host):
                return UnixStreamHTTPConnection(self.socket_path)

        self.server = xmlrpc.client.ServerProxy(
            'http://',
            transport=UnixStreamTransport('/var/run/supervisor.sock'))

    def get_info(self):
        result = None
        try:
            r = self.server.supervisor.getProcessInfo(options.servicename)
            result = dict(
                    name=r['name'],
                    state=r['statename'],
                    start=datetime.datetime.fromtimestamp(r['start']),
                    epoch_start=r['start'],
                    stop=datetime.datetime.fromtimestamp(r['stop']),
                    epoch_stop=r['stop'],
                    now=datetime.datetime.fromtimestamp(r['now']),
                    epoch_now=r['now'],
                    uptime='0',
                )
            if result['state'] == 'RUNNING':
                result['uptime'] = result['epoch_now'] - result['epoch_start']
        except xmlrpc.client.Fault:
            pass
        return result

    def start(self):
        try:
            self.server.supervisor.startProcess(options.servicename)
        except xmlrpc.client.Fault:
            pass

    def stop(self):
        try:
            self.server.supervisor.stopProcess(options.servicename)
        except xmlrpc.client.Fault:
            pass

    def restart(self):
        try:
            self.server.supervisor.stopProcess(options.servicename)
            self.server.supervisor.startProcess(options.servicename)
        except xmlrpc.client.Fault:
            pass


def main(config):
    if not options.cookie_secret:
        import logging
        logging.warn('\n\n\t\t!!! WARNNING !!!\n\n'
              'You must specify the cookie_secret option. It should be a long, '
              'random sequence of bytes to be used as the HMAC secret for the '
              'signature.\n\n'
              'To keep the Shadowsocks Web Interface runable as always it be, '
              'it\'s signed by a random cookie_secret option. Yes, this chould '
              'keep the service runable, but also effects the users have to '
              're-login every time the system administrator restart the '
              'service or reboot the system. YOU ARE NOTICED.\n\n'
              'You can create this HMAC string by typing following on server:\n'
              '\t%s --hmac' % sys.argv[0])
        options.cookie_secret = hmac_sha(randstr(1000), randstr(1000), 'sha512')

    handlers = [
        (r'/', RootHandler),
        (r'/dashboard', DashboardHandler),
        (r'/login', LoginHandler),
        (r'/logout', LogoutHandler),
        (r'/config', ConfigHandler),
        (r'/control', ControlHandler),
        (r'/control/start', ControlStartHandler),
        (r'/control/stop', ControlStopHandler),
        (r'/control/restart', ControlRestartHandler),
        (r'/hideme', PlaneConfigHandler),
    ]
    settings = dict(
        template_path=os.path.join(os.path.dirname(__file__),
                                   'templates/default'),
        static_path=os.path.join(os.path.dirname(__file__),
                                 'templates/default/assets'),
        cookie_secret=options.cookie_secret,
        login_url='/login',
        xsrf_cookies=True,
        debug=options.debug,
    )

    application = tornado.web.Application(handlers, **settings)
    application.config = config
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port, options.addr)
    tornado.ioloop.IOLoop.instance().start()

def start_with_config(config):
    tornado.options.parse_command_line('')
    main(config)

def hmac_sha(key, msg, type='sha224'):
    if type == 'md5':
        hmacstr = hmac.HMAC(key.encode('utf8'), msg.encode('utf8'),
                            md5).hexdigest()
        return hmacstr
    elif type == 'sha224':
        hmacstr = hmac.HMAC(key.encode('utf8'), msg.encode('utf8'),
                            sha224).hexdigest()
        return hmacstr
    elif type == 'sha256':
        hmacstr = hmac.HMAC(key.encode('utf8'), msg.encode('utf8'),
                            sha256).hexdigest()
        return hmacstr
    elif type == 'sha512':
        hmacstr = hmac.HMAC(key.encode('utf8'), msg.encode('utf8'),
                            sha512).hexdigest()
        return hmacstr
    else:
        return None

def randstr(leng=50):
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz'
                                 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                 '0123456789'
                                 '')
                    for i in range(leng))


if __name__ == '__main__':
    try:
        tornado.options.parse_command_line()
    except tornado.options.Error:
        sys.exit(1)

    if len(sys.argv) == 2 and sys.argv[1] == '--hmac':

        key = randstr()
        msg = randstr()
        print('HMAC-MD5    ( 32 bits): %s' % hmac_sha(key, msg, 'md5'))
        print('HMAC-SHA224 ( 56 bits): %s' % hmac_sha(key, msg, 'sha224'))
        print('HMAC-SHA256 ( 64 bits): %s' % hmac_sha(key, msg, 'sha256'))
        print('HMAC-SHA512 (128 bits): %s' % hmac_sha(key, msg, 'sha512'))

    elif len(sys.argv) == 2 and sys.argv[1] == '--debug':
        options.debug = True
        options.port = 8080
        options.addr = '0.0.0.0'
        options.servicename = 'shadowsocks-github'
        options.cookie_secret = hmac_sha(randstr(), randstr())
        # debug 'config' value
        config = {
            'local_port': 1080,
            'method': 'aes-256-cfb',
            'fast_open': False,
            'log-file': '/var/log/shadowsocks.log',
            'local_address': '127.0.0.1',
            'server_port': 8388,
            'timeout': 300,
            'pid-file': '/var/run/shadowsocks.pid',
            'server': '0.0.0.0',
            'password': b'ual3kiideiwahwee7Uyiehu7feitag2uuvahsahgai1oph5lee',
            'verbose': False,
            'workers': 1,
            'port_password': {
                '8389': b'ual3kiideiwahwee7Uyiehu7feitag2uuvahsahgai1oph5lee',
                '8388': b'fei5Ahzacohchohraquie5bopho3xa9be2ies5Pi8aegoongoh'}}
        main(config)

    else:
        tornado.options.print_help()
        sys.exit(0)
