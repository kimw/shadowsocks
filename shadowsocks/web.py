import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from tornado.options import define, options

import os
import base64
import datetime

define('port', default=8888, help='run on the given port', type=int)
define('debug', default=False, help='running in debug mode', type=bool)


class BaseHandler(tornado.web.RequestHandler): pass


class HomeHandler(BaseHandler):
    def initialize(self, config):
        self.config = config

    def get(self):
        messages = []
        # TODO: add some dashboard-like messages here
        if messages == []:
            messages = ['there\'s no any message']
        self.render('home.html', messages=messages)


class ConfigHandler(BaseHandler):
    def initialize(self, config):
        self.config = config

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
    def initialize(self, config):
        self.config = config
        print('config=', config)

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
        self.write('<pre>%s</pre>' % items)


class ControlHandler(BaseHandler):
    def get(self):
        self.write('<html><body>'
                   '<p>Under Construction.</p>'
                   '<p>start, stop and restart maybe coming soon.</p>'
                   '<p>you\'ll be taken to homepage in 8.388s.<br>'
                   '(the default port number? yes! to clowwindy.)</p>'
                   '<script type="text/javascript">'
                   'setTimeout(function(){window.location="/"}, 8388);'
                   '</script>'
                   '</body></html>')


def main(config):
    handlers = [
        (r'/', HomeHandler, dict(config=config)),
        (r'/config', ConfigHandler, dict(config=config)),
        (r'/control', ControlHandler),
        (r'/hideme', PlaneConfigHandler, dict(config=config)),
    ]
    settings = dict(
        template_path=os.path.join(os.path.dirname(__file__),
                                   'templates/default'),
        static_path=os.path.join(os.path.dirname(__file__),
                                 'templates/default/assets'),
        debug=options.debug,
    )
    application = tornado.web.Application(handlers, **settings)
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


def start_with_config(config):
    tornado.options.parse_command_line('')
    main(config)


if __name__ == '__main__':
    try:
        tornado.options.parse_command_line()
    except tornado.options.Error:
        sys.exit(1)
    options.debug = True
    options.port = 8080
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
