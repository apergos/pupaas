import os
import sys
import re
import time
import subprocess
import BaseHTTPServer
import getopt
import fcntl
import socket
import struct
import traceback

# TODO
# test all error conditions
# document

VERSION = "0.1.1"

# for python 2.6, e.g. lucid
# source:
# http://stackoverflow.com/questions/4814970/subprocess-check-output-doesnt-seem-to-exist-python-2-6-5
# code is actually a backport from python 2.7
if "check_output" not in dir(subprocess): # duck punch it in!
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd)
        return output
    subprocess.check_output = f


class PupServer(BaseHTTPServer.HTTPServer, object):
    """
    http server with workaround for gethostbyname
    failures, logging options, and a new attribute
    'manifest_base' which tells us the path to
    the puppet manifest tree
    """

    def __init__(self, options):
        'constructor'

        s_name = options['server']
        if not s_name:
            s_name = socket.gethostname()
            if s_name:
                try:
                    s_name = socket.gethostbyname(s_name)
                except socket.gaierror:
                    s_name = get_ip(options['iface'])

        super(PupServer, self).__init__((s_name, int(options['port'])),
                                        PupRequestHandler)
        self.manifest_base = options['manifests']
        self.logging = options['logging']


class PupRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler, object):
    server_version = 'PUPAAS/' + VERSION
    BUF_SIZE = 65536

    def log_error(self, formatstr, *args):
        'log errors to the logfile or stderr if there is no logfile'

        filedesc = get_log_filedesc(self.server.logging)

        filedesc.write("%s - - [%s] %s\n" % (self.client_address[0],
                                             self.log_date_time_string(),
                                             formatstr%args))
        if filedesc != sys.stderr:
            filedesc.close()

    def log_request(self, code='-', size='-'):
        "don't log requests"

        pass

    def get_manifest_path(self, path):
        'construct the full path to a manifest'

        return '/'.join([self.server.manifest_base.rstrip('/'),
                         path.lstrip('/')])

    def do_GET(self):
        """
        handle GET requests
        expect '/manifest/...' or '/fact/...'
        """

        if self.path[0] != '/':
            self.send_error(403)
            return

        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/', 1)
        if subcommand == 'manifest':
            self.get_manifest(rest)
        elif subcommand == 'fact':
            self.get_fact(rest)
        else:
            self.send_error(403)

    def get_manifest(self, path):
        """
        get the contents of a manifest
        and return them to the http client
        """

        if not check_manifest_path(self.path):
            self.send_error(403)
            return

        manifest_path = self.get_manifest_path(path)

        if not os.path.exists(manifest_path):
            self.send_error(404)
            return

        filehandle = None
        try:
            filehandle = open(manifest_path, "r")
        except:
            # note that if we can't open it that's still considered
            # server issues rather than 403, since it's in the manifest dir
            if filehandle:
                filehandle.close()
            log_traceback(self.server.logging)
            self.send_error(500)
            return

        file_info = os.fstat(filehandle.fileno())
        self.send_response(200)
        self.send_header('Last-modified',
                         self.date_time_string(file_info.st_mtime))
        self.send_header('Content-type', 'text/plain')
        if self.command == 'GET':
            self.send_header('Content-length', file_info.st_size)
        self.end_headers()

        if self.command == 'GET':
            contents = filehandle.read(PupRequestHandler.BUF_SIZE)
            while contents:
                self.wfile.write(contents)
                contents = filehandle.read(PupRequestHandler.BUF_SIZE)

        filehandle.close()

    def get_fact(self, path):
        'get and return the value of a facter fact'

        command = ['/usr/bin/facter', path]
        try:
            result = subprocess.check_output(command)
        except:
            log_traceback(self.server.logging)
            self.send_error(500)
            return

        if not result:
            self.send_error(404)
            return

        self.send_response(200, "OK")
        self.send_header('Last-modified', self.date_time_string(time.time()))
        self.send_header('Content-type', 'text/plain')
        if self.command == 'GET':
            self.send_header('Content-length', len(result))
        self.end_headers()

        if self.command == 'GET':
            self.wfile.write(result)

    do_HEAD = do_GET

    def do_PUT(self):
        """
        handle PUT requests
        these should be put of a manifest,
        nothing else is currently supported
        """

        if self.path[0] != '/':
            self.send_error(403)
            return

        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/', 1)
        if subcommand == 'manifest':
            self.put_manifest(rest)
        else:
            self.send_error(403)

    def put_manifest(self, path):
        """
        read contents of a manifest from the
        http client and save them into the specified
        location
        """

        if not check_manifest_path(path):
            self.send_error(403)
            return

        manifest_path = self.get_manifest_path(path)

        # don't overwrite existing file
        if os.path.exists(manifest_path):
            self.send_error(403)
            return

        filehandle = None
        try:
            filehandle = os.open(manifest_path,
                                 os.O_WRONLY |
                                 os.O_CREAT |
                                 os.O_EXCL)
        except:
            log_traceback(self.server.logging)
            self.send_error(500)
            if filehandle:
                filehandle.close()
            return
        filedesc = os.fdopen(filehandle, "w")
        fcntl.flock(filedesc, fcntl.LOCK_EX)

        # FIXME what server headers are required for PUT?
        if 'content-length' in self.headers:
            self.process_client_data(filedesc,
                                     int(self.headers['content-length']))
        else:
            self.process_client_data(filedesc)

        filedesc.close()
        self.send_response(201)
        self.send_header('Content-length', '0')
        self.end_headers()

    def process_client_data(self, filehandle, max_bytes=None):
        """
        read client PUT data and write it out to the open file,
        one buffer at a time
        """

        if max_bytes is None:
            contents = self.rfile.read(PupRequestHandler.BUF_SIZE)
            while contents:
                filehandle.write(contents)
                contents = self.rfile.read(PupRequestHandler.BUF_SIZE)
            return

        bytes_read = 0
        remaining = max_bytes

        contents = self.read_chunk(remaining)
        bytes_read = bytes_read + len(contents)
        remaining = remaining - len(contents)
        while contents:
            filehandle.write(contents)
            if not remaining:
                break
            contents = self.read_chunk(remaining)
            bytes_read = bytes_read + len(contents)
            remaining = remaining - len(contents)

    def read_chunk(self, remaining):
        'read up to a bufferful of data from the client'

        if remaining < PupRequestHandler.BUF_SIZE:
            return self.rfile.read(remaining)
        else:
            return self.rfile.read(PupRequestHandler.BUF_SIZE)

    def do_POST(self):
        """
        'handle POST requests
        these should be requests to apply
        a given manifest, no other requests
        are currently supported
        """

        if self.path[0] != '/':
            self.send_error(403)
            return

        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/', 1)
        if subcommand == 'apply':
            self.apply_manifest(rest)
        else:
            self.send_error(403)

    def apply_manifest(self, path):
        """
        puppet apply an existing manifest
        and return 200 on successful apply
        with change, 204 on success with no change,
        or error status code depending on the error
        """

        if not check_manifest_path(self.path):
            self.send_error(403)
            return

        manifest_path = self.get_manifest_path(path)

        if not os.path.exists(manifest_path):
            self.send_error(404)
            return

        # run the command, get error output if any
        command = ["/usr/bin/puppet", "apply", "--detailed-exitcodes",
                   manifest_path]
        proc = subprocess.Popen(command, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        try:
            stdoutdata, stderrdata = proc.communicate()
        except:
            log_traceback(self.server.logging)
            self.send_error(500)
            return
        if proc.returncode == 4 or proc.returncode == 6:
            # fixme should really send contents of stderr + possibly stdout here
            log_traceback(self.server.logging)
            self.send_error(500)
            return
        elif proc.returncode == 2:
            # something changed, should show it to the user
            self.send_response(200)
            self.send_header('Last-modified',
                             self.date_time_string(time.time()))
            self.send_header('Content-type', 'text/plain')
            self.send_header('Content-length', len(stdoutdata))
            self.end_headers()
            self.wfile.write(stdoutdata)
        elif proc.returncode == 0:
            self.send_response(204)
            self.send_header('Last-modified',
                             self.date_time_string(time.time()))
            self.end_headers()

    def do_DELETE(self):
        """
        handle DELETE requests
        these should be requests to delete a
        manifest; no other requests are currently
        supported
        """

        if self.path[0] != '/':
            self.send_error(403)
            return

        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/', 1)
        if subcommand == 'manifest':
            self.delete_manifest(rest)
        else:
            self.send_error(403)

    def delete_manifest(self, path):
        """
        delete a manifest and return 204 on
        success or an error code depending
        on the error
        """

        if not check_manifest_path(self.path):
            self.send_error(403)
            return

        manifest_path = self.get_manifest_path(path)

        if not os.path.exists(manifest_path):
            self.send_error(404)
            return

        # yes there is a race here, maybe something
        # else removed it. that's life.
        try:
            os.unlink(manifest_path)
        except:
            # note that if we don't have perms that's still considered
            # server issues rather than 403, since it's in the manifest dir
            log_traceback(self.server.logging)
            self.send_error(500)
            return

        self.send_response(204)
        self.send_header('Last-modified', self.date_time_string(time.time()))
        self.end_headers()

    def do_CONNECT(self):
        'let the base class handle connects'
        pass


def check_manifest_path(path):
    """
    check that manifest path ends in pp and that the rest is
    only ascii alphanumeric with '/' or - or _
    """
    if not path.endswith(".pp"):
        return False
    if not re.match("^[a-zA-Z0-9_\-/]+$", path[:-3]):
        return False
    return True

def get_ip(ifname):
    """
    hack to work around python broken getaddrinfo/gethostbyname
    when presented with names like 836937931829
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def get_log_filedesc(logfile):
    if logfile != "stderr":
        filedesc = None
        try:
            filehandle = os.open(logfile,
                                 os.O_WRONLY |
                                 os.O_APPEND |
                                 os.O_CREAT)
            filedesc = os.fdopen(filehandle, "a")
            fcntl.flock(filedesc, fcntl.LOCK_EX)
        except:
            if filedesc:
                filehandle.close()
            filedesc = sys.stderr
    else:
        filedesc = sys.stderr
    return filedesc

def log_traceback(logfile):
    """
    write traceback from exception to the
    log file or, if there is none, to stderr
    """
    filedesc = get_log_filedesc(logfile)

    traceback.print_exc(filedesc)
    if filedesc != sys.stderr:
        filedesc.close()

def show_version():
    'display the version of this script'

    print "pupaas.py " + VERSION + "\n"
    sys.exit(0)

def usage(message=None):
    """
    display a helpful usage message, with optional
    introductory text if desired
    """

    if message is not None:
        sys.stderr.write(message)
        sys.stderr.write("\n")
    usage_message = """Puppet as a service (pupaas)

Usage: pupaas.py [--config path] [--manifests path]
                [--port num] [--server] [--version] [--help]

Options:

  --config    (-c)  path to configuration file
                    default: /etc/pupaas/pupaas.conf
  --logging   (-l)  path file where errors will be logged
                    to log to stderr, specify 'stderr'
                    default: /var/log/pupaas_errors
  --manifests (-m)  path to puppet manifests to be read/written
                    default: /etc/puppet
  --port      (-p)  port number on which to listen
                    default: 8001
  --server    (-s)  server name/addr from which to serve
                    (use if host has multiple names/ips)
                    default: none
  --iface     (-i)  interface name to which to bind
                    (use if host has multiple configured
                    interfaces, as an alternative to
                    specifying --server)
                    default: eth0
  --version   (-v)  print version information and exit
  --help      (-h)  display this usage message

Confile file format:

  Comments (lines starting with #) and blank lines will be skipped
  Other lines are presumed to be of the format name = value

  Known config file names: logging, port, manifests, server, iface
"""
    sys.stderr.write(usage_message)
    sys.exit(1)

def opts_merge(defaults, configvals, cmdlinevals):
    """
    merge in options read from the command line,
    config file options and defaults, in that
    order of precedence
    """

    result = {}
    for name in cmdlinevals:
        result[name] = cmdlinevals[name]
    for name in configvals:
        if name not in result:
            result[name] = configvals[name]
    for name in defaults:
        if name not in result:
            result[name] = defaults[name]
    return result

def get_config(config_file, defaultpath):
    'read and stash options from config file'

    result = {}
    if not config_file:
        config_file = defaultpath
    filehandle = None
    try:
        filehandle = open(config_file, "r")
    except:
        if config_file == defaultpath:
            if filehandle:
                filehandle.close()
            return result
        else:
            raise

    errors = False
    # format: name=value (maybe blanks around equals sign)
    for line in filehandle:
        line = line.rstrip('\n')
        if (not line) or line.startswith('#'):
            continue
        if '=' not in line:
            errors = True
            sys.stderr.write("bad line '%s'\n" % line)
            continue
        (name, value) = line.split('=', 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            errors = True
            sys.stderr.write("bad line '%s'\n" % line)
            continue
        result[name] = value

    if errors:
        raise ValueError("Bad entries in config file")
    return result

def do_fork():
    """
    fork, exiting the parent process and leaving the
    child running
    """

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, err:
        sys.stderr.write("fork failed: %d (%s)\n" % (err.errno,
                                                     err.strerror))
        sys.exit(1)

def be_daemon():
    'do the daemon fork/setsid song and dance'

    do_fork()      # so child can be process leader
    os.setsid()    # new session with no controlling terminal
    do_fork()      # process leader exists, child can't get a controlling term
    os.chdir("/")  # only root filesystem kept in use
    os.umask(0)    # ditch any inherited umask

def process_options(options):
    """
    stuff options into a nice dict, return them
    along with the config_file name if any
    """

    args = {}
    config_file = None
    for (opt, val) in options:
        if opt in ["-c", "--config"]:
            config_file = val
        elif opt in ["-l", "--logging"]:
            args['logging'] = val
        elif opt in ["-m", "--manifests"]:
            if not re.match("^[a-zA-Z0-9/]+$", val):
                usage("manifest path must be alphanumeric with /")
            args['manifests'] = val
        elif opt in ["-p", "--port"]:
            if not val.isdigit():
                usage("port must be a number")
            args['port'] = val
        elif opt in ["-s", "--server"]:
            args['server'] = val
        elif opt in ["-s", "--iface"]:
            args['iface'] = val
        elif opt in ["-v", "--version"]:
            show_version()
        elif opt in ["h", "--help"]:
            usage()
        else:
            usage("Unknown option specified: %s" % opt)
    return config_file, args

def main():
    'do all the work, main entry point'

    defaults = {'port': '8001', 'manifests': '/etc/puppet',
                'logging': '/var/log/pupaas_errors',
                'server': None, 'iface': 'eth0'}
    default_config_file = '/etc/pupaas/pupaas.conf'

    try:
        (options, remainder) = getopt.gnu_getopt(
            sys.argv[1:], "c:l:m:p:vh", ["config=", "logging=",
                                         "manifests=", "port=",
                                         "server=", "iface=",
                                         "version", "help"])
    except getopt.GetoptError as err:
        usage("Unknown option specified: " + str(err))

    if len(remainder) > 0:
        usage("Unknown option(s) specified: <%s>" % remainder[0])

    config_file, args = process_options(options)
    configs = get_config(config_file, default_config_file)
    options = opts_merge(defaults, configs, args)

    be_daemon()
    puppet = PupServer(options)
    while True:
        puppet.handle_request()

if __name__ == '__main__':
    main()
