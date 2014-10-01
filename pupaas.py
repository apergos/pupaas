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

VERSION = "0.1"

# for python 2.6, e.g. lucid
# source: http://stackoverflow.com/questions/4814970/subprocess-check-output-doesnt-seem-to-exist-python-2-6-5
# code is actually a backport from python 2.7
if "check_output" not in dir( subprocess ): # duck punch it in!
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
    def __init__(self, options):
        s_name = options['server']
        if not s_name:
            s_name = socket.gethostname()
            if s_name:
                try:
                    s_name = socket.gethostbyname(s_name)
                except socket.gaierror:
                    s_name = self.get_ip(options['iface'])

        super( PupServer, self ).__init__((s_name, int(options['port'])),PupRequestHandler)
        self.manifest_base = options['manifests']
        self.logging = options['logging']

    def get_ip(self, ifname):
        # hack to work around python broken getaddrinfo/gethostbyname
        # when presented with names like 836937931829
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])

class PupRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler, object):
    server_version = 'PUPAAS/' + VERSION
    BUF_SIZE = 65536

    def log_error(self, format, *args):
        if self.server.logging != "stderr":
            fd = None
            try:
                f = os.open(self.server.logging, os.O_WRONLY | os.O_APPEND | os.O_CREAT )
                fd = os.fdopen(f,"a")
                fcntl.flock(fd, fcntl.LOCK_EX)
            except:
                if fd:
                    fd.close()
                fd = sys.stderr
        else:
            fd = sys.stderr

        fd.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(),
                                       format%args))
        if fd != sys.stderr:
            fd.close()

    def log_request(self, code='-', size='-'):
        pass

    def get_manifest_path(self, path):
        return '/'.join([self.server.manifest_base.rstrip('/'),path.lstrip('/')])

    def check_path(self,path):
        # check that it ends in pp and that the rest is only ascii alphanumeric with '/' or - or _
        if not path.endswith(".pp"):
            return False
        if not re.match("^[a-zA-Z0-9_\-/]+$",path[:-3]):
            return False
        return True

    def do_GET(self):
        # expect '/manifest/...' or '/fact/...')
        if self.path[0] != '/':
            self.send_error(403)
            return
            
        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/',1)
        if subcommand == 'manifest':
            self.get_manifest(rest)
        elif subcommand == 'fact':
            self.get_fact(rest)
        else:
            self.send_error(403)
            
    def get_manifest(self, path):
        if not self.check_path(self.path):
            self.send_error(403)
            return

        manifest_path = self.get_manifest_path(path)

        if not os.path.exists(manifest_path):
            self.send_error(404)
            return
            
        fd = None
        try:
            fd = open(manifest_path, "r")
        except:
            # note that if we can't open it that's still considered
            # server issues rather than 403, since it's in the manifest dir
            if fd:
                fd.close()
            self.send_error(500)
            return

        file_info = os.fstat(fd.fileno())
        self.send_response(200)
        self.send_header('Last-modified', self.date_time_string(file_info.st_mtime))
        self.send_header('Content-type', 'text/plain')
        if self.command == 'GET':
            self.send_header('Content-length',file_info.st_size)
        self.end_headers()

        if self.command == 'GET':
            contents = fd.read(PupRequestHandler.BUF_SIZE)
            while (contents):
                self.wfile.write(contents)
                contents = fd.read(PupRequestHandler.BUF_SIZE)

        fd.close()

    def get_fact(self, path):
        command = [ '/usr/bin/facter', path ]
        try:
            result = subprocess.check_output(command)
        except:
            if self.server.logging is None:
                fd = sys.stderr
            else:
                f = os.open(self.server.logging, os.O_WRONLY | os.O_APPEND | os.O_CREAT )
                fd = os.fdopen(f,"a")
                fcntl.flock(fd, fcntl.LOCK_EX)
            traceback.print_exc(fd)
            if fd != sys.stderr:
                fd.close()
            self.send_error(500)
            return
        
        if not result:
            self.send_error(404)
            return

        self.send_response(200, "OK")
        self.send_header('Last-modified', self.date_time_string(time.time()))
        self.send_header('Content-type', 'text/plain')
        if self.command == 'GET':
            self.send_header('Content-length',len(result))
        self.end_headers()

        if self.command == 'GET':
            self.wfile.write(result)

    do_HEAD = do_GET

    def do_PUT(self):
        if self.path[0] != '/':
            self.send_error(403)
            return
            
        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/',1)
        if subcommand == 'manifest':
            self.put_manifest(rest)
        else:
            self.send_error(403)

    def put_manifest(self, path):
        if not self.check_path(path):
            self.send_error(403)
            return

        manifest_path = self.get_manifest_path(path)

        # don't overwrite existing file
        if os.path.exists(manifest_path):
            self.send_error(403)
            return

        f = None
        try:
            f = os.open(manifest_path,os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except:
            self.send_error(500)
            if f:
                f.close()
            return
        fd = os.fdopen(f,"w")
        fcntl.flock(fd, fcntl.LOCK_EX)

        # FIXME what server headers are required for PUT?
        if 'content-length' in self.headers:
            self.process_client_data(fd,int(self.headers['content-length']))
        else:
            self.process_client_data(fd)

        fd.close()
        self.send_response(201)
        self.send_header('Content-length', '0')
        self.end_headers()

    def process_client_data(self, fd, max_bytes=None):
        if max_bytes is None:
            contents = self.rfile.read(PupRequestHandler.BUF_SIZE)
            while (contents):
                fd.write(contents)
                contents = self.rfile.read(PupRequestHandler.BUF_SIZE)
            return

        bytes_read = 0
        remaining = max_bytes

        contents = self.read_chunk(remaining)
        bytes_read = bytes_read + len(contents)
        remaining = remaining - len(contents)
        while (contents):
            fd.write(contents)
            if not remaining:
                break
            contents = read_chunk(remaining)
            bytes_read = bytes_read + len(contents)
            remaining = remaining - len(contents)

    def read_chunk(self, remaining):
        if remaining < PupRequestHandler.BUF_SIZE:
            return self.rfile.read(remaining)
        else:
            return self.rfile.read(PupRequestHandler.BUF_SIZE)

    def do_POST(self):
        if self.path[0] != '/':
            self.send_error(403)
            return
            
        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/',1)
        if subcommand == 'apply':
            self.apply_manifest(rest)
        else:
            self.send_error(403)

    def apply_manifest(self, path):
        if not self.check_path(self.path):
            self.send_error(403)
            return

        manifest_path = self.get_manifest_path(path)

        if not os.path.exists(manifest_path):
            self.send_error(404)
            return
        
        # run the command, get error output if any
        command = [ "/usr/bin/puppet", "apply", "--detailed-exitcodes", manifest_path ]
        proc = subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            stdoutdata, stderrdata = proc.communicate()
        except:
            self.send_error(500)
            return
        if proc.returncode == 4 or proc.returncode == 6:
            # fixme should really send contents of stderr + possibly stdout here
            self.send_error(500)
            return
        elif proc.returncode == 2:
            # something changed, should show it to the user
            self.send_response(200)
            self.send_header('Last-modified', self.date_time_string(time.time()))
            self.send_header('Content-type', 'text/plain')
            self.send_header('Content-length',len(stdoutdata))
            self.end_headers()
            self.wfile.write(stdoutdata)
        elif proc.returncode == 0:
            self.send_response(204)
            self.send_header('Last-modified', self.date_time_string(time.time()))
            self.end_headers()

    def do_DELETE(self):
        if self.path[0] != '/':
            self.send_error(403)
            return
            
        path = self.path[1:]
        if not '/' in path:
            self.send_error(403)
            return

        subcommand, rest = path.split('/',1)
        if subcommand == 'manifest':
            self.delete_manifest(rest)
        else:
            self.send_error(403)

    def delete_manifest(self, path):
        if not self.check_path(self.path):
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
            self.send_error(500)
            return

        self.send_response(204)
        self.send_header('Last-modified', self.date_time_string(time.time()))
        self.end_headers()
        
    def do_CONNECT(self):
        pass

def show_version():
    print "pupaas.py " + VERSION + "\n"
    sys.exit(0)

def usage(message = None):
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
    result = {}
    if not config_file:
        config_file = defaultpath
    fd = None
    try:
        fd = open(config_file,"r")
    except:
        if config_file == defaultpath:
            if fd:
                fd.close()
            return result
        else:
            raise

    errors = False
    # format: name=value (maybe blanks around equals sign)
    for line in fd:
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
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

def be_daemon():
    do_fork()      # so child can be process leader
    os.setsid()    # new session with no controlling terminal
    do_fork()      # process leader exists, child can't get a controlling terminal
    os.chdir("/")  # only root filesystem kept in use
    os.umask(0)    # ditch any inherited umask

if __name__ == '__main__':
    defaults = { 'port': '8001', 'manifests': '/etc/puppet', 'logging': '/var/log/pupaas_errors', 'server': None, 'iface': 'eth0' }
    args = {}
    default_config_file = '/etc/pupaas/pupaas.conf'
    config_file = None

    try:
        (options, remainder) = getopt.gnu_getopt(sys.argv[1:], "c:l:m:p:vh", ["config=","logging=", "manifests=", "port=","server=", "iface=", "version","help"])
    except getopt.GetoptError as err:
        usage("Unknown option specified: " + str(err))
    for (opt, val) in options:
        if opt in ["-c", "--config"]:
            config_file = val
        elif opt in ["-l", "--logging" ]:
            args['logging'] = val
        elif opt in ["-m", "--manifests" ]:
            if not re.match("^[a-zA-Z0-9/]+$",val):
                usage("manifest path must be alphanumeric with /")
            args['manifests'] = val
        elif opt in ["-p", "--port" ]:
            if not val.isdigit():
                usage("port must be a number")
            args['port'] = val
        elif opt in ["-s", "--server" ]:
            args['server'] = val
        elif opt in ["-s", "--iface" ]:
            args['iface'] = val
        elif opt in ["-v", "--version" ]:
            show_version()
        elif opt in ["h", "--help" ]:
            usage()
        else:
            usage("Unknown option specified: %s" % opt)

    if len(remainder) > 0:
        usage("Unknown option(s) specified: <%s>" % remainder[0])

    configs = get_config(config_file, default_config_file)
    options = opts_merge(defaults, configs, args)

    be_daemon()
    ps = PupServer(options)
    while (True):
        ps.handle_request()
