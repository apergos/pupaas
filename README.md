pupaas
======

pupaas.py is a very plain 'puppet as a service' script
that will allow the called to upload, delete and
apply a single puppet manifest to the host running
the script, or retrieve a fact via facter from
the host.

This was written to be used for docker containers
for bootstrapping things like networking information
that must be added to configuration scripts for
an application.

Quick instructions:

You need puppet and facter installed and configured
but you do not need puppetmaster to be running.

python pupaas.py  -m /home/ariel/src/pupaas/testing -c p.cf -l ~/mypupaaslog.txt

-m: the path where puppet manifests live (including
    modules, files; this is the top of the puppet tree)
-c: config file if you want one
-l: file where access/error logs are written

Now use curl or a program of your choice to connect to
localhost:8001 and try any of the following:
GET /manifest/relative-path-to-manifest   -- retrieves a manifest
PUT /manifest/relative-path-to-manifest   -- uploads a manifest if it does not already exist
DELETE /manifest/relative-path-to-manifest   -- deletes a manifest
POST /apply/relative-path-to-manifest   -- applies a manifest

GET /fact/factname -- retrieves a fact

More details:

This is a single threaded app meant to handle one request
at a time in serial.  It's just intended to manage configuration
changes that have to be done on a docker container after
the container is already running, nothing more than that.

For a sample configuration file, see pupaas.conf.sample in this directory.

For more detailed run-time options, run
python pupaas.py --help

License information: copyright Ariel T. Glenn 2013-2014, GPL v2 or later.
For details see the file COPYING in this directory.

