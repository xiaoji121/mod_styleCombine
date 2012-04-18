#!/bin/sh

killall java
/usr/alibaba/httpd/bin/httpd -f /home/admin/web-deploy/conf/httpd.conf -k stop
