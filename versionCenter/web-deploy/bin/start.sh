#!/bin/sh

dir=`pwd`
sh $dir/build.sh &

/usr/alibaba/httpd/bin/httpd -f /home/admin/web-deploy/conf/httpd.conf -k start
