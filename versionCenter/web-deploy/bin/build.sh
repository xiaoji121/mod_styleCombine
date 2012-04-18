#!/bin/sh

dir=`pwd`
logFile="$dir/stdout.log"

start() {
   java -jar /home/admin/web-deploy/lib/versionCenter.jar configPath=/home/admin/web-deploy/conf/conf.properties > $logFile 2>&1
}

check() {
   if [ -f $logFile ]; then
       result=`cat $logFile | grep "execute status is : true"`
        if [ ! -z "$result" ]; then
           exit 0
        fi
   fi
   exit 1;
}

start
check
