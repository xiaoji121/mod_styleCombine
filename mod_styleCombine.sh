#!/bin/bash

gzip=`which gzip`
STYLE_DOMAIN="http://style.china.alibaba.com"
DOWNLOAD_DIR="/home/zhiwen/output"
STYLE_VERSION_URI="styleVersion" 

#default 10 minutes
interval="10m"

lastModified=""
httpStatus=0

STYLE_VERSION_URL="${STYLE_DOMAIN}/${STYLE_VERSION_URI}.gz" 
DOWNLOAD_DIR_FILE="${DOWNLOAD_DIR}/${STYLE_VERSION_URI}.gz"
UNGZIP_DIR_FILE="${DOWNLOAD_DIR}/${STYLE_VERSION_URI}"

getLastModified() {
    if [ -f "$1" ]
        then lastModified=`cat $1 |grep "Last-Modified:" | awk -F"Last-Modified:" '{print $2}'`
        else lastModified=""
    fi
}

getHttpStatus() {
    if [ -f "$1" ]
        then httpStatus=`cat $1 |grep "HTTP/" | awk '{print $2}'`
        else httpStatus=0
    fi
}

ungzip() {
    `$gzip -cd $1 > $2`
}

download() {

    getLastModified $4

    if [ -z "$lastModified" ]

        then wget -q -S -t 0 -T 5 $1 -O $2 > $4 2>&1
             ungzip $2 $3
        else wget -q -S -t 0 -T 5 --header="If-Modified-Since:$lastModified" $1 -O ${2}_t > $4 2>&1

        getHttpStatus $4
        if [ $httpStatus -eq 200 ]
            then mv ${2}_t $2
                ungzip $2 $3
        fi
    fi
}

main() {
    mkdir -p $DOWNLOAD_DIR
    while [ true ]; do
        download "${STYLE_VERSION_URL}" "${DOWNLOAD_DIR_FILE}" "${UNGZIP_DIR_FILE}" "${DOWNLOAD_DIR}/response"
        sleep $interval
    done
}
main
