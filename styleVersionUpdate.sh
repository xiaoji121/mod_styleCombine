#!/bin/bash

gzip=`which gzip`
STYLE_DOMAIN="http://172.22.9.69"
DOWNLOAD_DIR="${forum_output}"
STYLE_VERSION_URI="styleVersion" 

#default 2 minutes
interval="2m"

lastModified=""
httpStatus=0

STYLE_VERSION_URL="${STYLE_DOMAIN}/${STYLE_VERSION_URI}.gz" 
DOWNLOAD_DIR_FILE="${DOWNLOAD_DIR}/${STYLE_VERSION_URI}.gz"
DOWNLOAD_DIR_FILE_TMP="${DOWNLOAD_DIR}/${STYLE_VERSION_URI}.gz_tmp"
UNGZIP_DIR_FILE="${DOWNLOAD_DIR}/${STYLE_VERSION_URI}"
RESPONSE_LOG="${DOWNLOAD_DIR}/response"

getLastModified() {
	responseLog=$1
	lastModified=""
    if [ -f "$responseLog" ]; then
        lastModified=`cat $responseLog |grep "Last-Modified:" | awk -F"Last-Modified:" '{print $2}'`
    fi
}

getHttpStatus() {
	responseLog=$1
	httpStatus=0
    if [ -f "$responseLog" ]; then
        httpStatus=`cat $responseLog |grep "HTTP/" | awk '{print $2}'`
        if [ -z "$httpStatus" ]; then
        	httpStatus=0
        fi
    fi
}

ungzip() {
    `$gzip -cd $1 > $2`
}

checkAndUngzip() {
	
	getHttpStatus $RESPONSE_LOG
        
    ##如果返回的内容是html内容则表示出错，不将版本文件替换；如果下载成功grep 二进制文件则会报错，所以添加-v去除错误
    isHtml=`cat ${DOWNLOAD_DIR_FILE_TMP} | head -10| grep "<" | grep -v "Binary file"`

	##http状态返回200表示正确，如果是304或其它则不做任何处理    
    if [ $httpStatus -eq 200 ] && [ -z "$isHtml" ]; then
    	## 将tmp文件修改成可用文件
        mv ${DOWNLOAD_DIR_FILE_TMP} ${DOWNLOAD_DIR_FILE}
        
        ##将文件减压到 ${UNGZIP_DIR_FILE} 目录文件中
        ungzip ${DOWNLOAD_DIR_FILE} ${UNGZIP_DIR_FILE}
    fi
}

download() {
	
	getHttpStatus $RESPONSE_LOG
	##只要不是304才去读取新的lastModified,否则lastModified永远不会被修改掉
	if [ $httpStatus -ne 304 ]; then
		getLastModified $RESPONSE_LOG	
	fi
    
	##如果有lastModified信息，则添加头信息去请求
	param=""
    if [ -n "$lastModified" ]; then
    	param="--header=If-Modified-Since:${lastModified}"
    fi
    ##下载版本文件
    wget -S -t 0 -T 5 "$param" ${STYLE_VERSION_URL} -O ${DOWNLOAD_DIR_FILE_TMP} > $RESPONSE_LOG 2>&1
    checkAndUngzip
}

main() {
    mkdir -p $DOWNLOAD_DIR
    if [ -f "${UNGZIP_DIR_FILE}" ]; then
    	rm ${UNGZIP_DIR_FILE}*
    fi
    if [ -f "$RESPONSE_LOG" ]; then
    	rm $RESPONSE_LOG
    fi
    
    while [ true ]; do
        ##下载调用
        download
        sleep $interval
    done
}

main
