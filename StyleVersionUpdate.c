/*
 * StyleVersionUpdate.c
 *
 *  Created on: Jul 21, 2012
 *      Author: zhiwen
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define WGET_CMD "wget -S -t 1 -T 5 "
#define BUFFER_PIECE_SIZE 128
#define DEFAULT_BUF_LEN 65536
#define REPONSE_LOG ".response.log"
#define TMP "_tmp"
#define LAST_MODIFIED_NAME "Last-Modified: "
#define HEADER "\"--header=If-Modified-Since:"
#define GZIP_CMD "/bin/gzip -cd "
#define USAGE "--($1=http://xxxx/styleVersion.gz)---($2=/home/admin/output/styleVersion.gz)----($3=5)"
int WGET_CMD_LEN = 0;
int REPONSE_LOG_LEN = 0;
int TMP_LEN = 0;
int LAST_MODIFIED_NAME_LEN = 0;
int HEADER_LEN = 0;
int GZIP_CMD_LEN = 0;
int LAST_MODIFIED_LEN = 40;

const char ZERO_END = '\0';
int debug = 1;

typedef struct {
	char *ptr;
	off_t used;
	off_t size;
} buffer;

void buffer_free(buffer *b) {
	if(NULL == b) {
		return;
	}
	free(b->ptr);
	free(b);
	return;
}

buffer *buffer_init() {
	buffer *buf = malloc(sizeof(buffer));
	if(NULL == buf) {
		return buf;
	}
	buf->ptr = NULL;
	buf->used = 0;
	buf->size = 0;
	return buf;
}
buffer *buffer_init_size(int size) {
	buffer *buf = buffer_init();
	if(NULL == buf) {
		return buf;
	}
	buf->ptr = malloc(size);
	if(NULL == buf->ptr) {
		buffer_free(buf);
		return NULL;
	}
	buf->size = size;
	return buf;
}

void debug_buffer(buffer *buf, char *name) {
	if(debug) {
		if(NULL == buf) {
			fprintf(stdout,"%s : is NULL \n", name);
			return;
		}
		fprintf(stdout,"%s:[%s] USED:[%ld] SIZE[%ld]\n", name, buf->ptr, buf->used, buf->size);
	}
}

typedef struct {
	int     intervalSecond;
	buffer *URLDomain;
	buffer *versionFilePath;
	buffer *expectVersionFilePath;
	buffer *reponseFilePath;
	buffer *tmpVersionFilePath;
}VersionUpdateConfig;

void initGlobalVar(){
	WGET_CMD_LEN = strlen(WGET_CMD);
	REPONSE_LOG_LEN = strlen(REPONSE_LOG);
	TMP_LEN = strlen(TMP);
	LAST_MODIFIED_NAME_LEN = strlen(LAST_MODIFIED_NAME);
	HEADER_LEN = strlen(HEADER);
	GZIP_CMD_LEN = strlen(GZIP_CMD);
	debug = 0;
}

static void stringAppend(buffer *buf, char *str, int strLen) {
	if(NULL == buf || NULL == str || strLen <= 0) {
		return;
	}
	if(0 == buf->size) {
		if(strLen > BUFFER_PIECE_SIZE) {
			buf->size = strLen + BUFFER_PIECE_SIZE;
		} else {
			buf->size = BUFFER_PIECE_SIZE;
		}
		buf->ptr = malloc(buf->size);
		buf->used = 0;
	}
	if(buf->used + strLen >= buf->size) {
		buf->size += (strLen + BUFFER_PIECE_SIZE);
		buf->ptr = realloc(buf->ptr, buf->size);
		printf("realloc===============");
	}
	memcpy(buf->ptr + buf->used, str, strLen);
	buf->used += strLen;
	buf->ptr[buf->used] = ZERO_END;
	return;
}

int getHttpStatus(char *response) {
	if(NULL == response) {
		return 0;
	}
	char *http = strstr(response, "304 Not Modified");
	if(NULL == http) {
		http = strstr(response, "200 OK");
		if(NULL == http) {
			return 404;
		}
		return 200;
	}
	return 304;
}

void getLastModified(char *response, buffer **modifiedBuf) {

	//释放上一次赋于他的内存空间，再接受新的赋值。不然这儿会有内存泄露
	buffer_free(*modifiedBuf);
	*modifiedBuf = NULL;

	if(NULL == response) {
		return;
	}
	char *lastModified = strstr(response, LAST_MODIFIED_NAME);
	if(NULL == lastModified) {
		return;
	}
	lastModified += LAST_MODIFIED_NAME_LEN;

	buffer *buf = buffer_init_size(LAST_MODIFIED_LEN);
	for(; (*lastModified !='\n' && buf->used < buf->size); ++lastModified) {
		buf->ptr[buf->used] = *lastModified;
		buf->used++;
	}
	buf->ptr[buf->used] = ZERO_END;
	*modifiedBuf = buf;
}

char *readResponse(char *responsePath) {
	if(NULL == responsePath) {
		return NULL;
	}
	char *responseBuf = NULL;
	struct stat st;
	if (stat(responsePath, &st) != -1) {
		responseBuf = malloc(sizeof(char) * st.st_size);
	}
	if(NULL == responseBuf) {
		return NULL;
	}
	int ifd = 0;
	if (-1 != (ifd = open(responsePath, O_RDONLY, 0600))){
		if(st.st_size != read(ifd, responseBuf, st.st_size)){
			fprintf(stderr, "readResponse error read bytes");
		}
		close(ifd);
	}
	return responseBuf;
}

void checkAndGzip(buffer *tmpFilePath, buffer *targetFilePath, buffer *expectFilePath, buffer *responsePath){
	char *responseCnt = readResponse(responsePath->ptr);
	int httpStatus = getHttpStatus(responseCnt);
	if(200 == httpStatus) {
		if(-1 != rename(tmpFilePath->ptr, targetFilePath->ptr)) {
			//system invoke unzip
			buffer *unzipCmd = buffer_init_size(20 + targetFilePath->used + expectFilePath->used);
			stringAppend(unzipCmd, GZIP_CMD, GZIP_CMD_LEN);
			stringAppend(unzipCmd, targetFilePath->ptr, targetFilePath->used);
			stringAppend(unzipCmd, " > ", 3);
			stringAppend(unzipCmd, expectFilePath->ptr, expectFilePath->used);

			debug_buffer(unzipCmd, "unzipCmd");
			if(-1 == system(unzipCmd->ptr)) {
				fprintf(stderr, "system(gzip....) error:%s\n", unzipCmd->ptr);
			}
			buffer_free(unzipCmd);
		}
	}
	free(responseCnt);
}
void intervalWork(VersionUpdateConfig *config) {

	if(debug) {
		fprintf(stdout, "start intervalWork\n");
	}
	//clean old responsefile
	remove(config->reponseFilePath->ptr);

	buffer *lastModifiedTime = NULL;

	int paramLen = config->URLDomain->used + config->tmpVersionFilePath->used + config->reponseFilePath->used;
	buffer *param = buffer_init_size(20 + paramLen);
	stringAppend(param, " ", 1);
	stringAppend(param, config->URLDomain->ptr, config->URLDomain->used);
	stringAppend(param, " -O ", 4);
	stringAppend(param, config->tmpVersionFilePath->ptr, config->tmpVersionFilePath->used);
	stringAppend(param, " > ", 3);
	stringAppend(param, config->reponseFilePath->ptr, config->reponseFilePath->used);
	stringAppend(param, " 2>&1 ", 6);

	while(1) {
		char *responseCnt = readResponse(config->reponseFilePath->ptr);
		int httpStatus = getHttpStatus(responseCnt);
		if(debug) {
			fprintf(stdout, "httpStatus:%d\n", httpStatus);
		}

		if(304 != httpStatus) {
			getLastModified(responseCnt, &lastModifiedTime);
		}
		debug_buffer(lastModifiedTime, "lastModifiedTime");
		//thread interval exec
		buffer *cmdBuf = buffer_init_size(LAST_MODIFIED_LEN + WGET_CMD_LEN + HEADER_LEN + param->used);
		stringAppend(cmdBuf, WGET_CMD, WGET_CMD_LEN);
		if(NULL != lastModifiedTime) {
			stringAppend(cmdBuf, HEADER, HEADER_LEN);
			stringAppend(cmdBuf, lastModifiedTime->ptr, lastModifiedTime->used);
			stringAppend(cmdBuf, "\"", 1);
		}
		stringAppend(cmdBuf, param->ptr, param->used);
		debug_buffer(cmdBuf, "cmdBuf");

		if(-1 == system(cmdBuf->ptr)) {
			fprintf(stderr, "system (wget...) error:%s\n", cmdBuf->ptr);
		}

		free(responseCnt);
		buffer_free(cmdBuf);

		checkAndGzip(config->tmpVersionFilePath, config->versionFilePath,
					config->expectVersionFilePath, config->reponseFilePath);

		sleep(config->intervalSecond);
	}
}

void parseArgs(VersionUpdateConfig *config, int argc, char *args[]) {

	if(argc < 3) {
		fprintf(stderr, "USAGE:%s\n", USAGE);
		return;
	}

	if(debug) {
		int i = 0;
		for(i = 0; i < argc; i++) {
			fprintf(stdout, "param $%d == %s\n", i, args[i]);
		}
	}

	char *URL = args[1];
	char *path = args[2];
	int   intervalSecond = atoi(args[3]);

	if(argc > 4) {
		debug = atoi(args[4]);
	}
	//global var
	int URLLen = strlen(URL);
	int pathLen = strlen(path);

	//interval time
	config->intervalSecond = intervalSecond;
	//url
	buffer *URLDomain = buffer_init_size(URLLen + 1);
	stringAppend(URLDomain, URL, URLLen);
	config->URLDomain = URLDomain;
	debug_buffer(URLDomain, "URLDomain");
	//source
	buffer *versionFilePath = buffer_init_size(pathLen + 1);
	stringAppend(versionFilePath, path, pathLen);
	config->versionFilePath = versionFilePath;
	debug_buffer(versionFilePath, "versionFilePath");
	//expect
	buffer *expectVersionFilePath = buffer_init_size(versionFilePath->size);
	stringAppend(expectVersionFilePath, path, pathLen - 3); //--clean .gz
	config->expectVersionFilePath = expectVersionFilePath;
	debug_buffer(expectVersionFilePath, "expectVersionFilePath");
	//response
	buffer *reponseFilePath = buffer_init_size(versionFilePath->size + REPONSE_LOG_LEN);
	stringAppend(reponseFilePath, expectVersionFilePath->ptr, expectVersionFilePath->used);
	stringAppend(reponseFilePath, REPONSE_LOG, REPONSE_LOG_LEN);
	config->reponseFilePath = reponseFilePath;
	debug_buffer(reponseFilePath, "reponseFilePath");
	//tmp
	buffer *tmpVersionFilePath = buffer_init_size(versionFilePath->size + TMP_LEN);
	stringAppend(tmpVersionFilePath, versionFilePath->ptr, versionFilePath->used);
	stringAppend(tmpVersionFilePath, TMP, TMP_LEN);
	config->tmpVersionFilePath = tmpVersionFilePath;
	debug_buffer(tmpVersionFilePath, "tmpVersionFilePath");
}

int main(int argc, char *argv[]) {

	VersionUpdateConfig *config = malloc(sizeof(VersionUpdateConfig));
	initGlobalVar();
	parseArgs(config, argc, argv);

	pthread_t tid;
	int ret = pthread_create(&tid, NULL, (void *)intervalWork, (void *)config);
	if(ret != 0) {
		fprintf(stderr, "create thread error\n", NULL);
		exit(1);
	}

	char buffer[DEFAULT_BUF_LEN];

	for(;;) {
		int nBytesRead = read(0,buffer, sizeof(buffer));
		if(nBytesRead == 0) {
			exit(2);
		}
		if(errno == EINTR) {
			continue;
		}
		if(debug) {
			fprintf(stdout,"%s\n", buffer);
		}
	}
}
