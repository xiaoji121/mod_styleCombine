/*
 * StyleVersionUpdate.c
 *
 *  Created on: Jul 21, 2012
 *      Author: zhiwen
 */
#include   <stdio.h>
#include   <stdlib.h>
#include   <string.h>
#include   <pthread.h>
#include   <errno.h>


#define  DEFAULT_BUF_LEN 65535

typedef struct {
	int  secondInterval;
	char *cmd;
}VersionUpdateConfig;

void intervalWork(VersionUpdateConfig *config) {

	while(1) {
		system(config->cmd);
		sleep(config->secondInterval);
	}
}

void parseArgs(VersionUpdateConfig *config, char *args[]) {
	config->secondInterval = atoi(args[1]);
	config->cmd = args[2];
}

int main(int argc, char *argv[]) {

	VersionUpdateConfig *config = malloc(sizeof(VersionUpdateConfig));
	parseArgs(config, argv);

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
		//fprintf(stderr, "input :%s\n", buffer);
		//FIXME:ADD IF
		if(errno == EINTR) {
			continue;
		}
	}
}
