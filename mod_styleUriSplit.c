/*
 * mod_styleSplit.c
 *
 *  Created on: Feb 6, 2012
 *      Author: zhiwen
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>
#include <time.h>
#include <math.h>

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "plugin.h"
#include "response.h"
#include "stat_cache.h"
#include "md5.h"

#define EXT_JS     ".js"
#define EXT_CSS    ".css"
#define DIR_SYMBOL "/"
#define JS_OUT     "js"
#define CSS_OUT     "css"
#define DEFAULT_BUF_SIZE 128
#define MAX_URI_SIZE (DEFAULT_BUF_SIZE * 1024) // 128K
#define LDLOG_MARK	__FILE__,__LINE__
#define URI_SEPARATOR "|"
#define IOBUF_SIZE 10240

const char ZERO_END = '\0';
__mode_t   myMasks = 0700;

typedef struct {

	buffer *combineFileDir;

} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;

} plugin_data;

/**
 * 文件信息
 */
typedef struct {
	buffer *filePath;
	struct fileObject *nextItem;

} fileObject;

/**
 * 文件信息包装
 */
typedef struct {
	fileObject *fObject;
	time_t      lastModified;
	buffer     *contentType;
	off_t       totalSize;
	buffer     *fileExt;
} fileObjectWrapper;

/**
 * 获取uri中是所需要的文件后缀，只支持.js/.css 其它文件后缀无法获取，返回NULL
 */
static char *getFileExt(char *uri, int len) {
	if (NULL == uri) {
		return NULL;
	}
	if (0 == memcmp(EXT_JS, uri + len - 3, 3)) {
		return EXT_JS;
	}
	if (0 == memcmp(EXT_CSS, uri + len - 4, 4)) {
		return EXT_CSS;
	}
	return NULL;
}

static int mkdir_recursive(char *dir) {
	char *p = dir;
	if (!dir || !dir[0])
		return 0;

	while ((p = strchr(p + 1, '/')) != NULL) {
		*p = '\0';
		if ((mkdir(dir, myMasks) != 0) && (errno != EEXIST)) {
			*p = '/';
			return -1;
		}
		*p++ = '/';
		if (!*p) return 0; /* Ignore trailing slash */
	}
	return (mkdir(dir, myMasks) != 0) && (errno != EEXIST) ? -1 : 0;
}

static int requestValid(connection *con) {
	// only accept get && head
	if (con->request.http_method != HTTP_METHOD_GET
			&& con->request.http_method != HTTP_METHOD_HEAD) {
		return 0;
	}
	//如果没有uri 或 域名后面加/ 都不需要处理
	if ((con->uri.path->used) == 0
			|| con->uri.path->ptr[con->uri.path->used - 2] == '/') {
		return 0;
	}
	if(NULL == getFileExt(con->uri.path->ptr, con->uri.path->used - 1)) {
		return 0;
	}
	if(NULL == strstr(con->uri.path->ptr, URI_SEPARATOR)) {
		return 0;
	}
	// uri_len over max_uri_size 128K
	if(con->uri.path->used > MAX_URI_SIZE) {
		return 0;
	}
	return 1;
}

/**
 * 根据uri的md5值+内容大小+最后修改时间生成一个合并后的文件名
 */
static buffer *createFilePath(server *srv, connection *con, fileObjectWrapper *fObjectWrapper) {

	UNUSED(srv);

	MD5_CTX ctx;
	unsigned char md[16];
	buffer *subUri = con->uri.path;
	int subUriLen = subUri->used - 1;

	buffer *filePath = buffer_init();
	buffer_prepare_append(filePath, 60);

	char *fileExt = fObjectWrapper->fileExt->ptr;
	buffer_append_string_len(filePath, DIR_SYMBOL, 1);
	buffer_append_string_len(filePath, ++fileExt, fObjectWrapper->fileExt->used - 2);
	buffer_append_string_len(filePath, DIR_SYMBOL, 1);

	// md5 string append
	MD5_Init(&ctx);
	MD5_Update(&ctx, (unsigned char *)subUri->ptr, subUriLen);
	MD5_Final(md, &ctx);

	// /home/admin/combined/js/(md5_hex)_(filesize)_(lastmodified).(js|css)
	buffer_append_string_encoded(filePath, (char *)md, sizeof(md), ENCODING_HEX);
	buffer_append_string_len(filePath, "_", 1);
	buffer_append_off_t(filePath, fObjectWrapper->totalSize);
	buffer_append_string_len(filePath, "_", 1);
	buffer_append_long(filePath, fObjectWrapper->lastModified);
	buffer_append_string_buffer(filePath, fObjectWrapper->fileExt);

	return filePath;
}

static int fileCombining(server *srv, connection *con, fileObjectWrapper *fObjectWrapper, buffer *targetFile) {

	if (NULL == fObjectWrapper|| NULL == targetFile || 0 == targetFile->used) {
		return -1;
	}
	//the first write fileCont into tmpFile
	buffer *targetFileTmp = buffer_init_buffer(targetFile);
	buffer_append_string_len(targetFileTmp, "_tmp", 4);

	int ifd, ofd, num;
	char buf[IOBUF_SIZE];
	fileObject *fObject = fObjectWrapper->fObject;

	if(-1 == (ofd = open(targetFileTmp->ptr, O_WRONLY|O_CREAT|O_EXCL, 0600))) {
		buffer_free(targetFileTmp);
		if(errno == EEXIST) {
			//表示此文件已经有线程在进行写操作了。不需要进行重复的写
			return 0;
		}
		if(con->conf.log_file_not_found) {
			log_error_write(srv, LDLOG_MARK,  "sbss",  "--fileWrite  ",targetFileTmp ," error:", strerror(errno));
		}
		return -1;
	}

	for(; NULL != fObject; fObject = fObject->nextItem) {
		if (-1 == (ifd = open(fObject->filePath->ptr, O_RDONLY, 0600))){
			if (con->conf.log_file_not_found) {
				log_error_write(srv, LDLOG_MARK, "sbss", "open inFilePath error",
						fObject->filePath, " failed:", strerror(errno));
			}
			continue;
		}
		while((num = read(ifd, buf, IOBUF_SIZE)) > 0) {
			if(write(ofd, buf, num) != num) {
				log_error_write(srv, LDLOG_MARK, "sbsbss", "writeFile error ==> sourceFile ", fObject->filePath,
						                                   "targetFile:", targetFileTmp,
						                                   "failed:", strerror(errno));
			}
		}
		close(ifd);
	}
	close(ofd);

	/**
	 * 将新合并后的文件最后修改时间，变更成当前文件的最后修改时间。
	 * 同时写到head的last_modified中，用户其它模块生成Etag或修改时间比较保持统一。
	 */
	struct utimbuf newTime;
	newTime.modtime = fObjectWrapper->lastModified;
	newTime.modtime = fObjectWrapper->lastModified;
	if(-1 == utime(targetFileTmp->ptr, &newTime)) {
		log_error_write(srv, LDLOG_MARK, "sbss", "utime error==>targetFileTmp:", targetFileTmp,
												   "failed:", strerror(errno));
	}

	//将合并好的临时文件重命名成真正的文件名
	if(-1 == rename(targetFileTmp->ptr, targetFile->ptr)) {
		log_error_write(srv, LDLOG_MARK, "sbsbss", "rename error==>oldName ", targetFileTmp,
												   "newName:", targetFile,
												   "failed:", strerror(errno));
	}
	buffer_free(targetFileTmp);
	return 1;
}

static void uriSplit(server *srv, connection *con, fileObjectWrapper *fObjectWrapper, buffer *docRoot) {

	fileObject *firstItem = NULL;
	fileObject *prevItem = NULL;
	stat_cache_entry *sce = NULL;
	time_t lastModified = 0;
	buffer *uriBuf = buffer_init_buffer(con->uri.path);
	char *value = NULL;
	while(NULL != (value = strsep(&uriBuf->ptr, URI_SEPARATOR))) {
		// /home/admin/www_cn/htdocs
		buffer *absFilePath = buffer_init_buffer(docRoot);
		// /js/a.js
		int len = strlen(value);
		buffer_append_string_len(absFilePath, value, len);
		// check and append ext ".js | .css"
		if(NULL == getFileExt(value, len)) {
			buffer_append_string_buffer(absFilePath, fObjectWrapper->fileExt);
		}

		if (con->conf.log_request_handling) {
			log_error_write(srv, LDLOG_MARK,  "sb",  "-- absFilePath is:", absFilePath);
		}

		if(HANDLER_ERROR == stat_cache_get_entry(srv, con, absFilePath, &sce)) {
			if (con->conf.log_file_not_found) {
				log_error_write(srv, LDLOG_MARK,  "sb",  "-- not fond subDocRoot", absFilePath);
			}
			buffer_free(absFilePath);
			continue;
		}

		fileObject *fObjectItem = malloc(sizeof(fileObject));
		fObjectItem->nextItem = NULL;
		fObjectItem->filePath = absFilePath;
		if(NULL == firstItem) {
			firstItem = fObjectItem;
			fObjectWrapper->contentType = sce->content_type;
		} else {
			prevItem->nextItem = fObjectItem;
		}
		prevItem = fObjectItem;
		if (lastModified < sce->st.st_mtime) {
			lastModified = sce->st.st_mtime;
		}
		fObjectWrapper->totalSize += sce->st.st_size;
	}
	if(0 == lastModified) {
		time(&lastModified);
	}
	fObjectWrapper->fObject = firstItem;
	fObjectWrapper->lastModified = lastModified;

	buffer_free(uriBuf);
}

int http_response_cachable(server *srv, connection *con, buffer *mtime) {
	char *swapMoneMatch = con->request.http_if_none_match;
	con->request.http_if_none_match = NULL;
	int handlerStatus = http_response_handle_cachable(srv, con, mtime);
	if (HANDLER_FINISHED == handlerStatus) {
		con->request.http_if_none_match = swapMoneMatch;
		return handlerStatus;
	}
	return handlerStatus;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_styleUriSplit_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	PATCH(combineFileDir);

	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *) srv->config_context->data[i];
		s = p->config_storage[i];

		if (!config_check_cond(srv, con, dc)) {
			continue;
		}
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("styleUriSplit.combine-fileDir"))) {
				PATCH(combineFileDir);
			}
		}
	}
	return 0;
}
#undef PATCH

PHYSICALPATH_FUNC(mod_styleUriSplit_physical) {
	if (con->conf.log_request_handling) {
		log_error_write(srv, LDLOG_MARK,  "s",  "-- handling mod_styleUriSplit_physical start");
	}

	if(0 == requestValid(con)) {
		return HANDLER_GO_ON;
	}

	plugin_data *p = p_d;
	mod_styleUriSplit_patch_connection(srv, con, p);

	buffer *combineFileDir = p->conf.combineFileDir;
	if(buffer_is_empty(combineFileDir)) {
		log_error_write(srv, LDLOG_MARK,  "sbs", "config is NULL combineFileDir[", combineFileDir, "]");
		return HANDLER_ERROR;
	}
	//如果 doc_root最后面没有 “/” 则需要加上
	buffer *fixedDocRoot =  buffer_init_buffer(con->conf.document_root);
	if('/' != con->conf.document_root->ptr[con->conf.document_root->used - 2]) {
		buffer_append_string_len(fixedDocRoot, "/", 1);
	}

	//uri 做分割操作
	fileObjectWrapper fObjectWrapper;
	fObjectWrapper.contentType = NULL;
	fObjectWrapper.fObject = NULL;
	fObjectWrapper.lastModified = 0;
	fObjectWrapper.totalSize = 0;
	fObjectWrapper.fileExt = buffer_init();

	char *urlStr = con->uri.path->ptr + con->uri.path->used - 1;
	if (0 == memcmp(EXT_JS, urlStr - 3, 3)) {
		buffer_copy_string_len(fObjectWrapper.fileExt, EXT_JS, 3);
	}
	if (0 == memcmp(EXT_CSS, urlStr - 4, 4)) {
		buffer_copy_string_len(fObjectWrapper.fileExt, EXT_CSS, 4);
	}

	uriSplit(srv, con, &fObjectWrapper, fixedDocRoot);

	if(NULL == fObjectWrapper.fObject) {
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- fObjectWrapper is NULL");
		}
		return HANDLER_GO_ON;
	}

	buffer *mtime = strftime_cache_get(srv, fObjectWrapper.lastModified);
	if (con->conf.log_request_handling) {
		log_error_write(srv, LDLOG_MARK, "sbsss",
				"last_modified[", mtime,
				"]http_if_modified_since [", con->request.http_if_modified_since, "]");
	}

	if (HANDLER_FINISHED == http_response_cachable(srv, con, mtime)) {
		return HANDLER_FINISHED;
	}

	buffer *filePath = createFilePath(srv, con, &fObjectWrapper);

	buffer *combinedFullPath = buffer_init();
	buffer_prepare_append(combinedFullPath, combineFileDir->used + DEFAULT_BUF_SIZE);
	buffer_append_string_buffer(combinedFullPath, combineFileDir);
	buffer_append_string_buffer(combinedFullPath, filePath);

	if (con->conf.log_request_handling) {
		log_error_write(srv, LDLOG_MARK,  "sb",  "-- combinedFullPath", combinedFullPath);
	}

	time_t combinedMtime = 0;
	stat_cache_entry *sce = NULL;
	if(HANDLER_ERROR != stat_cache_get_entry(srv, con, combinedFullPath, &sce)) {
		combinedMtime = sce->st.st_mtime;
	}
	if(combinedMtime != fObjectWrapper.lastModified) {
		int combinResult = fileCombining(srv, con, &fObjectWrapper, combinedFullPath);
		if(1 == combinResult) {
			mtime = strftime_cache_get(srv, fObjectWrapper.lastModified);
			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(fObjectWrapper.contentType));
			response_header_overwrite(srv, con, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(mtime));
		}
		if(0 == combinResult) {
			/**
			 * if file combine not finished then wait 1 second
			 */
			log_error_write(srv, LDLOG_MARK,  "sb",  "--fileCombining sleep", combinedFullPath);
			sleep(1);
		}
	}

	buffer_copy_string_buffer(con->uri.path, filePath);
	/**
	 * 修改文件的物理路径为指定的路径
	 * 不然在 response.c 470行检查文件时将出错
	 * code=[ if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {xxx}]
	 */
	buffer_copy_string_buffer(con->physical.doc_root, combineFileDir);
	buffer_copy_string_buffer(con->physical.path, combinedFullPath);
	buffer_copy_string_buffer(con->physical.rel_path, filePath);

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling file as mod_styleUriSplit");
		log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
		log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
		log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		log_error_write(srv, __FILE__, __LINE__,  "sb", "URI         :", con->uri.path);
	}
	//free no used buff
	buffer_free(fixedDocRoot);
	buffer_free(filePath);
	buffer_free(combinedFullPath);
	buffer_free(fObjectWrapper.fileExt);

	fileObject *freeObject = fObjectWrapper.fObject;
	while (NULL != freeObject) {
		fileObject *tmpFreeObject = freeObject;
		buffer_free(tmpFreeObject->filePath);
		freeObject = freeObject->nextItem;
		free(tmpFreeObject);
	}
	return HANDLER_GO_ON;
}

INIT_FUNC(mod_styleUriSplit_init) {
	plugin_data *p = calloc(1, sizeof(*p));
	return p;
}

SETDEFAULTS_FUNC(mod_styleUriSplit_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
			//合并好的文件存放目录
			{ "styleUriSplit.combine-fileDir", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER },
			//NULL conf
			{ NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s = malloc(sizeof(plugin_config));

		s->combineFileDir = buffer_init();
		cv[0].destination = s->combineFileDir;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, ((data_config *) srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}

		if (!buffer_is_empty(s->combineFileDir)) {
			mkdir_recursive(s->combineFileDir->ptr);
			struct stat st;
			if (0 != stat(s->combineFileDir->ptr, &st)) {
				log_error_write(srv, __FILE__, __LINE__, "sbs", "can't stat styleUriSplit.combine-fileDir", s->combineFileDir, strerror(errno));
				return HANDLER_ERROR;
			}
			//创建js合并后的临时文件 /home/zhiwen/output/combo/style/js
			buffer *js_dir = buffer_init_buffer(s->combineFileDir);
			buffer_append_string(js_dir, DIR_SYMBOL);
			buffer_append_string(js_dir, JS_OUT);

			if(-1 == mkdir(js_dir->ptr, myMasks)) {
				if (errno != EEXIST) {
					log_error_write(srv, LDLOG_MARK, "sbss", "js_dir create", js_dir, "failed", strerror(errno));
					return HANDLER_ERROR;
				}
			}
			buffer_free(js_dir);

			//创建css合并后的临时文件 /home/zhiwen/output/combo/style/css
			buffer *css_dir = buffer_init_buffer(s->combineFileDir);
			buffer_append_string(css_dir, DIR_SYMBOL);
			buffer_append_string(css_dir, CSS_OUT);

			if(-1 == mkdir(css_dir->ptr, myMasks)) {
				if (errno != EEXIST) {
					log_error_write(srv, LDLOG_MARK, "sbss", "css_dir create", css_dir, "failed", strerror(errno));
					return HANDLER_ERROR;
				}
			}
			buffer_free(css_dir);
		}
	}
	return HANDLER_GO_ON;
}

FREE_FUNC(mod_styleUriSplit_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) {
		return HANDLER_GO_ON;
	}

	if (p->config_storage) {
		size_t i;
		for(i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			buffer_free(s->combineFileDir);
			free(s);
		}
		free(p->config_storage);
	}
	free(p);
	return HANDLER_GO_ON;
}

int mod_styleUriSplit_plugin_init(plugin *p) {
	p->version = LIGHTTPD_VERSION_ID;
	p->name = buffer_init_string("mod_styleUriSplit");

	p->init = mod_styleUriSplit_init;
	p->handle_physical = mod_styleUriSplit_physical;
	p->set_defaults = mod_styleUriSplit_set_defaults;

	p->cleanup = mod_styleUriSplit_free;

	p->data = NULL;
	return 0;
}
