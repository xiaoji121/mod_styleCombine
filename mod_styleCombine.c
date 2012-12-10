/**
 * zhiwen.mizw@alibaba-inc.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
#include <malloc.h>

#include "httpd.h"
#include "apr_buckets.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "util_filter.h"
#include "http_request.h"
#include "apr_pools.h"
#include "apr_hash.h"

#define STYLE_COMBINE_NAME "styleCombine"

module AP_MODULE_DECLARE_DATA styleCombine_module;

#define MODULE_BRAND "styleCombine/1.0.1"
#define EXT_JS ".js"
#define EXT_CSS ".css"
#define URI_SEPARATOR "|"
#define POSITION_TOP "top"
#define POSITION_HEAD "head"
#define POSITION_FOOTER "footer"
#define DEBUG_MODE "_debugMode_="
#define RUN_MODE_STATUS "dis"
#define JS_TAG_EXT_PREFIX_TXT "<script type=\"text/javascript\" src=\""
#define JS_TAG_EXT_SUFFIX_TXT "\"></script>"
#define JS_TAG_PREFIX_TXT "<script type=\"text/javascript\">"
#define JS_TAG_SUFFIX_TXT "</script>"
#define CSS_PREFIX_TXT "<link rel=\"stylesheet\" href=\""
#define CSS_SUFFIX_TXT "\" />"

#define BUFFER_PIECE_SIZE 128
#define DEFAULT_CONTENT_LEN (1024 << 8) //262144
#define DOMAIN_COUNTS 2
#define MAX_STYLE_TAG_LEN 2183
//去右空格
#define TRIM_RIGHT(p) while(isspace(*p)){ ++p; }

#define BUFFER_CLEAN(buffer) if(NULL != buffer) { buffer->used = 0; buffer->ptr[0] = ZERO_END; }

//解析field属性的值，有空格则去空格
#define FIELD_PARSE(p, ret) {\
	while(isspace(*p)){ ++p; }\
	if('=' == *p++) {\
		if('"' == *p || '\'' == *p) { ++p; } \
		while(isspace(*p)){ ++p; }\
	} else { ret = -1; } \
}

// clean .js  and .css ext
#define CLEAN_EXT(styleField) {\
	if(styleField->styleType) {\
		styleField->styleUri->used -= 3;\
	} else {\
		styleField->styleUri->used -= 4;\
	}\
}

//字符串拼接
#define STRING_APPEND(pool, buf, str, strLen) {\
	int appenStat = 0;\
	if(NULL == buf || NULL == str || strLen <= 0) { appenStat = -1; }\
	if(0 == buf->size) { appenStat = -1; }\
	if(-1 != appenStat) {\
		if(buf->used + strLen >= buf->size) {\
			char *data = buf->ptr;\
			if(!prepare_buffer_size(pool, buf, buf->size + (strLen + BUFFER_PIECE_SIZE))) {\
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "realloc error[%d] [%s]===[%ld]", getpid(),str, buf->size);\
				appenStat = -1;\
			}\
			if(-1 != appenStat) { memcpy(buf->ptr, data, buf->used); }\
		}\
		if(-1 != appenStat) {\
			memcpy(buf->ptr + buf->used, str, strLen);\
			buf->used += strLen;\
			buf->ptr[buf->used] = ZERO_END;\
		}\
	}\
}

#define INIT_TAG_CONFIG(tagConfig, nVersion, haveNewLine, sType, haveExt) {\
	tagConfig->version = nVersion;\
	tagConfig->isNewLine = haveNewLine;\
	tagConfig->styleType = sType;\
	tagConfig->needExt = haveExt;\
}

int JS_TAG_PREFIX_LEN     = 0, JS_TAG_SUFFIX_LEN     = 0;
int JS_TAG_EXT_PREFIX_LEN = 0, JS_TAG_EXT_SUFFIX_LEN = 0;
int CSS_PREFIX_LEN        = 0, CSS_SUFFIX_LEN        = 0;
int DEBUG_MODE_LEN        = 12;

/***********global variable************/
const char ZERO_END       = '\0';
/*position char */
enum PositionEnum { TOP, HEAD, FOOTER, NONE };
const char matches[]      = {"</body>"};
int styleTableSize        = 40000;

__time_t      prevTime    = 0;
char         *appRunMode  = NULL;
server_rec   *server;

typedef struct {
	char *ptr;
	off_t used;
	off_t size;
} buffer;

typedef struct {
	buffer *prefix;
	buffer *mark;
	buffer *refTag;
	buffer *closeTag;
	char    suffix;
	/*0:表示css; 1:表示js*/
	unsigned int styleType;
} ParserTag;

ParserTag             *cssPtag;
ParserTag             *jsPtag;

typedef struct ListNode ListNode;
struct ListNode {
	ListNode   *next;
    const void *value;
};
typedef struct {
	int                   size;
	ListNode             *first;
	ListNode             *head;
} LinkedList;

typedef struct {
	unsigned int   enabled;
	char          *filterCntType;
	buffer        *oldDomains[DOMAIN_COUNTS];
	buffer        *newDomains[DOMAIN_COUNTS];
	buffer        *asyncVariableNames[DOMAIN_COUNTS];
	char          *versionFilePath;
	unsigned int   maxUrlLen;
	unsigned int   printLog;
	char          *appName;
	LinkedList    *blackList;
	LinkedList    *whiteList;
} CombineConfig;

typedef struct {
	int                 debugMode;
	buffer             *buf;
    apr_bucket_brigade *pbbOut;
} CombineCtx;

typedef struct {
	buffer               *styleUri;
	int                   async;
	buffer               *group;
	enum PositionEnum     position;
	buffer               *version;
	int                   styleType;
	int                   domainIndex;
	int          		  isCombined;
} StyleField;

typedef struct {
	buffer          *domain;
	buffer          *styleUri;
	buffer          *version;
	buffer          *group;
	off_t            async;
	int              isNewLine;
	int              styleType;
	int              needExt;
	int              debugMode;
	request_rec     *r;
} TagConfig;

typedef struct {
	off_t			 domainIndex;
	buffer          *group;
	LinkedList      *list[2];
} StyleList;

typedef struct {
	apr_pool_t   *oldPool;
	apr_pool_t   *newPool;
	apr_table_t  *styleTable;
	apr_time_t    mtime;
} StyleVersionEntry;

StyleVersionEntry svsEntry;

LinkedList *linked_list_create(apr_pool_t *pool) {
	LinkedList *list = (LinkedList *) apr_palloc(pool, sizeof(LinkedList));
	if(NULL == list) {
		return NULL;
	}
	list->first = NULL, list->head = NULL, list->size = 0;
	return list;
}

StyleField *style_field_create(apr_pool_t *pool) {
	StyleField *styleField = (StyleField *) apr_palloc(pool, sizeof(StyleField));
	if(NULL == styleField) {
		return NULL;
	}
	styleField->async = 0;
	styleField->styleUri = NULL;
	styleField->version = NULL;
	styleField->position = NONE;
	styleField->styleType = 0;
	styleField->domainIndex = 0;
	styleField->isCombined = 0;
	styleField->group = NULL;
	return styleField;
}

buffer *buffer_init_size(apr_pool_t *pool, size_t in_size) {
	buffer *buf = (buffer *) apr_palloc(pool, sizeof(buffer));
	if(NULL == buf) {
		return buf;
	}
	buf->ptr = NULL;
	buf->used = 0;
	buf->size = 0;
	if(!prepare_buffer_size(pool, buf, in_size)) {
		return NULL;
	}
	return buf;
}
int prepare_buffer_size(apr_pool_t *pool, buffer *buf, size_t in_size) {
	if(NULL == buf) {
		return 0;
	}
	int size = APR_ALIGN_DEFAULT(in_size);
	if(size < in_size) {
		return 0;
	}
	buf->ptr = (char *) apr_palloc(pool, size);
	if(NULL == buf->ptr) {
		return 0;
	}
	buf->size = size;
	return size;
}

int add(apr_pool_t *pool, LinkedList *list, void *item) {
	if (NULL == list || NULL == item) {
		return 0;
	}
	ListNode *node = (ListNode *) apr_palloc(pool, sizeof(ListNode));
	if(NULL == node) {
		return 0;
	}
	node->next = NULL;
	node->value = item;
	if (NULL == list->first) {
		list->first = node;
		list->size = 0;
	} else {
		list->head->next = node;
	}
	++list->size;
	list->head = node;
	return 1;
}

static void formatParser(apr_table_t *table, char *str, server_rec *server) {
	if (NULL == str || NULL == table) {
		return;
	}
	char *name = NULL, *value = NULL;
	char *srcStr = str;
	char *strLine = NULL;
	while (NULL != (strLine = strsep(&srcStr, "\n"))) {
		name = NULL, value = NULL;
		name = strsep(&strLine, "=");
		if (NULL == name || strlen(name) <= 1) {
			continue;
		}
		value = strLine;
		if (NULL == value || strlen(value) < 1) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
					"formatParser value error value=[%s],strLine=[%s]", value, strLine);
			continue;
		}
		apr_table_set(table, name, value);
		strLine = NULL;
	}
	return;
}

buffer *getStrVersion(request_rec *r, buffer *styleUri, CombineConfig *pConfig){
	buffer *buf =  buffer_init_size(r->pool, 64);
	if(NULL == buf) {
		return NULL;
	}
	const char *strVersion = NULL;
	if(NULL != svsEntry.styleTable) {
		strVersion = apr_table_get(svsEntry.styleTable, styleUri->ptr);
		if(NULL == strVersion) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
						"==can't getVersion:ReqURI:[%s]==>StyleURI:[%s]", r->unparsed_uri, styleUri->ptr);
		}
	}
	if(NULL == strVersion) {
		time_t tv;
		time(&tv);
		//build a dynic version in 6 minutes
		apr_snprintf(buf->ptr, buf->size, "%ld", (tv / 300));
		buf->used = strlen(buf->ptr);
		return buf;
	}
	STRING_APPEND(r->pool, buf, (char *) strVersion, strlen(strVersion));
	return buf;
}

static enum PositionEnum strToPosition(char *str, int **posLen) {
	if(NULL == str) {
		return NONE;
	}
	if (0 == strncmp(POSITION_TOP, str, 3)) {
		*posLen = (int *)3;
		return TOP;
	}
	if (0 == strncmp(POSITION_HEAD, str, 4)) {
		*posLen = (int *)4;
		return HEAD;
	}
	if (0 == strncmp(POSITION_FOOTER, str, 6)) {
		*posLen = (int *)6;
		return FOOTER;
	}
	*posLen = (int *)0;
	return NONE;
}

static void loadStyleVersion(server_rec *server, apr_pool_t *req_pool, CombineConfig *pConfig) {
	if(NULL == pConfig) {
		return;
	}
	apr_finfo_t finfo;
	apr_file_t *fd = NULL;
	apr_size_t amt;
	int intervalSecd = 20;
	time_t tm;
	if(NULL == pConfig->versionFilePath) {
		return;
	}
	time(&tm);
	if(0 != prevTime && (tm - prevTime) <= intervalSecd) {
		return;
	}
	prevTime = tm;
	apr_status_t rc = apr_stat(&finfo, pConfig->versionFilePath, APR_FINFO_MIN, req_pool);
	if(APR_SUCCESS != rc || finfo.mtime == svsEntry.mtime) {
		return;
	}
	if(5 == pConfig->printLog) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
				"==pid[%d]reload styleVersion File lastLoadTime: %lld == fmtime:%lld", getpid(), svsEntry.mtime, finfo.mtime);
	}
	//modify the mtime
	svsEntry.mtime = finfo.mtime;
	rc = apr_file_open(&fd, pConfig->versionFilePath, APR_READ | APR_BINARY | APR_XTHREAD,
					   APR_OS_DEFAULT, req_pool);
	if(rc != APR_SUCCESS) {
		apr_file_close(fd);
		return;
	}
	amt = (apr_size_t)finfo.size;
	char *versionBuf = apr_palloc(req_pool, amt + 1);
	if(NULL == versionBuf) {
		apr_file_close(fd);
		return;
	}
	rc = apr_file_read(fd, versionBuf, &amt);
	if(APR_SUCCESS == rc) {
		//create new pool
		apr_pool_t *newPool = NULL;
		apr_pool_create(&newPool, server->process->pool);
		if(NULL == newPool) {
			apr_file_close(fd);
			return;
		}
		svsEntry.newPool = newPool;
		//create new table
		apr_table_t  *newTable = apr_table_make(newPool, styleTableSize);
		formatParser(newTable, versionBuf, server);
		svsEntry.styleTable = newTable;
		// get the module runtime status(off/on)
		appRunMode = (char *)apr_table_get(newTable, pConfig->appName);
		//释放老的内存池时，先将新的内存池填上，避免线程安全问题；因为老的内存池其它地方可能还在使用
		if(NULL != svsEntry.oldPool) {
			apr_pool_destroy((apr_pool_t *) svsEntry.oldPool);
		}
		svsEntry.oldPool = newPool;
	}
	apr_file_close(fd);
	return;
}

static StyleField *tagParser(request_rec *r, CombineConfig *pConfig, ParserTag *ptag, char *maxTagBuf, off_t maxTagLen) {
	if(NULL == pConfig || NULL == ptag || NULL == maxTagBuf) {
		return NULL;
	}
	//domain find & checker
	off_t tagLen = ptag->prefix->used + ptag->refTag->used;
	if(maxTagLen <= (tagLen + 1)){
		return NULL;
	}
	buffer *domain = NULL;
	int dIndex = 0;
	char *currURL = NULL, *tmpMaxTagBuf = maxTagBuf + tagLen;
	for(dIndex = 0; dIndex < DOMAIN_COUNTS; dIndex++) {
		domain = pConfig->oldDomains[dIndex];
		if(NULL == domain) {
			continue;
		}
		char *urlStart = strstr(tmpMaxTagBuf, domain->ptr);
		if(NULL != urlStart) {
			currURL = urlStart;
			break;
		}
	}
	//对于没有域名的css/js不进行处理
	if (NULL == currURL) {
		return NULL;
	}
	//style mark checker only css
	if(0 == ptag->styleType) {
		tmpMaxTagBuf = maxTagBuf + ptag->prefix->used + 5; // +5 = {' rel='}
		if (NULL == strstr(tmpMaxTagBuf, ptag->mark->ptr)) {
			return NULL;
		}
	}
	register char ch;
	char *currURI = currURL + domain->used;
	register int groupLen = 0, hasDo = 0, stop = 0;
	//min len <script src="">
	buffer *styleUri = buffer_init_size(r->pool, (maxTagLen - domain->used - 10));
	if(NULL == styleUri) {
		return NULL;
	}
	while(*currURI) {
		ch = *(currURI++);
		switch(ch) {
		case '"':
			stop = 1;
			break;
		case '\'':
			stop = 1;
			break;
		case '>':
			stop = 1;
			break;
		case '?':
			//清除uri后面带的参数
			stop = 1;
			break;
		case '.':
			++hasDo;
			break;
		}
		if(stop) {
			break;
		}
		if(isspace(ch)) {
			continue;
		}
		styleUri->ptr[styleUri->used++] = ch;
	}
	if (!hasDo) { //没有带有.js/.css后缀
		return NULL;
	}
	styleUri->ptr[styleUri->used] = ZERO_END;
	StyleField *styleField = style_field_create(r->pool);
	if(NULL == styleField) {
		return NULL;
	}
	// get pos & async & group
	char *fieldParser = NULL;
	buffer *group = NULL;
	char *urlStart = currURL - ptag->refTag->used - 1; // -1 == ' '
	enum PositionEnum position = NONE;
	tmpMaxTagBuf = maxTagBuf + ptag->prefix->used;
	while(*tmpMaxTagBuf) {
		if(tmpMaxTagBuf == urlStart) {
			tmpMaxTagBuf += (styleUri->used + ptag->refTag->used + domain->used) + 2; // 2 == \"\"
		}
		if(isspace(*tmpMaxTagBuf)) {
			fieldParser = tmpMaxTagBuf;
			fieldParser++;
			switch(*fieldParser) {
			case 'p':
				if(0 == memcmp(++fieldParser, "os", 2)) {
					tmpMaxTagBuf += 4; // pos
					int ret = 0;
					FIELD_PARSE(tmpMaxTagBuf, ret);
					if(ret == -1) {
						continue;
					}
					int *posLen = (int *) 0;
					position = strToPosition((tmpMaxTagBuf), &posLen);
					tmpMaxTagBuf += (int) posLen;
					continue;
				}
				break;
			case 'a':
				if(0 == memcmp(++fieldParser, "sync", 4)) {
					tmpMaxTagBuf += 6; // async
					int ret = 0;
					FIELD_PARSE(tmpMaxTagBuf, ret);
					if(ret == -1) {
						continue;
					}
					if(0 == memcmp(tmpMaxTagBuf, "true", 4)) {
						styleField->async = 1;
						tmpMaxTagBuf += 4;
						continue;
					}
				}
				break;
			case 'g':
				if(0 == memcmp(++fieldParser, "roup", 4)) {
					tmpMaxTagBuf += 6;// group
					int ret = 0;
					FIELD_PARSE(tmpMaxTagBuf, ret);
					if(ret == -1) {
						continue;
					}
					groupLen = 0, stop = 0;
					char *s = tmpMaxTagBuf;
					while(*s) {
						switch(*s) {
						case '\'':
							stop = 1;
							break;
						case '"':
							stop = 1;
							break;
						case ' ':
							stop = 1;
							break;
						}
						if(stop) {
							break;
						}
						++s;
						++groupLen;
					}
					if(groupLen) {
						group = buffer_init_size(r->pool, groupLen + 8);
						STRING_APPEND(r->pool, group, tmpMaxTagBuf, groupLen);
						tmpMaxTagBuf += groupLen;
						continue;
					}
				}
				break;
			}
		}
		tmpMaxTagBuf++;
	}
	styleField->domainIndex = dIndex;
	styleField->styleType = ptag->styleType;
	styleField->position = position;
	styleField->styleUri = styleUri;
	if(NULL == group) {
		//group和pos 都为空时，保持原地不变
		if(NONE == position) {
			styleField->async = 0;
			return styleField;
		}
		//当只有async属性时，保证原地不变
		if(styleField->async) {
			styleField->async = 0;
			styleField->position = NONE;
			return styleField;
		}
	} else {
		if(NONE == position && !styleField->async) {
			styleField->group = NULL;
			return styleField;
		}
	}
	//pos
	char g;
	if(NONE != position && NULL == group) {
		//create default group
		group = buffer_init_size(r->pool, 24);
		STRING_APPEND(r->pool, group, "_def_group_name_", 16);
		g = '0' + (int) position;
	} else {
		g = '0' + styleField->async;
	}
	group->ptr[group->used++] = g;
	group->ptr[group->used] = ZERO_END;
	styleField->group = group;
	return styleField;
}

static void makeVersion(apr_pool_t *pool, buffer *buf, buffer *versionBuf) {
	STRING_APPEND(pool, buf, "?_v=", 4);
	if(NULL != versionBuf) {
		if(versionBuf->used > 32) {
			int i = 0;
			char md5[3];
			unsigned char digest[16];
			apr_md5(digest, (const void *)versionBuf->ptr, versionBuf->used);
			BUFFER_CLEAN(versionBuf);
			for(i = 0; i < 16; i++) {
				apr_snprintf(md5, 3, "%02x", digest[i]);
				STRING_APPEND(pool, versionBuf, md5, 2);
			}
		}
		STRING_APPEND(pool, buf, versionBuf->ptr, versionBuf->used);
	}
}

static void addExtStyle(buffer *destBuf, TagConfig *tagConfig) {
	if(!destBuf ||!tagConfig || !tagConfig->styleUri || !tagConfig->styleUri->used) {
		return;
	}
	if (tagConfig->isNewLine) {
		STRING_APPEND(tagConfig->r->pool, destBuf, "\n", 1);
	}
	if (tagConfig->styleType) {
		STRING_APPEND(tagConfig->r->pool, destBuf, JS_TAG_EXT_PREFIX_TXT, JS_TAG_EXT_PREFIX_LEN);
	} else {
		STRING_APPEND(tagConfig->r->pool, destBuf, CSS_PREFIX_TXT, CSS_PREFIX_LEN);
	}
	STRING_APPEND(tagConfig->r->pool, destBuf, tagConfig->domain->ptr, tagConfig->domain->used);
	STRING_APPEND(tagConfig->r->pool, destBuf, tagConfig->styleUri->ptr, tagConfig->styleUri->used);
	//append ext
	if(tagConfig->needExt) {
		if (tagConfig->styleType) {
			STRING_APPEND(tagConfig->r->pool, destBuf, EXT_JS, 3);
		} else {
			STRING_APPEND(tagConfig->r->pool, destBuf, EXT_CSS, 4);
		}
	}
	//append version
	makeVersion(tagConfig->r->pool, destBuf, tagConfig->version);
	//append the version ext
	if (tagConfig->styleType) {
		STRING_APPEND(tagConfig->r->pool, destBuf, EXT_JS, 3);
	} else {
		STRING_APPEND(tagConfig->r->pool, destBuf, EXT_CSS, 4);
	}
	if(2 == tagConfig->debugMode) {
		if(tagConfig->group) {
			STRING_APPEND(tagConfig->r->pool, destBuf, "\" group=\"", 9);
			STRING_APPEND(tagConfig->r->pool, destBuf, tagConfig->group->ptr, tagConfig->group->used);
		}
	}
	if (tagConfig->styleType) {
		STRING_APPEND(tagConfig->r->pool, destBuf, JS_TAG_EXT_SUFFIX_TXT, JS_TAG_EXT_SUFFIX_LEN);
	} else {
		STRING_APPEND(tagConfig->r->pool, destBuf, CSS_SUFFIX_TXT, CSS_SUFFIX_LEN);
	}
	return;
}

/**
 * 将js/css列表合并成一个url,并放到相应的位置上去
 */
static void combineStyles(CombineConfig *pConfig, TagConfig *tagConfig, LinkedList *styleList,
								buffer *combinedStyleBuf[], buffer *tmpUriBuf, buffer *versionBuf) {
	if(NULL == styleList) {
		return;
	}
	StyleField *styleField = NULL;
	ListNode *node = styleList->first;
	if(NULL == node || NULL == (styleField = (StyleField *)node->value)) {
		return;
	}
	register buffer *combinedBuf = NULL;
	combinedBuf = combinedStyleBuf[styleField->position];
	int count = 0;
	tagConfig->styleType = styleField->styleType;
	tagConfig->domain    = pConfig->newDomains[styleField->domainIndex];
	tagConfig->group     = styleField->group;
	INIT_TAG_CONFIG(tagConfig, versionBuf, 1, tagConfig->styleType, 1);
	while(NULL != node) {
		styleField = (StyleField *) node->value;
		if (count) {
			STRING_APPEND(tagConfig->r->pool, tmpUriBuf, URI_SEPARATOR, 1);
		} else {
			count++;
		}
		//url拼接在一起的长度超过配置的长度，则需要分成多个请求来处理。(域名+uri+下一个uri +版本长度 + 参数名称长度[版本长度36 + 参数名称长度4])
		int urlLen = (tagConfig->domain->used + tmpUriBuf->used + styleField->styleUri->used);
		if (urlLen + 40  >= pConfig->maxUrlLen) {
			//将合并的url最后一个|字符去除
			tmpUriBuf->ptr[--tmpUriBuf->used] = ZERO_END;
			tagConfig->styleUri = tmpUriBuf;
			addExtStyle(combinedBuf, tagConfig);
			BUFFER_CLEAN(versionBuf);
			BUFFER_CLEAN(tmpUriBuf);
		}
		CLEAN_EXT(styleField);
		STRING_APPEND(tagConfig->r->pool, tmpUriBuf, styleField->styleUri->ptr, styleField->styleUri->used);
		STRING_APPEND(tagConfig->r->pool, versionBuf, styleField->version->ptr, styleField->version->used);
		node = node->next;
	}
	tagConfig->styleUri = tmpUriBuf;
	addExtStyle(combinedBuf, tagConfig);
	return;
}

static void addAsyncStyle(apr_pool_t *pool, buffer *buf, buffer *versionBuf, int styleType) {
	if (styleType) {
		STRING_APPEND(pool, buf, EXT_JS, 3);
	} else {
		STRING_APPEND(pool, buf, EXT_CSS, 4);
	}
	makeVersion(pool, buf, versionBuf);
	if (styleType) {
		STRING_APPEND(pool, buf, EXT_JS, 3);
	} else {
		STRING_APPEND(pool, buf, EXT_CSS, 4);
	}
}

//var tt="{"group1":{"css":["http://xx/a1.css"],"js":["http://xx/a1.js"]},"group2":{"css":[],"js":["http://xx/a2.js"]}}"
static void combineStylesAsync(request_rec *r, CombineConfig *pConfig, StyleList *styleList,
								buffer *combinedStyleBuf[], buffer *tmpUriBuf, buffer *versionBuf) {
	if(NULL == styleList || NULL == pConfig || NULL == combinedStyleBuf) {
		return;
	}
	buffer *headBuf = combinedStyleBuf[HEAD];
	headBuf->ptr[headBuf->used++] = '"';
	STRING_APPEND(r->pool, headBuf, styleList->group->ptr, styleList->group->used - 1);
	STRING_APPEND(r->pool, headBuf, "\":{\"css\"", 8);
	unsigned int i = 0, count = 0;
	for(i = 0; i < 2; i++) {
		LinkedList *list = styleList->list[i];
		if(NULL == list || !list->size) {
			if(i) {
				STRING_APPEND(r->pool, headBuf, "\"js\":[]", 7); // "js":[]
			} else {
				STRING_APPEND(r->pool, headBuf, ":[],", 4); // "css":[],
			}
			continue;
		}
		if(i) {
			STRING_APPEND(r->pool, headBuf, "\"js\"", 4);
		}
		BUFFER_CLEAN(tmpUriBuf);
		BUFFER_CLEAN(versionBuf);
		STRING_APPEND(r->pool, headBuf, ":[", 2);
		ListNode *node = list->first;
		StyleField *styleField = (StyleField *) node->value;
		buffer *domain = pConfig->newDomains[styleField->domainIndex];
		STRING_APPEND(r->pool, tmpUriBuf, domain->ptr, domain->used);
		for(count = 0; NULL != node; count++) {
			styleField = (StyleField *) node->value;
			if(count) {
				STRING_APPEND(r->pool, tmpUriBuf, URI_SEPARATOR, 1);
			}
			//url拼接在一起的长度超过配置的长度，则需要分成多个请求来处理。(域名+uri+下一个uri +版本长度 + 参数名称长度[版本长度36 + 参数名称长度4])
			int urlLen = (domain->used + tmpUriBuf->used + styleField->styleUri->used);
			if (urlLen + 40  >= pConfig->maxUrlLen) {
				//将合并的url最后一个|字符去除
				tmpUriBuf->ptr[--tmpUriBuf->used] = ZERO_END;
				addAsyncStyle(r->pool, tmpUriBuf, versionBuf, i);
				//copy to head
				STRING_APPEND(r->pool, headBuf, "\"", 1);
				STRING_APPEND(r->pool, headBuf, tmpUriBuf->ptr, tmpUriBuf->used);
				BUFFER_CLEAN(tmpUriBuf);
				BUFFER_CLEAN(versionBuf);
				//if not the end
				if(list->size >= count + 1) {
					STRING_APPEND(r->pool, headBuf, "\",", 2);
					STRING_APPEND(r->pool, tmpUriBuf, domain->ptr, domain->used);
				}
			}
			CLEAN_EXT(styleField);
			STRING_APPEND(r->pool, tmpUriBuf, styleField->styleUri->ptr, styleField->styleUri->used);
			STRING_APPEND(r->pool, versionBuf, styleField->version->ptr, styleField->version->used);
			node = node->next;
		}
		if(tmpUriBuf->used) {
			STRING_APPEND(r->pool, headBuf, "\"", 1);
			addAsyncStyle(r->pool, tmpUriBuf, versionBuf, i);
		}
		STRING_APPEND(r->pool, headBuf, tmpUriBuf->ptr, tmpUriBuf->used);
		if (i) {
			STRING_APPEND(r->pool, headBuf, "\"]", 2);
		} else {
			STRING_APPEND(r->pool, headBuf, "\"],", 3);
		}
	}
	STRING_APPEND(r->pool, headBuf, "},", 2);
}

/**
 * 用于开发时，打开调试模块调用。将js/css的位置做移动，但不做合并
 */
static void combineStylesDebug(CombineConfig *pConfig, TagConfig *tagConfig, LinkedList *fullStyleList, buffer *combinedStyleBuf[]) {
	ListNode *styleNode = NULL;
	if(NULL == fullStyleList || NULL == (styleNode = fullStyleList->first)) {
		return;
	}
	register buffer *combinedBuf = NULL;
	register int i = 0;
	while(NULL != styleNode) {
		StyleList *styleList = (StyleList *) styleNode->value;
		for(i = 0; i < 2; i++) {
			ListNode *node = NULL;
			LinkedList *list = styleList->list[i];
			if(NULL == list || NULL == (node = list->first)) {
				continue;
			}
			StyleField *styleField = (StyleField *)node->value;
			if(NULL == styleField) {
				continue;
			}
			if(NONE == styleField->position || styleField->async) {
				combinedBuf = combinedStyleBuf[FOOTER];
			} else {
				combinedBuf = combinedStyleBuf[styleField->position];
			}
			tagConfig->styleType = styleField->styleType;
			tagConfig->domain    = pConfig->newDomains[styleField->domainIndex];
			INIT_TAG_CONFIG(tagConfig, NULL, 1, tagConfig->styleType, 0);
			while(NULL != node) {
				styleField = (StyleField *) node->value;
				tagConfig->version  = styleField->version;
				tagConfig->styleUri = styleField->styleUri;
				tagConfig->group    = styleField->group;
				addExtStyle(combinedBuf, tagConfig);
				node = node->next;
			}
		}
		styleNode = (ListNode *) styleNode->next;
	}
	return;
}
/**
 * style去重，对于异步style去重必须是当整个页面都解析完之后再进行，因为一些异步的js写在页面开始的地方.
 * 页面实际页面上非异步的style还没有解析到，导致无法与页面上的style去重效果
 *
 * key的生成策略，
 * 非异步为：域名下标+URI
 * 异步为：域名下标+URI+组名
 */
static int isRepeat(request_rec *r, apr_hash_t *duplicats, StyleField *styleField) {
	if(NULL == duplicats) {
		return 0;
	}
	int len = styleField->styleUri->used;
	//make a key
	buffer *key = buffer_init_size(r->pool, len + 26);
	if(NULL == key) {
		return 0;
	}
	//add domain area
	key->ptr[key->used++] = '0' + styleField->domainIndex;
	STRING_APPEND(r->pool, key, styleField->styleUri->ptr, styleField->styleUri->used);
	if(NULL != apr_hash_get(duplicats, key->ptr, key->used)) {
		//if uri has exsit then skiping it
		return 1;
	}
	if(styleField->async) {
		//add group area
		STRING_APPEND(r->pool, key, styleField->group->ptr, styleField->group->used);
		if(NULL != apr_hash_get(duplicats, key->ptr, key->used)) {
			//if uri has exsit then skiping it
			return 1;
		}
	}
	apr_hash_set(duplicats, key->ptr, key->used, "1");
	return 0;
}

static void addBucket(conn_rec *c, apr_bucket_brigade *pbbkOut, char *str, int strLen) {
	if(NULL == str || strLen <= 0) {
		return;
	}
	apr_bucket *pbktOut = NULL;
	pbktOut = apr_bucket_heap_create(str, strLen, NULL, c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(pbbkOut, pbktOut);
	return;
}

static void stringSplit(apr_pool_t *pool, int arrayLen, buffer *arrays[], char *string, char seperator) {
	if(NULL == string || NULL == arrays) {
		return;
	}
	int i = 0;
	char *ts = string;
	for(i = 0; i < arrayLen; i++) {
		if(NULL == ts) {
			continue;
		}
		char *domain = strchr(ts, seperator);
		buffer *buf = buffer_init_size(pool, 64);
		if(NULL == buf) {
			continue;
		}
		if(NULL != domain) {
			STRING_APPEND(pool, buf, ts, (domain - ts));
			arrays[i] = buf;
			ts = ++domain;//move char of ';'
		} else {
			if(NULL == ts) {
				break;
			}
			int len = strlen(ts);
			if(len > 0) {
				STRING_APPEND(pool, buf, ts, len);
				arrays[i] = buf;
				ts += len;
			}
			break;
		}
	}
}

/**
 *反向查找字符串所在下标，并返回下标索引
 */
static int rStrSearch(const char *str, unsigned int slen, const char matches[], unsigned int mlen) {
	int i = 0, mindex = --mlen;
	for(i = --slen; i >= 0; i--) {
		if(mindex < 0) {
			return ++i;
		}
		if(str[i] == matches[mindex]) {
			mindex --;
			continue;
		}
		if(mindex < mlen) {
			mindex = mlen;
			++i;
		}
	}
	return -1;
}

static void resetHtml(conn_rec *c, apr_bucket_brigade *pbbkOut,
						buffer *combinedStyleBuf[], buffer *buf) {
	if(NULL== buf || NULL == buf->ptr) {
		return;
	}
	char *sourceHtml = buf->ptr;
	int index = 0;
	char *headIndex = strstr(sourceHtml, "</head>");
	if(NULL != headIndex) {
		addBucket(c, pbbkOut, sourceHtml, (index = headIndex - sourceHtml));
	}
	addBucket(c, pbbkOut, combinedStyleBuf[TOP]->ptr, combinedStyleBuf[TOP]->used);
	addBucket(c, pbbkOut, combinedStyleBuf[HEAD]->ptr, combinedStyleBuf[HEAD]->used);

	char *endHtmlIndex = (buf->ptr + buf->used);
	char *middleIndex = (sourceHtml + index);
	//因为</body>在整个dom的后部分，从后往前找更近一些
	int r = rStrSearch(middleIndex, buf->used - index, matches, 7);
	char *footerIndex = NULL;
	if(r != -1) {
		footerIndex = middleIndex + r;
	}
	if(NULL != footerIndex) {
		addBucket(c, pbbkOut, middleIndex, (footerIndex - middleIndex));
		addBucket(c, pbbkOut, combinedStyleBuf[FOOTER]->ptr, combinedStyleBuf[FOOTER]->used);
		addBucket(c, pbbkOut, footerIndex, (endHtmlIndex - footerIndex));
	} else {
		addBucket(c, pbbkOut, middleIndex, (endHtmlIndex - middleIndex));
		addBucket(c, pbbkOut, combinedStyleBuf[FOOTER]->ptr, combinedStyleBuf[FOOTER]->used);
	}
	return;
}

static inline char *strSearch(const char *str1, int **matchedType, int **isExpression) {
	register char *cp = (char *) str1;
	register char *s1 = NULL;

	register int r = -1;
	while (*cp) {
		//compare first
		if ('<' == *cp) {
			s1 = cp;
			s1++;
			switch (*s1) {
				case 's': //script
					r = memcmp("cript", ++s1, 5);
					*matchedType = (int *) 1; //js
					break;
				case 'l': //link
					r = memcmp("ink", ++s1, 3);
					*matchedType = (int *) 0; //css
					break;
				case '!': //process:<!--[if IE]> <!--[if IE 5.5]>
					if (0 == memcmp("--", ++s1, 2)) {
						if ('[' == *(s1 + 2)) {
							cp += 12; //skip "<!--[if IE]>"
							*isExpression = (int *) 1;
							continue;
						}
						//skip comments "<!--xxxxx -->"
						for (; *cp != '\0'; cp++) {
							if (0 == memcmp(cp, "-->", 3)) {
								cp += 3; // skip "-->"
								break;
							}
						}
					} else if('[' == *s1) {
						//skip  "<![endif]-->"
						cp += 12;
						*isExpression = (int *) 0;
					}
					break;
				case 't'://if is textarea then skip over
					if(0 == memcmp("extarea", ++s1, 7)) {
						cp += 10;//<textarea>
						while (*cp) {
							if(0 == memcmp("</textarea>", cp, 11)) {
								cp += 11;
								break;
							}
							++cp;
						}
					}
					break;
				case 'T':
					if (0 == memcmp("EXTAREA", ++s1, 7)) {
						cp += 10; //<textarea>
						while (*cp) {
							if(0 == memcmp("</TEXTAREA>", cp, 11)) {
								cp += 11;
								break;
							}
							++cp;
						}
					}
					break;
				default:
					if ('<' != *s1) {
						cp += 3; //skip min tag len  "<a>"
					}
					break;
			}
			if (r == 0) {
				return (cp);
			}
		}
		cp++;
	}
	*matchedType = NULL;
	return (NULL);
}

static int htmlParser(request_rec *r, buffer *combinedStyleBuf[], buffer *destBuf, CombineConfig *pConfig, CombineCtx *ctx) {
	char *maxTagBuf      = (char *) apr_palloc(r->pool, MAX_STYLE_TAG_LEN);
	if(NULL == maxTagBuf) {
		return 0;
	}
	TagConfig *tagConfig = (TagConfig *) apr_palloc(r->pool, sizeof(TagConfig));
	if(NULL == tagConfig) {
		return 0;
	}
	tagConfig->r         = r;
	tagConfig->async     = 0;
	tagConfig->debugMode = 0;
	tagConfig->domain    = NULL;
	tagConfig->group     = NULL;
	tagConfig->styleUri  = NULL;
	INIT_TAG_CONFIG(tagConfig, NULL, 0, 0, 0);
	LinkedList *asyncGroups[DOMAIN_COUNTS];
	apr_hash_t *domains[DOMAIN_COUNTS];
	LinkedList *syncGroupList                  = linked_list_create(r->pool);
	apr_hash_t *duplicates                     = apr_hash_make(r->pool);
	int maxTagSize                             = MAX_STYLE_TAG_LEN - 10;
	register ParserTag *ptag                   = NULL;
	int           *matchedType = 0, *isExpression = 0;
	register char *curPoint    = NULL, *tmpPoint  = NULL;
	register int   i = 0, k = 0, isProcessed = 0, combinBufSize = 100;
	for(i = 0; i < DOMAIN_COUNTS; i++) {
		domains[i] = NULL;
		asyncGroups[i] = NULL;
	}
	char *subHtml = ctx->buf->ptr;
	while (NULL != (curPoint = strSearch(subHtml, &matchedType, &isExpression))) {
		tmpPoint = curPoint;
		STRING_APPEND(r->pool, destBuf, subHtml, curPoint - subHtml);
		//此时表示当前是js文件，需要使用js的标签来处理
		ptag = (1 == (int) matchedType ? jsPtag:cssPtag);
		//1 skip&filter
		//2 getField {getType, getPos, getAsync, getGroup}
		char ch = 0, suffixChar = ptag->suffix;
		int spaceChar = 0 , k = 0;
		for (i = 0; ((ch = *(curPoint++)) != suffixChar) && i < maxTagSize; i++) {
			//换行直接跳过
			if('\n' == ch || '\r' == ch) {
				continue;
			}
			if('\t' == ch) { // change \t to space
				ch = ' ';
			}
			if(isspace(ch)) {
				if(spaceChar) {
					spaceChar = 1;
					++maxTagSize;
					continue;
				}
				spaceChar = 1;
			} else {
				spaceChar = 0;
			}
			maxTagBuf[k++] = ch;
		}
		maxTagBuf[k++] = suffixChar;
		maxTagBuf[k] = ZERO_END;
		if (ptag->styleType) {
			/**
			 * js 的特殊处理，需要将结束符找出来，</script>
			 * 结束符中间可能有空格或制表符，所以忽略这些
			 * 如果没有结束符，将不进行处理.
			 */
			//clean \r\n \n \t & empty char
			TRIM_RIGHT(curPoint);
			if (memcmp(ptag->closeTag->ptr, curPoint, ptag->closeTag->used) != 0) {
				//找不到结束的</script>
				STRING_APPEND(r->pool, destBuf, maxTagBuf, k);
				subHtml = curPoint;
				continue;
			}
			curPoint += ptag->closeTag->used;
		}
		StyleField *styleField = tagParser(r, pConfig, ptag, maxTagBuf, i);
		if (NULL == styleField) {
			STRING_APPEND(r->pool, destBuf, maxTagBuf, k);
			if(ptag->styleType) {
				STRING_APPEND(r->pool, destBuf, ptag->closeTag->ptr, ptag->closeTag->used);
			}
			subHtml = curPoint;
			continue;
		}
		isProcessed = 1;
		tagConfig->domain = pConfig->newDomains[styleField->domainIndex];
		tagConfig->styleUri = styleField->styleUri;
		tagConfig->async = styleField->async;
		tagConfig->group = styleField->group;
		//process expression <!--[if IE]> for js/css CAN'T clean duplicate
		if(((int) isExpression)) {
			//拿uri去获取版本号
			buffer *nversion = getStrVersion(r, styleField->styleUri, pConfig);
			styleField->version = nversion;
			INIT_TAG_CONFIG(tagConfig, nversion, 0, ptag->styleType, 0);
			addExtStyle(destBuf, tagConfig);
			subHtml = curPoint;
			continue;
		}
		//clean duplicate
		if(!styleField->async && isRepeat(r, duplicates, styleField)) {
			subHtml = curPoint;
			continue;
		}
		//拿uri去获取版本号
		buffer *nversion = getStrVersion(r, styleField->styleUri, pConfig);
		styleField->version = nversion;
		INIT_TAG_CONFIG(tagConfig, nversion, 0, ptag->styleType, 0);
		//当没有使用异步并且又没有设置位置则保持原位不动
		if(0 == styleField->async && NONE == styleField->position) {
			addExtStyle(destBuf, tagConfig);
			subHtml = curPoint;
			continue;
		}
		StyleList *styleList = NULL;
		apr_hash_t *styleMap = domains[styleField->domainIndex];
		if(NULL == styleMap) {
			styleMap = apr_hash_make(r->pool);
			domains[styleField->domainIndex] = styleMap;
		} else {
			styleList = apr_hash_get(styleMap, styleField->group->ptr, styleField->group->used);
		}
		if(NULL != styleList && NULL != styleList->list[styleField->styleType]) {
			add(r->pool, styleList->list[styleField->styleType], styleField);
		} else {
			LinkedList *list = linked_list_create(r->pool);
			if(NULL == list) {
				addExtStyle(destBuf, tagConfig);
				subHtml = curPoint;
				continue;
			}
			if(NULL == styleList) {
				styleList = (StyleList *) apr_palloc(r->pool, sizeof(StyleList));
				if(NULL == styleList) {
					addExtStyle(destBuf, tagConfig);
					subHtml = curPoint;
					continue;
				}
				styleList->list[0] = NULL, styleList->list[1] = NULL;
				/**
				 * 将所有group按出现的顺序放入一个list；合并style时按这个顺序输出到页面上。
				 */
				if(styleField->async) {
					LinkedList *asyncList = asyncGroups[styleField->domainIndex];
					if(NULL == asyncList) {
						asyncGroups[styleField->domainIndex] = asyncList = linked_list_create(r->pool);
					}
					add(r->pool, asyncList, styleList);
				} else {
					add(r->pool, syncGroupList, styleList);
				}
			}
			add(r->pool, list, styleField);
			styleList->domainIndex = styleField->domainIndex;
			styleList->group = styleField->group;
			styleList->list[styleField->styleType] = list;
			/**
			 * 通过使用hash来控制每个group对应一个list
			 */
			apr_hash_set(styleMap, styleField->group->ptr, styleField->group->used, styleList);
		}
		//clean \r\n \n \t & empty char
		TRIM_RIGHT(curPoint);
		subHtml = curPoint;
	}
	if(isProcessed) {
		//append the tail html
		int subHtmlLen = (ctx->buf->ptr + ctx->buf->used) - subHtml;
		STRING_APPEND(r->pool, destBuf, subHtml, subHtmlLen);

		//async clean duplicates
		ListNode *node = NULL;
		for(i = 0; i < DOMAIN_COUNTS; i++) {
			LinkedList *asyncList = asyncGroups[i];
			if(NULL == asyncList) {
				continue;
			}
			node = asyncList->first;
			while(NULL != node) {
				StyleList *styleList = (StyleList *) node->value;
				for(k = 0; k < 2; k++) {
					LinkedList *list = styleList->list[k];
					if(NULL == list || !list->size) {
						continue;
					}
					ListNode *parentNode = NULL;
					ListNode *styleNode = (ListNode *) list->first;
					while(NULL != styleNode) {
						StyleField *styleField = (StyleField *) styleNode->value;
						if(isRepeat(r, duplicates, styleField)) {
							//if exeist delete this node
							if(NULL == parentNode) {
								list->first = styleNode->next;
							} else {
								parentNode->next = styleNode->next;
							}
							styleNode = styleNode->next;
							--list->size;
							continue;
						}
						parentNode = styleNode;
						styleNode = styleNode->next;
					}
				}
				node = node->next;
			}
		}
		if(0 == ctx->debugMode) {
			buffer *versionBuf = buffer_init_size(r->pool, 1000);
			if(!versionBuf) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "if(isProcessed){has Error}:[%s]", r->unparsed_uri);
				return 0;
			}
			buffer *tmpUriBuf = buffer_init_size(r->pool, pConfig->maxUrlLen + 50);
			if(!tmpUriBuf) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "if(isProcessed){has Error}:[%s]", r->unparsed_uri);
				return 0;
			}
			int addScriptPic = 0;
			for(i = 0; i < DOMAIN_COUNTS; i++) {
				LinkedList *asyncList = asyncGroups[i];
				if(NULL == asyncList) {
					continue;
				}
				if(0 == addScriptPic) {
					STRING_APPEND(r->pool, combinedStyleBuf[HEAD], "\n<script type=\"text/javascript\">\n", 33);
				}
				++addScriptPic;
				//1、先合并需要异步加载的js/css
				if(NULL != (node = asyncList->first)) {
					StyleList *styleList = (StyleList *) node->value;
					STRING_APPEND(r->pool, combinedStyleBuf[HEAD], "var ", 4);
					buffer *variableName = pConfig->asyncVariableNames[styleList->domainIndex];
					STRING_APPEND(r->pool, combinedStyleBuf[HEAD], variableName->ptr, variableName->used);
					STRING_APPEND(r->pool, combinedStyleBuf[HEAD], "={", 2);
					while(NULL != node) {
						styleList = (StyleList *) node->value;
						combineStylesAsync(r, pConfig, styleList, combinedStyleBuf, tmpUriBuf, versionBuf);
						node = (ListNode *) node->next;
					}
					--combinedStyleBuf[HEAD]->used;
					STRING_APPEND(r->pool, combinedStyleBuf[HEAD], "};\n", 3);
				}
			}
			if(addScriptPic) {
				STRING_APPEND(r->pool, combinedStyleBuf[HEAD], "</script>\n", 10);
			}
			//2、将外部引入的js/css进行合并
			if(NULL != syncGroupList && NULL != (node = syncGroupList->first)) {
				while(NULL != node) {
					StyleList *styleList = (StyleList *) node->value;
					for(i = 0; i < 2; i++) {
						LinkedList *list = styleList->list[i];
						if(NULL == list) {
							continue;
						}
						BUFFER_CLEAN(tmpUriBuf);
						BUFFER_CLEAN(versionBuf);
						combineStyles(pConfig, tagConfig, list, combinedStyleBuf, tmpUriBuf, versionBuf);
					}
					node = (ListNode *) node->next;
				}
			}
		} else if(2 == ctx->debugMode){
			//debug mode 2
			tagConfig->debugMode = ctx->debugMode;
			combineStylesDebug(pConfig, tagConfig, syncGroupList, combinedStyleBuf);
			for(i = 0; i < DOMAIN_COUNTS; i++) {
				LinkedList *asyncList = asyncGroups[i];
				if(NULL != asyncList) {
					combineStylesDebug(pConfig, tagConfig, asyncList, combinedStyleBuf);
				}
			}
		}
	}
	if(0 != destBuf->size) {
		destBuf->ptr[destBuf->used] = ZERO_END;
	}
	return isProcessed;
}

static int contentTypeMatch(request_rec *r, char *contentType) {
	if(NULL == contentType) {
		return 0;
	}
	if(r->content_type && r->content_type[0]) {
		char *cntType = apr_pstrdup(r->pool, r->content_type);
		char *pt = cntType;
		for(; pt && *pt; ++pt) {
			if ((';' != *pt) && (' ' != *pt)) {
				*pt = tolower(*pt);
				continue;
			}
			*pt = ';';
			*(++pt) = ZERO_END;
			break;
		}
		return NULL != strstr(contentType, cntType);
	}
	return 0;
}
static int uriFilter(request_rec *r, LinkedList *list) {
	if(NULL == list || NULL == list->first) {
		return 0;
	}
	if(NULL == r->uri) {
		return 0;
	}
	ListNode *node = list->first;
	for(; NULL != node; node = node->next) {
		ap_regex_t *regex = (ap_regex_t *) node->value;
		if (AP_REG_NOMATCH == ap_regexec(regex, r->uri, 0, NULL, 0)) {
			continue;
		} else {
			return 1;
		}
	}
	return 0;
}

static void *configServerCreate(apr_pool_t *p, server_rec *s) {
	CombineConfig *pConfig = apr_palloc(p, sizeof(CombineConfig));
	if(NULL == pConfig) {
		return NULL;
	}
	JS_TAG_EXT_PREFIX_LEN = strlen(JS_TAG_EXT_PREFIX_TXT);
	JS_TAG_EXT_SUFFIX_LEN = strlen(JS_TAG_EXT_SUFFIX_TXT);

	JS_TAG_PREFIX_LEN = strlen(JS_TAG_PREFIX_TXT);
	JS_TAG_SUFFIX_LEN = strlen(JS_TAG_SUFFIX_TXT);

	CSS_PREFIX_LEN = strlen(CSS_PREFIX_TXT);
	CSS_SUFFIX_LEN = strlen(CSS_SUFFIX_TXT);
	svsEntry.mtime = 0; svsEntry.newPool = NULL; svsEntry.oldPool = NULL; svsEntry.styleTable = NULL;

	pConfig->enabled = 0;
	pConfig->printLog = 0;
	pConfig->filterCntType = NULL;
	pConfig->appName = NULL;
	int i = 0;
	for(i = 0; i < DOMAIN_COUNTS; i++) {
		pConfig->oldDomains[i] = NULL;
		pConfig->newDomains[i] = NULL;
	}

	char *variableNames = "styleDomain0;styleDomain1;";
	stringSplit(p, DOMAIN_COUNTS, pConfig->asyncVariableNames, variableNames, ';');

	pConfig->blackList = linked_list_create(p);
	pConfig->whiteList = linked_list_create(p);
	/**
	 * see http://support.microsoft.com/kb/208427/EN-US
	 * default len for ie 2083 char
	 */
	pConfig->maxUrlLen = 1500;

	jsPtag = apr_palloc(p, sizeof(ParserTag));
	if(NULL == jsPtag) {
		return NULL;
	}
	cssPtag = apr_palloc(p, sizeof(ParserTag));
	if(NULL == cssPtag) {
		return NULL;
	}
	// js config
	buffer *jsPrefix = apr_palloc(p, sizeof(buffer));
	if(NULL == jsPrefix) {
		return NULL;
	}
	jsPrefix->ptr = "<script";
	jsPrefix->used = strlen(jsPrefix->ptr);
	jsPrefix->size = jsPrefix->used;

	buffer *jsCloseTag  = apr_palloc(p, sizeof(buffer));
	if(NULL == jsCloseTag) {
		return NULL;
	}
	jsCloseTag->ptr = "</script>";
	jsCloseTag->used = strlen(jsCloseTag->ptr);
	jsCloseTag->size = jsCloseTag->used;

	buffer *jsMark  = apr_palloc(p, sizeof(buffer));
	if(NULL == jsMark) {
		return NULL;
	}
	jsMark->ptr = "src";
	jsMark->used = strlen(jsMark->ptr);
	jsMark->size = jsMark->used;

	buffer *jsRefTag  = apr_palloc(p, sizeof(buffer));
	if(NULL == jsRefTag) {
		return NULL;
	}
	jsRefTag->ptr = " src=";
	jsRefTag->used = strlen(jsRefTag->ptr);
	jsRefTag->size = jsRefTag->used;

	jsPtag->prefix = jsPrefix;
	jsPtag->mark = jsMark;
	jsPtag->refTag = jsRefTag;
	jsPtag->suffix = '>';
	jsPtag->closeTag = jsCloseTag;
	jsPtag->styleType = 1;

	//css config
	buffer *cssPrefix = apr_palloc(p, sizeof(buffer));
	if(NULL == cssPrefix) {
		return NULL;
	}
	cssPrefix->ptr = "<link";
	cssPrefix->used = strlen(cssPrefix->ptr);
	cssPrefix->size = cssPrefix->used;

	buffer *cssRefTag  = apr_palloc(p, sizeof(buffer));
	if(NULL == cssRefTag) {
		return NULL;
	}
	cssRefTag->ptr = " href=";
	cssRefTag->used = strlen(cssRefTag->ptr);
	cssRefTag->size = cssRefTag->used;

	buffer *cssCloseTag  = apr_palloc(p, sizeof(buffer));
	if(NULL == cssCloseTag) {
		return NULL;
	}
	cssCloseTag->ptr = ">";
	cssCloseTag->used = strlen(cssCloseTag->ptr);
	cssCloseTag->size = cssCloseTag->used;

	buffer *cssMark  = apr_palloc(p, sizeof(buffer));
	if(NULL == cssMark) {
		return NULL;
	}
	cssMark->ptr = "stylesheet";
	cssMark->used = strlen(cssMark->ptr);
	cssMark->size = cssMark->used;

	cssPtag->prefix = cssPrefix;
	cssPtag->mark = cssMark;
	cssPtag->refTag = cssRefTag;
	cssPtag->suffix = '>';
	cssPtag->closeTag = cssCloseTag;
	cssPtag->styleType = 0;
	return pConfig;
}

static void styleCombineInsert(request_rec *r) {
	CombineConfig *pConfig = ap_get_module_config(r->server->module_config, &styleCombine_module);
	if(!pConfig->enabled) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "not support styleCombineModule!");
		return;
	}
	ap_add_output_filter(STYLE_COMBINE_NAME, NULL, r, r->connection);
	return;
}

static apr_status_t styleCombineOutputFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {
	request_rec *r      = f->r;
	conn_rec    *c      = r->connection;
	CombineCtx  *ctx    = f->ctx;
	server = r->server;
	if (APR_BRIGADE_EMPTY(pbbIn)) {
		return APR_SUCCESS;
	}
	const char * encode = apr_table_get(r->headers_out, "Content-Encoding");
	if(encode && 0 == strcasecmp(encode, "gzip")) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	if(NULL != apr_table_get(r->notes, STYLE_COMBINE_NAME)) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	CombineConfig *pConfig = NULL;
	pConfig = ap_get_module_config(r->server->module_config, &styleCombine_module);
	if(NULL == pConfig) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	if(!contentTypeMatch(r, pConfig->filterCntType)){
		return ap_pass_brigade(f->next, pbbIn);
	}
	/**
	 * 1add runMode
	 * 添加模块的动态开关，由版本文件内容来控制
	 */
	if(NULL != appRunMode && 0 == memcmp(appRunMode, RUN_MODE_STATUS, 3)) {
		loadStyleVersion(r->server, r->pool, pConfig);
		return ap_pass_brigade(f->next, pbbIn);
	}
	/**
	 * 2 block & white list
	 */
	if(uriFilter(r, pConfig->blackList)) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	if(uriFilter(r, pConfig->whiteList)) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	/**
	 * 3add debugMode
	 * 本次请求禁用此模块，用于开发调试使用
	 */
	int           debugMode  = 0;
	if(NULL != r->parsed_uri.query) {
		char *debugModeParam = strstr(r->parsed_uri.query, DEBUG_MODE);
		if(NULL != debugModeParam && ZERO_END != *(debugModeParam += DEBUG_MODE_LEN)) {
			debugMode = atoi(&(*debugModeParam));
			if(debugMode > 2 || debugMode < 0) {
				debugMode = 0;
			}
		}
	}
	if(debugMode == 1) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	if (NULL == ctx) {
		apr_allocator_t *alt = apr_pool_allocator_get(r->pool);
		if(NULL != alt) {
			apr_allocator_max_free_set(alt, 20480);
		}
		ctx = f->ctx = apr_palloc(r->pool, sizeof(*ctx));
		if(NULL == ctx) {
			return ap_pass_brigade(f->next, pbbIn);
		}
		ctx->pbbOut = apr_brigade_create(r->pool, c->bucket_alloc);
		if(NULL == ctx->pbbOut) {
			return ap_pass_brigade(f->next, pbbIn);
		}
		ctx->buf = buffer_init_size(r->pool, DEFAULT_CONTENT_LEN);
		if(NULL == ctx->buf) {
			return ap_pass_brigade(f->next, pbbIn);
		}
		//set debugMode value
		ctx->debugMode = debugMode;
	}
	int isEOS = 0;
	apr_bucket *pbktIn = NULL;
	for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
	            pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
	            pbktIn = APR_BUCKET_NEXT(pbktIn)) {
		if(APR_BUCKET_IS_EOS(pbktIn)) {
			isEOS = 1;
			break;
		}
		const char *data;
		apr_size_t len; //read len
		apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);
		STRING_APPEND(r->pool, ctx->buf, (char *) data, len);
		apr_bucket_delete(pbktIn);
	}
	if(!isEOS) {
		return OK;
	}
	struct timeval start, end;
	if(9 == pConfig->printLog) {
		gettimeofday(&start, NULL);
	}
	if(ctx->buf->used > 0) {
		ctx->buf->ptr[ctx->buf->used] = ZERO_END;
		//load version
		loadStyleVersion(r->server, r->pool, pConfig);
		int i = 0;
		buffer *combinedStyleBuf[3] = {NULL, NULL, NULL};
		buffer *destBuf = buffer_init_size(r->pool, ctx->buf->used);
		if(NULL != destBuf) {
			for(i = 0; i < 3; i++) {
				combinedStyleBuf[i] = buffer_init_size(r->pool, 1000);
			}
		}
		if(combinedStyleBuf[TOP] && combinedStyleBuf[HEAD] && combinedStyleBuf[FOOTER]) {
			//if find any style
			if(htmlParser(r, combinedStyleBuf, destBuf, pConfig, ctx)) {
				resetHtml(c, ctx->pbbOut, combinedStyleBuf, destBuf);
			} else {
				addBucket(c, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
			}
		} else {
			addBucket(c, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
		}
	}
	//append eos
	APR_BRIGADE_INSERT_TAIL(ctx->pbbOut, apr_bucket_eos_create(c->bucket_alloc));
	apr_table_get(r->notes, "ok");
	apr_brigade_cleanup(pbbIn);

	if(9 == pConfig->printLog) {
		gettimeofday(&end, NULL);
		int usedtime = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "===end processed: URI[%s]==Result[%d us]", r->uri, usedtime);
	}
	return ap_pass_brigade(f->next, ctx->pbbOut);
}

static const char *setEnabled(cmd_parms *cmd, void *dummy, int arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	pConfig->enabled = arg;
	return NULL;
}

static const char *setFilterCntType(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine filterCntType value may not be null.";
	} else {
		pConfig->filterCntType = apr_pstrdup(cmd->pool, arg);
	}
	return NULL;
}

static const char *setAppName(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine appName can't be null OR empty";
	} else {
		pConfig->appName = apr_pstrdup(cmd->pool, arg);
	}
	return NULL;
}

static const char *setOldDomains(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine old domain value may not be null";
	} else {
		stringSplit(cmd->pool, DOMAIN_COUNTS, pConfig->oldDomains, apr_pstrdup(cmd->pool, arg), ';');
	}
	return NULL;
}

static const char *setNewDomains(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine new domain value may not be null";
	} else {
		stringSplit(cmd->pool, DOMAIN_COUNTS, pConfig->newDomains, apr_pstrdup(cmd->pool, arg), ';');
	}
	return NULL;
}

static const char *setAsyncVariableNames(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) < 1)) {
		return "styleCombine new domain value may not be null";
	} else {
		stringSplit(cmd->pool, DOMAIN_COUNTS, pConfig->asyncVariableNames, apr_pstrdup(cmd->pool, arg), ';');
	}
	return NULL;
}

static const char *setMaxUrlLen(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	int len = 0;
	if ((NULL == arg) || (len = atoi(arg)) < 1) {
		ap_log_error(APLOG_MARK, LOG_ERR, 0, cmd->server, "maxUrlLen too small, will set default  2083!");
	} else {
		pConfig->maxUrlLen = len;
	}
	return NULL;
}

static const char *setPrintLog(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if(NULL != arg) {
		pConfig->printLog = atoi(arg);
	}
	return NULL;
}

static const char *setVersionFilePath(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if(NULL != arg) {
		pConfig->versionFilePath = apr_pstrdup(cmd->pool, arg);
	} else {
		return "styleCombine versionFilePath value may not be null";
	}
	return NULL;
}

static const char *setBlackList(cmd_parms *cmd, void *in_dconf, const char *arg) {
	if(NULL == arg) {
		return NULL;
	}
	ap_regex_t *regexp;
	const char *str = apr_pstrdup(cmd->pool, arg);
	CombineConfig * pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	regexp = ap_pregcomp(cmd->pool, str, AP_REG_EXTENDED);
	if (!regexp) {
		return apr_pstrcat(cmd->pool, "blankList: cannot compile regular expression '", str, "'", NULL);
	}
	add(cmd->pool, pConfig->blackList, regexp);
	return NULL;
}

static const char *setWhiteList(cmd_parms *cmd, void *in_dconf, const char *arg) {
	if(NULL == arg) {
		return NULL;
	}
	ap_regex_t *regexp;
	const char *str = apr_pstrdup(cmd->pool, arg);
	CombineConfig * pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	regexp = ap_pregcomp(cmd->pool, str, AP_REG_EXTENDED);
	if (!regexp) {
		return apr_pstrcat(cmd->pool, "whiteList: cannot compile regular expression '", str, "'", NULL);
	}
	add(cmd->pool, pConfig->whiteList, regexp);
	return NULL;
}

static const command_rec styleCombineCmds[] =
{
		AP_INIT_FLAG("enabled", setEnabled, NULL, OR_ALL, "open or close this module"),

		AP_INIT_TAKE1("appName", setAppName, NULL, OR_ALL, "app name"),

		AP_INIT_TAKE1("filterCntType", setFilterCntType, NULL, OR_ALL, "filter content type"),

		AP_INIT_TAKE1("oldDomains", setOldDomains, NULL, OR_ALL, "style old domain url"),

		AP_INIT_TAKE1("newDomains", setNewDomains, NULL, OR_ALL, "style new domain url"),

		AP_INIT_TAKE1("asyncVariableNames", setAsyncVariableNames, NULL, OR_ALL, "the name for asynStyle of variable"),

		AP_INIT_TAKE1("maxUrlLen", setMaxUrlLen, NULL, OR_ALL, "url max len default is IE6 length support"),

		AP_INIT_TAKE1("printLog", setPrintLog, NULL, OR_ALL, " set printLog level"),

		AP_INIT_TAKE1("versionFilePath", setVersionFilePath, NULL, OR_ALL, "style versionFilePath dir"),

		AP_INIT_RAW_ARGS("blackList", setBlackList, NULL, OR_ALL, "style versionFilePath dir"),

		AP_INIT_RAW_ARGS("whiteList", setWhiteList, NULL, OR_ALL, "style versionFilePath dir"),

		{ NULL }
};

static int configRequired(server_rec *s, char *name, void * value) {
	if(NULL == value) {
		ap_log_error(APLOG_MARK, LOG_ERR, 0, s, "mod_styleCombine config [%s] value can't be null or empty", name);
		return 1;
	}
	return 0;
}
static apr_status_t styleCombine_post_conf(apr_pool_t *p, apr_pool_t *plog,
											apr_pool_t *tmp, server_rec *s) {
	ap_add_version_component(p, MODULE_BRAND);
	int resultCount = 0;
	CombineConfig *pConfig = NULL;
	pConfig = ap_get_module_config(s->module_config, &styleCombine_module);
	resultCount += configRequired(s, "pconfig", pConfig);
	if(resultCount) {
		return !OK;
	}
	resultCount += configRequired(s, "appName", pConfig->appName);
	resultCount += configRequired(s, "filterCntType", pConfig->filterCntType);
	resultCount += configRequired(s, "versionFilePath", pConfig->versionFilePath);
	int i = 0, domainCount = 0;
	for(i = 0; i < DOMAIN_COUNTS; i++) {
		if(NULL == pConfig->newDomains[i] && NULL == pConfig->oldDomains[i]) {
			continue;
		}
		if(pConfig->newDomains[i] && pConfig->oldDomains[i]) {
			++domainCount;
			continue;
		}
		resultCount += configRequired(s, "newDomains", pConfig->newDomains[i]);
		resultCount += configRequired(s, "oldDomains", pConfig->oldDomains[i]);
	}
	for(i = 0; i < domainCount; i++) {
		resultCount += configRequired(s, "asyncVariableNames", pConfig->asyncVariableNames[i]);
	}
	if(resultCount) {
		return !OK;
	}
	return OK;
}

static void styleCombine_register_hooks(apr_pool_t *p) {
	ap_hook_post_config(styleCombine_post_conf, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_insert_filter(styleCombineInsert, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter(STYLE_COMBINE_NAME, styleCombineOutputFilter, NULL, AP_FTYPE_RESOURCE);
    return;
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA styleCombine_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    configServerCreate,    /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    styleCombineCmds,      /* table of config file commands       */
    styleCombine_register_hooks  /* register hooks                      */
};
