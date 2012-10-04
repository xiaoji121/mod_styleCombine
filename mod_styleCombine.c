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
/** Default alignment */
#define APR_ALIGN_DEFAULT(size) APR_ALIGN(size, 8)

int JS_TAG_PREFIX_LEN = 0, JS_TAG_SUFFIX_LEN = 0;
int JS_TAG_EXT_PREFIX_LEN = 0, JS_TAG_EXT_SUFFIX_LEN = 0;
int CSS_PREFIX_LEN = 0, CSS_SUFFIX_LEN = 0;
int DEBUG_MODE_LEN = 12;

/***********global variable************/
const char ZERO_END = '\0';
/*position char */
enum PositionEnum{TOP, HEAD, FOOTER, NONE};
const char matches[] = {"</body>"};
int styleTableSize = 40000;

apr_pool_t   *globalPool = NULL;
apr_table_t  *styleVersionTable = NULL;
apr_time_t    lastLoadTime;
__time_t      prevTime = 0;
char         *appRunMode = NULL;
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
	off_t                 size;
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
	unsigned int        debugMode;
	buffer             *buf;
    apr_bucket_brigade *pbbOut;
} CombineCtx;

typedef struct {
	buffer               *styleUri;
	unsigned int          async;
	buffer               *group;
	enum PositionEnum     position;
	buffer               *version;
	unsigned int          styleType;
	unsigned int          domainIndex;
	unsigned int          isCombined;
} StyleField;

typedef struct {
	buffer          *domain;
	buffer          *styleUri;
	buffer          *version;
	buffer          *group;
	off_t            async;
	unsigned int     isNewLine;
	unsigned int     styleType;
	unsigned int     needExt;
} TagConfig;

typedef struct {
	off_t			 domainIndex;
	buffer          *group;
	LinkedList      *list[2];
} StyleList;

void fillTagConfigParams(TagConfig *tagConfig, buffer *version,
		int isNewLine, int styleType, int needExt) {
	tagConfig->version = version;
	tagConfig->isNewLine = isNewLine;
	tagConfig->styleType = styleType;
	tagConfig->needExt = needExt;
}

void linked_list_init(LinkedList *list) {
	if(NULL == list) {
		return;
	}
	list->first = NULL, list->head = NULL, list->size = 0;
}

StyleField *style_field_create() {
	StyleField *styleField = malloc(sizeof(StyleField));
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

void buffer_free(buffer *b) {
	if(NULL == b) {
		return;
	}
	free(b->ptr);
	free(b);
	return;
}

void style_field_free(StyleField *styleField) {
	if(NULL == styleField) {
		return;
	}
	buffer_free(styleField->version);
	buffer_free(styleField->group);
	buffer_free(styleField->styleUri);
	free(styleField);
	return;
}

buffer *buffer_init_size(int in_size) {
	buffer *buf = malloc(sizeof(buffer));
	if(NULL == buf) {
		return buf;
	}
	buf->ptr = NULL;
	buf->used = 0;
	buf->size = 0;
	int size = APR_ALIGN_DEFAULT(in_size);
	if(size < in_size) {
		buffer_free(buf);
		return NULL;
	}
	buf->ptr = (char *) malloc(size);
	if(NULL == buf->ptr) {
		buffer_free(buf);
		return NULL;
	}
	buf->size = size;
	return buf;
}

void add(LinkedList *list, void *item) {
	if (NULL == list || NULL == item) {
		return;
	}
	ListNode *node = malloc(sizeof(ListNode));
	if(NULL == node) {
		return;
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
}

void buffer_clean(buffer *buf) {
	if(NULL == buf) {
		return;
	}
	buf->used = 0;
	buf->ptr[0]=ZERO_END;
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
	}
	memcpy(buf->ptr + buf->used, str, strLen);
	buf->used += strLen;
	buf->ptr[buf->used] = ZERO_END;
	return;
}

static void formatParser(apr_table_t *table, char *str, server_rec *server) {
	if (NULL == str || NULL == table) {
		return;
	}
	char *name = NULL, *value = NULL;
	char *srcStr = str;
	char *strLine = NULL;
	while (NULL != (strLine = strsep(&srcStr, "\n"))) {
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
	}
	return;
}

buffer *getStrVersion(buffer *styleUri, request_rec *r, CombineConfig *pConfig){
	buffer *buf =  buffer_init_size(64);
	if(NULL == buf) {
		return NULL;
	}
	const char *strVersion = NULL;
	if(NULL != styleVersionTable) {
		strVersion = apr_table_get(styleVersionTable, styleUri->ptr);
	}
	if(NULL == strVersion) {
		time_t tv;
		time(&tv);
		//build a dynic version in 6 minutes
		snprintf(buf->ptr, buf->size, "%ld", (tv / 300));
		buf->used = strlen(buf->ptr);
		return buf;
	}
	stringAppend(buf, (char *) strVersion, strlen(strVersion));
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

static void loadStyleVersion(request_rec *r, CombineConfig *pConfig) {

	if(NULL == pConfig) {
		return;
	}
	apr_pool_t *pool = r->pool;
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
	apr_status_t rc = apr_stat(&finfo, pConfig->versionFilePath, APR_FINFO_MIN, pool);
	if(APR_SUCCESS == rc && finfo.mtime != lastLoadTime) {
		if(5 == pConfig->printLog) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
					"==reload styleVersion File lastLoadTime: %ld == fmtime:%ld", lastLoadTime, finfo.mtime);
		}
		lastLoadTime = finfo.mtime;
		rc = apr_file_open(&fd, pConfig->versionFilePath, APR_READ | APR_BINARY | APR_XTHREAD,
						   APR_OS_DEFAULT, pool);
		if(rc != APR_SUCCESS) {
			apr_file_close(fd);
		 	return;
		}
		amt = (apr_size_t)finfo.size;
		apr_table_t  *newTable = NULL;
		char         *versionBuf = apr_pcalloc(pool, amt + 1);

		if(NULL == versionBuf) {
			apr_file_close(fd);
			return;
		}
		rc = apr_file_read(fd, versionBuf, &amt);
		if(APR_SUCCESS == rc) {

			apr_pool_t *newPool = NULL;
			apr_pool_create(&newPool, r->server->process->pool);
			if(NULL == newPool) {
				apr_file_close(fd);
				return ;
			}
			newTable = apr_table_make(newPool, styleTableSize);
			formatParser(newTable, versionBuf, r->server);
			styleVersionTable = newTable;
			apr_pool_t *oldPool = globalPool;
			globalPool = newPool;
			//free old pool
			if(NULL != oldPool) {
				apr_pool_destroy(oldPool);
			}
			appRunMode = (char *)apr_table_get(styleVersionTable, pConfig->appName);
		}
		apr_file_close(fd);
	}
	return;
}

static StyleField *tagParser(CombineConfig *pConfig, ParserTag *ptag, char *maxTagBuf, off_t maxTagLen) {
	if(NULL == pConfig || NULL == ptag || NULL == maxTagBuf) {
		return NULL;
	}
	//domain find & checker
	off_t tagLen = ptag->prefix->used + ptag->refTag->used;
	//FIXME: HAS BUG
	if(maxTagLen <= (pConfig->oldDomains[0]->used + (tagLen + 1))){
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
	char *currURI = currURL + domain->used;
	register int groupLen = 0, hasDo = 0, stop = 0;
	//min len <script src="">
	buffer *styleUri = buffer_init_size(maxTagLen - domain->used - 15);
	while(*currURI) {
		if(*currURI == '"' || *currURI == '\'' || *currURI == ptag->suffix) {
			break;
		}
		if(isspace(*currURI)) {
			continue;
		}
		switch(*currURI) {
		case '.':
			++hasDo;
			break;
		case '?':
			//清除uri后面带的参数
			stop = 1;
			break;
		default:
			break;
		}
		if(stop) {
			break;
		}
		styleUri->ptr[styleUri->used++] = *currURI;
		++currURI;
	}
	if (!hasDo) { //没有带有.js/.css后缀
		buffer_free(styleUri);
		return NULL;
	}
	StyleField *styleField = style_field_create();
	if(NULL == styleField) {
		buffer_free(styleUri);
		return NULL;
	}
	styleUri->ptr[styleUri->used] = ZERO_END;
	// get pos & async & group
	buffer *group = NULL;
	char *urlStart = currURL - ptag->refTag->used - 1; // -1 == ' '
	enum PositionEnum position = NONE;
	tmpMaxTagBuf = maxTagBuf + ptag->prefix->used;
	while(*tmpMaxTagBuf) {
		if(tmpMaxTagBuf == urlStart) {
			tmpMaxTagBuf += (styleUri->used + ptag->refTag->used + domain->used) + 2; // 2 == \"\"
		}
		if(isspace(*tmpMaxTagBuf)) {
			++tmpMaxTagBuf;
			switch(*tmpMaxTagBuf) {
			case 'p':
				if(0 == memcmp(++tmpMaxTagBuf, "os=", 3)) {
					int *posLen = (int *) 0;
					position = strToPosition((tmpMaxTagBuf += 4), &posLen);
					tmpMaxTagBuf += (int) posLen;
				}
				break;
			case 'a':
				if(0 == memcmp(++tmpMaxTagBuf, "sync=", 5)) {
					tmpMaxTagBuf += 6;
					if(0 == memcmp(tmpMaxTagBuf, "true", 4)) {
						styleField->async = 1;
						tmpMaxTagBuf += 4;
					}
				}
				break;
			case 'g':
				if(0 == memcmp(++tmpMaxTagBuf, "roup=", 5)) {
					groupLen = 0;
					tmpMaxTagBuf += 6;
					char *s = tmpMaxTagBuf;
					while(*s) {
						switch(*s) {
						case '\'':
							stop = 1;
							break;
						case '"':
							stop = 1;
							break;
						}
						if(stop) {
							break;
						}
						++s;
						++groupLen;
					}
					group = buffer_init_size(groupLen + 8);
					stringAppend(group, tmpMaxTagBuf, groupLen);
					tmpMaxTagBuf += groupLen;
				}
				break;
			default:
				//处理多空格情况下的问题
				--tmpMaxTagBuf;
				break;
			}
		}
		++tmpMaxTagBuf;
	}
	styleField->domainIndex = dIndex;
	styleField->styleType = ptag->styleType;
	styleField->position = position;
	styleField->styleUri = styleUri;
	if(NONE == position && NULL == group) {
		return styleField;
	}
	char g;
	if(NONE != position && NULL == group) {
		//create default group
		group = buffer_init_size(24);
		stringAppend(group, "_def_group_name_", 16);
		g = '0' + (int) position;
	} else {
		g = '0' + styleField->async;
	}
	group->ptr[group->used++] = g;
	group->ptr[group->used] = ZERO_END;
	styleField->group = group;
	return styleField;
}

static void addExtStyle(buffer *destBuf, TagConfig *tagConfig) {
	if(!destBuf ||!tagConfig || !tagConfig->styleUri || !tagConfig->styleUri->used) {
		return;
	}
	if (tagConfig->isNewLine) {
		stringAppend(destBuf, "\n", 1);
	}
	if (tagConfig->styleType) {
		stringAppend(destBuf, JS_TAG_EXT_PREFIX_TXT, JS_TAG_EXT_PREFIX_LEN);
	} else {
		stringAppend(destBuf, CSS_PREFIX_TXT, CSS_PREFIX_LEN);
	}
	stringAppend(destBuf, tagConfig->domain->ptr, tagConfig->domain->used);
	stringAppend(destBuf, tagConfig->styleUri->ptr, tagConfig->styleUri->used);
	//append ext
	if(tagConfig->needExt) {
		if (tagConfig->styleType) {
			stringAppend(destBuf, EXT_JS, 3);
		} else {
			stringAppend(destBuf, EXT_CSS, 4);
		}
	}
	//append version
	stringAppend(destBuf, "?_v=", 4);
	if(NULL != tagConfig->version) {
		if(tagConfig->version->used > 32) {
			int i = 0;
			char md5[3];
			unsigned char digest[16];
			apr_md5(digest, (const void *)tagConfig->version->ptr, tagConfig->version->used);
			buffer_clean(tagConfig->version);
			for(i = 0; i < 16; i++) {
				snprintf(md5, 3, "%02x", digest[i]);
				stringAppend(tagConfig->version, md5, 2);
			}
		}
		stringAppend(destBuf, tagConfig->version->ptr, tagConfig->version->used);
	}
	//append the version ext
	if (tagConfig->styleType) {
		stringAppend(destBuf, EXT_JS, 3);
		stringAppend(destBuf, JS_TAG_EXT_SUFFIX_TXT, JS_TAG_EXT_SUFFIX_LEN);
	} else {
		stringAppend(destBuf, EXT_CSS, 4);
		stringAppend(destBuf, CSS_SUFFIX_TXT, CSS_SUFFIX_LEN);
	}
	return;
}

static void cleanExt(StyleField *styleField) {
	if(styleField->styleType) {
		styleField->styleUri->used -= 3; // clean .js ext
	} else {
		styleField->styleUri->used -= 4; // clean .css ext
	}
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
	tagConfig->domain  = pConfig->newDomains[styleField->domainIndex];
	fillTagConfigParams(tagConfig, versionBuf, 1, tagConfig->styleType, 1);
	while(NULL != node) {
		ListNode *freeNode = node;
		styleField = (StyleField *) node->value;
		if (count) {
			stringAppend(tmpUriBuf, URI_SEPARATOR, 1);
		} else {
			count++;
		}
		//url拼接在一起的长度超过配置的长度，则需要分成多个请求来处理。
		int urlLen = (tagConfig->domain->used + tmpUriBuf->used + styleField->styleUri->used);
		if (urlLen >= pConfig->maxUrlLen) {
			//将合并的url最后一个|字符去除
			tmpUriBuf->ptr[--tmpUriBuf->used] = ZERO_END;
			tagConfig->styleUri = tmpUriBuf;
			addExtStyle(combinedBuf, tagConfig);
			buffer_clean(versionBuf);
			buffer_clean(tmpUriBuf);
		}
		cleanExt(styleField);
		stringAppend(tmpUriBuf, styleField->styleUri->ptr, styleField->styleUri->used);
		stringAppend(versionBuf, styleField->version->ptr, styleField->version->used);
		node = node->next;
		style_field_free(styleField);
		free(freeNode);
	}
	tagConfig->styleUri = tmpUriBuf;
	addExtStyle(combinedBuf, tagConfig);
	return;
}

//var tt="{"group1":{"css":"http://xx/a1.css","js":"http://xx/a1.js"},"group2":{"js":"http://xx/a2.js"}}"
static void combineStylesAsync(CombineConfig *pConfig, StyleList *styleList, buffer *combinedStyleBuf[],
								buffer *versionBuf) {
	if(NULL == styleList || NULL == pConfig || NULL == combinedStyleBuf) {
		return;
	}
	buffer *headBuf = combinedStyleBuf[HEAD];
	headBuf->ptr[headBuf->used++] = '\'';
	stringAppend(headBuf, styleList->group->ptr, styleList->group->used - 1);
	stringAppend(headBuf, "':{'css'", 8);
	unsigned int i = 0, k = 0;
	for(i = 0; i < 2; i++) {
		LinkedList *list = styleList->list[i];
		if(NULL == list) {
			if(i) {
				stringAppend(headBuf, "'js':''", 7); // "js":""
			}
			continue;
		}
		if(i) {
			stringAppend(headBuf, "'js'", 4);
		}
		stringAppend(headBuf, ":'", 2);
		ListNode *node = list->first;
		StyleField *styleField = (StyleField *) node->value;
		stringAppend(headBuf, pConfig->newDomains[styleField->domainIndex]->ptr, pConfig->newDomains[styleField->domainIndex]->used);
		for(k = 0; NULL != node; k++) {
			styleField = (StyleField *) node->value;
			cleanExt(styleField);
			if(list->size >= k + 1 && k != 0) {
				stringAppend(headBuf, URI_SEPARATOR, 1);
			}
			stringAppend(headBuf, styleField->styleUri->ptr, styleField->styleUri->used);
			stringAppend(versionBuf, styleField->version->ptr, styleField->version->used);
			ListNode *freeNode = node;
			node = node->next;
			style_field_free(styleField);
			free(freeNode);
		}
		if (i) {
			stringAppend(headBuf, EXT_JS, 3);
		} else {
			stringAppend(headBuf, EXT_CSS, 4);
		}
		stringAppend(headBuf, "?_v=", 4);
		stringAppend(headBuf, versionBuf->ptr, versionBuf->used);
		if (i) {
			stringAppend(headBuf, EXT_JS, 3);
			stringAppend(headBuf, "'", 1);
		} else {
			stringAppend(headBuf, EXT_CSS, 4);
			stringAppend(headBuf, "',", 2);
		}
		free(list);
		buffer_clean(versionBuf);
	}
	stringAppend(headBuf, "},", 2);
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
		ListNode *freeStyleNode = styleNode;
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
			combinedBuf = combinedStyleBuf[styleField->position];
			tagConfig->styleType = styleField->styleType;
			tagConfig->domain  = pConfig->newDomains[styleField->domainIndex];
			fillTagConfigParams(tagConfig, NULL, 1, tagConfig->styleType, 0);
			while(NULL != node) {
				ListNode *freeNode = node;
				styleField = (StyleField *) node->value;
				tagConfig->version = styleField->version;
				tagConfig->styleUri = styleField->styleUri;
				addExtStyle(combinedBuf, tagConfig);
				node = node->next;
				style_field_free(styleField);
				free(freeNode);
			}
			free(list);
		}
		styleNode = (ListNode *) styleNode->next;
		free(styleList); free(freeStyleNode);
	}
	return;
}

static int isRepeat(request_rec *r, apr_hash_t *duplicats, StyleField *styleField) {
	if(NULL == duplicats) {
		return 0;
	}
	//make a key
	char *key = apr_palloc(r->pool, styleField->styleUri->used + 2);
	if(NULL == key) {
		return 0;
	}
	off_t keylen = 0;
	//add domain area
	key[keylen++] = '0' + styleField->domainIndex;
	memcpy((key + keylen), styleField->styleUri->ptr, styleField->styleUri->used);
	key[keylen += styleField->styleUri->used] = ZERO_END;
	if(NULL != apr_hash_get(duplicats, key, keylen)) {
		//if uri has exsit then skiping it
		return 1;
	}
	apr_hash_set(duplicats, key, keylen, "1");
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
		char *domain = strchr(ts, seperator);
		buffer *buf = (buffer *) apr_palloc(pool, sizeof(buffer)) ;
		buf->ptr = (char *) apr_palloc(pool, 64) ;
		if(NULL == buf->ptr) {
			continue;
		}
		buf->used = 0, buf->size = 64;
		if(NULL != domain) {
			stringAppend(buf, ts, (domain - ts));
			arrays[i] = buf;
			ts = ++domain;//move char of ';'
		} else {
			if(NULL == ts) {
				break;
			}
			int len = strlen(ts);
			if(len > 0) {
				stringAppend(buf, ts, len);
				arrays[i] = buf;
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

static inline char *strSearch(buffer *dest, const char *str1, int **matchedType, int **isExpression) {
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
				case '!':
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
	char *maxTagBuf = malloc(pConfig->maxUrlLen + 100);
	if(NULL == maxTagBuf) {
		return 0;
	}
	TagConfig *tagConfig = malloc(sizeof(TagConfig));
	if(NULL == tagConfig) {
		return 0;
	}
	LinkedList *syncGroupList = (LinkedList *)malloc(sizeof(LinkedList));
	linked_list_init(syncGroupList);
	LinkedList *asyncGroups[DOMAIN_COUNTS];
	apr_hash_t *domains[DOMAIN_COUNTS];
	apr_hash_t *duplicates = apr_hash_make(r->pool);
	int maxTagSize = (pConfig->maxUrlLen + 98);
	int *matchedType = 0, *isExpression = 0;
	register int  i = 0, k = 0, isProcessed = 0,combinBufSize = 100;
	register ParserTag *ptag = NULL;
	register char *curPoint = NULL, *tmpPoint = NULL;
	for(i = 0; i < DOMAIN_COUNTS; i++) {
		domains[i] = NULL;
		asyncGroups[i] = NULL;
	}
	char *subHtml = ctx->buf->ptr;
	while (NULL != (curPoint = strSearch(destBuf, subHtml, &matchedType, &isExpression))) {
		tmpPoint = curPoint;
		stringAppend(destBuf, subHtml, curPoint - subHtml);
		//此时表示当前是js文件，需要使用js的标签来处理
		ptag = (1 == (int) matchedType ? jsPtag:cssPtag);
		//1 skip&filter
		//2 getField {getType, getPos, getAsync, getGroup}
		for (i = 0; (curPoint[i] != ptag->suffix) && i < maxTagSize; i++) {
			maxTagBuf[i] = curPoint[i];
		}
		maxTagBuf[i++] = ptag->suffix;
		curPoint += i;
		maxTagBuf[i] = ZERO_END;
		if (ptag->styleType) {
			/**
			 * js 的特殊处理，需要将结束符找出来，</script>
			 * 结束符中间可能有空格或制表符，所以忽略这些
			 * 如果没有结束符，将不进行处理.
			 */
			for(; (isspace(*curPoint) && *curPoint != ZERO_END); curPoint++);

			if (memcmp(ptag->closeTag->ptr, curPoint, ptag->closeTag->used) != 0) {
				//找不到结束的</script>
				stringAppend(destBuf, maxTagBuf, i);
				subHtml = curPoint;
				continue;
			}
			curPoint += ptag->closeTag->used;
		}
		StyleField *styleField = tagParser(pConfig, ptag, maxTagBuf, i);
		if (NULL == styleField) {
			stringAppend(destBuf, maxTagBuf, i);
			if(ptag->styleType) {
				stringAppend(destBuf, ptag->closeTag->ptr, ptag->closeTag->used);
			}
			subHtml = curPoint;
			style_field_free(styleField);
			continue;
		}
		tagConfig->domain = pConfig->newDomains[styleField->domainIndex];
		tagConfig->styleUri = styleField->styleUri;
		tagConfig->async = styleField->async;
		tagConfig->group = styleField->group;
		//process expression <!--[if IE]> for js/css CAN'T clean duplicate
		if(((int) isExpression)) {
			//拿uri去获取版本号
			buffer *nversion = getStrVersion(styleField->styleUri, r, pConfig);
			styleField->version = nversion;
			fillTagConfigParams(tagConfig, nversion, 0, ptag->styleType, 0);
			addExtStyle(destBuf, tagConfig);
			subHtml = curPoint;
			style_field_free(styleField);
			continue;
		}
		//FIXME:去重部分，对于异步与同步加载的js来说需要特别处理，否则会出错
		//clean duplicate
		if(!styleField->async && isRepeat(r, duplicates, styleField)) {
			subHtml = curPoint;
			style_field_free(styleField);
			continue;
		}
		isProcessed = 1;
		//拿uri去获取版本号
		buffer *nversion = getStrVersion(styleField->styleUri, r, pConfig);
		styleField->version = nversion;
		fillTagConfigParams(tagConfig, nversion, 0, ptag->styleType, 0);
		//当没有使用异步并且又没有设置位置则保持原位不动
		if(0 == styleField->async && NONE == styleField->position) {
			addExtStyle(destBuf, tagConfig);
			subHtml = curPoint;
			style_field_free(styleField);
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
			add(styleList->list[styleField->styleType], styleField);
		} else {
			LinkedList *list = malloc(sizeof(LinkedList));
			if(NULL == list) {
				addExtStyle(destBuf, tagConfig);
				subHtml = curPoint;
				style_field_free(styleField);
				continue;
			}
			linked_list_init(list);
			if(NULL == styleList) {
				styleList = malloc(sizeof(StyleList));
				if(NULL == styleList) {
					addExtStyle(destBuf, tagConfig);
					subHtml = curPoint;
					style_field_free(styleField);
					continue;
				}
				styleList->list[0] = NULL, styleList->list[1] = NULL;
				/**
				 * 将所有group按出现的顺序放入一个list；合并style时按这个顺序输出到页面上。
				 */
				if(styleField->async) {
					LinkedList *asyncList = asyncGroups[styleField->domainIndex];
					if(NULL == asyncList) {
						asyncList = (LinkedList *)malloc(sizeof(LinkedList));
						linked_list_init(asyncList);
						asyncGroups[styleField->domainIndex] = asyncList;
					}
					add(asyncList, styleList);
				} else {
					add(syncGroupList, styleList);
				}
			}
			add(list, styleField);
			styleList->domainIndex = styleField->domainIndex;
			styleList->group = styleField->group;
			styleList->list[styleField->styleType] = list;
			/**
			 * 通过使用hash来控制每个group对应一个list
			 */
			apr_hash_set(styleMap, styleField->group->ptr, styleField->group->used, styleList);
		}
		//clean \r\n \n \t & empty char
		while(isspace(*curPoint)) {
			++curPoint;
		}
		subHtml = curPoint;
	}
	if(isProcessed) {
		//append the tail html
		int subHtmlLen = (ctx->buf->ptr + ctx->buf->used) - subHtml;
		stringAppend(destBuf, subHtml, subHtmlLen);

		//async clean duplicates
		ListNode *node = NULL;
		for(i = 0; i < DOMAIN_COUNTS; i++) {
			LinkedList *asyncList = asyncGroups[i];
			if(NULL == asyncList) {
				continue;
			}
			if(NULL != (node = asyncList->first)) {
				while(NULL != node) {
					StyleList *styleList = (StyleList *) node->value;
					for(i = 0; i < 2; i++) {
						LinkedList *list = styleList->list[i];
						if(NULL == list) {
							continue;
						}
						ListNode *parentNode = NULL, *freeStyleNode = NULL;
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
								freeStyleNode = styleNode;
								styleNode = styleNode->next;
								--list->size;
								style_field_free((StyleField *) freeStyleNode->value);
								free(freeStyleNode);
								continue;
							}
							parentNode = styleNode;
							styleNode = styleNode->next;
						}
					}
					node = node->next;
				}
			}
		}
		if(0 == ctx->debugMode) {
			buffer *versionBuf = buffer_init_size(1000);
			if(!versionBuf) {
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
					stringAppend(combinedStyleBuf[HEAD], "\n<script type=\"text/javascript\">\n", 33);
				}
				++addScriptPic;
				//1、先合并需要异步加载的js/css
				if(NULL != (node = asyncList->first)) {
					StyleList *styleList = (StyleList *) node->value;
					stringAppend(combinedStyleBuf[HEAD], "var ", 4);
					buffer *variableName = pConfig->asyncVariableNames[styleList->domainIndex];
					stringAppend(combinedStyleBuf[HEAD], variableName->ptr, variableName->used);
					stringAppend(combinedStyleBuf[HEAD], "=\"{", 3);
					while(NULL != node) {
						ListNode *freeNode = node;
						styleList = (StyleList *) node->value;
						combineStylesAsync(pConfig, styleList, combinedStyleBuf, versionBuf);
						node = (ListNode *) node->next;
						free(freeNode);
					}
					--combinedStyleBuf[HEAD]->used;
					stringAppend(combinedStyleBuf[HEAD], "}\";\n", 4);
				}
			}
			if(addScriptPic) {
				stringAppend(combinedStyleBuf[HEAD], "</script>\n", 10);
			}
			//2、将外部引入的js/css进行合并
			if(NULL != syncGroupList && NULL != (node = syncGroupList->first)) {
				buffer *tmpUriBuf = buffer_init_size(pConfig->maxUrlLen + 50);
				if(!tmpUriBuf) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "if(isProcessed){has Error}:[%s]", r->unparsed_uri);
					return 0;
				}
				while(NULL != node) {
					ListNode *freeNode = node;
					StyleList *styleList = (StyleList *) node->value;
					for(i = 0; i < 2; i++) {
						LinkedList *list = styleList->list[i];
						if(NULL == list) {
							continue;
						}
						buffer_clean(tmpUriBuf);
						buffer_clean(versionBuf);
						combineStyles(pConfig, tagConfig, list, combinedStyleBuf, tmpUriBuf, versionBuf);
						free(list);
					}
					node = (ListNode *) node->next;
					free(styleList); free(freeNode);
				}
				buffer_free(tmpUriBuf);
			}
			buffer_free(versionBuf);
		} else if(2 == ctx->debugMode){
			//debug mode 2
			combineStylesDebug(pConfig, tagConfig, syncGroupList, combinedStyleBuf);
			for(i = 0; i < DOMAIN_COUNTS; i++) {
				LinkedList *asyncList = asyncGroups[i];
				if(NULL == asyncList) {
					combineStylesDebug(pConfig, tagConfig, asyncList, combinedStyleBuf);
				}
			}
		}
	}
	if(0 != destBuf->size) {
		destBuf->ptr[destBuf->used] = ZERO_END;
	}
	free(tagConfig); free(maxTagBuf);
	free(syncGroupList);
	for(i = 0; i < DOMAIN_COUNTS; i++) {
		LinkedList *asyncList = asyncGroups[i];
		if(NULL == asyncList) {
			free(asyncList);
		}
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

	pConfig->enabled = 0;
	pConfig->printLog = 0;
	pConfig->filterCntType = NULL;
	pConfig->appName = "modCombine";

	char *variableNames = "_async_style_url_0;_async_style_url_1;";
	stringSplit(p, DOMAIN_COUNTS, pConfig->asyncVariableNames, variableNames, ';');

	pConfig->blackList = apr_palloc(p, sizeof(LinkedList));
	linked_list_init(pConfig->blackList);
	pConfig->whiteList = apr_palloc(p, sizeof(LinkedList));
	linked_list_init(pConfig->whiteList);
	/**
	 * see http://support.microsoft.com/kb/208427/EN-US
	 * default len for ie 2083 char
	 */
	pConfig->maxUrlLen = 2083;

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
		loadStyleVersion(r, pConfig);
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
	int debugMode = 0;
	if(NULL != r->parsed_uri.query) {
		char *debugModeParam = strstr(r->parsed_uri.query, DEBUG_MODE);
		if(NULL != debugModeParam) {
			debugModeParam += DEBUG_MODE_LEN;
			if(*debugModeParam == '1') {
				debugMode = 1;
				return ap_pass_brigade(f->next, pbbIn);
			}
			if(*debugModeParam == '2') {
				debugMode = 2;
			}
		}
	}
	if (NULL == ctx) {
		ctx = f->ctx = apr_palloc(r->pool, sizeof(*ctx));
		if(NULL == ctx) {
			return ap_pass_brigade(f->next, pbbIn);
		}
		ctx->pbbOut = apr_brigade_create(r->pool, c->bucket_alloc);
		if(NULL == ctx->pbbOut) {
			return ap_pass_brigade(f->next, pbbIn);
		}
		ctx->buf = buffer_init_size(DEFAULT_CONTENT_LEN);
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
		//the end
		if(APR_BUCKET_IS_EOS(pbktIn)) {
			isEOS = 1;
			break;
		}
		const char *data;
		apr_size_t len;
		//read len
		apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);
		stringAppend(ctx->buf, (char *) data, len);
		apr_bucket_delete(pbktIn);
	}
	if(!isEOS) {
		return OK;
	}
	struct timeval start;
	if(9 == pConfig->printLog) {
		gettimeofday(&start, NULL);
	}
	if(ctx->buf->used > 0) {
		ctx->buf->ptr[ctx->buf->used] = ZERO_END;
		//load version
		loadStyleVersion(r, pConfig);
		int i = 0;
		buffer *combinedStyleBuf[3] = {NULL, NULL, NULL};
		buffer *destBuf = buffer_init_size(ctx->buf->used);
		if(NULL != destBuf) {
			for(i = 0; i < 3; i++) {
				combinedStyleBuf[i] = buffer_init_size(1000);
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
		for(i = 0; i < 3; i++) {
			buffer_free(combinedStyleBuf[i]);
		}
		buffer_free(destBuf);
	}
	//append eos
	APR_BRIGADE_INSERT_TAIL(ctx->pbbOut, apr_bucket_eos_create(c->bucket_alloc));
	apr_table_get(r->notes, "ok");
	buffer_free(ctx->buf);
	apr_brigade_cleanup(pbbIn);

	if(9 == pConfig->printLog) {
		struct timeval end;
		gettimeofday(&end, NULL);
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "===end process: URI[%s]==start[%ld]==end[%ld]==Result[%ld]",
				r->uri, start.tv_usec, end.tv_usec, end.tv_usec - start.tv_usec);
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
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine new domain value may not be null";
	} else {
		stringSplit(cmd->pool, DOMAIN_COUNTS, pConfig->asyncVariableNames, apr_pstrdup(cmd->pool, arg), ';');
	}
	return NULL;
}

static const char *setMaxUrlLen(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	int len = 0;
	if ((NULL == arg) || (len = atoi(arg)) < pConfig->maxUrlLen) {
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
	add(pConfig->blackList, regexp);
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
	add(pConfig->whiteList, regexp);
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

static apr_status_t styleCombine_init_module(apr_pool_t *p, apr_pool_t *plog,
											apr_pool_t *tp, server_rec *s) {
	ap_add_version_component(p, MODULE_BRAND);
	return APR_SUCCESS;
}

static void styleCombine_register_hooks(apr_pool_t *p) {
	ap_hook_post_config(styleCombine_init_module, NULL, NULL, APR_HOOK_MIDDLE);
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
