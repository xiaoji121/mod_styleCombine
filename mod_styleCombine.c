/**
 * zhiwen.mizw@alibaba-inc.com
 * 2013-04-20
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/stat.h>
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
#include "apr_lib.h"

module AP_MODULE_DECLARE_DATA                styleCombine_module;

#define STYLE_COMBINE_NAME                   "styleCombine"
#define MODULE_BRAND                         STYLE_COMBINE_NAME"/2.0.0"

#define EXT_JS                               ".js"
#define EXT_CSS                              ".css"

#define URI_SEPARATOR                        "|"

#define POSITION_TOP                         "top"
#define POSITION_HEAD                        "head"
#define POSITION_FOOTER                      "footer"

#define DEBUG_MODE                           "_debugMode_="
#define RUN_MODE_STATUS                      "dis"

#define JS_TAG_EXT_PREFIX_TXT                "<script type=\"text/javascript\" src=\""
#define JS_TAG_EXT_SUFFIX_TXT                "\"></script>"
#define JS_TAG_PREFIX_TXT                    "<script type=\"text/javascript\">"
#define JS_TAG_SUFFIX_TXT                    "</script>"
#define CSS_PREFIX_TXT                       "<link rel=\"stylesheet\" href=\""
#define CSS_SUFFIX_TXT                       "\" />"

#define BUFFER_PIECE_SIZE                    128
#define DEFAULT_CONTENT_LEN                  (1024 << 8) //262144
#define DOMAIN_COUNTS                        2
#define MAX_STYLE_TAG_LEN                    2183
//去右空格
#define TRIM_RIGHT(p) while(isspace(*p)){ ++p; }

#define BUFFER_CLEAN(buffer) if(NULL != buffer) { buffer->used = 0; buffer->ptr[0] = ZERO_END; }

//解析field属性的值，有空格则去空格
#define FIELD_PARSE(p, ret, symbl) {\
	while(isspace(*p)){ ++p; }\
	if('=' == *p++) {\
		while(isspace(*p)){ ++p; }\
		if('"' == *p || '\'' == *p) { ++p; symbl = 1;} \
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

#define INIT_TAG_CONFIG(tagConfig, req, stylefield, newDomain, newDebugMode, haveNewLine, haveExt) {\
	tagConfig->r = req;\
	tagConfig->styleField = stylefield;\
	tagConfig->domain = newDomain;\
	tagConfig->debugMode = newDebugMode;\
	tagConfig->isNewLine = haveNewLine;\
	tagConfig->needExt = haveExt;\
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

static int  JS_TAG_PREFIX_LEN                 = 0, JS_TAG_SUFFIX_LEN        = 0;
static int  JS_TAG_EXT_PREFIX_LEN             = 0, JS_TAG_EXT_SUFFIX_LEN    = 0;
static int  CSS_PREFIX_LEN                    = 0, CSS_SUFFIX_LEN           = 0;

static int         DEBUG_MODE_LEN             = 12;
static const char  ZERO_END                   = '\0';
static time_t      prevTime                   = 0;
static char        *appRunMode                = NULL;
static server_rec  *server;

/*position char */
enum PositionEnum { TOP, HEAD, FOOTER, NONE };

enum TagNameEnum { BHEAD, EHEAD, LINK, SCRIPT, TEXTAREA, COMMENT_EXPRESSION, TN_NONE };
static char *patterns[6] = { "head", "/head", "link", "script", "textarea", "!--" };
static int   patternsLen[6];

typedef struct {
	char              *ptr;
	off_t              used;
	off_t              size;
} buffer;

typedef struct {
	buffer            *prefix;
	buffer            *mark;
	buffer            *refTag;
	buffer            *closeTag;
	int                suffix;
	int                styleType; /*0:表示css; 1:表示js*/
} StyleParserTag;

static StyleParserTag *styleParserTags[2] = {NULL, NULL};

typedef struct ListNode ListNode;
struct ListNode {
	ListNode          *next;
    const void        *value;
};

typedef struct {
	int                size;
	ListNode          *first;
	ListNode          *head;
} LinkedList;

typedef struct {
	int                enabled;
	int                maxUrlLen;
	int                printLog;
	char              *filterCntType;
	char              *versionFilePath;
	buffer            *appName;
	buffer            *oldDomains[DOMAIN_COUNTS];
	buffer            *newDomains[DOMAIN_COUNTS];
	buffer            *asyncVariableNames[DOMAIN_COUNTS];
	LinkedList        *blackList;
	LinkedList        *whiteList;
} CombineConfig;

typedef struct {
	int                 debugMode;
	buffer             *buf;
    apr_bucket_brigade *pbbOut;
} CombineCtx;

typedef struct {
	int                   async;
	int                   styleType;
	int                   domainIndex;
	buffer               *styleUri;
	buffer               *group;
	buffer               *media;
	buffer               *version;
	enum PositionEnum     position;
} StyleField;

typedef struct {
	StyleField          *styleField;
	buffer              *domain;
	int                  isNewLine;
	int                  needExt;
	int                  debugMode;
	request_rec         *r;
} TagConfig;

typedef struct {
	int   			     domainIndex;
	buffer              *group;
	LinkedList          *list[2];
} StyleList;

typedef struct {
	apr_pool_t          *oldPool;
	apr_pool_t          *newPool;
	apr_hash_t          *styleHTable;
	apr_time_t           mtime;
} StyleVersionEntry;

static StyleVersionEntry svsEntry;

typedef struct ContentBlock {
	int                  bIndex;
	int                  eIndex;
	//用于存放，那些没有合并的style；有内容时 bIndex和eIndex都视无效
	buffer              *cntBlock;
	//当前对象的类型如是：<head>,</head>, </body>等
	enum TagNameEnum     tagNameEnum;
} ContentBlock;

LinkedList *linked_list_create(apr_pool_t *pool) {
	LinkedList *list = (LinkedList *) apr_palloc(pool, sizeof(LinkedList));
	if(NULL == list) {
		return NULL;
	}
	list->first = NULL, list->head = NULL, list->size = 0;
	return list;
}

StyleField *style_field_create(apr_pool_t *pool) {
	StyleField *styleField  = (StyleField *) apr_palloc(pool, sizeof(StyleField));
	if(NULL == styleField) {
		return NULL;
	}
	styleField->async       = 0;
	styleField->styleUri    = NULL;
	styleField->version     = NULL;
	styleField->position    = NONE;
	styleField->styleType   = 0;
	styleField->domainIndex = 0;
	styleField->group       = NULL;
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
	buf->ptr[0] = ZERO_END;
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

static ContentBlock *contentBlock_create_init(apr_pool_t *pool, int bIndex, int eIndex, enum TagNameEnum tagNameEnum) {
	if(eIndex <= bIndex) {
		return NULL;
	}
	ContentBlock *contentBlock = (ContentBlock *) apr_palloc(pool, sizeof(ContentBlock));
	if(NULL == contentBlock) {
		return NULL;
	}
	contentBlock->bIndex       = bIndex,  contentBlock->eIndex = eIndex;
	contentBlock->cntBlock     = NULL;
	contentBlock->tagNameEnum  = tagNameEnum;
	return contentBlock;
}

static void formatParser(apr_pool_t *pool, apr_hash_t *htable, char *str) {
	if (NULL == str || NULL == htable) {
		return;
	}
	char *name    = NULL, *value = NULL;
	int   nameLen =0, valueLen = 0;
	char *srcStr  = str;
	char *strLine = NULL;
	while (NULL != (strLine = strsep(&srcStr, "\n"))) {
		name = NULL, value = NULL;
		name = strsep(&strLine, "=");
		if (NULL == name || (nameLen = strlen(name)) <= 1) {
			continue;
		}
		value = strLine;
		if (NULL == value || (valueLen = strlen(value)) < 1) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "formatParser value error value=[%s],strLine=[%s]", value, strLine);
			continue;
		}
		buffer *vbuf = buffer_init_size(pool, valueLen);
		STRING_APPEND(pool, vbuf, value, valueLen);

		char *key = apr_palloc(pool, nameLen + 1);
		memcpy(key, name, nameLen);
		key[nameLen + 1] = ZERO_END;

		apr_hash_set(htable, key, nameLen, vbuf);
		strLine = NULL;
	}
	return;
}

/**
 * 拿当前字符串与模式字符串先比较两人最后的字符是否相等，如果相等再比较全部。
 */
static int compare(char *input, char *pattern, int patternLen, int ignorecase) {
	if(NULL == input || NULL == pattern) {
		return -1;
	}
	++input;
	++pattern; --patternLen;
	char *endChar = input + patternLen - 1;
	if(*endChar == ZERO_END || tolower(*endChar) != *(pattern + patternLen - 1)) {
		return -1;
	}
	if(ignorecase) {
		return strncasecmp(input, pattern, patternLen);
	}
	return memcmp(input, pattern, patternLen);
}

static void loadStyleVersion(server_rec *server, apr_pool_t *req_pool, CombineConfig *pConfig) {
	if(NULL == pConfig || NULL == pConfig->versionFilePath) {
		return;
	}
	time_t tm;
	time(&tm);
	int intervalSecd      = 20;
	if(0 != prevTime && (tm - prevTime) <= intervalSecd) {
		return;
	}
	apr_finfo_t  finfo;
	prevTime              = tm;
	apr_status_t rc = apr_stat(&finfo, pConfig->versionFilePath, APR_FINFO_MIN, req_pool);
	if(APR_SUCCESS != rc || finfo.mtime == svsEntry.mtime) {
		return;
	}
	apr_file_t     *fd        = NULL;
	rc = apr_file_open(&fd, pConfig->versionFilePath, APR_READ | APR_BINARY | APR_XTHREAD,
					   APR_OS_DEFAULT, req_pool);
	if(rc != APR_SUCCESS) {
		apr_file_close(fd);
		return;
	}
	//modify the mtime
	svsEntry.mtime   = finfo.mtime;
	apr_size_t amt   = (apr_size_t)finfo.size;
	char *versionBuf = apr_pcalloc(req_pool, amt + 1);
	if(NULL == versionBuf) {
		apr_file_close(fd);
		return;
	}
	rc = apr_file_read(fd, versionBuf, &amt);
	apr_file_close(fd);
	if(APR_SUCCESS != rc) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "== readVersion Config error [%d]", APR_SUCCESS);
		return;
	}
	apr_pool_t *newPool = NULL;
	apr_pool_create(&newPool, server->process->pool);
	if(NULL == newPool) {
		return;
	}
	svsEntry.newPool = newPool;
	svsEntry.styleHTable = apr_hash_make(newPool);
	formatParser(newPool, svsEntry.styleHTable, versionBuf);
	// 获取应用的运行状态(off/on)
	buffer *appStatusBuf = (buffer *) apr_hash_get(svsEntry.styleHTable, pConfig->appName->ptr, pConfig->appName->used);
	if(NULL != appStatusBuf) {
		appRunMode = appStatusBuf->ptr;
	}
	//释放老的内存池时，先将新的内存池填上，避免线程安全问题；因为老的内存池其它地方可能还在使用
	if(NULL != svsEntry.oldPool) {
		apr_pool_destroy((apr_pool_t *) svsEntry.oldPool);
	}
	svsEntry.oldPool = newPool;
	return;
}

static void addBucket(conn_rec *c, apr_bucket_brigade *pbbkOut, char *str, int strLen) {
	if(NULL == str || strLen <= 0) {
		return;
	}
	apr_bucket *pbktOut = NULL;
	pbktOut = apr_bucket_heap_create(str, strLen, NULL, c->bucket_alloc);
	if(NULL != pbktOut) {
		APR_BRIGADE_INSERT_TAIL(pbbkOut, pbktOut);
	}
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

static int getFieldValueLen(char *str, int symbl) {
	if(NULL == str) {
		return 0;
	}
	register int valueLen = 0, stop = 0;
	while(*str) {
		switch(*str) {
		case '\'':
		case '"':
			stop = 1;
			break;
		case ' ':
			//如果是以单双引号开始和结束的，中间可以有空格；否则以空格为结束
			if(1 == symbl) {
				break;
			}
			stop = 1;
			break;
		}
		if(stop) {
			break;
		}
		++str;
		++valueLen;
	}
	return valueLen;
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

static int parserTag(request_rec *r, CombineConfig *pConfig, int styleType, buffer *tagBuf, StyleField **pStyleField, char *input) {

	StyleParserTag *ptag = styleParserTags[styleType];

	if(NULL == pConfig || NULL == ptag || NULL == input || NULL == tagBuf) {
		return 0;
	}
	char *inputTemp     = input;
	//偏移开头部分(<link, <script), 传进来的input没有<打头，但所有的<link,<script 后面必须紧接空格，所以长度正好抵消
	inputTemp          += ptag->prefix->used;
	int count           = ptag->prefix->used;
	char ch , pchar;

	for(ch = *inputTemp; (ZERO_END != ch && ch != ptag->suffix); ch = *(++inputTemp), count++) {
		//换行直接跳过, 并去除重复的空格
		if('\n' == ch || '\r' == ch) {
			continue;
		}
		ch = ('\t' == ch ? ' ': ch); //将\t转为空格
		if(isspace(ch) && isspace(pchar)) {
			continue;
		}
		pchar           = ch;

		if(tagBuf->used + 1 < tagBuf->size) {
			tagBuf->ptr[tagBuf->used++] = ch;
		} else {
			//FIXME:add log  the url is too long
			return count;
		}
	}
	tagBuf->ptr[tagBuf->used] = ZERO_END;
	if (ptag->styleType) {
		//对script需要特别处理，因为它是以</script>为结束，那么需要确定它是否是这样的。
		//如果不是那么则认为它是一个script代码块，或无效的js引用
		++inputTemp, ++count;
		TRIM_RIGHT(inputTemp);
		if (memcmp(ptag->closeTag->ptr, inputTemp, ptag->closeTag->used) != 0) {
			return count;
		}
		inputTemp       += ptag->closeTag->used;
		count           += ptag->closeTag->used;
	}
	//===start parser===
	int dIndex           = 0;
	buffer *domain       = NULL;
	char *tagBufPtr      = tagBuf->ptr,  *currURL = NULL;
	for(dIndex = 0; dIndex < DOMAIN_COUNTS; dIndex++) {
		domain = pConfig->oldDomains[dIndex];
		if(NULL == domain) {
			continue;
		}
		char *domainIndex = strstr(tagBufPtr, domain->ptr);
		if(NULL != domainIndex) {
			currURL = domainIndex;
			break;
		}
	}
	if(NULL == currURL) {
		return count;
	}

	if(0 == ptag->styleType) {
		//如果是css 则检查它的rel属性是否为stylesheet
		if (NULL == strstr(tagBufPtr, ptag->mark->ptr)) {
			return count;
		}
	}

	char *currURI    = currURL + domain->used;
	int groupLen     = 0,     hasDo = 0,  stop = 0;
	buffer *styleUri = buffer_init_size(r->pool, (tagBuf->used - domain->used));
	if(NULL == styleUri) {
		return count;
	}
	while(*currURI) {
		ch = *(currURI++);
		switch(ch) {
		case '"':
		case '\'':
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
	if (!hasDo) { //没有带有.js/.css后缀的style文件将忽略处理
		return count;
	}
	styleUri->ptr[styleUri->used] = ZERO_END;
	StyleField *styleField = style_field_create(r->pool);
	if(NULL == styleField) {
		return count;
	}
	*pStyleField = styleField;
	int retValue               = 0, hasSymble  = 0;
	//记录到URL和属性名的开始位置，如： href="xx" 记录的则是h前面的空格位置
	char *urlIndex             = currURL - ptag->refTag->used - 1;
	buffer *group              = NULL,   *media = NULL;
	enum PositionEnum position = NONE;
	while(*tagBufPtr) {
		if(tagBufPtr == urlIndex) {
			//解析属性的时候，URL直接跳过不做解析，因为URL中没有属性内容以提高效率
			tagBufPtr += (styleUri->used + ptag->refTag->used + domain->used);
		}
		if(!isspace(*tagBufPtr)) {
			++tagBufPtr;
			continue;
		}
		++tagBufPtr;  //偏移空格
		//parser media
		if(0 == memcmp(tagBufPtr, "media", 5)) {
			tagBufPtr   += 5; //偏移media
			retValue     = 0,  hasSymble = 0;
			FIELD_PARSE(tagBufPtr, retValue, hasSymble);
			if(retValue == -1) {
				continue;
			}
			int valueLen = getFieldValueLen(tagBufPtr, hasSymble);
			if(valueLen > 0) {
				media = buffer_init_size(r->pool, valueLen + 8);
				STRING_APPEND(r->pool, media, tagBufPtr, valueLen);
				tagBufPtr += valueLen;
				continue;
			}
		}
		//parser customize field
		int fieldPrefixLen = 8;
		if(0 != memcmp(tagBufPtr, "data-sc-", fieldPrefixLen)) {
			tagBufPtr++;
			continue;
		}
		tagBufPtr         += fieldPrefixLen;
		switch(*tagBufPtr) {
		case 'p': //data-sc-pos
			if(0 == compare(tagBufPtr, "pos", 3, 0)) {
				tagBufPtr   += 3;
				retValue     = 0,  hasSymble = 0;
				FIELD_PARSE(tagBufPtr, retValue, hasSymble);
				if(retValue == -1) {
					continue;
				}
				int *posLen = (int *) 0;
				position    = strToPosition(tagBufPtr, &posLen);
				tagBufPtr  += ((int) posLen) + hasSymble;
				continue;
			}
			break;
		case 'a': //data-sc-async
			if(0 == compare(tagBufPtr, "async", 5, 0)) {
				tagBufPtr   += 5;
				retValue     = 0,  hasSymble = 0;
				FIELD_PARSE(tagBufPtr, retValue, hasSymble);
				if(retValue == -1) {
					continue;
				}
				if(0 == memcmp(tagBufPtr, "true", 4)) {
					styleField->async = 1;
					tagBufPtr        += 4 + hasSymble;
					continue;
				}
			}
			break;
		case 'g': //data-sc-group
			if(0 == compare(tagBufPtr, "group", 5, 0)) {
				tagBufPtr     += 5;
				retValue       = 0,  hasSymble = 0;
				FIELD_PARSE(tagBufPtr, retValue, hasSymble);
				if(retValue == -1) {
					continue;
				}
				int valueLen    = getFieldValueLen(tagBufPtr, hasSymble);
				if(valueLen > 0) {
					group       = buffer_init_size(r->pool, valueLen + 8);
					STRING_APPEND(r->pool, group, tagBufPtr, valueLen);
					tagBufPtr   += valueLen;
					continue;
				}
				continue;
			}
			break;
		}
	}
	styleField->domainIndex = dIndex;
	styleField->styleType   = ptag->styleType;
	styleField->position    = position;
	styleField->styleUri    = styleUri;
	styleField->media       = media;
	if(NULL == group) {
		//group和pos 都为空时，保持原地不变
		if(NONE == position) {
			styleField->async = 0;
			return count;
		}
		//当只有async属性时，保证原地不变
		if(styleField->async) {
			styleField->async   = 0;
			styleField->position = NONE;
			return count;
		}
	} else {
		if(NONE == position && !styleField->async) {
			styleField->group = NULL;
			return count;
		}
	}
	//pos build
	char g;
	if(NONE != position && NULL == group) {
		//create default group
		group = buffer_init_size(r->pool, 24);
		STRING_APPEND(r->pool, group, "_def_group_name_", 16);
		g     = '0' + (int) position;
	} else {
		g     = '0' + styleField->async;
	}
	group->ptr[group->used++] = g;
	group->ptr[group->used]   = ZERO_END;
	styleField->group         = group;
	return count;
}

static buffer *getStrVersion(request_rec *r, buffer *styleUri, CombineConfig *pConfig){
	buffer *versionBuf = NULL;
	if(NULL != svsEntry.styleHTable) {
		versionBuf = (buffer *) apr_hash_get(svsEntry.styleHTable, styleUri->ptr, styleUri->used);
	}
	if(NULL == versionBuf) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "==can't getVersion:ReqURI:[%s]==>StyleURI:[%s]", r->unparsed_uri, styleUri->ptr);
		time_t tv;
		time(&tv);
		versionBuf      = buffer_init_size(r->pool, 64);
		//build a dynic version in 6 minutes
		apr_snprintf(versionBuf->ptr, versionBuf->size, "%ld", (tv / 300));
		versionBuf->used = strlen(versionBuf->ptr);
	}
	return versionBuf;
}

static void makeVersion(apr_pool_t *pool, buffer *buf, buffer *versionBuf) {
	STRING_APPEND(pool, buf, "?_v=", 4);
	if(NULL != versionBuf) {
		if(versionBuf->used > 32) {
			char md5[3];
			unsigned char digest[16];
			apr_md5(digest, (const void *)versionBuf->ptr, versionBuf->used);
			BUFFER_CLEAN(versionBuf);
			int i = 0;
			for(i = 0; i < 16; i++) {
				apr_snprintf(md5, 3, "%02x", digest[i]);
				STRING_APPEND(pool, versionBuf, md5, 2);
			}
		}
		STRING_APPEND(pool, buf, versionBuf->ptr, versionBuf->used);
	}
}

static int addExtStyle(buffer *destBuf, TagConfig *tagConfig) {
	if(!destBuf ||!tagConfig || !tagConfig->styleField) {
		return 0;
	}
	StyleField *styleField = tagConfig->styleField;
	if (tagConfig->isNewLine) {
		STRING_APPEND(tagConfig->r->pool, destBuf, "\n", 1);
	}
	if (styleField->styleType) {
		STRING_APPEND(tagConfig->r->pool, destBuf, JS_TAG_EXT_PREFIX_TXT, JS_TAG_EXT_PREFIX_LEN);
	} else {
		STRING_APPEND(tagConfig->r->pool, destBuf, CSS_PREFIX_TXT, CSS_PREFIX_LEN);
	}
	STRING_APPEND(tagConfig->r->pool, destBuf, tagConfig->domain->ptr, tagConfig->domain->used);
	STRING_APPEND(tagConfig->r->pool, destBuf, styleField->styleUri->ptr, styleField->styleUri->used);
	//append ext
	if(tagConfig->needExt) {
		if (styleField->styleType) {
			STRING_APPEND(tagConfig->r->pool, destBuf, EXT_JS, 3);
		} else {
			STRING_APPEND(tagConfig->r->pool, destBuf, EXT_CSS, 4);
		}
	}
	//append version
	makeVersion(tagConfig->r->pool, destBuf, styleField->version);
	//append the version ext
	if (styleField->styleType) {
		STRING_APPEND(tagConfig->r->pool, destBuf, EXT_JS, 3);
	} else {
		STRING_APPEND(tagConfig->r->pool, destBuf, EXT_CSS, 4);
	}
	if(2 == tagConfig->debugMode) {
		if(styleField->group) {
			STRING_APPEND(tagConfig->r->pool, destBuf, "\" data-sc-group=\"", 17);
			STRING_APPEND(tagConfig->r->pool, destBuf, styleField->group->ptr, styleField->group->used);
		}
	}
	//扩充media属性
	if(NULL != styleField->media) {
		STRING_APPEND(tagConfig->r->pool, destBuf, "\" media=\"", 9);
		STRING_APPEND(tagConfig->r->pool, destBuf, styleField->media->ptr, styleField->media->used);
	}
	if (styleField->styleType) {
		STRING_APPEND(tagConfig->r->pool, destBuf, JS_TAG_EXT_SUFFIX_TXT, JS_TAG_EXT_SUFFIX_LEN);
	} else {
		STRING_APPEND(tagConfig->r->pool, destBuf, CSS_SUFFIX_TXT, CSS_SUFFIX_LEN);
	}
	return 1;
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

static int htmlParser(request_rec *req, CombineCtx *ctx, CombineConfig *pConfig) {

	if (NULL == ctx->buf) {
		return 0;
	}
	char *input           = ctx->buf->ptr;
	//创建一个列表，用于存放所有的索引对象，包括一些未分组和未指定位置的style
	ContentBlock *block   = NULL;
	LinkedList *blockList = linked_list_create(req->pool);

	//用于去重的 hash
	apr_hash_t *duplicates= apr_hash_make(req->pool);

	//用于存放解析出来的style URL 长度为 maxURL的2倍
	buffer     *tagBuf    = buffer_init_size(pConfig->maxUrlLen * 2);

	//域名数组，用于存放不同域名下的styleMap
	apr_hash_t *domains[DOMAIN_COUNTS] = {NULL, NULL};

	//用于存放 同步（直接加载）的style列表
	LinkedList *syncStyleList  = linked_list_create(req->pool);

	//用于存放 异步的style列表
	LinkedList *asyncStyleList = linked_list_create(req->pool);

	int styleType              = 0, styleCount    = 0;
	enum TagNameEnum tnameEnum = LINK;
	char *istr                 = input, *istrTemp = NULL;
	int isExpression           = 0, retIndex = 0, bIndex = 0, eIndex = 0;
	int offsetLen = 0;

	while (*istr) {
		if ('<' != *istr) {
			++istr, ++eIndex;
			continue;
		}
		++istr, ++eIndex;
		switch (*istr) {
		case 'H':
		case 'h': // find <head>
			retIndex = compare(istr, patterns[BHEAD], patternsLen[BHEAD], 0);
			if(0 != retIndex) {
				istr++ , eIndex++;                         //偏移 h 1个字符长度
				continue;
			}
			eIndex       += offsetLen = patternsLen[BHEAD] + 1; //偏移 > 1个结束符字符长度
			block         = contentBlock_create_init(req->pool, bIndex, eIndex, BHEAD);
			bIndex        = eIndex;
			istr         += offsetLen;
			add(req->pool, blockList, (void *) block);
			break;
		case '/': // find </head>
			retIndex = compare(istr, patterns[EHEAD], patternsLen[EHEAD], 0);
			if(0 != retIndex) {
				istr++, eIndex++;
				continue;
			}
			block         = contentBlock_create_init(req->pool, bIndex, --eIndex, EHEAD);
			bIndex        = eIndex;
			eIndex       += offsetLen = patternsLen[EHEAD] + 1;  //偏移 /head> 6个字符长度
			istr         += offsetLen;
			add(req->pool, blockList, (void *) block);
			break;
		case 'T':
		case 't': // find <textarea ...>...</textarea>  must be suppor (upper&lower) case
			retIndex = compare(istr, patterns[TEXTAREA], patternsLen[TEXTAREA], 1);
			if (0 != retIndex) {
				istr++ , eIndex++;
				continue;
			}
			char *textArea = istr + patternsLen[TEXTAREA] + 1; // 偏移 textarea> 9个字符长度
			while(*textArea) {
				if(0 == strncasecmp("</textarea>", textArea, 11)) {
					textArea += 11;         // 偏移 </textarea> 11字符长度
					break;
				}
				++textArea;
			}
			eIndex       += offsetLen = textArea - (istr - 1);
			block         = contentBlock_create_init(req->pool, bIndex, eIndex, TEXTAREA);
			bIndex        = eIndex;
			istr         += offsetLen;
			add(req->pool, blockList, (void *) block);
			break;
		case 'l': // find link
		case 's': // find script
			if('s' == *istr) { //默认是 link
				styleType              = 1;
				tnameEnum              = SCRIPT;
			}
			retIndex = compare(istr, patterns[tnameEnum], patternsLen[tnameEnum], 0);
			if(0 != retIndex) {
				istr++ , eIndex++;
				continue;
			}
			block         = contentBlock_create_init(req->pool, bIndex, --eIndex, tnameEnum);
			add(req->pool, blockList, (void *) block);
			bIndex        = eIndex;
			//parser Tag
			StyleField *styleField = NULL;
			int retLen = parserTag(req, pConfig, styleType, tagBuf, &styleField, istr);
			if(NULL == styleField) { //a error style
				block->eIndex += retLen + 1;
				bIndex         = block->eIndex;
				eIndex         = block->eIndex;
				istr          += retLen;
				continue;
			}

			TagConfig *tagConfig = (TagConfig *) apr_palloc(req->pool, sizeof(TagConfig));
			if(NULL == tagConfig) {
				continue;
			}
			INIT_TAG_CONFIG(tagConfig, req, styleField, pConfig->newDomains[styleField->domainIndex], ctx->debugMode, 0, 0);
			++styleCount; //计数有多少个style

			//IE条件表达式里面的style不能做去重操作
			if(isExpression) {
				styleField->version = getStrVersion(req, styleField->styleUri, pConfig);
				block               = contentBlock_create_init(req->pool, 0, 1, TN_NONE);
				block->cntBlock     = buffer_init_size(req->pool, tagConfig->domain->used + styleField->styleUri->used + 100);
				addExtStyle(block->cntBlock, tagConfig);
				add(req->pool, blockList, (void *) block);
				bIndex              = eIndex += retLen;
				istr               += retLen;
				continue;
			}
			//clean duplicate
			if(!styleField->async && isRepeat(req, duplicates, styleField)) {
				bIndex              = eIndex += retLen;
				istr               += retLen;
				continue;
			}

			buffer *nversion    = getStrVersion(req, styleField->styleUri, pConfig);
			styleField->version = nversion;

			//当没有使用异步并且又没有设置位置则保持原位不动
			if(0 == styleField->async && NONE == styleField->position) {
				block               = contentBlock_create_init(req->pool, 0, 1, TN_NONE);
				block->cntBlock     = buffer_init_size(req->pool, tagConfig->domain->used + styleField->styleUri->used + 100);
				addExtStyle(block->cntBlock, tagConfig);
				add(req->pool, blockList, (void *) block);
				bIndex              = eIndex += retLen;
				istr               += retLen;
				continue;
			}

			/**
			 * ---domains[2]               两个域名
			 *    ---groupsMap[N]          域名下有多个分组，用于对每个分组内容进行隔离（异步和同步的都放在这里面）
			 *       ---styleList[2]       每个分组下面有js、css列表
			 *       |  ---itemList[N]     js/css列表
			 *       |
			 * 输出/合并时根据以下两个List 按顺序输出；（styleList指针为上面注释中所指的 "styleList[2]" 的指针）
			 *    ---syncStyleList         存放所有同步（直接加载）的 styleList指针
			 *    ---asyncStyleList        存放所有异步的 styleList指针
			 *
			 */

			StyleList *styleList = NULL;
			apr_hash_t *groupsMap = domains[styleField->domainIndex];
			if(NULL == groupsMap) {
				domains[styleField->domainIndex] = groupsMap = apr_hash_make(req->pool);
			} else {
				styleList = apr_hash_get(groupsMap, styleField->group->ptr, styleField->group->used);
			}

			if(NULL == styleList || NULL == styleList->list[styleField->styleType]) {
				if(NULL == styleList) {
					styleList = (StyleList *) apr_palloc(req->pool, sizeof(StyleList));
					if(NULL == styleList) {
						//FIXME: 如果内存分配失败，则丢掉当前这个数据
						continue;
					}
					styleList->list[0] = NULL, styleList->list[1] = NULL;
					/**
					 * 将所有的styleList放入相应的 异步和非异步的列表中去。用于输出合并时使用。
					 */
					add(req->pool, (styleField->async == 1 ? asyncStyleList : syncStyleList), styleList);
				}

				LinkedList *itemList = linked_list_create(req->pool);
				if(NULL == itemList) {
					//FIXME: 如果内存分配失败，则丢掉当前这个数据
					continue;
				}

				add(req->pool, itemList, styleField);
				styleList->domainIndex = styleField->domainIndex;
				styleList->group = styleField->group;
				styleList->list[styleField->styleType] = itemList;
				/**
				 * 通过使用hash来控制每个group对应一个list
				 */
				apr_hash_set(groupsMap, styleField->group->ptr, styleField->group->used, styleList);
			} else {
				add(req->pool, styleList->list[styleField->styleType], styleField);
			}

			break;
		case '!':

			/**
			 * 对HTML语法的注释和IE注释表达式的支持
			 *
			 * 1.	<!--[if lt IE 7]> <html class="ie6" lang="en"> <![endif]-->   
			 * 2.	<!--[if IE 7]>    <html class="ie7" lang="en"> <![endif]-->   
			 * 3.	<!--[if IE 8]>    <html class="ie8" lang="en"> <![endif]-->   
			 * 4.	<!--[if IE 9]>    <html class="ie9" lang="en"> <![endif]-->   
			 * 5.	<!--[if gt IE 9]> <html lang="en"> <![endif]--> 
			 * 6.	<!--[if !IE]>-->  <html lang="en"> <!--<![endif]--> 
			 * 7.   <!--  .....  -->
			 *
			 */
			retIndex = compare(istr, patterns[COMMENT_EXPRESSION], patternsLen[COMMENT_EXPRESSION], 0);
			if (0 != retIndex) {
				// 处理IE条件表达式是否结束
				istrTemp = istr + 1;
				if(0 == memcmp(istrTemp , "[endif]", 7)) {
					isExpression = 0;
					istr += 11, eIndex += 11;               //偏移 ![endif]--> 11个字符长度
					continue;
				}
				istr++, eIndex++;                     //偏移 ! 1个字符长度
				continue;
			}
			istr += patternsLen[COMMENT_EXPRESSION];    //偏移 <!-- 4个长度
			eIndex += patternsLen[COMMENT_EXPRESSION];

			// 对第6种语法结束进行判断处理
			if(0 == memcmp(istr, "<![endif]", 9)) {
				isExpression = 0;
				istr += 12, eIndex += 12;
				continue;
			}

			// 处理当前是否为IE表达式开始
			if(0 == memcmp(istr, "[if", 3)) {
				isExpression = 1;
				istr += 8, eIndex += 8;                     //偏移 [if IE]> 8个字符“以最小集的长度来换算，其它 eq IE9/ge IE6则忽略”
				continue;
			}

			// 处理当前是一段 HTML 解释语法
			while(*istr) {
				if (0 == memcmp(istr, "-->", 3)) {
					istr += 2, eIndex += 2;                 // 偏移 --> 3个字符长度，由于当前已经是-所以只需要偏移2位
					break;
				}
				istr++, eIndex++;
			}
			break;
		case 'i':
			//<img
			istr++, eIndex++;
			break;
		default:
			istr++, eIndex++;
			break;
		}
	}

	block         = contentBlock_create_init(req->pool, bIndex, eIndex, TN_NONE);
	add(req->pool, blockList, (void *) block);
	//test
	ListNode *node = blockList->first;
	for(; NULL != node; node = node->next) {
		ContentBlock *tb = (ContentBlock *) node->value;
		int toffsetLen =  tb->eIndex - tb->bIndex;
		char *buf = apr_palloc(req->pool, toffsetLen);
		memcpy(buf, input+tb->bIndex, toffsetLen);
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, req->server, "[%s]", buf);
	}
	return styleCount;
}

static int putValueToBuffer(buffer *buf, char *str) {
	if(NULL == buf || NULL == str) {
		return 0;
	}
	buf->ptr   = str;
	buf->used  = strlen(str);
	buf->size  = buf->used;
	return 1;
}

static void *configServerCreate(apr_pool_t *p, server_rec *s) {
	CombineConfig *pConfig = apr_palloc(p, sizeof(CombineConfig));
	if(NULL == pConfig) {
		return NULL;
	}
	JS_TAG_EXT_PREFIX_LEN  = strlen(JS_TAG_EXT_PREFIX_TXT);
	JS_TAG_EXT_SUFFIX_LEN  = strlen(JS_TAG_EXT_SUFFIX_TXT);

	JS_TAG_PREFIX_LEN      = strlen(JS_TAG_PREFIX_TXT);
	JS_TAG_SUFFIX_LEN      = strlen(JS_TAG_SUFFIX_TXT);

	CSS_PREFIX_LEN         = strlen(CSS_PREFIX_TXT);
	CSS_SUFFIX_LEN         = strlen(CSS_SUFFIX_TXT);

	DEBUG_MODE_LEN         = strlen(DEBUG_MODE);

	svsEntry.mtime         = 0;
	svsEntry.newPool       = NULL; svsEntry.oldPool = NULL;
	svsEntry.styleHTable   = NULL;

	pConfig->enabled       = 1;
	pConfig->printLog      = 0;
	pConfig->filterCntType = "text/htm;text/html";
	pConfig->appName       = NULL;
	int i = 0;
	for(i = 0; i < DOMAIN_COUNTS; i++) {
		pConfig->oldDomains[i] = NULL;
		pConfig->newDomains[i] = NULL;
	}

	for(i = 0; i < 6; i++) {
		patternsLen[i] = strlen(patterns[i]);
	}

	char *variableNames    = "styleDomain0;styleDomain1;";
	stringSplit(p, DOMAIN_COUNTS, pConfig->asyncVariableNames, variableNames, ';');

	pConfig->blackList     = linked_list_create(p);
	pConfig->whiteList     = linked_list_create(p);
	/**
	 * see http://support.microsoft.com/kb/208427/EN-US
	 * default len for ie 2083 char
	 */
	pConfig->maxUrlLen     = 1500;

	for(i = 0; i < 2; i++) {
		styleParserTags[i] = apr_palloc(p, sizeof(StyleParserTag));
		if(NULL == styleParserTags[i]) {
			return NULL;
		}
	}
	StyleParserTag *cssPtag = styleParserTags[0], *jsPtag = styleParserTags[1];

	//==css config==
	buffer *cssPrefix = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(cssPrefix, "<link")) {
		return NULL;
	}
	buffer *cssRefTag  = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(cssRefTag, " href=")) {
		return NULL;
	}
	buffer *cssCloseTag  = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(cssCloseTag, ">")) {
		return NULL;
	}
	buffer *cssMark  = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(cssCloseTag, "stylesheet")) {
		return NULL;
	}
	cssPtag->prefix = cssPrefix;
	cssPtag->mark = cssMark;
	cssPtag->refTag = cssRefTag;
	cssPtag->suffix = '>';
	cssPtag->closeTag = cssCloseTag;
	cssPtag->styleType = 0;

	// === js config ===
	buffer *jsPrefix       = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(jsPrefix, "<script")) {
		return NULL;
	}
	buffer *jsCloseTag     = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(jsCloseTag, "</script>")) {
		return NULL;
	}
	buffer *jsMark         = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(jsMark, "src")) {
		return NULL;
	}
	buffer *jsRefTag       = apr_palloc(p, sizeof(buffer));
	if(!putValueToBuffer(jsRefTag, " src=")) {
		return NULL;
	}
	jsPtag->prefix         = jsPrefix;
	jsPtag->mark           = jsMark;
	jsPtag->refTag         = jsRefTag;
	jsPtag->suffix         = '>';
	jsPtag->closeTag       = jsCloseTag;
	jsPtag->styleType      = 1;

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
	 * 2 black & white list
	 */
	/**
		黑名单
		  在黑名单里找到，不使用模块
		  在黑名单里没有找到，使用模块
		白名单
		  在白名单里找到，使用模块
		  在白名单里没有找到，不使用模块

		黑白名单都有 优先使用黑名单
		黑白名单都没有  使用模块
	 */
	if(pConfig->blackList->size > 0) {
		if(uriFilter(r, pConfig->blackList)) {
			return ap_pass_brigade(f->next, pbbIn);
		}
	}
	if(pConfig->whiteList->size > 0) {
		if(!uriFilter(r, pConfig->whiteList)) {
			return ap_pass_brigade(f->next, pbbIn);
		}
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

		apr_table_unset(r->headers_out, "Content-Length");
		apr_table_unset(r->headers_out, "Content-MD5");
		//set debugMode value
		ctx->debugMode = debugMode;
	}

	//FIXME:保留trunked传输方式
	apr_bucket *pbktIn = NULL;
	for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
	            pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
	            pbktIn = APR_BUCKET_NEXT(pbktIn)) {
		if(APR_BUCKET_IS_EOS(pbktIn)) {
			int pstatus = htmlParser(r, ctx, pConfig);
			if(0 == pstatus) {  //FIXME: 没有找到任何的style，则直接保持原来的数据输出，不需要做任何变化

			}
			addBucket(r->connection, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
			//append EOS
			APR_BRIGADE_INSERT_TAIL(ctx->pbbOut, pbktIn);
			apr_table_setn(r->notes, STYLE_COMBINE_NAME, "ok");
			return ap_pass_brigade(f->next, ctx->pbbOut);
		}
		const char *data;
		apr_size_t  len;
		apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);
		STRING_APPEND(r->pool, ctx->buf, (char *) data, len);
		apr_bucket_delete(pbktIn);
	}
	return OK;
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
	int appNameLen = 0;
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (appNameLen = strlen(arg)) <= 1) {
		return "styleCombine appName can't be null OR empty";
	} else {
		pConfig->appName = buffer_init_size(cmd->pool, appNameLen);
		STRING_APPEND(cmd->pool, pConfig->appName, (char *) arg, appNameLen);
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

static int parseargline(char *str, char **pattern) {
    char quote;
    while (apr_isspace(*str)) {
        ++str;
    }
    /*
     * determine first argument
     */
    quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
    *pattern = str;
    for (; *str; ++str) {
        if ((apr_isspace(*str) && !quote) || (*str == quote)) {
            break;
        }
        if (*str == '\\' && apr_isspace(str[1])) {
            ++str;
            continue;
        }
    }
    if (!*str) {
        return 1;
    }
    *str++ = '\0';
    return 0;
}

static const char *setBlackList(cmd_parms *cmd, void *in_dconf, const char *arg) {
	if(NULL == arg) {
		return NULL;
	}
	ap_regex_t *regexp;
	char *str = apr_pstrdup(cmd->pool, arg);
	CombineConfig * pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	char *pattern = NULL;
	parseargline(str, &pattern);
	regexp = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED);
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
	char *str = apr_pstrdup(cmd->pool, arg);
	CombineConfig * pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	char *pattern = NULL;
	parseargline(str, &pattern);
	regexp = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED);
	if (!regexp) {
		return apr_pstrcat(cmd->pool, "whiteList: cannot compile regular expression '", str, "'", NULL);
	}
	add(cmd->pool, pConfig->whiteList, regexp);
	return NULL;
}

static const command_rec styleCombineCmds[] =
{
		AP_INIT_FLAG("scEnabled", setEnabled, NULL, OR_ALL, "open or close this module"),

		AP_INIT_TAKE1("scAppName", setAppName, NULL, OR_ALL, "app name"),

		AP_INIT_TAKE1("scFilterCntType", setFilterCntType, NULL, OR_ALL, "filter content type"),

		AP_INIT_TAKE1("scOldDomains", setOldDomains, NULL, OR_ALL, "style old domain url"),

		AP_INIT_TAKE1("scNewDomains", setNewDomains, NULL, OR_ALL, "style new domain url"),

		AP_INIT_TAKE1("scAsyncVariableNames", setAsyncVariableNames, NULL, OR_ALL, "the name for asynStyle of variable"),

		AP_INIT_TAKE1("scMaxUrlLen", setMaxUrlLen, NULL, OR_ALL, "url max len default is IE6 length support"),

		AP_INIT_TAKE1("scPrintLog", setPrintLog, NULL, OR_ALL, " set printLog level"),

		AP_INIT_TAKE1("scVersionFilePath", setVersionFilePath, NULL, OR_ALL, "style versionFilePath dir"),

		AP_INIT_RAW_ARGS("scBlackList", setBlackList, NULL, OR_ALL, "style versionFilePath dir"),

		AP_INIT_RAW_ARGS("scWhiteList", setWhiteList, NULL, OR_ALL, "style versionFilePath dir"),

		{ NULL }
};

static int configRequired(server_rec *s, char *name, void * value) {
	if(NULL == value) {
		ap_log_error(APLOG_MARK, LOG_ERR, 0, s, "mod_styleCombine config [%s] value can't be null or empty", name);
		return 1;
	}
	return 0;
}
static apr_status_t styleCombine_post_conf(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *tmp, server_rec *s) {
	CombineConfig *pConfig = ap_get_module_config(s->module_config, &styleCombine_module);
	if(NULL == pConfig || 0 == pConfig->enabled) {
		return OK;
	}
	ap_add_version_component(p, MODULE_BRAND);
	int resultCount = 0;

	resultCount += configRequired(s, "scPconfig", pConfig);
	if(resultCount) {
		return !OK;
	}
	resultCount += configRequired(s, "scAppName", pConfig->appName->ptr);
	resultCount += configRequired(s, "scFilterCntType", pConfig->filterCntType);
	resultCount += configRequired(s, "scVersionFilePath", pConfig->versionFilePath);
	int i = 0, domainCount = 0;
	for(i = 0; i < DOMAIN_COUNTS; i++) {
		if(NULL == pConfig->newDomains[i] && NULL == pConfig->oldDomains[i]) {
			continue;
		}
		if(pConfig->newDomains[i] && pConfig->oldDomains[i]) {
			++domainCount;
			continue;
		}
		resultCount += configRequired(s, "scNewDomains", pConfig->newDomains[i]);
		resultCount += configRequired(s, "scOldDomains", pConfig->oldDomains[i]);
	}
	for(i = 0; i < domainCount; i++) {
		resultCount += configRequired(s, "scAsyncVariableNames", pConfig->asyncVariableNames[i]);
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
