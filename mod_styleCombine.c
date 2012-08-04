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

#define MODULE_BRAND "styleCombine/1.0.0"
#define EXT_JS ".js"
#define EXT_CSS ".css"
#define URI_SEPARATOR "|"
#define FIELD_POSITION "pos=" //position
#define POSITION_LEN 4
#define POSITION_TOP "top"
#define POSITION_HEAD "head"
#define POSITION_FOOTER "footer"
#define DEBUG_MODE "_debugMode_="
#define RUN_MODE_STATUS "dis"
#define JS_PREFIX_TXT "<script type=\"text/javascript\" src=\""
#define JS_SUFFIX_TXT "\"></script>"
#define CSS_PREFIX_TXT "<link rel=\"stylesheet\" href=\""
#define CSS_SUFFIX_TXT "\" />"

#define URI_VERSION_LEN  30
#define BUFFER_PIECE_SIZE 128
#define DEFAULT_CONTENT_LEN (1024 << 10)// default html content size 1M

int JS_PREFIX_TXT_LEN = 0;
int JS_SUFFIX_TXT_LEN = 0;
int CSS_PREFIX_TXT_LEN = 0;
int CSS_SUFFIX_TXT_LEN = 0;
int DEBUG_MODE_LEN = 12;

/***********global variable************/
const char ZERO_END = '\0';
/*position char */
enum PositionEnum{TOP, HEAD, FOOTER, NONE};

int styleTableSize = 40000;

volatile apr_pool_t   *globalPool = NULL;
volatile apr_table_t  *styleTable = NULL;
volatile apr_time_t    lastLoadTime;
volatile __time_t      prevTime = 0;
char                  *appRunMode = NULL;


typedef struct {
	char *ptr;
	off_t used;
	off_t size;
} buffer;

typedef struct {
	buffer *prefix;
	buffer *mark;
	buffer *closeTag;
	char    suffix;
	/*0:表示css; 1:表示js*/
	char    styleType;
} ParserTag;

ParserTag             *cssPtag;
ParserTag             *jsPtag;
server_rec            *server;

typedef struct {
	int        enabled;
	char      *filterCntType;
	buffer    *oldDomain;
	buffer    *newDomain;
	char      *versionFilePath;
	int        maxUrlLen;
	int        logMode;
	char      *appName;
	int        enableFilterURLParams;
	//style combined auto not impl yet
//	int        delBlankSpace;
//	int        styleIsCombined;
} CombineConfig;

typedef struct {
	int                 debugMode;
	buffer             *buf;
    apr_bucket_brigade *pbbOut;
} CombineCtx;

typedef struct {
	enum PositionEnum postion;
	buffer           *styleUri;
	time_t            version;
	int               size;
	struct StyleLinkList *prevItem;
} StyleLinkList;

typedef struct {
	buffer *topBuf;
	buffer *headBuf;
	buffer *footerBuf;
} CombinedStyle;

static void printf_log(buffer *buf, char *str) {
//	char strBuf[10240];
//	memset(strBuf,0,10240);
//	sprintf(&strBuf,str,buf,buf->ptr,buf->size,buf->used);
//	ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "%s", strBuf);
	return ;
}

buffer *buffer_init() {
	buffer *buf = malloc(sizeof(buffer));
	if(NULL == buf) {
		return buf;
	}
	buf->ptr = NULL;
	buf->used = 0;
	buf->size = 0;
	printf_log(buf, "buffer_init: buf=%p  ptr=%p size=%ld used=%ld");
	return buf;
}

void buffer_free(buffer *b) {
	if(NULL == b) {
		return;
	}
	printf_log(b, "buffer_free: buf=%p  ptr=%p size=%ld used=%ld");
	free(b->ptr);
	free(b);
	return;
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
	printf_log(buf, "buffer_init_size: buf=%p  ptr=%p size=%ld used=%ld");
	return buf;
}

void buffer_clean(buffer *buf) {
	if(NULL == buf) {
		return;
	}
	buf->used = 0;
	buf->ptr[0]=ZERO_END;
}

void combinedStyle_free(CombinedStyle *c) {
	if(NULL == c) {
		return;
	}
	buffer_free(c->footerBuf);
	buffer_free(c->headBuf);
	buffer_free(c->topBuf);
	return;
}

/**
 * get uri extention
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
		printf_log(buf, "stringAppend malloc: buf=%p  ptr=%p size=%ld used=%ld");
	}
	if(buf->used + strLen >= buf->size) {
		printf_log(buf, "stringAppend old realloc: buf=%p  ptr=%p size=%ld used=%ld");
		buf->size += (strLen + BUFFER_PIECE_SIZE);
		buf->ptr = realloc(buf->ptr, buf->size);
		printf_log(buf, "stringAppend new realloc: buf=%p  ptr=%p size=%ld used=%ld");
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

time_t getURIVersion(buffer *uri, char *singleUri, request_rec *r, CombineConfig *pConfig) {
	if(NULL == uri || NULL == singleUri) {
		return 0;
	}

	time_t newVersion = 0;
	char *fileExt = getFileExt(uri->ptr, uri->used);
	if (NULL == fileExt) {
		return 0;
	}
	int uriLen = uri->used;

	if(NULL == styleTable) {
		time(&newVersion);
		newVersion = newVersion / 600;

		uri->ptr[uri->used] = ZERO_END;
		// add log
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		  "=method=getURIVersion err, urls:[%s] requestURI:[%s]", uri->ptr, r->unparsed_uri);

		return newVersion;
	}

	int i , t = 0;
	for(i = 0; i < uriLen; ++i, ++t) {
		if(i != 0 && 0 == memcmp(&uri->ptr[i], URI_SEPARATOR, 1)) {
			singleUri[t] = ZERO_END;
		} else {
			singleUri[t] = uri->ptr[i];
			if((i + 1) != uriLen) {
				continue;
			}
			singleUri[++t] = ZERO_END;
		}
		if (NULL == getFileExt(singleUri, t)) {
			memcpy(singleUri + t, fileExt, strlen(fileExt));
		}
		t = -1;
		if(NULL != styleTable) {
			const char *strVs = apr_table_get(styleTable, singleUri);
			if(NULL != strVs) {
				newVersion += atol(strVs);
			} else {
				// add log
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				"==method=getURIVersion err, uris[%s]  uri:[%s]  requestURI:[%s]", uri->ptr, singleUri, r->unparsed_uri);
			}
		}
	}
	if (newVersion <= 0) {
		time(&newVersion);
		newVersion = newVersion / 600;
	}
	return newVersion;
}

static enum PositionEnum strToPosition(char *str) {
	if(NULL == str) {
		return NONE;
	}
	if (0 == strncmp(POSITION_TOP, str, 3)) {
		return TOP;
	}
	if (0 == strncmp(POSITION_HEAD, str, 4)) {
		return HEAD;
	}
	if (0 == strncmp(POSITION_FOOTER, str, 6)) {
		return FOOTER;
	}
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
	struct timeval tv;
	if(NULL == pConfig->versionFilePath) {
		return;
	}
	gettimeofday(&tv, NULL);
	if(0 != prevTime && (tv.tv_sec - prevTime) <= intervalSecd) {
		return;
	}
	prevTime = tv.tv_sec;
	apr_status_t rc = apr_stat(&finfo, pConfig->versionFilePath, APR_FINFO_MIN, pool);

	if(APR_SUCCESS == rc && finfo.mtime != lastLoadTime) {
		if(pConfig->logMode) {
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
			styleTable = newTable;
			apr_pool_t *oldPool = globalPool;
			globalPool = newPool;
			//free old pool
			if(NULL != oldPool) {
				apr_pool_destroy(oldPool);
			}
			appRunMode = apr_table_get(styleTable, pConfig->appName);
		}
		apr_file_close(fd);
	}
	return;
}

static int tagFilter(CombineConfig *pConfig, ParserTag *ptag, char *maxTagBuf, buffer *maxUrlBuf) {
	if(NULL == pConfig || NULL == ptag || NULL == maxTagBuf || NULL == maxUrlBuf) {
		return 0;
	}
	if (NULL == strstr(maxTagBuf, ptag->mark->ptr)) {
		//表示是一个非 css / javascript 文件引用，则跳过处理
		return 0;
	}
	char *curURLDomain = strstr(maxTagBuf, pConfig->oldDomain->ptr);
	if (NULL == curURLDomain) {
		//对于没有域名的css/js不进行处理
		return 0;
	}
	maxUrlBuf->used = 0;
	curURLDomain += pConfig->oldDomain->used;
	register int i = 0, hasDo = 0;
	register char tmpChr;
	for (; (tmpChr = curURLDomain[i]) != ptag->suffix
			&& tmpChr != '\"'
			&& tmpChr != '\''
			&& (i < pConfig->maxUrlLen); ++i) {

		if(isspace(tmpChr)) {
			continue;
		}
		maxUrlBuf->ptr[maxUrlBuf->used++] = tmpChr;
		if ('.' == tmpChr) {
			++hasDo;
		}
	}
	if (!hasDo) {
		//no .js/.css ext
		return 0;
	}
	maxUrlBuf->ptr[maxUrlBuf->used] = ZERO_END;
	return maxUrlBuf->used;
}

static void addTag(CombineConfig *pConfig, int styleType, buffer *destBuf,
									buffer *uri, time_t version, int newLine, int needExt) {
	if(NULL == destBuf || NULL == uri || !uri->used) {
		return ;
	}
	//add new line
	if(newLine) {
		stringAppend(destBuf, "\n", 1);
	}
	if (0 == styleType) {
		stringAppend(destBuf, CSS_PREFIX_TXT, CSS_PREFIX_TXT_LEN);
	} else {
		stringAppend(destBuf, JS_PREFIX_TXT, JS_PREFIX_TXT_LEN);
	}
	stringAppend(destBuf, pConfig->newDomain->ptr, pConfig->newDomain->used);
	stringAppend(destBuf, uri->ptr, uri->used);

	//append ext
	if(needExt) {
		//append the version ext
		if (0 == styleType) {
			stringAppend(destBuf, EXT_CSS, 4);
		} else {
			stringAppend(destBuf, EXT_JS, 3);
		}
	}
	//append version
	char strVersion[URI_VERSION_LEN];
	snprintf(strVersion, URI_VERSION_LEN - 1, "?_v=%ld", version);
	stringAppend(destBuf, strVersion , strlen(strVersion));

	//append the version ext
	if (0 == styleType) {
		stringAppend(destBuf, EXT_CSS, 4);
		stringAppend(destBuf, CSS_SUFFIX_TXT, CSS_SUFFIX_TXT_LEN);
	} else {
		stringAppend(destBuf, EXT_JS, 3);
		stringAppend(destBuf, JS_SUFFIX_TXT, JS_SUFFIX_TXT_LEN);
	}
	//destBuf->ptr[destBuf->used] = ZERO_END;
	return;
}

/**
 * 将js/css列表合并成一个url,并放到相应的位置上去
 */
static void combineStyles(CombineConfig *pConfig, int styleType, StyleLinkList *linkList,
								CombinedStyle *combinedStyle, CombinedStyle *tmpCombine) {
	if(NULL == linkList) {
		return;
	}
	register time_t topVersion = 0, headVersion = 0, footerVersion = 0;
	register int top = 0, head = 0, footer = 0;
	register buffer *tmpUriBuf = NULL;

	for (; NULL != linkList; linkList = linkList->prevItem) {
		switch (linkList->postion) {
			case TOP: //top
				topVersion += linkList->version;
				tmpUriBuf = tmpCombine->topBuf;
				if (top > 0) {
					stringAppend(tmpUriBuf, URI_SEPARATOR, 1);
					break;
				}
				top = 1;
				break;
			case HEAD: //head
				headVersion += linkList->version;
				tmpUriBuf = tmpCombine->headBuf;
				if (head > 0) {
					stringAppend(tmpUriBuf, URI_SEPARATOR, 1);
					break;
				}
				head = 1;
				break;
			case FOOTER: //footer
				footerVersion += linkList->version;
				tmpUriBuf = tmpCombine->footerBuf;
				if (footer > 0) {
					stringAppend(tmpUriBuf, URI_SEPARATOR, 1);
					break;
				}
				footer = 1;
				break;
			default:
				break;
		}
		//url拼接在一起的长度超过配置的长度，则需要分成多个请求来处理。
		int urlLen = (pConfig->newDomain->used + tmpUriBuf->used + linkList->styleUri->used);
		if (urlLen >= pConfig->maxUrlLen) {
			//将合并的url最后一个|字符去除
			tmpUriBuf->ptr[--tmpUriBuf->used] = ZERO_END;
			switch(linkList->postion) {
				case TOP:
					addTag(pConfig, styleType, combinedStyle->topBuf, tmpUriBuf, topVersion, 1, 1);
					topVersion = 0;
					break;
				case HEAD:
					addTag(pConfig, styleType, combinedStyle->headBuf, tmpUriBuf, headVersion, 1, 1);
					headVersion = 0;
					break;
				case FOOTER:
					addTag(pConfig, styleType, combinedStyle->footerBuf, tmpUriBuf, footerVersion, 1, 1);
					footerVersion = 0;
					break;
				default:
					break;
			}
			//reset value
			tmpUriBuf->used = 0;
		}

		if(0 == styleType) {
			linkList->styleUri->used -= 4; // clean .css ext
		} else {
			linkList->styleUri->used -= 3; // clean .js ext
		}
		stringAppend(tmpUriBuf, linkList->styleUri->ptr, linkList->styleUri->used);
	}
	addTag(pConfig, styleType, combinedStyle->topBuf, tmpCombine->topBuf, topVersion, 1, 1);
	addTag(pConfig, styleType, combinedStyle->headBuf, tmpCombine->headBuf, headVersion, 1, 1);
	addTag(pConfig, styleType, combinedStyle->footerBuf, tmpCombine->footerBuf, footerVersion, 1, 1);
	return;
}

/**
 * 用于开发时，打开调试模块调用。将js/css的位置做移动，但不做合并
 */
static void combineStylesDebug(CombineConfig *pConfig, int styleType, StyleLinkList *linkList,
								CombinedStyle *combinedStyle) {
	if(NULL == linkList) {
		return;
	}
	for (; NULL != linkList; linkList = linkList->prevItem) {
		switch (linkList->postion) {
			case TOP: //top
				addTag(pConfig, styleType, combinedStyle->topBuf, linkList->styleUri, linkList->version, 1, 0);
				break;
			case HEAD: //head
				addTag(pConfig, styleType, combinedStyle->headBuf, linkList->styleUri, linkList->version, 1, 0);
				break;
			case FOOTER: //footer
				addTag(pConfig, styleType, combinedStyle->footerBuf, linkList->styleUri, linkList->version, 1, 0);
				break;
			default:
				break;
		}
	}
	return;
}

static int isRepeat(apr_hash_t *duplicats, buffer *buf) {
	if(NULL == duplicats) {
		return 0;
	}
	if(NULL != apr_hash_get(duplicats, buf->ptr, buf->used)) {
		//if uri has exsit then skiping it
		return 1;
	}
	apr_hash_set(duplicats, buf->ptr, buf->used, "0");
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
static void resetHtml(conn_rec *c, apr_bucket_brigade *pbbkOut,
						CombinedStyle *combinedStyle, buffer *buf) {
	if(NULL== buf || NULL == buf->ptr) {
		return;
	}
	char *sourceHtml = buf->ptr;

	int index = 0;
	char *headIndex = strstr(sourceHtml, "</head>");
	if(NULL != headIndex) {
		addBucket(c, pbbkOut, sourceHtml, (index = headIndex - sourceHtml));
	}
	addBucket(c, pbbkOut, combinedStyle->topBuf->ptr, combinedStyle->topBuf->used);
	addBucket(c, pbbkOut, combinedStyle->headBuf->ptr, combinedStyle->headBuf->used);

	char *endHtmlIndex = buf->ptr + buf->used;
	char *middleIndex = (sourceHtml + index);
	char *footerIndex = strstr(middleIndex, "</body>");
	if(NULL != footerIndex) {
		addBucket(c, pbbkOut, middleIndex, (footerIndex - middleIndex));
		addBucket(c, pbbkOut, combinedStyle->footerBuf->ptr, combinedStyle->footerBuf->used);
		addBucket(c, pbbkOut, footerIndex, (endHtmlIndex - footerIndex));
	} else {
		addBucket(c, pbbkOut, middleIndex, (endHtmlIndex - middleIndex));
		addBucket(c, pbbkOut, combinedStyle->footerBuf->ptr, combinedStyle->footerBuf->used);
	}
	return;
}

static inline char *strSearch(const char * str1, char **matchedType, char **isExpression) {
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
					*matchedType = "j"; //js
					break;
				case 'l': //link
					r = memcmp("ink", ++s1, 3);
					*matchedType = "c"; //css
					break;
				case '!':
					if (0 == memcmp("--", ++s1, 2)) {
						if ('[' == *(s1 + 2)) {
							cp += 12; //skip "<!--[if IE]>"
							*isExpression = "1";
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
						*isExpression = "0";
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

static int htmlParser(request_rec *r, CombinedStyle *combinedStyle, buffer *dstBuf, CombineConfig *pConfig, CombineCtx *ctx) {

	char *maxTagBuf = apr_palloc(r->pool, pConfig->maxUrlLen + 100);
	if(NULL == maxTagBuf) {
		return 0;
	}
	buffer *maxUrlBuf = buffer_init_size(pConfig->maxUrlLen);
	if(NULL == maxUrlBuf) {
		return 0;
	}
	apr_hash_t *duplicates = apr_hash_make(r->pool);
	StyleLinkList *jsLinkList = NULL;
	StyleLinkList *cssLinkList = NULL;
	StyleLinkList *jsPrevLinkList = NULL;
	StyleLinkList *cssPrevLinkList = NULL;

	char *subHtml = ctx->buf->ptr;
	int maxTagSize = (pConfig->maxUrlLen + 98);
	char *matchedType = NULL;
	char *isExpression = "0";
	//(js/css)应该放置的位置 h:head; f:footer; l:lib(表示公共类库，放在<head>里面)
	register enum PositionEnum position = HEAD;
	register int isProcessed = 0;
	register ParserTag *ptag = NULL;
	register int i = 0;
	register char *curPoint = NULL;
	register char *tmpPoint = NULL;

	while (NULL != (curPoint = strSearch(subHtml, &matchedType, &isExpression))) {

		position = HEAD; //set HEAD detault pos
		tmpPoint = curPoint;

		stringAppend(dstBuf, subHtml, curPoint - subHtml);
		//此时表示当前是js文件，需要使用js的标签来处理
		if(0 == memcmp(matchedType, "j", 1)) {
			ptag = jsPtag;
		} else {
			ptag = cssPtag;
		}
		for (i = 0; (curPoint[i] != ptag->suffix) && i < maxTagSize; i++) {
			maxTagBuf[i] = curPoint[i];
		}
		maxTagBuf[i++] = ptag->suffix;
		curPoint += i;
		maxTagBuf[i] = ZERO_END;
		if (0 == tagFilter(pConfig, ptag, maxTagBuf, maxUrlBuf)) {
			stringAppend(dstBuf, maxTagBuf, i);
			subHtml = curPoint;
			continue;
		}
		isProcessed = 1;

		//清除uri后面带的参数
		if(pConfig->enableFilterURLParams) {
			char *paramPos = strchr(maxUrlBuf->ptr, '?');
			if(NULL != paramPos) {
				int index = paramPos - maxUrlBuf->ptr;
				maxUrlBuf->ptr[index] = ZERO_END;
				maxUrlBuf->used = index;
			}
		}

		//拿uri去获取版本号，url有可以是用户已经拼好的，需要做拆分后再获取版本
		buffer *styleUriBuf = apr_palloc(r->pool, sizeof(buffer));
		if(NULL == styleUriBuf) {
			continue;
		}
		styleUriBuf->used = 0;
		styleUriBuf->size = maxUrlBuf->used + 1;
		styleUriBuf->ptr = apr_palloc(r->pool, styleUriBuf->size);

		time_t nversion = getURIVersion(maxUrlBuf, styleUriBuf->ptr, r, pConfig);

		stringAppend(styleUriBuf, maxUrlBuf->ptr, maxUrlBuf->used);

		if (1 == ptag->styleType) {
			/**
			 * js 的特殊处理，需要将结束符找出来，</script>
			 * 结束符中间可能有空格或制表符，所以忽略这些
			 * 如果没有结束符，将不进行处理.
			 */
			for(; (isspace(*curPoint) && *curPoint != ZERO_END); curPoint++);

			if (memcmp(ptag->closeTag->ptr, curPoint, ptag->closeTag->used) != 0) {
				//找不到结束的</script>
				stringAppend(dstBuf, maxTagBuf, i);
				subHtml = curPoint;
				continue;
			}
			curPoint += ptag->closeTag->used;

			if(isRepeat(duplicates, styleUriBuf)) {
				subHtml = curPoint;
				continue;
			}
			//parser field
			char *fpois = strstr(maxTagBuf, FIELD_POSITION);
			if(NULL != fpois) {
				fpois += POSITION_LEN + 1;
				position = strToPosition(fpois);
			} else {
				position = NONE;
			}

			if (NONE == position) {
				addTag(pConfig, ptag->styleType, dstBuf, maxUrlBuf, nversion, 0, 0);
				subHtml = curPoint;
				continue;
			}
		} else {
			if(isRepeat(duplicates, styleUriBuf)) {
				subHtml = curPoint;
				continue;
			}
		}
		//process expression <!--[if IE]>
		if(0 == memcmp(isExpression, "1", 1)) {
			addTag(pConfig, ptag->styleType, dstBuf, maxUrlBuf, nversion, 0, 0);
			subHtml = curPoint;
			continue;
		}

		//is combined tag string
		if (NULL != strstr(maxUrlBuf->ptr, URI_SEPARATOR)) {
			switch (position) {
				case TOP: //top
					addTag(pConfig, ptag->styleType, combinedStyle->topBuf, maxUrlBuf, nversion, 1, 0);
					break;
				case HEAD://head
					addTag(pConfig, ptag->styleType, combinedStyle->headBuf, maxUrlBuf, nversion, 1, 0);
					break;
				case FOOTER://footer
					addTag(pConfig, ptag->styleType, combinedStyle->footerBuf, maxUrlBuf, nversion, 1, 0);
					break;
				default:
					break;
			}
		} else {
			//add to linkList
			StyleLinkList *linkItem = apr_palloc(r->pool, sizeof(StyleLinkList));
			if(NULL == linkItem) {
				continue;
			}
			linkItem->prevItem = NULL;

			linkItem->styleUri = styleUriBuf;
			linkItem->postion = position;
			linkItem->version = nversion;
			if(0 == ptag->styleType) {
				if (NULL == cssLinkList) {
					cssLinkList = linkItem;
					cssLinkList->size = 0;
				} else {
					cssPrevLinkList->prevItem = linkItem;
				}
				++cssLinkList->size;
				cssPrevLinkList = linkItem;
			} else {
				if (NULL == jsLinkList) {
					jsLinkList = linkItem;
					jsLinkList->size = 0;
				} else {
					jsPrevLinkList->prevItem = linkItem;
				}
				++jsLinkList->size;
				jsPrevLinkList = linkItem;
			}
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
		stringAppend(dstBuf, subHtml, subHtmlLen);

		if(0 == ctx->debugMode) {
			//create
			int combinBufSize = 0;
			if(NULL != cssLinkList && cssLinkList->size > 0) {
				combinBufSize = cssLinkList->size;
			}
			if(NULL != jsLinkList && jsLinkList->size > combinBufSize) {
				combinBufSize = jsLinkList->size;
			}
			combinBufSize *= 50;

			CombinedStyle tmpCombine;
			tmpCombine.topBuf = buffer_init_size(combinBufSize);
			tmpCombine.headBuf = buffer_init_size(combinBufSize);
			tmpCombine.footerBuf = buffer_init_size(combinBufSize);
			if(!tmpCombine.topBuf || !tmpCombine.headBuf || !tmpCombine.footerBuf) {
				//app has error now skip this processer
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "if(isProcessed){has Error}:[%s]", r->unparsed_uri);
				return 0;
			}
			combineStyles(pConfig, cssPtag->styleType, cssLinkList, combinedStyle, &tmpCombine);
			//reset
			buffer_clean(tmpCombine.topBuf);
			buffer_clean(tmpCombine.headBuf);
			buffer_clean(tmpCombine.footerBuf);
			combineStyles(pConfig, jsPtag->styleType, jsLinkList, combinedStyle, &tmpCombine);
			//free
			combinedStyle_free(&tmpCombine);
		} else if(2 == ctx->debugMode){
			//debug mode 2
			combineStylesDebug(pConfig, cssPtag->styleType, cssLinkList, combinedStyle);
			combineStylesDebug(pConfig, jsPtag->styleType, jsLinkList, combinedStyle);
		}
	}
	if(NULL != duplicates) {
		apr_hash_clear(duplicates);
	}
	if(0 != dstBuf->size) {
		dstBuf->ptr[dstBuf->used] = ZERO_END;
	}
	buffer_free(maxUrlBuf);
	return isProcessed;
}

static void *configServerCreate(apr_pool_t *p, server_rec *s) {

	CombineConfig *pConfig = apr_palloc(p, sizeof(CombineConfig));
	if(NULL == pConfig) {
		return NULL;
	}
	JS_PREFIX_TXT_LEN = strlen(JS_PREFIX_TXT);
	JS_SUFFIX_TXT_LEN = strlen(JS_SUFFIX_TXT);
	CSS_PREFIX_TXT_LEN = strlen(CSS_PREFIX_TXT);
	CSS_SUFFIX_TXT_LEN = strlen(CSS_SUFFIX_TXT);

	pConfig->enabled = 0;
	pConfig->logMode = 0;
	pConfig->enableFilterURLParams = 0;
	pConfig->filterCntType = NULL;
	pConfig->appName = "modCombine";
	/**
	 * see http://support.microsoft.com/kb/208427/EN-US
	 * default len for ie 2083 char
	 */
	pConfig->maxUrlLen = 2083;
	pConfig->oldDomain = apr_palloc(p, sizeof(buffer));
	if(NULL == pConfig->oldDomain) {
		return NULL;
	}
	pConfig->newDomain = apr_palloc(p, sizeof(buffer));
	if(NULL == pConfig->newDomain) {
		return NULL;
	}
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

	jsPtag->prefix = jsPrefix;
	jsPtag->mark = jsMark;
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
	if(r->content_type && r->content_type[0]) {
		char *contentType = apr_pstrdup(r->pool, r->content_type);
		char *pt = contentType;
		for(; pt && *pt; ++pt) {
			if ((';' != *pt) && (' ' != *pt)) {
				*pt = tolower(*pt);
				continue;
			}
			*pt = ';';
			*(++pt) = ZERO_END;
			break;
		}
		if(!strstr(pConfig->filterCntType, contentType)) {
			return ap_pass_brigade(f->next, pbbIn);
		}
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
	 * 2add debugMode
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
		stringAppend(ctx->buf, data, len);

		apr_bucket_delete(pbktIn);
	}
	if(!isEOS) {
		return OK;
	}
	if(pConfig->logMode) {
		time_t start = 0;
		time(&start);
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "======styleCombine start process: %s == %ld", r->uri, start);
	}
	if(ctx->buf->used > 0) {
		ctx->buf->ptr[ctx->buf->used] = ZERO_END;

		CombinedStyle combinedStyle;
		combinedStyle.footerBuf = buffer_init();
		combinedStyle.topBuf = buffer_init();
		combinedStyle.headBuf = buffer_init();
		//load version
		loadStyleVersion(r, pConfig);

		buffer *dstBuf = buffer_init_size(ctx->buf->used);
		if(dstBuf && combinedStyle.footerBuf && combinedStyle.topBuf && combinedStyle.headBuf) {
			//if find any style
			if(htmlParser(r, &combinedStyle, dstBuf, pConfig, ctx)) {
				resetHtml(c, ctx->pbbOut, &combinedStyle, dstBuf);
			} else {
				addBucket(c, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
			}
		} else {
			addBucket(c, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
		}
		//free
		combinedStyle_free(&combinedStyle);
		buffer_free(dstBuf);
	}
	//append eos
	APR_BRIGADE_INSERT_TAIL(ctx->pbbOut, apr_bucket_eos_create(c->bucket_alloc));
	apr_table_get(r->notes, "ok");
	buffer_free(ctx->buf);
	apr_brigade_cleanup(pbbIn);

	if(pConfig->logMode) {
		time_t end = 0;
		time(&end);
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "========styleCombine end: %s == %ld", r->uri, end);
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

static const char *setOldDomain(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine old domain value may not be null";
	} else {
		pConfig->oldDomain->ptr = apr_pstrdup(cmd->pool, arg);
		pConfig->oldDomain->used = strlen(arg);
		pConfig->oldDomain->size = pConfig->oldDomain->used;
	}
	return NULL;
}

static const char *setNewDomain(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine new domain value may not be null";
	} else {
		pConfig->newDomain->ptr = apr_pstrdup(cmd->pool, arg);
		pConfig->newDomain->used = strlen(arg);
		pConfig->newDomain->size = pConfig->newDomain->used;
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

static const char *setLogMode(cmd_parms *cmd, void *dummy, int arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	pConfig->logMode = arg;
	return NULL;
}

static const char *setEnableFilterURLParams(cmd_parms *cmd, void *dummy, int arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	pConfig->enableFilterURLParams = arg;
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

static const command_rec styleCombineCmds[] =
{
		AP_INIT_FLAG("enabled", setEnabled, NULL, OR_ALL, "open or close this module"),

		AP_INIT_TAKE1("appName", setAppName, NULL, OR_ALL, "app name"),

		AP_INIT_TAKE1("filterCntType", setFilterCntType, NULL, OR_ALL, "filter content type"),

		AP_INIT_TAKE1("oldDomain", setOldDomain, NULL, OR_ALL, "style old domain url"),

		AP_INIT_TAKE1("newDomain", setNewDomain, NULL, OR_ALL, "style new domain url"),

		AP_INIT_TAKE1("maxUrlLen", setMaxUrlLen, NULL, OR_ALL, "url max len"),

		AP_INIT_FLAG("logMode", setLogMode, NULL, OR_ALL, " debug mode"),

		AP_INIT_FLAG("enableFilterURLParams", setEnableFilterURLParams, NULL, OR_ALL, "open or close this module to process filter uri?xx=xx"),

		// part version command
		AP_INIT_TAKE1("versionFilePath", setVersionFilePath, NULL, OR_ALL, "style versionFilePath dir"),

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
