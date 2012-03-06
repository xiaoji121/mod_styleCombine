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
#define HTTP_PROTOCOL "http"
#define HTTPS_PROTOCOL "https"
#define EXT_JS ".js"
#define EXT_CSS ".css"
#define URI_SEPARATOR "|"
#define URI_QUERY_CHAR "?"
#define URI_QUERY_PARAM "?_v="
#define URI_VERSION_LEN  20

#define DEFAULT_BUF_SIZE 128

#define DEFAULT_CONTENT_LEN (1024 << 10)  // default html content size 1M

#define FIELD_POSITION "pos=" //position
#define POSITION_LEN 4
#define POSITION_TOP "top"
#define POSITION_HEAD "head"
#define POSITION_FOOTER "footer"

#define JS_PREFIX_TXT "<script type=\"text/javascript\" src=\""
#define JS_SUFFIX_TXT "\"></script>"
#define CSS_PREFIX_TXT "<link rel=\"stylesheet\" href=\""
#define CSS_SUFFIX_TXT "\" />"

typedef struct {
	char *ptr;
	off_t used;
	off_t size;
} buffer;

typedef struct {
	buffer *prefix;
	buffer *mark;
	char    suffix;
	buffer *closeTag;
	int styleType; /*0:表示css; 1:表示js*/
} ParserTag;

/***********global variable************/
const char ZERO_END = '\0';
/*position char */
const char pf = 'f'; //footer
const char pt = 't'; //top
const char ph = 'h'; //head

ParserTag    *cssPtag;
ParserTag    *jsPtag;
apr_table_t  *styleTable;
apr_time_t    lastLoadTime;


typedef struct {
	int        enabled;
	char      *filterCntType;
	buffer    *domain;
	int        maxUrlLen;
	char      *versionFilePath;

	//style combined auto not impl yet
	int        delBlankSpace;
	int        styleIsCombined;
} CombineConfig;


typedef struct {
	buffer             *buf;
    apr_bucket_brigade *pbbOut;
} CombineCtx;

typedef struct {
	char     postion;
	buffer  *styleUri;
	time_t   version;
	struct styleLinkList *prevItem;
} StyleLinkList;

/**
 * save combined style
 */
typedef struct {
	buffer *topBuf;
	buffer *headBuf;
	buffer *footerBuf;
} CombinedStyle;

buffer *buffer_init() {
	buffer *buf = malloc(sizeof(buffer));
	if(buf == NULL) {
		return buf;
	}
	buf->ptr = NULL;
	buf->used = 0;
	buf->size = 0;
	return buf;
}

buffer *buffer_init_size(int size) {
	buffer *buf = buffer_init();
	if(buf == NULL) {
		return buf;
	}
	buf->ptr = malloc(size);
	buf->size = size;
	return buf;
}

void buffer_free(buffer *b) {
	if(b == NULL) {
		return;
	}
	free(b->ptr);
	free(b);
}
void combinedStyle_free(CombinedStyle *c) {
	if(c == NULL) {
		return ;
	}
	buffer_free(c->footerBuf);
	buffer_free(c->headBuf);
	buffer_free(c->topBuf);
}

void free_linkedList(StyleLinkList *link) {
	for(; link != NULL; link = link->prevItem) {
		StyleLinkList *tmpLink = link;
		free(tmpLink->styleUri);
		free(tmpLink);
	}
}
/**
 * get uri extention
 */
static char *getFileExt(char *uri, int len) {
	if (uri == NULL) {
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
	if(buf == NULL || str == NULL || strLen <= 0) {
		return;
	}
	if(buf->size == 0) {
		if(strLen > DEFAULT_BUF_SIZE) {
			buf->size = strLen + DEFAULT_BUF_SIZE;
		} else {
			buf->size = DEFAULT_BUF_SIZE;
		}
		buf->ptr = malloc(buf->size);
		buf->used = 0;
	}
	if(buf->used + strLen >= buf->size) {
		buf->size += (strLen + DEFAULT_BUF_SIZE);
		buf->ptr = realloc(buf->ptr, buf->size);
	}
	memcpy(buf->ptr + buf->used, str, strLen);
	buf->used += strLen;
}

static void formatParser(apr_table_t *table, char *str, int len) {
	if(str == NULL) {
		return;
	}
	int i;
	char *name,*next;
	char *value=str;

	for(i=0 ;i < len ;i++) {
		name = strsep(&value, "=");
		if(name == NULL || memcmp(name, "", 1) == 0) {
			break;//the end
		}
		next =value;
		value=strsep(&next,"\n");
		if(next == NULL || memcmp(name, "", 1) == 0) {
			break;
		}
		apr_table_set(table, name, value);
		value=next;
	}
}

time_t getURIVersion(buffer *uri, char *singleUri) {

	time_t lastModified = 0;
	time_t newVersion = 0;

	char *fileExt = getFileExt(uri->ptr, uri->used);
	if (fileExt == NULL) {
		return 0;
	}
	int fileExtLen = strlen(fileExt);
	int uriLen = uri->used;

	int i , t = 0;
	for(i = 0; i < uriLen; ++i, ++t) {
		if(i != 0 && memcmp(&uri->ptr[i], URI_SEPARATOR, 1) == 0) {
			singleUri[t] = ZERO_END;
		} else {
			singleUri[t] = uri->ptr[i];
			if((i + 1) != uriLen) {
				continue;
			}
			singleUri[++t] = uri->ptr[++i];
			singleUri[t] = ZERO_END;
		}
		if (getFileExt(singleUri, t) == NULL) {
			memcpy(singleUri + t, fileExt, fileExtLen);
		}
		t = -1;

		if(styleTable != NULL) {
			const char *strVs = apr_table_get(styleTable, singleUri);
			if(strVs != NULL) {
				newVersion = atol(strVs);
			}
		}
		if (lastModified < newVersion) {
			lastModified = newVersion;
		}
	}
	if (lastModified == 0) {
		time(&lastModified);//FIXME: do'nt use current time
	}
	return lastModified;
}

static char strToPosition(char *str) {
	if(str == NULL) {
		return ' ';
	}
	if (strncmp(POSITION_TOP, str, 3) == 0)
		return 't';
	if (strncmp(POSITION_HEAD, str, 4) == 0)
		return 'h';
	if (memcmp(POSITION_FOOTER, str, 6) == 0)
		return 'f';
	return ' ';
}

static void loadStyleVersion(apr_pool_t *pool,CombineConfig *pConfig) {

	apr_finfo_t finfo;
	apr_file_t *fd = NULL;
	apr_size_t amt;

	apr_status_t rc = apr_stat(&finfo, pConfig->versionFilePath, APR_FINFO_OWNER, pool);

	if(APR_SUCCESS == rc && finfo.mtime != lastLoadTime) {

		lastLoadTime = finfo.mtime;

		rc = apr_file_open(&fd, pConfig->versionFilePath, APR_READ | APR_BINARY | APR_XTHREAD,
						   APR_OS_DEFAULT, pool);
		if(rc != APR_SUCCESS) {
		 return;
		}
		buffer *versionBuf = buffer_init_size(finfo.size);

		amt = (apr_size_t)finfo.size;
		rc = apr_file_read(fd, versionBuf->ptr, &amt);
		if(rc == APR_SUCCESS) {
			versionBuf->used = finfo.size;
			formatParser(styleTable, versionBuf->ptr, versionBuf->used);
		}
		buffer_free(versionBuf);
	}
}

static int tagFilter(CombineConfig *pConfig, ParserTag *ptag, char *tagBuf, buffer *uriBuf) {

	if (strstr(tagBuf, ptag->mark->ptr) == NULL) {
		//表示是一个非 css / javascript 文件引用，则跳过处理
		return 0;
	}

	char *curURLDomain = strstr(tagBuf, pConfig->domain->ptr);
	if (curURLDomain == NULL) {
		//对于没有域名的css/js不进行处理
		return 0;
	}
	curURLDomain += pConfig->domain->used;
	int i, hasDo = 0;
	char tmpChr;
	for (i = 0;
			(tmpChr = curURLDomain[i]) != ptag->suffix
			&& tmpChr != '\"'
			&& tmpChr != '\'' && (i < pConfig->maxUrlLen); i++) {

		uriBuf->ptr[i] = tmpChr;
		if (tmpChr == '.') {
			++hasDo;
		}
	}
	if (hasDo == 0) {
		//no .js/.css ext
		return 0;
	}
	uriBuf->used = i++;
	uriBuf->ptr[i] = ZERO_END;
	return uriBuf->used;
}

static void addTag(CombineConfig *pConfig, int styleType, buffer *destBuf, buffer *uri, time_t version) {
	if(uri == NULL || uri->used == 0) {
		return ;
	}

	if (styleType == 0) {
		stringAppend(destBuf, CSS_PREFIX_TXT, strlen(CSS_PREFIX_TXT));
	} else {
		stringAppend(destBuf, JS_PREFIX_TXT, strlen(JS_PREFIX_TXT));
	}
	stringAppend(destBuf, pConfig->domain->ptr, pConfig->domain->used);
	stringAppend(destBuf, uri->ptr, uri->used);
	stringAppend(destBuf, URI_QUERY_PARAM, 4);

	char strVersion[URI_VERSION_LEN];
	snprintf(strVersion, URI_VERSION_LEN - 1, "%ld", version);
	stringAppend(destBuf, strVersion , strlen(strVersion));

	if (styleType == 0) {
		stringAppend(destBuf, EXT_CSS, 4);
		stringAppend(destBuf, CSS_SUFFIX_TXT, strlen(CSS_SUFFIX_TXT));
	} else {
		stringAppend(destBuf, EXT_JS, 3);
		stringAppend(destBuf, JS_SUFFIX_TXT, strlen(JS_SUFFIX_TXT));
	}
	destBuf->ptr[destBuf->used] = ZERO_END;
}

static void combineStyles(CombineConfig *pConfig, int styleType, StyleLinkList *linkList,
								CombinedStyle *combinedStyle, CombinedStyle *tmpCombine) {
	if(linkList == NULL) {
		return;
	}

	time_t tv = 0, hv = 0, fv = 0, tmpVersion = 0;

	int f = 0, t = 0, h = 0;
	buffer *tmpUriBuf = NULL;
	buffer *tmpPositionBuf = NULL;

	for (; linkList != NULL; linkList = linkList->prevItem) {
		register time_t nlastModified = linkList->version;
		switch (linkList->postion) {
		case 'f':
			if (fv < nlastModified) {
				fv = nlastModified;
			}
			tmpUriBuf = tmpCombine->footerBuf;
			if (f > 0)
				stringAppend(tmpUriBuf, URI_SEPARATOR, 1);
			else
				f++;
			break;
		case 't':
			if (tv < nlastModified) {
				tv = nlastModified;
			}
			tmpUriBuf = tmpCombine->topBuf;
			if (t > 0)
				stringAppend(tmpUriBuf, URI_SEPARATOR, 1);
			else
				t++;
			break;
		case 'h':
			if (hv < nlastModified) {
				hv = nlastModified;
			}
			tmpUriBuf = tmpCombine->headBuf;
			if (h > 0)
				stringAppend(tmpUriBuf, URI_SEPARATOR, 1);
			else
				h++;
			break;
		}

		//control url over max long  max_uri = 128*1024
		if (tmpUriBuf->used > pConfig->maxUrlLen) {
			if (linkList->postion == pf) {
				f = 1;
				tmpVersion = fv;
				tmpPositionBuf = combinedStyle->footerBuf;
			}
			if (linkList->postion == pt) {
				t = 1;
				tmpVersion = tv;
				tmpPositionBuf = combinedStyle->topBuf;
			}
			if (linkList->postion == ph) {
				h = 1;
				tmpVersion = hv;
				tmpPositionBuf = combinedStyle->headBuf;
			}

			addTag(pConfig, styleType, tmpPositionBuf, tmpUriBuf, tmpVersion);

			//reset value
			tmpUriBuf->used = 0;
			tmpUriBuf->ptr[0] = ZERO_END; //clean no used string
		}
		stringAppend(tmpUriBuf, linkList->styleUri->ptr, linkList->styleUri->used);
	}

	addTag(pConfig, styleType, combinedStyle->topBuf, tmpCombine->topBuf, tv);
	addTag(pConfig, styleType, combinedStyle->headBuf, tmpCombine->headBuf, hv);
	addTag(pConfig, styleType, combinedStyle->footerBuf, tmpCombine->footerBuf, fv);
}

static int isRepeat(apr_hash_t *duplicats, char *destUri, int len) {
	if(apr_hash_get(duplicats, destUri, len) != NULL) {
		//if uri has exsit then skiping it
		return 1;
	}
	apr_hash_set(duplicats, destUri, len, "0");
	return 0;
}

static void addBucket(conn_rec *c, apr_bucket_brigade *pbbkOut, char *str, int strLen) {
	if(str == NULL || strLen <= 0) {
		return;
	}
	apr_bucket *pbktOut = NULL;
	pbktOut = apr_bucket_heap_create(str, strLen, NULL, c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(pbbkOut, pbktOut);
}
static void resetHtml(conn_rec *c, apr_bucket_brigade *pbbkOut,
						CombinedStyle *combinedStyle, buffer *buf) {

	char *sourceHtml = buf->ptr;
	if(sourceHtml == NULL) {
		return;
	}

	int headIndex = 0;
	char *headPosit = strstr(sourceHtml, "</head>");
	if(headPosit != NULL) {
		addBucket(c, pbbkOut, sourceHtml, (headIndex = headPosit - sourceHtml));
	}
	addBucket(c, pbbkOut, combinedStyle->topBuf->ptr, combinedStyle->topBuf->used);
	addBucket(c, pbbkOut, combinedStyle->headBuf->ptr, combinedStyle->headBuf->used);

	char *middle = (sourceHtml + headIndex);
	char *footerPosit = strstr(sourceHtml, "</body>");
	if(footerPosit != NULL) {
		addBucket(c, pbbkOut, middle, (footerPosit - middle));
		addBucket(c, pbbkOut, combinedStyle->footerBuf->ptr, combinedStyle->footerBuf->used);
		addBucket(c, pbbkOut, footerPosit, strlen(footerPosit));
	} else {
		addBucket(c, pbbkOut, middle, strlen(middle));
		addBucket(c, pbbkOut, combinedStyle->footerBuf->ptr, combinedStyle->footerBuf->used);
	}
}

static inline char *strSearch(const char * str1, char **matchedType, char **isExpression) {
	char *cp = (char *) str1;
	char *s1;

	register int r = -1;
	while (*cp) {
		//compare first
		if (*cp == '<') {
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
			case '!': //
				if (memcmp("--", ++s1, 2) == 0) {
					//!--[if IE]> keep this
					if (*(cp = s1 + 2) == '[') {
						cp++;
						*isExpression = "1";
						continue;
					}
					//skip comments part
					for (; *cp != '\0'; cp++) {
						if (memcmp(cp, "-->", 3) == 0) {
							break;
						}
					}
				} else if(*s1 == '[') {
					*isExpression = "0";
				}
				break;
			}
			if (r == 0) {
				return (cp);
			}
			if (*s1 != '<') {
				cp += 3; //skip 3
				continue;
			}
		}
		cp++;
	}
	*matchedType = NULL;
	return (NULL);
}

static int htmlParser(request_rec *r, CombinedStyle *combinedStyle, buffer *dstBuf, CombineConfig *pConfig, buffer *sourceCnt) {

	char               *maxTagBuf = apr_palloc(r->pool, pConfig->maxUrlLen + 100);
	buffer             *maxUrlBuf = buffer_init_size(pConfig->maxUrlLen);
	apr_hash_t         *duplicates = apr_hash_make(r->pool);

	if(maxTagBuf == NULL || maxUrlBuf == NULL) {
		return 0;
	}
	StyleLinkList      *jsLinkList = NULL;
	StyleLinkList      *cssLinkList = NULL;
	StyleLinkList      *jsPrevLinkList = NULL;
	StyleLinkList      *cssPrevLinkList = NULL;

	char *subHtml = sourceCnt->ptr;
	int ssize = (pConfig->maxUrlLen + 98);
	char *matchedType = NULL;
	char *isExpression = "0";
	//(js/css)应该放置的位置 h:head; f:footer; l:lib(表示公共类库，放在<head>里面)
	register char position = 'h';
	register int isProcessed = 0;
	register ParserTag *ptag = NULL;
	register int i = 0;
	register char *curPoint = NULL;
	register char *tmpPoint = NULL;

	while ((curPoint = strSearch(subHtml, &matchedType, &isExpression)) != NULL) {

		position = 'h';
		tmpPoint = curPoint;

		stringAppend(dstBuf, subHtml, curPoint - subHtml);

		if(memcmp(matchedType, "j", 1) == 0) {
			ptag = jsPtag;
		} else {
			ptag = cssPtag;
		}
		for (i = 0; (curPoint[i] != ptag->suffix) && i < ssize; i++) {
			maxTagBuf[i] = curPoint[i];
		}
		maxTagBuf[i++] = ptag->suffix;
		curPoint += i;
		maxTagBuf[i] = ZERO_END;
		if (tagFilter(pConfig, ptag, maxTagBuf, maxUrlBuf) == 0) {
			stringAppend(dstBuf, maxTagBuf, i);
			subHtml = curPoint;
			continue;
		}
		isProcessed = 1;

		int singleUriLen = maxUrlBuf->used;
		char *singleUri = apr_palloc(r->pool, singleUriLen);
		// 0:single style; 1:multi style
		time_t nversion = getURIVersion(maxUrlBuf, singleUri);
		memcpy(singleUri, maxUrlBuf->ptr, maxUrlBuf->used);

		if (ptag->styleType == 1) {
			/**
			 * js 的特殊处理，需要将结束符找出来，</script>
			 * 结束符中间可能有空格或制表符，所以忽略这些
			 * 如果没有结束符，将不进行处理.
			 */
			for(; isspace(*curPoint) && *curPoint != ZERO_END; curPoint++);

			if (memcmp(ptag->closeTag->ptr, curPoint, ptag->closeTag->used) != 0) {
				//找不到结束的</script>
				stringAppend(dstBuf, maxTagBuf, i);
				subHtml = curPoint;
				continue;
			}
			curPoint += ptag->closeTag->used;

			if(isRepeat(duplicates, singleUri, singleUriLen)) {
				subHtml = curPoint;
				continue;
			}
			//parser field
			char *fpois = strstr(maxTagBuf, FIELD_POSITION);
			if(fpois != NULL) {
				fpois += POSITION_LEN + 1;
			}
			position = strToPosition(fpois);
			if (position == ' ') {
				addTag(pConfig, ptag->styleType, dstBuf, maxUrlBuf, nversion);
				subHtml = curPoint;
				continue;
			}
		} else {
			if(isRepeat(duplicates, singleUri, singleUriLen)) {
				subHtml = curPoint;
				continue;
			}
		}
		//process expression <!--[if IE]>
		if(memcmp(isExpression, "1", 1) == 0) {
			addTag(pConfig, ptag->styleType, dstBuf, maxUrlBuf, nversion);
			subHtml = curPoint;
			continue;
		}

		//combined tag string
		if (strstr(maxUrlBuf->ptr, URI_SEPARATOR) != NULL) {
			buffer *tmpPosBuf = NULL;
			switch (position) {
			case 'f':
				tmpPosBuf = combinedStyle->footerBuf;
				break;
			case 't':
				tmpPosBuf = combinedStyle->topBuf;
				break;
			case 'h':
				tmpPosBuf = combinedStyle->headBuf;
				break;
			}
			addTag(pConfig, ptag->styleType, tmpPosBuf, maxUrlBuf, nversion);
		} else {
			//add to linkList
			StyleLinkList *linkItem = malloc(sizeof(StyleLinkList));
			linkItem->prevItem = NULL;

			buffer *styleUri = buffer_init();
			styleUri->ptr = singleUri;
			styleUri->used = singleUriLen;
			styleUri->size = singleUriLen;
			linkItem->styleUri = styleUri;

			/*
			linkItem->styleUri = buffer_init_size(maxUrlBuf->used + 1);
			memcpy(linkItem->styleUri->ptr, maxUrlBuf->ptr, maxUrlBuf->used);
			linkItem->styleUri->used = maxUrlBuf->used;
			*/

			linkItem->postion = position;
			linkItem->version = nversion;

			if(ptag->styleType == 0) {
				if (cssLinkList == NULL) {
					cssLinkList = linkItem;
				} else {
					cssPrevLinkList->prevItem = linkItem;
				}
				cssPrevLinkList = linkItem;
			} else {
				if (jsLinkList == NULL) {
					jsLinkList = linkItem;
				} else {
					jsPrevLinkList->prevItem = linkItem;
				}
				jsPrevLinkList = linkItem;
			}
		}
		subHtml = curPoint;
	}
	if(isProcessed) {
		stringAppend(dstBuf, subHtml, strlen(subHtml));
		//create
		CombinedStyle tmpCombine;
		tmpCombine.topBuf = buffer_init();
		tmpCombine.headBuf = buffer_init();
		tmpCombine.footerBuf = buffer_init();

		combineStyles(pConfig, cssPtag->styleType, cssLinkList, combinedStyle, &tmpCombine);
		free_linkedList(cssLinkList);
		//reset
		tmpCombine.topBuf->used = 0;
		tmpCombine.headBuf->used = 0;
		tmpCombine.footerBuf->used = 0;

		combineStyles(pConfig, jsPtag->styleType, jsLinkList, combinedStyle, &tmpCombine);
		free_linkedList(jsLinkList);
		//free
		combinedStyle_free(&tmpCombine);
	}
	buffer_free(maxUrlBuf);
	apr_hash_clear(duplicates);

	if(0 != dstBuf->size) {
		dstBuf->ptr[dstBuf->used] = ZERO_END;
	}
	return isProcessed;
}

static void *configServerCreate(apr_pool_t *p, server_rec *s) {

	CombineConfig *pConfig = apr_palloc(p, sizeof(CombineConfig));
	pConfig->enabled = 0;
	pConfig->filterCntType = NULL;
	/**
	 * see http://support.microsoft.com/kb/208427/EN-US
	 * default len for ie 2083 char
	 */
	pConfig->maxUrlLen = 2083;

	pConfig->domain = apr_palloc(p, sizeof(buffer));

	jsPtag = apr_palloc(p, sizeof(ParserTag));
	cssPtag = apr_palloc(p, sizeof(ParserTag));

	// js config
	buffer *jsPrefix = apr_palloc(p, sizeof(buffer));
	jsPrefix->ptr = "<script";
	jsPrefix->used = strlen(jsPrefix->ptr);
	jsPrefix->size = jsPrefix->used;

	buffer *jsCloseTag  = apr_palloc(p, sizeof(buffer));
	jsCloseTag->ptr = "</script>";
	jsCloseTag->used = strlen(jsCloseTag->ptr);
	jsCloseTag->size = jsCloseTag->used;

	buffer *jsMark  = apr_palloc(p, sizeof(buffer));
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
	cssPrefix->ptr = "<link";
	cssPrefix->used = strlen(cssPrefix->ptr);
	cssPrefix->size = cssPrefix->used;

	buffer *cssCloseTag  = apr_palloc(p, sizeof(buffer));
	cssCloseTag->ptr = ">";
	cssCloseTag->used = strlen(cssCloseTag->ptr);
	cssCloseTag->size = cssCloseTag->used;

	buffer *cssMark  = apr_palloc(p, sizeof(buffer));
	cssMark->ptr = "stylesheet";
	cssMark->used = strlen(cssMark->ptr);
	cssMark->size = cssMark->used;

	cssPtag->prefix = cssPrefix;
	cssPtag->mark = cssMark;
	cssPtag->suffix = '>';
	cssPtag->closeTag = cssCloseTag;
	cssPtag->styleType = 0;

	//create version table
	styleTable = apr_table_make(p, 5000);

	return pConfig;
}

static void styleCombineInsert(request_rec *r) {
	CombineConfig *pConfig = ap_get_module_config(r->server->module_config, &styleCombine_module);
	if(pConfig->enabled == 0) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "not support styleCombineModule!");
		return;
	}
	ap_add_output_filter(STYLE_COMBINE_NAME, NULL, r, r->connection);
}

static apr_status_t styleCombineOutputFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {

	request_rec *r      = f->r;
	conn_rec *c         = r->connection;
	CombineCtx *ctx     = f->ctx;
	CombineConfig *pConfig = NULL;
	pConfig = ap_get_module_config(r->server->module_config, &styleCombine_module);

	if (APR_BRIGADE_EMPTY(pbbIn)) {
		return APR_SUCCESS;
	}
	const char * encode = apr_table_get(r->headers_out, "Content-Encoding");
	if(encode && strcasecmp(encode, "gzip") == 0) {
		return ap_pass_brigade(f->next, pbbIn);
	}
	if(apr_table_get(r->notes, STYLE_COMBINE_NAME) != NULL) {
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

	if (ctx == NULL) {
		ctx = f->ctx = apr_palloc(r->pool, sizeof(*ctx));
		ctx->pbbOut = apr_brigade_create(r->pool, c->bucket_alloc);
		ctx->buf = buffer_init_size(DEFAULT_CONTENT_LEN);
		if(ctx->buf == NULL) {
			return ap_pass_brigade(f->next, pbbIn);
		}
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
	if(isEOS == 0) {
		return OK;
	}
	if(ctx->buf->used > 0) {
		ctx->buf->ptr[ctx->buf->used] = ZERO_END;

		CombinedStyle combinedStyle;
		combinedStyle.footerBuf = buffer_init();
		combinedStyle.topBuf = buffer_init();
		combinedStyle.headBuf = buffer_init();
		//load version
//		loadStyleVersion(r->pool, pConfig);

		buffer *dstBuf = buffer_init_size(ctx->buf->used);
		if(dstBuf != NULL
				&&combinedStyle.footerBuf != NULL
				&&combinedStyle.topBuf != NULL
				&&combinedStyle.headBuf != NULL) {
			//if find any style
			if(htmlParser(r, &combinedStyle, dstBuf, pConfig, ctx->buf)) {
				resetHtml(c, ctx->pbbOut, &combinedStyle, dstBuf);
			} else {
				addBucket(c, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
			}
		} else {
			addBucket(c, ctx->pbbOut, ctx->buf->ptr, ctx->buf->used);
		}

		apr_bucket *pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(ctx->pbbOut, pbktEOS);

		//free
		combinedStyle_free(&combinedStyle);
		buffer_free(dstBuf);
	}
	apr_table_get(r->notes, "ok");
	buffer_free(ctx->buf);

	apr_brigade_cleanup(pbbIn);

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

static const char *setDomain(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if ((NULL == arg) || (strlen(arg) <= 1)) {
		return "styleCombine domain value may not be null";
	} else {
		pConfig->domain->ptr = apr_pstrdup(cmd->pool, arg);
		pConfig->domain->used = strlen(arg);
		pConfig->domain->size = pConfig->domain->used;
	}
	return NULL;
}

static const char *setMaxUrlLen(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	int len = 0;
	if ((NULL == arg) || (len = atoi(arg)) < pConfig->maxUrlLen) {
		ap_log_error(APLOG_MARK, LOG_ERR, 0, cmd->server, "maxUrlLen to small, will set default  2083!");
	} else {
		pConfig->maxUrlLen = len;
	}
	return NULL;
}

static const char *setVersionFilePath(cmd_parms *cmd, void *dummy, const char *arg) {
	CombineConfig *pConfig = ap_get_module_config(cmd->server->module_config, &styleCombine_module);
	if(arg != NULL) {
		pConfig->versionFilePath = apr_pstrdup(cmd->pool, arg);
	} else {
		return "styleCombine versionFilePath value may not be null";
	}
	return NULL;
}

static const command_rec styleCombineCmds[] =
{
		AP_INIT_FLAG("enabled", setEnabled, NULL, OR_ALL, "open or close this module"),

		AP_INIT_TAKE1("filterCntType", setFilterCntType, NULL, OR_ALL, "filter content type"),

		AP_INIT_TAKE1("domain", setDomain, NULL, OR_ALL, "style version domain url"),

		AP_INIT_TAKE1("maxUrlLen", setMaxUrlLen, NULL, OR_ALL, "url max len"),

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
