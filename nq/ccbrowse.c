/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Browser Client Iplementation
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 26-Apr-2003
 * CREATED BY    : Alexey Yarovinsky
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccapi.h"
#include "ccbrowse.h"
#include "cctrans.h"
#include "ccrap.h"
#include "ccdcerpc.h"
#include "ccsrvsvc.h"
#include "nqapi.h"
#include "cmfinddc.h"
#include "ccnetlgn.h"

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEOLDBROWSERAPI)

/* static functions */

#ifdef UD_NQ_USETRANSPORTNETBIOS
static NQ_STATUS getDomainBackupListByDomain(const NQ_WCHAR * domain, NQ_BYTE * buffer, NQ_UINT16 bufferLen, NQ_UINT16 * entries, NQ_UINT16 * totalAvail);
static NQ_STATUS sendGetBackupListRequest(NSSocketHandle socket, NQ_UINT16 bufferLen, const NQ_WCHAR *domain);
static NQ_STATUS recvGetBackupListResponse(NSSocketHandle socket, NQ_BYTE *buffer, NQ_UINT16 bufferLen, NQ_UINT16 *entries, NQ_UINT16 *totalAvail);
static NQ_STATUS getDomainBackupListW(NQ_WCHAR *domain, NQ_BYTE *buffer, NQ_UINT16 bufferLen, NQ_UINT16 *entries, NQ_UINT16 *totalAvail , NQ_BOOL findAny);
static NQ_BOOL getWorkgroupsByWg(NQ_WCHAR *workgroup, NQ_BYTE *listBuffer, NQ_COUNT bufferSize, NQ_INT *count, NQ_BOOL unicode);
static NQ_BOOL getTrustedDomains(NQ_WCHAR *workgroup, NQ_BYTE *listBuffer, NQ_COUNT bufferSize, NQ_INT *count, NQ_BOOL unicode);
static NQ_BOOL getHostsInWorkgroupByWg(NQ_WCHAR *workgroup, NQ_BYTE *listBuffer, NQ_COUNT bufferSize, NQ_INT *count, NQ_BOOL unicode);
#endif /* UD_NQ_USETRANSPORTNETBIOS */
static NQ_BOOL getSharesOnHost(NQ_WCHAR *hostName, NQ_BYTE *listBuffer, NQ_COUNT bufferSize, NQ_INT *count, NQ_BOOL unicode);
static void enumerateAnsiCallback(const NQ_CHAR* shareName, void* params);
static NQ_STATUS enumerateUnicodeCallback(const NQ_WCHAR* shareName, void * params);
static void enumerateAnsiShareCallback(const NQ_CHAR* shareName, void* params);
static NQ_STATUS enumerateUnicodeShareCallback(const NQ_WCHAR* shareName, void * params);
static NQ_BOOL getShareInfo(NQ_WCHAR *hostName, NQ_WCHAR *shareName, NQ_UINT16 *type, NQ_BYTE *remarkBuffer, NQ_INT bufferSize, NQ_BOOL unicodeResult);

#ifdef UD_NQ_USETRANSPORTNETBIOS
/* static parameters */
static NQ_UINT32 backupListReplyTimeoutSec = UD_CC_CLIENTRESPONSETIMEOUT; /* default timeout */
#endif

/* host name buffer */

#define NAMEPOOL_SIZE 100

#define BACKUP_NAME_MAX_SIZE 17

typedef struct {
    NQ_CHAR netName[BACKUP_NAME_MAX_SIZE];
} BackupList;

/* Beginning of packed structures definition */

#include "sypackon.h"

typedef SY_PACK_PREFIX struct
{
    NQ_SCHAR LANMAN[17];
}
SY_PACK_ATTR BrowserReq;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE OpCode;
    NQ_SBYTE Count;
    NQ_SUINT32 Token;
}
SY_PACK_ATTR GetBackupListReq_t;

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE OpCode;
    NQ_SBYTE Count;
    NQ_SUINT32 Token;
/*    NQ_SCHAR Servers[0];*/
}
SY_PACK_ATTR GetBackupListRsp;

#include "sypackof.h"

/* End of packed structures definition */

/* parameters for share saving callback */
typedef struct
{
    NQ_BYTE* dest;      /* pointer to the place in the destination buffer */
    NQ_COUNT size;      /* Remaining space in the buffer */
    NQ_INT count;       /* result count */
    NQ_INT result;      /* result code */
    NQ_BOOL unicode;    /* convert to unicode/ASCII */
}
NameEnumParams;

/* -- Static data -- */

static NQ_WCHAR pdcDomain[CM_BUFFERLENGTH(NQ_WCHAR, CM_DNS_NAMELEN)];
SYMutex guard;

#ifdef UD_NQ_USETRANSPORTNETBIOS
static BackupList servers[32];
static NSSocketHandle requestSocket = NULL;     /* shared socket for browse requests */
#endif /* UD_NQ_USETRANSPORTNETBIOS */

/* -- API functions -- */

NQ_BOOL ccBrowseStart(void)
{
#ifdef UD_NQ_USETRANSPORTNETBIOS
    requestSocket = nsGetCommonDatagramSocket();
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    cmAnsiToUnicode(pdcDomain, cmNetBiosGetDomain()->name);
    syMutexCreate(&guard);
    return TRUE;
}

void ccBrowseShutdown(void)
{
    /* DO NOT delete the requestSocket as it is shared */
    syMutexDelete(&guard);
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

void nqSetClientDefaultWorkgroupA(NQ_CHAR * workgroup)
{
    if (syStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        syMutexTake(&guard);
        cmAnsiToUnicode(pdcDomain, workgroup);
        syMutexGive(&guard);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "workgroup name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
    }
}

void nqSetClientDefaultWorkgroupW(
    NQ_WCHAR *workgroup
   )
{
    if (syWStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        syMutexTake(&guard);
        cmWStrncpy(pdcDomain, workgroup, CM_DNS_NAMELEN);
        syMutexGive(&guard);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "workgroup name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
    }
}

void nqGetClientDefaultWorkgroupA(NQ_CHAR * workgroup)
{
    syMutexTake(&guard);
    cmUnicodeToAnsi(workgroup, pdcDomain);
    syMutexGive(&guard);
}

void nqGetClientDefaultWorkgroupW(NQ_WCHAR * workgroup)
{
    syMutexTake(&guard);
    cmWStrcpy(workgroup, pdcDomain);
    syMutexGive(&guard);
}

NQ_BOOL nqGetWorkgroupsA(NQ_CHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    NQ_CHAR temp[CM_BUFFERLENGTH(NQ_CHAR, CM_DNS_NAMELEN)];

    syMutexTake(&guard);
    cmUnicodeToAnsi(temp, pdcDomain);

#ifndef UD_NQ_USETRANSPORTNETBIOS
    if (cmGetFullDomainName())
        syStrcpy(temp, cmGetFullDomainName());
#endif
    syMutexGive(&guard);

    return nqGetWorkgroupsByWgA(temp, listBuffer, bufferSize, count);
}

NQ_BOOL nqGetWorkgroupsW(NQ_WCHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    NQ_WCHAR temp[CM_BUFFERLENGTH(NQ_CHAR, CM_DNS_NAMELEN)];

    syMutexTake(&guard);
    cmWStrcpy(temp, pdcDomain);
#ifndef UD_NQ_USETRANSPORTNETBIOS
    if (cmGetFullDomainName())
        cmAnsiToUnicode(temp, cmGetFullDomainName());
#endif
    syMutexGive(&guard);

    return nqGetWorkgroupsByWgW(temp, listBuffer, bufferSize, count);
}

NQ_BOOL nqGetWorkgroupsByWgA(NQ_CHAR *workgroup, NQ_CHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "workgroup:%s list:%p size:%d count:%p", workgroup ? workgroup : "", listBuffer, bufferSize, count);

    if (syStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        NQ_WCHAR tmp[CM_BUFFERLENGTH(NQ_WCHAR, CM_DNS_NAMELEN)];

        *count = 0;
        cmAnsiToUnicode(tmp, workgroup);
#ifdef UD_NQ_USETRANSPORTNETBIOS
        syMutexTake(&guard);
        result = getWorkgroupsByWg(tmp, (NQ_BYTE*)listBuffer, bufferSize, count, FALSE);
        syMutexGive(&guard);
#endif /* UD_NQ_USETRANSPORTNETBIOS */

        result |= getTrustedDomains(tmp, (NQ_BYTE*)listBuffer, bufferSize, count, FALSE);

        goto Exit;
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
    sySetLastError(NQ_ERR_BADPARAM);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL nqGetWorkgroupsByWgW(NQ_WCHAR * workgroup, NQ_WCHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "workgroup:%s list:%p size:%d count:%p", cmWDump(workgroup), listBuffer, bufferSize, count);

    if (cmWStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        *count = 0;
#ifdef UD_NQ_USETRANSPORTNETBIOS
        syMutexTake(&guard);
        result = getWorkgroupsByWg(workgroup, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE);
        syMutexGive(&guard);
#endif /* UD_NQ_USETRANSPORTNETBIOS */

        result |= getTrustedDomains(workgroup, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE);

        goto Exit;
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
    sySetLastError(NQ_ERR_BADPARAM);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}


/* an item representing an abstract network entity: it may be a domain, a server or a share */
typedef struct
{
    CMItem item;                /* inherited CMItem */
    const NQ_CHAR * aName;      /* ASCII name. May be NULL when ASCII name was not requested yet */
}
NetItem;


/* This callback function is called from several result parsers when they encounter another item.
   This function creates an item and adds it to the respective list */
static void addNameCallback(const NQ_WCHAR * name, void * list)
{
    CMList * pList = (CMList *)list;   /* casted pointer */

    cmListItemCreateAndAdd(pList, sizeof(NetItem), name, NULL, CM_LISTITEM_NOLOCK);
}

static NQ_BOOL getTrustedDomains(
    NQ_WCHAR * workgroup,
    NQ_BYTE * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT * count,
    NQ_BOOL unicode
    )
{
    NQ_WCHAR * dc = NULL;        /* domain controller in Unicode */
    NQ_CHAR * dcA = NULL;        /* the same in ASCII */
    NQ_CHAR * workgroupA = NULL; /* workgroup copy in ASCII */
    NQ_HANDLE netlogon;
    NQ_BOOL result = FALSE;
    NQ_STATUS status;
    NQ_CHAR * cmpString = NULL;
    NQ_UINT32 res = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "workgroup:%s list:%p size:%d count:%d unicode:%s", cmWDump(workgroup), listBuffer, bufferSize, *count, unicode ? "TRUE" : "FALSE");

    /* check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        res = (NQ_UINT32)NQ_ERR_NOTREADY;
        goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Workgroup: %s, buffer size: %d, count: %d, %s", cmWDump(workgroup), bufferSize, *count, unicode ? "unicode" : "ascii");

    /* allocate buffers and convert strings */
    workgroupA = cmMemoryCloneWStringAsAscii(workgroup);
    dcA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_BYTE) * CM_DNS_NAMELEN);
    if (NULL == workgroupA || NULL == dcA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = (NQ_UINT32)NQ_ERR_OUTOFMEMORY;
        goto Exit;
    }

    /* find domain controller by domain name */
    if ((status = cmGetDCNameByDomain(workgroupA, dcA)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to get dc for domain %s", workgroupA);
        res = (NQ_UINT32)syGetLastError();
        goto Exit;
    }

    /* allocate more buffers and strings and free used */
    dc = cmMemoryCloneAString(dcA);
    if (NULL == dc)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = (NQ_UINT32)NQ_ERR_OUTOFMEMORY;
        goto Exit;
    }

    /* try netlogon pipe to get trusted domains  */
    if ((netlogon = ccDcerpcConnect(dc, NULL, ccNetlogonGetPipe(), TRUE)) != NULL)
    {
        CMList list;
        CMIterator iterator;

        cmListStart(&list);

        res = ccDsrEnumerateDomainTrusts(netlogon, dc, addNameCallback, &list);
        if (NQ_SUCCESS == res)
        {
            /* add new domains into listBuffer */
            cmListIteratorStart(&list, &iterator);
            while (cmListIteratorHasNext(&iterator))
            {
                NetItem * pItem;    /* name entry */
                NQ_COUNT maxSize;   /* number of bytes to have in the buffer */
                NQ_BOOL foundDuplicate = FALSE;

                pItem = (NetItem *)cmListIteratorNext(&iterator);
                maxSize = cmWStrlen(pItem->item.name) + 1;
                if (unicode)
                    maxSize *= (NQ_COUNT)sizeof(NQ_WCHAR);
                if (bufferSize < maxSize)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "More data available");
                    res = (NQ_UINT32)NQ_ERR_MOREDATA;
                    break;
                }

                if (unicode)
                {
                    NQ_INT cpyCounter , serverCount = *count;
                    NQ_WCHAR  *lastChar;

                    lastChar = (NQ_WCHAR *)listBuffer;
                    for (cpyCounter = 0 ; cpyCounter < serverCount; cpyCounter++)
                    {
                        if (syWStrcmp(lastChar, pItem->item.name) == 0)
                        {
                            foundDuplicate = TRUE;
                            break;
                        }
                          lastChar = syWStrchr(lastChar , cmWChar('\0')) + 1;
                    }
                    if (!foundDuplicate && (cpyCounter == 0 || cpyCounter == serverCount))
                    {
                        cmWStrcpy((NQ_WCHAR *)lastChar, pItem->item.name);
                        lastChar = syWStrchr(lastChar , cmWChar('\0')) + 1;
                        *lastChar++ = cmWChar('\0');
                        (*count)++;
                        result = TRUE;
                    }
                }
                else
                {
                    NQ_INT cpyCounter , serverCount = *count;
                    NQ_CHAR * lastChar;

                    lastChar = (NQ_CHAR *)listBuffer;
                    cmpString = cmMemoryCloneWStringAsAscii(pItem->item.name);
                    if (NULL == cmpString)
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                        res = (NQ_UINT32)NQ_ERR_NOMEM;
                        goto Exit;
                    }
                    else
                    {
                        for (cpyCounter = 0 ; cpyCounter < serverCount; cpyCounter++)
                        {
                            if (syStrcmp(cmpString, lastChar) == 0)
                            {
                                foundDuplicate = TRUE;
                                break;
                            }
                            lastChar = syStrchr(lastChar , '\0') + 1;
                        }
                        if (!foundDuplicate && (cpyCounter == 0 || cpyCounter == serverCount))
                        {
                            syStrcpy(lastChar, cmpString);
                            lastChar = syStrchr(lastChar , '\0') + 1;
                            *lastChar = '\0';
                            (*count)++;
                            result = TRUE;
                        }
                        cmMemoryFree(cmpString);
                        cmpString = NULL;
                    }
                }
            }
            cmListIteratorTerminate(&iterator);
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to enumerate domain trusts");
        }
        ccDcerpcDisconnect(netlogon);
        cmListShutdown(&list);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect to netlogon pipe");
        res = (NQ_UINT32)syGetLastError();
    }

Exit:
    cmMemoryFree(workgroupA);
    cmMemoryFree(dcA);
    cmMemoryFree(dc);
    cmMemoryFree(cmpString);
    sySetLastError(res);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

static NQ_BOOL getWorkgroupsByWg(
    NQ_WCHAR *workgroup,
    NQ_BYTE *listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT *count,
    NQ_BOOL unicode
   )
{
    NQ_UINT16  cnt = 0;       /* counter */
    NQ_INT     retryCount;    /* retry count */
    NQ_STATUS  status;        /* operation result */
    NQ_BOOL    ret = FALSE;   /* return value */
    NQ_WCHAR*  server = NULL; /* next server name */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "workgroup:%s list:%p size:%d count:%p unicode:%s", cmWDump(workgroup), listBuffer, bufferSize, count, unicode ? "TRUE" : "FALSE");

    *count = 0;

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        goto Exit;
    }

    if (cmWStrlen(workgroup) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount > 0; retryCount--)
    {
        NQ_UINT16 total;

        if ((status = getDomainBackupListW(workgroup, (NQ_BYTE *) &servers, sizeof(servers), &cnt, &total , TRUE)) != NQ_ERR_OK)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving domain backup list");
            sySetLastError((NQ_UINT32)status);
            continue;
        }
        if (cnt == 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "No domain backup servers found");
            sySetLastError(NQ_ERR_GETDATA);
            continue;
        }
        if (cnt > 0)
        {
            NameEnumParams   params;      /* parameters for callback */
            NQ_COUNT         i;

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Found %d domain backup server(s)", cnt);

            server = (NQ_WCHAR*)cmMemoryAllocate(sizeof(NQ_WCHAR) * CM_DNS_NAMELEN);
            if (NULL == server)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                sySetLastError(NQ_ERR_OUTOFMEMORY);
                goto Exit;
            }

            for (i = 0; i < cnt; i++)
            {
                cmAnsiToUnicode(server, servers[i].netName);

                params.count = 0;
                params.dest = listBuffer;
                params.size = bufferSize;
                params.unicode = unicode;
                params.result = NQ_ERR_OK;

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Querying server: %s", servers[i].netName);
                if (NQ_ERR_OK == (status = ccRapNetServerEnum(server, enumerateAnsiCallback, &params, SV_TYPE_DOMAIN_ENUM, NULL)))
                {
                    *count = params.count;
                    sySetLastError((NQ_UINT32)params.result);
                    ret = (params.result == NQ_ERR_OK);
                    goto Exit;
                }
            }
            cmMemoryFree(server);
            server = NULL;
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving domains list");
            sySetLastError((NQ_UINT32)status);
        }
    }

Exit:
    cmMemoryFree(server);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", ret ? "TRUE" : "FALSE");
    return ret;
}


NQ_BOOL nqGetHostsInWorkgroupA(NQ_CHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    NQ_CHAR * domainA;     /* DC name in ASCII */
    NQ_INT res = FALSE;    /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "list:%p size:%d count:%p", listBuffer, bufferSize, count);

    syMutexTake(&guard);
    domainA = cmMemoryCloneWStringAsAscii(pdcDomain);
    syMutexGive(&guard);
    if (NULL == domainA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = nqGetHostsInWorkgroupByWgA(domainA, listBuffer, bufferSize, count);

Exit:
    cmMemoryFree(domainA);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}


NQ_BOOL nqGetHostsInWorkgroupW(NQ_WCHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    return nqGetHostsInWorkgroupByWgW(pdcDomain, listBuffer, bufferSize, count);
}

NQ_BOOL nqGetHostsInWorkgroupByWgA(NQ_CHAR * workgroup, NQ_CHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    NQ_BOOL result = FALSE;             /* operation result */
    NQ_WCHAR * workgroupA = NULL;  /* in ASCII */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "workgroup:%s list:%p size:%d count:%p", workgroup ? workgroup : "", listBuffer, bufferSize, count);

    if (syStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        workgroupA = cmMemoryCloneAString(workgroup);
        if (NULL == workgroupA)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }

        result = getHostsInWorkgroupByWg(workgroupA, (NQ_BYTE*)listBuffer, bufferSize, count, FALSE);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
    }

Exit:
    cmMemoryFree(workgroupA);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL nqGetHostsInWorkgroupByWgW(NQ_WCHAR * workgroup, NQ_WCHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "workgroup:%s list:%p size:%d count:%p", cmWDump(workgroup), listBuffer, bufferSize, count);

    if (cmWStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        result = getHostsInWorkgroupByWg(workgroup, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

static NQ_BOOL getHostsInWorkgroupByWg(
    NQ_WCHAR * workgroup,
    NQ_BYTE * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT *count,
    NQ_BOOL unicode
   )
{
    NQ_INT            retryCount;
    NQ_BOOL           ret = FALSE;
    NQ_CHAR*          workgroupA = NULL;
    NQ_WCHAR*         server = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "workgroup:%s list:%p size:%d count:%p unicode:%s", cmWDump(workgroup), listBuffer, bufferSize, count, unicode ? "TRUE" : "FALSE");

    *count = 0;

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        goto Exit;
    }

    if (cmWStrlen(workgroup) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount > 0; retryCount--)
    {
        NQ_UINT16        total;
        NQ_UINT16        cnt = 0;
        NQ_STATUS        status;

        /* try DC */
        workgroupA = cmMemoryCloneWStringAsAscii(workgroup);
        if (workgroupA == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }

        status = cmGetDCNameByDomain(workgroupA, servers[0].netName);
        cmMemoryFree(workgroupA);
        workgroupA = NULL;
        if (NQ_SUCCESS == status)
        {
            cnt = 1;
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "No DC found");

            /* try backup list */
            if ((status = getDomainBackupListW(workgroup, (NQ_BYTE *) &servers, sizeof(servers), &cnt, &total, TRUE)) != NQ_ERR_OK)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving domain backup list");
                sySetLastError(NQ_ERR_GETDATA);
                continue;
            }
            if (cnt == 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "No domain backup servers found");
                sySetLastNqError(NQ_ERR_GETDATA);
                continue;
            }
        }
        if (cnt > 0)
        {
            NameEnumParams     params;      /* parameters for callback */
            NQ_COUNT           i;

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Found %d domain backup server(s)", cnt);

            server = (NQ_WCHAR*)cmMemoryAllocate(sizeof(NQ_WCHAR) * CM_DNS_NAMELEN);
            if (NULL == server)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                sySetLastError(NQ_ERR_OUTOFMEMORY);
                goto Exit;
            }

            for (i = 0; i < cnt; i++)
            {
                cmAnsiToUnicode(server, servers[i].netName);

                params.count = 0;
                params.dest = listBuffer;
                params.size = bufferSize;
                params.unicode = unicode;
                params.result = NQ_ERR_OK;

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Querying server: %s", servers[i].netName);
                if (NQ_ERR_OK == (status = ccRapNetServerEnum(server, enumerateAnsiCallback, &params, SV_TYPE_ALL, workgroup)))
                {
                    *count = params.count;
                    sySetLastError((NQ_UINT32)params.result);
                    ret = (params.result == NQ_ERR_OK);
                    goto Exit;
                }
            }
            cmMemoryFree(server);
            server = NULL;
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving hosts");
            sySetLastError((NQ_UINT32)status);
        }
    }

Exit:
    cmMemoryFree(server);
    cmMemoryFree(workgroupA);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", ret ? "TRUE" : "FALSE");
    return ret;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

NQ_BOOL nqGetSharesOnHostA(
    NQ_CHAR * hostName,
    NQ_CHAR * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT * count
   )
{
    NQ_WCHAR * hostNameW = NULL; /* host name in Unicode */
    NQ_BOOL result = FALSE;      /* Unicode operation resulkt */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "host:%s list:%p size:%d count:%p", hostName ? hostName : "", listBuffer, bufferSize, count);

    hostNameW = cmMemoryCloneAString(hostName);
    if (NULL == hostNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    result = getSharesOnHost(hostNameW, (NQ_BYTE *)listBuffer, bufferSize, count, FALSE);

Exit:
    cmMemoryFree(hostNameW);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL nqGetSharesOnHostW(
    NQ_WCHAR * hostName,
    NQ_WCHAR * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT *count
   )
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "host:%s list:%p size:%d count:%p", cmWDump(hostName), listBuffer, bufferSize, count);

    if (cmWStrlen(hostName) < CM_DNS_NAMELEN)
    {
        result = getSharesOnHost(hostName, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL nqGetShareInfoA(
    NQ_CHAR * hostName,
    NQ_CHAR * shareName,
    NQ_UINT16 * type,
    NQ_CHAR * remarkBuffer,
    NQ_INT bufferSize
   )
{
    NQ_BOOL result = FALSE;         /* operation result */
    NQ_WCHAR * hostW = NULL;        /* host name in Unicode */
    NQ_WCHAR * shareW = NULL;       /* share name in Unicode */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "host:%s share:%s type:%p buff:%p size:%d", hostName ? hostName : "", shareName ? shareName : "", type, remarkBuffer, bufferSize);

    hostW = cmMemoryCloneAString(hostName);
    shareW = cmMemoryCloneAString(shareName);
    if (NULL == hostW || NULL == shareW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    result = getShareInfo(hostW, shareW, type, (NQ_BYTE *)remarkBuffer, bufferSize, FALSE);

Exit:
    cmMemoryFree(hostW);
    cmMemoryFree(shareW);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL nqGetShareInfoW(
    NQ_WCHAR * hostName,
    NQ_WCHAR * shareName,
    NQ_UINT16 * type,
    NQ_WCHAR * remarkBuffer,
    NQ_INT bufferSize
   )
{
    return getShareInfo(hostName, shareName, type, (NQ_BYTE *)remarkBuffer, bufferSize, TRUE);
}

static NQ_BOOL getShareInfo(
    NQ_WCHAR * hostName,
    NQ_WCHAR * shareName,
    NQ_UINT16 * type,
    NQ_BYTE * remarkBuffer,
    NQ_INT bufferSize,
    NQ_BOOL unicodeResult
   )
{
    NQ_INT retryCount;
    NQ_STATUS status;
    NQ_BOOL result = FALSE;
    AMCredentialsW *pCredentials = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "host:%s share:%s type:%p buff:%p size:%d unicode:%s", cmWDump(hostName), cmWDump(shareName), type, remarkBuffer, bufferSize, unicodeResult ? "TRUE" : "FALSE");

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        goto Exit;
    }

    pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    udGetCredentials(NULL, pCredentials->user,
                           pCredentials->password,
                           pCredentials->domain.name);


    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount > 0; retryCount--)
    {
        NQ_HANDLE pipe = ccDcerpcConnect(hostName, pCredentials, ccSrvsvcGetPipe(), TRUE);

        if (NULL == pipe)
        {
            if ((status = ccRapNetShareInfo(hostName, shareName, type, (NQ_WCHAR*)remarkBuffer, bufferSize, unicodeResult)) != NQ_ERR_OK)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                sySetLastError((NQ_UINT32)status);
                continue;
            }
        }
        else
        {
            if ((status = ccSrvsvcGetShareInfo(pipe, hostName, shareName, type, remarkBuffer, bufferSize, unicodeResult)) != NQ_ERR_OK)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                sySetLastError((NQ_UINT32)status);
                ccDcerpcDisconnect(pipe);
                continue;
            }

            ccDcerpcDisconnect(pipe);
        }

        result = TRUE;
        goto Exit;
    }

Exit:
    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

static NQ_BOOL getSharesOnHost(
    NQ_WCHAR * hostName,
    NQ_BYTE * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT * count,
    NQ_BOOL unicode
   )
{
    NQ_INT retryCount;
    NQ_STATUS status;
    AMCredentialsW *pCredentials = NULL;
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "host:%s list:%p size:%d count:%p unicode:%s", cmWDump(hostName), listBuffer, bufferSize, count, unicode ? "TRUE" : "FALSE");

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        goto Exit;
    }

    if (cmWStrlen(hostName) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Host name is too long");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    pCredentials = (AMCredentialsW *)cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    udGetCredentials(NULL, pCredentials->user,
                           pCredentials->password,
                           pCredentials->domain.name);

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount > 0; retryCount--)
    {
        NQ_HANDLE pipe;                 /* pipe handle for SRVSVC */
        NameEnumParams params;          /* parameters to be passed into callback */

        params.dest = listBuffer;
        params.size = bufferSize;
        params.count = 0;
        params.unicode = unicode;
        params.result = NQ_ERR_OK;

        pipe = ccDcerpcConnect(hostName, pCredentials, ccSrvsvcGetPipe(), TRUE);
        if (NULL == pipe)
        {
            if (syGetLastError() == NQ_ERR_LOGONFAILURE)
                retryCount = 0;
            if ((status = ccRapNetShareEnum(hostName, enumerateAnsiShareCallback, &params)) != NQ_ERR_OK)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                sySetLastError((NQ_UINT32)status);
                continue;
            }
        }
        else
        {
            if ((status = ccSrvsvcEnumerateShares(pipe, hostName, enumerateUnicodeShareCallback, &params)) != NQ_SUCCESS)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                ccDcerpcDisconnect(pipe);
                sySetLastError((NQ_UINT32)params.result);
                continue;
            }
            ccDcerpcDisconnect(pipe);
        }
        *count = params.count;
        sySetLastError((NQ_UINT32)params.result);
        result = (params.result == NQ_ERR_OK);
        goto Exit;
    }

Exit:
    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#ifdef UD_NQ_USETRANSPORTNETBIOS

static NQ_STATUS getDomainBackupListByDomain(
    const NQ_WCHAR * domain,
    NQ_BYTE * buffer,
    NQ_UINT16 bufferLen,
    NQ_UINT16 * entries,
    NQ_UINT16 * totalAvail
    )
{
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s buff:%p length:%d entries:%p available:%p", cmWDump(domain), buffer, bufferLen, entries, totalAvail);

    *entries = *totalAvail = 0;

    if ((status = sendGetBackupListRequest(requestSocket, bufferLen, domain)) != NQ_ERR_OK)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending GetBackupList request");
    }
    else
        status = recvGetBackupListResponse(requestSocket, buffer, bufferLen, entries, totalAvail);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

static NQ_STATUS getDomainBackupListW(
    NQ_WCHAR * domain,
    NQ_BYTE * buffer,
    NQ_UINT16 bufferLen,
    NQ_UINT16 * entries,
    NQ_UINT16 * totalAvail,
    NQ_BOOL     findAny
    )
{
    static const NQ_WCHAR browser[] = { cmWChar(0x01),
                                        cmWChar(0x02),
                                        cmWChar('_'),
                                        cmWChar('_'),
                                        cmWChar('M'),
                                        cmWChar('S'),
                                        cmWChar('B'),
                                        cmWChar('R'),
                                        cmWChar('O'),
                                        cmWChar('W'),
                                        cmWChar('S'),
                                        cmWChar('E'),
                                        cmWChar('_'),
                                        cmWChar('_'),
                                        cmWChar(0x02),
                                        cmWChar('\0')};

    NQ_STATUS           status = NQ_ERR_GENERAL;
    const NQ_WCHAR  *   domainToUse = NULL;
    NQ_WCHAR        *   domainToMod = NULL;
    NQ_WCHAR        *   point;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s buff:%p len:%d entr:%p avail:%p findAny:%s", cmWDump(domain), buffer, bufferLen, entries, totalAvail, findAny ? "TRUE" : "FALSE");

    point = syWStrchr(domain, cmWChar('.'));
    if (point != NULL)
    {
        domainToMod = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((syWStrlen(domain)-syWStrlen(point)+1) * sizeof(NQ_WCHAR)));
        if (NULL != domainToMod)
        {
            syWStrncpy(domainToMod , domain , syWStrlen(domain)-syWStrlen(point));
            domainToMod[syWStrlen(domain)-syWStrlen(point)] = cmWChar('\0');
            domainToUse = cmMemoryCloneWString(domainToMod);
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastNqError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }
    }
    else
        domainToUse = cmMemoryCloneWString(domain);

    if (NULL == domainToUse)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastNqError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    status = getDomainBackupListByDomain(domainToUse, buffer, bufferLen, entries, totalAvail);
    if (NULL != domain && NQ_SUCCESS != status && findAny)
        status = getDomainBackupListByDomain(browser, buffer, bufferLen, entries, totalAvail);

Exit:
    cmMemoryFree(domainToUse);
    cmMemoryFree(domainToMod);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

static NQ_UINT32 createToken(void)
{
    static NQ_UINT32 token = 1;
    NQ_UINT32 res;

    res = token++;
    return res;
}

void ccSetGetBackupListTimeout(NQ_UINT32 seconcds)
{
	backupListReplyTimeoutSec = seconcds;
}

static NQ_STATUS sendGetBackupListRequest(NSSocketHandle socket, NQ_UINT16 bufferLen, const NQ_WCHAR * domain)
{
    CMNetBiosNameInfo dstName;
    CMCifsTransactionRequest * transCmd;
    TransParamCmd * paramCmd;
    NQ_UINT paramCount;
    NQ_UINT dataCount;
    BrowserReq browser = { "\\MAILSLOT\\BROWSE" };
    GetBackupListReq_t request;
    NQ_BYTE * data, * parameters;
    NQ_STATUS status = NQ_ERR_GENERAL;
    NQ_UINT32 token = createToken();

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%p len:%d domain:%s", socket, bufferLen, cmWDump(domain));

    dstName.isGroup = TRUE;
    cmUnicodeToAnsi(dstName.name, domain);
    cmNetBiosNameFormat(dstName.name, domain[0] == cmWChar(0x01)? 0x01 : CM_NB_POSTFIX_MASTERBROWSER);

    request.OpCode = 9;
    request.Count = (NQ_SBYTE)bufferLen/sizeof(BackupList);
    cmPutSUint32(request.Token, cmHtol32(token));

    transCmd = ccTransGetCmdPacket(&parameters, 3);
    if (NULL == transCmd)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_NOMEM);
        status = NQ_ERR_NOMEM;
        goto Exit;
    }

    paramCmd = (TransParamCmd *)parameters;
    cmPutSUint32(transCmd->timeout, cmHtol32(1000));

    data = (NQ_BYTE*)(transCmd + 1);

    cmPutUint16(data, cmHtol16(1));
    cmPutUint16(data + 2, cmHtol16(1));
    cmPutUint16(data + 2*2, cmHtol16(2));

    syMemcpy((char*)paramCmd->Data, &browser, sizeof(browser));
    paramCount = sizeof(browser);

    data = (NQ_BYTE *)paramCmd + paramCount;
    syMemcpy(data, &request, sizeof(request));
    dataCount = 2 * 3;

    status = ccTransSendTo(
            socket,
            &dstName,
            transCmd,
            sizeof(browser),
            &paramCount,
            (NQ_BYTE *) paramCmd,
            &dataCount,
            data,
            0
            );
    ccTransPutCmdPacket(transCmd);
    if (NQ_ERR_OK != status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid GetBackupList response");
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

static NQ_STATUS recvGetBackupListResponse(
    NSSocketHandle socket,
    NQ_BYTE * buffer,
    NQ_UINT16 bufferLen,
    NQ_UINT16 * entries,
    NQ_UINT16 * totalAvail
    )
{
    CMNetBiosNameInfo srcName;    /* NBT name to query */
    NQ_UINT dataCount;            /* number of bytes in response */
    NQ_CHAR * server;             /* pointer to next server name */
    GetBackupListRsp * data;      /* pointer to RAP structure in response */
    NQ_STATUS status;             /* last result */
    NQ_BYTE * rspData;            /* pointer to data in response */
    NQ_UINT16 i;                  /* number of entries in response */
    NQ_BYTE * pBuffer = NULL;     /* pointer to the response buffer to free later */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%p buff:%p len:%d entr:%p avail:%p", socket, buffer, bufferLen, entries, totalAvail);

    status = ccTransReceiveFrom(socket, &srcName, NULL, NULL, &dataCount, &rspData, &pBuffer, backupListReplyTimeoutSec);
    data = (GetBackupListRsp *)rspData;
    if (status != NQ_ERR_OK || data->OpCode != 10)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid RecvGetBackupList response");
        goto Exit;
    }

    *totalAvail = data->Count;

    for (i = 0, server = (NQ_CHAR*)(data + 1); i < data->Count && i < bufferLen/sizeof(BackupList); i++)
    {
        syStrcpy(((BackupList *)buffer)[i].netName, server);
        server += syStrlen(server) + 1;
    }

    *entries = i;

Exit:
    cmMemoryFree(pBuffer);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

static NQ_STATUS enumerateUnicodeCallback(const NQ_WCHAR * name, void * params)
{
    NameEnumParams* callParams;   /* casted pointer to parameters */
    NQ_UINT nameLen;     /* this name actual length including terminating zero */
    NQ_STATUS res = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s params:%p", cmWDump(name), params);

    callParams = (NameEnumParams*)params;
    if (callParams->size >= cmWStrlen(name) * sizeof(NQ_WCHAR) + 2)
    {
        if (callParams->unicode)
        {
            cmWStrcpy((NQ_WCHAR*)callParams->dest, name);
            nameLen = (NQ_UINT)((cmWStrlen((NQ_WCHAR*)callParams->dest) + 1) * sizeof(NQ_WCHAR));
        }
        else
        {
            cmUnicodeToAnsi((NQ_CHAR*)callParams->dest, name);
            nameLen = (NQ_UINT)((syStrlen((NQ_CHAR*)callParams->dest) + 1) * sizeof(NQ_CHAR));
        }
        callParams->size -= nameLen;
        callParams->dest += nameLen;
        callParams->count++;
    }
    else
    {
        callParams->result = NQ_ERR_MOREDATA;
        LOGERR(CM_TRC_LEVEL_ERROR, "Buffer size for enumerate shares is too small.");
        res = NQ_ERR_MOREDATA;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

static NQ_STATUS enumerateUnicodeShareCallback(const NQ_WCHAR* name, void* params)
{
    ShareCallbackItem      *    pItem = (ShareCallbackItem *)params;

    return enumerateUnicodeCallback(name , pItem->params);
}

static void enumerateAnsiCallback(const NQ_CHAR* name, void* params)
{
    NameEnumParams* callParams;   /* casted pointer to parameters */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s params:%p", name ? name : "", params);

    callParams = (NameEnumParams*)params;
    if (callParams->size >= syStrlen(name) * sizeof(NQ_WCHAR) + 2)
    {
        NQ_UINT nameLen;     /* this name actual length including terminating zero */

        if (callParams->unicode)
        {
            cmAnsiToUnicode((NQ_WCHAR*)callParams->dest, name);
            nameLen = (NQ_UINT)((cmWStrlen((NQ_WCHAR*)callParams->dest) + 1) * sizeof(NQ_WCHAR));
        }
        else
        {
            syStrcpy((NQ_CHAR*)callParams->dest, name);
            nameLen = (NQ_UINT)((syStrlen((NQ_CHAR*)callParams->dest) + 1) * sizeof(NQ_CHAR));
        }
        callParams->size -= nameLen;
        callParams->dest += nameLen;
        callParams->count++;
        callParams->result = NQ_ERR_OK;
    }
    else
    {
        callParams->result = NQ_ERR_MOREDATA;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void enumerateAnsiShareCallback(const NQ_CHAR* name, void* params)
{
    ShareCallbackItem      *    pItem = (ShareCallbackItem *)params;

    enumerateAnsiCallback(name , pItem->params);
}



#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEOLDBROWSERAPI */
