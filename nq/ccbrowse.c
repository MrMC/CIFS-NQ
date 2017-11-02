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
static void enumerateUnicodeCallback(const NQ_WCHAR* shareName, void * params);
static NQ_BOOL getShareInfo(NQ_WCHAR *hostName, NQ_WCHAR *shareName, NQ_UINT16 *type, NQ_BYTE *remarkBuffer, NQ_INT bufferSize, NQ_BOOL unicodeResult);

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
    NQ_COUNT size;      /* remaning space in the buffer */
    NQ_INT count;       /* result count */
    NQ_INT result;      /* result code */
    NQ_BOOL unicode;    /* convert to unicode/ascii */
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
    if (syStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        NQ_BOOL result = TRUE;
        NQ_WCHAR tmp[CM_BUFFERLENGTH(NQ_WCHAR, CM_DNS_NAMELEN)];

        *count = 0;
        cmAnsiToUnicode(tmp, workgroup);
#ifdef UD_NQ_USETRANSPORTNETBIOS
        syMutexTake(&guard);
        result = getWorkgroupsByWg(tmp, (NQ_BYTE*)listBuffer, bufferSize, count, FALSE);
        syMutexGive(&guard);

#endif /* UD_NQ_USETRANSPORTNETBIOS */
        if (result)
        {
            result = getTrustedDomains(tmp, (NQ_BYTE*)listBuffer, bufferSize, count, FALSE) ? TRUE : result;
        }

        return result;
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
    sySetLastError(NQ_ERR_BADPARAM);

    return FALSE;
}

NQ_BOOL nqGetWorkgroupsByWgW(NQ_WCHAR * workgroup, NQ_WCHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    if (cmWStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        NQ_BOOL result = TRUE;

        *count = 0;
#ifdef UD_NQ_USETRANSPORTNETBIOS
        syMutexTake(&guard);
        result = getWorkgroupsByWg(workgroup, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE);
        syMutexGive(&guard);
#endif /* UD_NQ_USETRANSPORTNETBIOS */
        if (result)
        {        
            result = getTrustedDomains(workgroup, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE) ? TRUE : result;
        }

        return result;
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
    sySetLastError(NQ_ERR_BADPARAM);

    return FALSE;
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
    CMList * pList = (CMList *) list;   /* casted pointer */

    cmListItemCreateAndAdd(pList, sizeof(NetItem), name, NULL , FALSE);
}

static NQ_BOOL getTrustedDomains(
    NQ_WCHAR * workgroup,
    NQ_BYTE * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT * count,
    NQ_BOOL unicode       
    )
{
    NQ_WCHAR * dc;				/* domain controller in Unicode */
    NQ_CHAR * dcA;				/* the same in ASCII */
    NQ_CHAR * workgroupA;		/* workgroup copy in ASCII */
    NQ_HANDLE netlogon;
    NQ_BOOL result = FALSE;
    NQ_UINT32 status;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);    
    
    /* check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        return result;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Workgroup: %s, buffer size: %d, count: %d, %s", cmWDump(workgroup), bufferSize, *count, unicode ? "unicode" : "ascii");

    /* allocate buffers and convert strings */
    workgroupA = cmMemoryCloneWStringAsAscii(workgroup);
    dcA = cmMemoryAllocate(sizeof(NQ_BYTE) * CM_DNS_NAMELEN);
	if (NULL == workgroupA || NULL == dcA)
	{
    	cmMemoryFree(workgroupA);
    	cmMemoryFree(dcA);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    
    /* find domain controller by domain name */
    if (cmGetDCNameByDomain(workgroupA, dcA) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to get dc for domain %s", workgroupA);
    	cmMemoryFree(workgroupA);
    	cmMemoryFree(dcA);
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return FALSE;        
    }
    
    /* allocate more buffers and strings and free used */
    dc = cmMemoryCloneAString(dcA);
	cmMemoryFree(workgroupA);
	cmMemoryFree(dcA);
 	if (NULL == dc)
	{
    	cmMemoryFree(dc);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

    /* try netlogon pipe to get trusted domains  */
    if ((netlogon = ccDcerpcConnect(dc, NULL, ccNetlogonGetPipe(), TRUE)) != NULL)
    {
        CMList list;
        CMIterator iterator;

        cmListStart(&list);

        status = ccDsrEnumerateDomainTrusts(netlogon, dc, addNameCallback, &list);
        if (NQ_SUCCESS == status)
        {
            /* add new domains into listBuffer */
            cmListIteratorStart(&list, &iterator);
            while (cmListIteratorHasNext(&iterator))
            {
                NetItem * pItem;    /* name entry */
                NQ_COUNT maxSize;   /* number of bytes to have in the buffer */

                pItem = (NetItem *)cmListIteratorNext(&iterator);
                maxSize = cmWStrlen(pItem->item.name) + 1;
                if (unicode)
                    maxSize *= (NQ_COUNT)sizeof(NQ_WCHAR);
                if (bufferSize < maxSize)
                {
                    sySetLastError(NQ_ERR_MOREDATA);
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
							break;
  					    lastChar = syWStrchr(lastChar , cmWChar('\0')) + 1; 
					}                    
					if (cpyCounter == 0 || cpyCounter == serverCount)
					{
						cmWStrcpy((NQ_WCHAR *)lastChar, pItem->item.name);
					    lastChar = syWStrchr(lastChar , cmWChar('\0')) + 1; 
                        *lastChar++ = cmWChar('\0');
						(*count)++;
					}
                }
                else
                {
                	NQ_INT cpyCounter , serverCount = *count;
					NQ_CHAR  *lastChar , *cmpString;

                    lastChar = (NQ_CHAR *)listBuffer;
					cmpString = cmMemoryCloneWStringAsAscii(pItem->item.name);
					if (NULL == cmpString)
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                        sySetLastError(NQ_ERR_NOMEM);
                    }
					else
                    {
                        for (cpyCounter = 0 ; cpyCounter < serverCount; cpyCounter++)
					    { 	
                            if (syStrcmp(cmpString, lastChar) == 0)
						    {
							    break;
						    }
    					    lastChar = syStrchr(lastChar , '\0') + 1; 
					    }
					    if (serverCount == 0 || cpyCounter == serverCount)
					    {
						    syStrcpy(lastChar, cmpString);
    					    lastChar = syStrchr(lastChar , '\0') + 1; 
                            *lastChar = '\0';
						    (*count)++;
					    }
                        cmMemoryFree(cmpString);
                    }
                }
            }
            cmListIteratorTerminate(&iterator);
        }
        else
        {
            sySetLastError(status);
        }
        ccDcerpcDisconnect(netlogon);
        cmListShutdown(&list);
    }
    else
    {
         LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect to netlogon pipe");
    }
    
  	cmMemoryFree(dc);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
    NQ_WCHAR * server;		/* next server name */
    NQ_UINT16 cnt, total;	/* counters */
    NQ_INT retryCount;		/* repeat three times */
    NQ_STATUS status;		/* operation result */


    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        return FALSE;
    }

    if (cmWStrlen(workgroup) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        sySetLastError(NQ_ERR_BADPARAM);
        return FALSE;
    }

    server = cmMemoryAllocate(sizeof(NQ_WCHAR) * CM_DNS_NAMELEN);
	if (NULL == server)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

    for (retryCount = CC_BROWSE_RETRYCOUNT; retryCount>0; retryCount--)
    {
        NameEnumParams params;      /* parameters for callback */

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

        TRC1P( "Found %d domain backup server(s)", cnt );

        cmAnsiToUnicode(server, servers[cnt-1].netName);

        params.count = 0;
        params.dest = listBuffer;
        params.size = bufferSize;
        params.unicode = unicode;
        params.result = NQ_ERR_OK;

        if ((status = ccRapNetServerEnum(server, enumerateAnsiCallback, &params, SV_TYPE_DOMAIN_ENUM, NULL)) != NQ_ERR_OK)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving domains list");
            sySetLastError((NQ_UINT32)status);
            continue;
        }

        *count = params.count;
        sySetLastError((NQ_UINT32)params.result);
        cmMemoryFree(server);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return params.result == NQ_ERR_OK;
    }
	cmMemoryFree(server);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return FALSE;
}


NQ_BOOL nqGetHostsInWorkgroupA(NQ_CHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
	NQ_CHAR * domainA;	/* DC name in ASCII */
	NQ_INT res;			/* operation result */
	
	syMutexTake(&guard);
	domainA = cmMemoryCloneWStringAsAscii(pdcDomain);
	syMutexGive(&guard);
	if (NULL == domainA)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	res = nqGetHostsInWorkgroupByWgA(domainA, listBuffer, bufferSize, count);
	cmMemoryFree(domainA);
    return res;
}


NQ_BOOL nqGetHostsInWorkgroupW(NQ_WCHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    return nqGetHostsInWorkgroupByWgW(pdcDomain, listBuffer, bufferSize, count);
}

NQ_BOOL nqGetHostsInWorkgroupByWgA(NQ_CHAR * workgroup, NQ_CHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    if (syStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        NQ_BOOL result;			/* operation result */
        NQ_WCHAR * workgroupA;	/* in ASCII */

        workgroupA = cmMemoryCloneAString(workgroup);
    	if (NULL == workgroupA)
    	{
    		sySetLastError(NQ_ERR_OUTOFMEMORY);
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    		return FALSE;
    	}

        result = getHostsInWorkgroupByWg(workgroupA, (NQ_BYTE*)listBuffer, bufferSize, count, FALSE);
    	cmMemoryFree(workgroupA);

        return result;
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
    sySetLastError(NQ_ERR_BADPARAM);

    return FALSE;
}

NQ_BOOL nqGetHostsInWorkgroupByWgW(NQ_WCHAR * workgroup, NQ_WCHAR * listBuffer, NQ_COUNT bufferSize, NQ_INT *count)
{
    if (cmWStrlen(workgroup) < CM_DNS_NAMELEN)
    {
        NQ_BOOL result;

        result = getHostsInWorkgroupByWg(workgroup, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE);

        return result;
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
    sySetLastError(NQ_ERR_BADPARAM);

    return FALSE;
}

static NQ_BOOL getHostsInWorkgroupByWg(
    NQ_WCHAR * workgroup,
    NQ_BYTE * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT *count,
    NQ_BOOL unicode
   )
{
    NQ_CHAR  * workgroupA;
    NQ_CHAR  * serverA;  
    NQ_WCHAR * server;
    NQ_INT retryCount;
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    *count = 0;

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        sySetLastError(NQ_ERR_NOTREADY);
        return FALSE;
    }

    if (cmWStrlen(workgroup) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        sySetLastError(NQ_ERR_BADPARAM);
        return FALSE;
    }
	
    workgroupA = cmMemoryCloneWStringAsAscii(workgroup);
    if (workgroupA == NULL)
    {
	    sySetLastError(NQ_ERR_OUTOFMEMORY);
	    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	    return FALSE;
    }    

    server = cmMemoryAllocate(sizeof(NQ_WCHAR) * CM_DNS_NAMELEN);
	if (NULL == server)
	{
        cmMemoryFree(workgroupA);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

	for (retryCount= CC_BROWSE_RETRYCOUNT; retryCount>0; retryCount--)
    {
        NameEnumParams  params;      /* parameters for callback */
        NQ_STATUS       res;        

        serverA = (NQ_CHAR *)cmMemoryAllocate(UD_NQ_HOSTNAMESIZE * sizeof(NQ_CHAR));
        if (serverA == NULL)
        {
            cmMemoryFree(server);
            cmMemoryFree(workgroupA);
		    sySetLastError(NQ_ERR_OUTOFMEMORY);
		    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		    return FALSE;
	    }  

        /* try DC */
        res = cmGetDCNameByDomain(workgroupA, serverA);        
        if (res != NQ_SUCCESS)
        {
            NQ_UINT16 cnt, total;

            cmMemoryFree(serverA);
            LOGERR(CM_TRC_LEVEL_ERROR, "No DC found");

			/* try backup list */
			if ((status = getDomainBackupListW(workgroup, (NQ_BYTE *) &servers, sizeof(servers), &cnt, &total, TRUE)) != NQ_ERR_OK)
	        {
	            LOGERR(CM_TRC_LEVEL_ERROR,"Error retrieving domain backup list");
	            sySetLastError(NQ_ERR_GETDATA);
	            continue;
	        }
	        if (cnt == 0)
	        {
	            TRCERR("No domain backup servers found");
	            sySetLastNqError(NQ_ERR_GETDATA);
	            continue;
	        }
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Found %d domain backup server(s)", cnt);
			
			serverA = (NQ_CHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_CHAR) * (syStrlen(servers[cnt - 1].netName) + 1)));
	        if (serverA == NULL)
	        {
	            cmMemoryFree(server);
	            cmMemoryFree(workgroupA);
			    sySetLastError(NQ_ERR_OUTOFMEMORY);
			    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return FALSE;
		    }
			syStrcpy(serverA, servers[cnt - 1].netName);
        }

        cmAnsiToUnicode(server, serverA);
		cmMemoryFree(serverA);
        params.count = 0;
        params.dest = listBuffer;
        params.size = bufferSize;
        params.unicode = unicode;
        params.result = NQ_ERR_OK;

        if ((status = ccRapNetServerEnum(server, enumerateAnsiCallback, &params,
                                    0xffffffff /*SV_TYPE_WORKSTATION | SV_TYPE_SERVER*/, workgroup)) != NQ_ERR_OK)
        {    
            LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving hosts list");
            sySetLastError((NQ_UINT32)status);
            continue;
        }

        *count = params.count;
        cmMemoryFree(server);
        cmMemoryFree(workgroupA);
        sySetLastError((NQ_UINT32)params.result);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return params.result == NQ_ERR_OK;
    }
	
	cmMemoryFree(server);
	cmMemoryFree(workgroupA);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return FALSE;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

NQ_BOOL nqGetSharesOnHostA(
    NQ_CHAR * hostName,
    NQ_CHAR * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT * count
   )
{
	NQ_WCHAR * hostNameW;	/* host name in Unicode */
	NQ_BOOL result;			/* Unicode operation resulkt */
	
	hostNameW = cmMemoryCloneAString(hostName);
	if (NULL == hostNameW)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

	result = getSharesOnHost(hostNameW, (NQ_BYTE *)listBuffer, bufferSize, count, FALSE);
	cmMemoryFree(hostNameW);
	
	return result;
}

NQ_BOOL nqGetSharesOnHostW(
    NQ_WCHAR * hostName,
    NQ_WCHAR * listBuffer,
    NQ_COUNT bufferSize,
    NQ_INT *count
   )
{
    if (cmWStrlen(hostName) < CM_DNS_NAMELEN)
    {
        return getSharesOnHost(hostName, (NQ_BYTE*)listBuffer, bufferSize, count, TRUE);
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Workgroup name is too long");
    sySetLastError(NQ_ERR_BADPARAM);

    return FALSE;
}

NQ_BOOL nqGetShareInfoA(
    NQ_CHAR * hostName,
    NQ_CHAR * shareName,
    NQ_UINT16 * type,
    NQ_CHAR * remarkBuffer,
    NQ_INT bufferSize
   )
{
    NQ_BOOL result;			/* operation result */
    NQ_WCHAR * hostW;		/* host name in Unicode */ 
    NQ_WCHAR * shareW;		/* share name in Unicode */

    hostW = cmMemoryCloneAString(hostName);
    shareW = cmMemoryCloneAString(shareName);
	if (NULL == hostW || NULL == shareW)
	{
		cmMemoryFree(hostW);
		cmMemoryFree(shareW);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

    result = getShareInfo(hostW, shareW, type, (NQ_BYTE *)remarkBuffer, bufferSize, FALSE);

    cmMemoryFree(hostW);
	cmMemoryFree(shareW);

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
    AMCredentialsW *pCredentials = NULL;
#ifndef UD_CM_UNICODEAPPLICATION
    AMCredentialsA *pCredentialsA = NULL;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        sySetLastError(NQ_ERR_NOTREADY);
        return FALSE;
    }

    pCredentials = cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
	{
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
#ifdef UD_CM_UNICODEAPPLICATION
    udGetCredentials(NULL, pCredentials->user,
                           pCredentials->password,
                           pCredentials->domain.name);
#else
    pCredentialsA = cmMemoryAllocate(sizeof(AMCredentialsA));
    if (NULL == pCredentialsA)
	{
    	cmMemoryFree(pCredentials);
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    udGetCredentials(NULL, pCredentialsA->user,
                           pCredentialsA->password,
                           pCredentialsA->domain.name);
    amCredentialsAsciiiToW(pCredentials, pCredentialsA);
    cmMemoryFree(pCredentialsA);
#endif

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

        cmMemoryFree(pCredentials);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }

    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return FALSE;
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
#ifndef UD_CM_UNICODEAPPLICATION
    AMCredentialsA *pCredentialsA = NULL;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        sySetLastError(NQ_ERR_NOTREADY);
        return FALSE;
    }

    if (cmWStrlen(hostName) >= CM_DNS_NAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Host name is too long");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        sySetLastError(NQ_ERR_BADPARAM);
        return FALSE;
    }

    pCredentials = cmMemoryAllocate(sizeof(AMCredentialsW));
    if (NULL == pCredentials)
 	{
 		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
 		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
 		return FALSE;
 	}
 #ifdef UD_CM_UNICODEAPPLICATION
     udGetCredentials(NULL, pCredentials->user,
                            pCredentials->password,
                            pCredentials->domain.name);
 #else
     pCredentialsA = cmMemoryAllocate(sizeof(AMCredentialsA));
     if (NULL == pCredentialsA)
	 {
		cmMemoryFree(pCredentials);
		sySetLastNqError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	 }
     udGetCredentials(NULL, pCredentialsA->user,
                            pCredentialsA->password,
                            pCredentialsA->domain.name);
     amCredentialsAsciiiToW(pCredentials, pCredentialsA);
     cmMemoryFree(pCredentialsA);
 #endif

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
            if ((status = ccRapNetShareEnum(hostName, enumerateAnsiCallback, &params)) != NQ_ERR_OK)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                sySetLastError((NQ_UINT32)status);
                continue;
            }
        }
        else
        {
            if ((status = ccSrvsvcEnumerateShares(pipe, hostName, enumerateUnicodeCallback, &params)) != NQ_ERR_OK)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error retrieving shares list");
                sySetLastError((NQ_UINT32)status);
                ccDcerpcDisconnect(pipe);
                continue;
            }
            ccDcerpcDisconnect(pipe);
        }
        cmMemoryFree(pCredentials);
        *count = params.count;
        sySetLastError((NQ_UINT32)params.result);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return params.result == NQ_ERR_OK;
    }

    cmMemoryFree(pCredentials);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return FALSE;
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    *entries = *totalAvail = 0;

    if ((status = sendGetBackupListRequest(requestSocket, bufferLen, domain)) != NQ_ERR_OK)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending GetBackupList request");
    }
    else
        status = recvGetBackupListResponse(requestSocket, buffer, bufferLen, entries, totalAvail);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
    NQ_STATUS           status;
    const NQ_WCHAR  *   domainToUse = NULL;
    NQ_WCHAR        *   domainToMod = NULL;
    NQ_WCHAR        *   point;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
	}
	else
		domainToUse = cmMemoryCloneWString(domain);

    if (NULL == domainToUse)
        domainToUse = cmMemoryCloneWString(browser);
  
    status = getDomainBackupListByDomain(domainToUse, buffer, bufferLen, entries, totalAvail);
    if (NULL != domain && NQ_SUCCESS != status && findAny)
        status = getDomainBackupListByDomain(browser, buffer, bufferLen, entries, totalAvail);

    cmMemoryFree(domainToUse);
    cmMemoryFree(domainToMod);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}

static NQ_UINT32 createToken(void)
{
    static NQ_UINT32 token = 1;
    NQ_UINT32 res;

    res = token++;
    return res;
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
    NQ_STATUS status;
    NQ_UINT32 token = createToken();

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    dstName.isGroup = TRUE;
    cmUnicodeToAnsi(dstName.name, domain);
    cmNetBiosNameFormat(dstName.name, domain[0] == cmWChar(0x01)? 0x01 : CM_NB_POSTFIX_MASTERBROWSER);

    request.OpCode = 9;
    request.Count = (NQ_SBYTE)bufferLen/sizeof(BackupList);
    cmPutSUint32(request.Token, cmHtol32(token));

    transCmd = ccTransGetCmdPacket(&parameters, 3);
    if (NULL == transCmd)
    {
        sySetLastError(NQ_ERR_NOMEM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOMEM;
    }

    paramCmd = (TransParamCmd *)parameters;
    cmPutSUint32(transCmd->timeout, cmHtol32((NQ_UINT32)1000));

    data = (NQ_BYTE*)(transCmd + 1);

    cmPutUint16(data, cmHtol16(1));
    cmPutUint16(data + 2, cmHtol16(1));
    cmPutUint16(data + 2*2, cmHtol16(2));

    syMemcpy((char*) paramCmd->Data, &browser, sizeof(browser));
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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return status;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_ERR_OK;
}

static NQ_STATUS recvGetBackupListResponse(
    NSSocketHandle socket,
    NQ_BYTE * buffer,
    NQ_UINT16 bufferLen,
    NQ_UINT16 * entries,
    NQ_UINT16 * totalAvail
    )
{
    CMNetBiosNameInfo srcName;	/* NBT name to query */
    NQ_UINT dataCount;			/* number of bytes in response */
    NQ_CHAR * server;			/* pointer to next server name */
    GetBackupListRsp * data;	/* pointer to RAP structure in response */
    NQ_STATUS status;			/* last result */
    NQ_BYTE * rspData;			/* pointer to data in response */
    NQ_UINT16 i;				/* number of entries in response */
    NQ_BYTE * pBuffer = NULL;	/* pointer to the response buffer to free later */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    status = ccTransReceiveFrom(socket, &srcName, NULL, NULL, &dataCount, &rspData, &pBuffer);
    data = (GetBackupListRsp *)rspData;
    if (status != NQ_ERR_OK || data->OpCode != 10)
    {
        if (NULL != pBuffer)
            cmMemoryFree(pBuffer);
        LOGERR(CM_TRC_LEVEL_ERROR, "No valid RecvGetBackupList response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return status;
    }

    *totalAvail = data->Count;

    for (i = 0, server = (NQ_CHAR*)(data + 1); i < data->Count && i < bufferLen/sizeof(BackupList); i++)
    {
        syStrcpy(((BackupList *)buffer)[i].netName, server);
        server += syStrlen(server) + 1;
    }
    cmMemoryFree(pBuffer);

    *entries = i;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_ERR_OK;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

static void enumerateUnicodeCallback(const NQ_WCHAR * name, void * params)
{
    NameEnumParams* callParams;   /* casted pointer to parameters */
    NQ_UINT nameLen;     /* this name actual length including terminating zero */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void enumerateAnsiCallback(const NQ_CHAR* name, void* params)
{
    NameEnumParams* callParams;   /* casted pointer to parameters */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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


#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEOLDBROWSERAPI */
