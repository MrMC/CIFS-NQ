/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of file search commands
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 10-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "cstrans2.h"
#include "csfnames.h"
#include "csutils.h"
#include "cssearch.h"
#include "cmstring.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implement search commands and subcommands. CIFS and "NT" commands are paired.
   Commands in a pair use the same code (local functions) for composing one entry. */

/*
    Static functions and data
    -------------------------
 */
static NQ_WCHAR fileNameBuff[CM_MAXFILENAMELEN];

/* get file information and fill a directory entry for Search */

static NQ_UINT32                            /* SMB error or 0 */
fillSearchEntry(
    const NQ_WCHAR* pFileName,              /* filename */
    CMCifsSearchDirectoryEntry* entry       /* entry to fill */
    );


/*====================================================================
 * PURPOSE: Perform SEARCH command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *
 *          This function uses ResumeKey in the following way:
 *           - if no ResumeKey is specified or the reservedForServer field is null
 *             the directory is opened from the beginning
 *           - if there is a value in the reservedForServer field, it is treated as
 *             a directory FID
 *           - after the last file in the directory is read it is closed and
 *             its FID released
 *====================================================================
 */

NQ_UINT32
csComSearch(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsSearchRequest* searchRequest;     /* casted request */
    CMCifsSearchResponse* searchResponse;   /* casted response */
    NQ_BOOL unicodeRequired;                /* whether client requires UNICODE */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    const CSShare* pShare;                  /* pointer to the share */
    NQ_WCHAR* pFileName;                    /* filename to search */
    CSTid tid;                              /* required tree ID */
    CSUid uid;                              /* required user ID */
    CMCifsSearchRequestExtension*
        searchRequestExtension;             /* the second component of the request */
    NQ_UINT16 attributes;                   /* required file attributes */
    static const NQ_WCHAR noName[] = {cmWChar(0)}; /* empty name for volume information */
    CMCifsSearchDirectoryEntry* pEntry;     /* directory entry pointer */
    NQ_UINT entryCount = 0;                 /* number of entries in the response */
    CSTree* pTree;                          /* pointer to the tree descriptor */
    CSUser* pUser;                          /* pointer to the user descriptor */
    CSSearch* pSearch = NULL;               /* pointer to the search descriptor */
    NQ_STATIC NQ_WCHAR tFileName[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];   /* for converting search name to ANSI */
    NQ_STATIC NQ_CHAR fileName[CM_BUFFERLENGTH(NQ_CHAR, UD_FS_FILENAMELEN)];     /* for converting search name to ANSI */
    NQ_UINT nameLen;                        /* source name lenth */
    NQ_CHAR *name;

    TRCB();

    /* read unicode flag and set it to ASCII */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;
    cmPutSUint16(pHeaderOut->flags2, (NQ_UINT16)(cmGetSUint16(pHeaderOut->flags2) & ~(cmHtol16(SMB_FLAGS2_UNICODE))));

    /* cast pointers */

    searchRequest = (CMCifsSearchRequest*) pRequest;
    searchResponse = (CMCifsSearchResponse*) *pResponse;

    /* search format */

    if (   searchRequest->wordCount != SMB_SEARCH_REQUEST_WORDCOUNT
        || cmGetSUint16(searchRequest->byteCount) < SMB_SEARCH_REQUEST_MINBYTES
        || searchRequest->bufferFormat < SMB_FIELD_ASCII
       )
    {
        TRCERR("Illegal WordCount, ByteCount or BufferFormat");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* withdraw UID and TID */

    uid = cmLtoh16(cmGetSUint16(pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));

    /* check access to share */

    if ((returnValue = csCanReadShare(tid)) != NQ_SUCCESS)
    {
        TRCERR("Access denied");
        TRCE();
        return returnValue;
    }

    pUser = csGetUserByUid(uid);
    if (pUser == NULL)
    {
        TRCERR("Illegal UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

    pTree = csGetTreeByTid(tid);
    if (pTree == NULL)
    {
        TRCERR("Illegal TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
    }

    pShare = csGetShareByUidTid(uid, tid);
    if (pShare == NULL)
    {
        TRCERR("Illegal TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
    }

    /* start composing the response */

    searchResponse->wordCount = SMB_SEARCH_RESPONSE_WORDCOUNT;
    searchResponse->bufferFormat = SMB_FIELD_VARIABLE;
    pEntry = (CMCifsSearchDirectoryEntry*) (searchResponse + 1);

    /* process a volume label request */

    attributes = cmLtoh16(cmGetSUint16(searchRequest->searchAttributes));

    if (attributes & SMB_ATTR_VOLUME)
    {
        /* convert filename to host filename, simulating empty file name in ANSI */

        TRC("volume label required");

        if ((pFileName = cmCifsNtohFilename(
        					fileNameBuff,
                            pShare->map,
                            noName,
                            FALSE,
							TRUE
                            )
            ) == NULL
           )
        {
            TRCERR("Illegal filename");
            TRCE();
            return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
        }

        /* fill file information */

        if ((returnValue = fillSearchEntry(pFileName, pEntry)) != 0)
        {
            TRCERR("Unable to read file information");

            TRCE();
            return returnValue;
        }
        cmPutSUint16(pEntry->lastWriteTime, 0);
        cmPutSUint16(pEntry->lastWriteDate, 0);
        
        /* update this information */

        pEntry->resumeKey.reserved = SMB_ATTR_VOLUME;
        pEntry->fileAttributes = SMB_ATTR_VOLUME;

        /* this response contains one entry */

        entryCount = 1;
    }
    else
    {
        NQ_UINT entryIndex;                /* index of the current entry in the directory */
        NQ_UINT maxCount;                  /* limit for the number of entries in response */
        NQ_BYTE *serverCookie;

        /* skip to the ResumeKey block */

        {
            NQ_BYTE* tmpPtr;       /* used for parsing the filename */

            if (unicodeRequired)
            {
                tmpPtr = (NQ_BYTE*)(searchRequest + 1);
                tmpPtr = cmAllignTwo(tmpPtr);
                searchRequestExtension =
                    (CMCifsSearchRequestExtension*)
                        (  tmpPtr
                         + (cmWStrlen((NQ_WCHAR*)tmpPtr) + 1) * sizeof(NQ_WCHAR)
                        );
                syWStrcpy(tFileName, (NQ_WCHAR*)(tmpPtr));
            }
            else
            {
                tmpPtr = (NQ_BYTE*)(searchRequest + 1);
                searchRequestExtension =
                    (CMCifsSearchRequestExtension*)(tmpPtr + syStrlen((NQ_CHAR*)tmpPtr) + 1);
                syAnsiToUnicode(tFileName, (NQ_CHAR*)(searchRequest + 1));
            }

            {
                NQ_WCHAR *pName;

                pName = syWStrrchr(tFileName, cmWChar('\\'));
                if (pName == NULL)
                {
                    pName = tFileName;
                }
                else
                {
                    pName++;
                }
                syUnicodeToAnsi(fileName, pName);
            }

            TRC1P("fileName = %s", fileName);
            nameLen = (NQ_UINT)syStrlen(fileName);
            if (nameLen > sizeof(pEntry->resumeKey.fileName))
            {
                nameLen = sizeof(pEntry->resumeKey.fileName);
            }

        }

        /* prepare counts: use the least of 1) required limit 2) number of entries fitting
           in the buffer */

        {
            NQ_UINT maxFittingCount;   /* maximum number of directory entries that fits the buffer */

            maxCount = (NQ_UINT)cmLtoh16(cmGetSUint16(searchRequest->maxCount));
            maxFittingCount =   (NQ_UINT)(CS_MAXBUFFERSIZE - (NQ_UINT)((NQ_BYTE*)pEntry - (NQ_BYTE*)pHeaderOut))
                              / sizeof(*pEntry);
            if (maxFittingCount < maxCount)
            {
                maxCount = maxFittingCount;
            }
        }

        /* distinguish between the 1st call and a subsequent call */

        if (cmGetSUint16(searchRequestExtension->resumeKeyLength) == 0)
        {
            /* convert filename to host filename */

            if ((pFileName = cmCifsNtohFilename(
            					fileNameBuff,
                                pShare->map,
                                (NQ_WCHAR*)(searchRequest + 1),
                                unicodeRequired,
								TRUE
                                )
                ) == NULL
               )
            {
                TRCERR("Illegal filename");
                TRCE();
                return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
            }

            if (!csCheckPath(pShare, pFileName, (NQ_UINT)syWStrlen(pShare->map), pUser->preservesCase))
            {
                TRCERR("Path does not exists");
                TRC1P(" path: %s", cmWDump(pFileName));
                return csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath);
            }

            if ((pSearch = csGetNewSearch(pTree)) == NULL)
            {
                TRCERR("SID overflow");
                TRCE();
                return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
            }
            pSearch->attributes = attributes;

            csEnumerateSourceName(&pSearch->enumeration, pFileName, pUser->preservesCase);

            /* on first call: start directory search from the beginning */

            entryIndex = 0;
        }
        else
        {
            CMCifsSearchResumeKey* pResumeKey;  /* pointer to resume key in request */
            CSSid sid;


            /* on a subsequent call: continue searching the directory from the
               index in the request's ResumeKey and use the saved attributes */

            pResumeKey = (CMCifsSearchResumeKey*)(searchRequestExtension + 1);
            serverCookie = (NQ_BYTE *)pResumeKey->serverCookie;
            sid = cmGetUint16(serverCookie);
            serverCookie = serverCookie + sizeof(CSSid);
            entryIndex = (NQ_UINT)cmGetUint16(serverCookie);
            if ((pSearch = csGetSearchBySid(sid)) == NULL)
            {
                TRCERR("Illegal SID");
                TRC1P(" value: %d", sid);
                TRCE();
                return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
            }
            attributes = pSearch->attributes;
        }

        if (pSearch->enumeration.isReady)
        {
            while ((pFileName = csNextSourceName(&pSearch->enumeration)) != NULL)
            {
                SYFileInformation fileInfo; /* for querying file information */

                /* file candidate found - compare attributes */
         
                /* skip "." and ".." entries */
                if (*(pFileName + syWStrlen(pFileName) - 1) == '.')
                    continue;

                if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
                {
                    /* set default info details for corrupted file */
                    syMemset(&fileInfo, 0, sizeof(fileInfo));
                }
                
                if (csMatchFileAttributes(attributes, (NQ_UINT16)fileInfo.attributes))
                {
                    if ((NQ_UINT16)fileInfo.attributes & SMB_ATTR_DIRECTORY)    
                    {                      
                        if (attributes & SMB_ATTR_DIRECTORY)
                        {
                            /* fill file information */  
                            
                            if ((returnValue = fillSearchEntry(pFileName, pEntry)) != 0)
                            {
                                csReleaseSearch(pSearch->sid);

                                TRCERR("Unable to read file information");
                                TRCE();
                                return returnValue;
                            }                      
                        }
                        else
                            continue;                      
                    }
                    else   
                    {                      
                        /* fill file information */
                        
                        if ((returnValue = fillSearchEntry(pFileName, pEntry)) != 0)
                        {
                            csReleaseSearch(pSearch->sid);

                            TRCERR("Unable to read file information");
                            TRCE();
                            return returnValue;
                        }      
                    }
                   
                    /* add ResumeKey */

                    pEntry->resumeKey.reserved = 0x08; /* undocumented */
                    syMemset(pEntry->resumeKey.fileName, ' ', sizeof(pEntry->resumeKey.fileName));
                    name = (NQ_CHAR *)pEntry->resumeKey.fileName;
                    syMemcpy(name, fileName, nameLen);
                    serverCookie = pEntry->resumeKey.serverCookie;
                    cmPutUint16(
                        serverCookie,
                        pSearch->sid
                        );
                    serverCookie = serverCookie + sizeof(CSSid);
                    cmPutUint16(
                    	serverCookie,
                        (NQ_UINT16)entryIndex);

                    /* continue */

                    entryIndex++;
                    entryCount++;
                    pEntry++;

                    if (entryCount >= maxCount)
                        break;
                }
            }

            /* no files found */
            if (NULL == pFileName && entryCount == 0)
            {              
                csReleaseSearch(pSearch->sid);
                
                TRCERR("No more files");
                TRCE();
                return csErrorReturn(SMB_STATUS_NO_MORE_FILES, DOS_ERRnofiles);
            }           
        }
        else
        {
            csReleaseSearch(pSearch->sid);

            TRCERR("No more files");
            TRCE();
            return csErrorReturn(SMB_STATUS_NO_MORE_FILES, DOS_ERRnofiles);
        }
    }

    /* release search even if there are still entries to be send in this search */
    /* windows bug: windows never completes the first search request which causes sids table overflow */ 
    
    if (pSearch) csReleaseSearch(pSearch->sid);
    
    /* continue composing the response message */

    cmPutSUint16(searchResponse->count, cmHtol16((NQ_UINT16)entryCount));
    cmPutSUint16(searchResponse->byteCount, cmHtol16((NQ_UINT16)
        ( sizeof(searchResponse->bufferFormat)
        + sizeof(searchResponse->dataLength)
        + sizeof(*pEntry) * entryCount
        )));
    cmPutSUint16(searchResponse->dataLength, cmHtol16((NQ_UINT16)(sizeof(*pEntry) * entryCount)));

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*searchResponse) - 3 + cmLtoh16(cmGetSUint16(searchResponse->byteCount));

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform FindClose2 command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComFindClose2(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsFindClose2Request* closeRequest;  /* casted request */
    CMCifsFindClose2Response* closeResponse;/* casted response */
    NQ_UINT32 returnValue;                     /* error code in NT format or 0 for no error */
    CSSid sid;                              /* required search ID */
    CSSearch		*	pSearch = NULL;
#ifdef UD_NQ_INCLUDEEVENTLOG
	UDFileAccessEvent   eventInfo;
	CSUser *			pUser = NULL;
	NQ_WCHAR noName[] = CM_WCHAR_NULL_STRING;  /* empty name for file */;
	NQ_IPADDRESS noIP = CM_IPADDR_ZERO;
#endif /* UD_NQ_INCLUDEEVENTLOG */


    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*closeResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* cast pointers */

    closeRequest = (CMCifsFindClose2Request*) pRequest;
    closeResponse = (CMCifsFindClose2Response*) *pResponse;

    /* check format */

    if (   closeRequest->wordCount != SMB_FINDCLOSE2_REQUEST_WORDCOUNT
        || cmGetSUint16(closeRequest->byteCount) != 0
       )
    {
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find search descriptor */

    sid = cmLtoh16(cmGetSUint16(closeRequest->sid));
    if ((pSearch = csGetSearchBySid(sid)) == NULL)
    {
        TRCERR("Illegal SID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
	eventInfo.tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
	eventInfo.fileName = pSearch->enumeration.path;
	eventInfo.rid = csGetUserRid(pUser);
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_CLOSE,
		pUser? pUser->name : noName,
		pUser? pUser->ip : &noIP,
		0,
		(const NQ_BYTE *)&eventInfo
		);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    csReleaseSearch(sid);

#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_CLOSE,
		pUser? pUser->name : noName,
		pUser? pUser->ip : &noIP,
		0,
		(const NQ_BYTE *)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* compose the response */

    closeResponse->wordCount = 0;
    cmPutSUint16(closeResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*closeResponse);

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: Perform FindFirst2 subcommand
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT structure with subcommand parameters:
 *              IN pointer to the CIFS header
 *              IN pointer to the parameter area
 *              OUT pointer to the data area
 *              OUT length of the parameter area
 *              OUT length of the data area
 *
 * RETURNS: SMB error or 0 on success
 *
 * NOTES:   This command may be continued by FindNext2. For this purpose it
 *          creates a search descriptor identified by SID. Search descriptor
 *          contains also search context structure used for enumerating file names
 *          (see file CSFNAMES.C for more)
 *====================================================================
 */

NQ_UINT32
csTransaction2FindFirst(
    CSTransaction2Descriptor* descriptor
    )
{
    CMCifsFindFirst2Request* findRequest;   /* casted request */
    CMCifsFindFirst2Response* findResponse; /* casted response */
    NQ_BOOL unicodeRequired;                /* whether client requires UNICODE */
    CMCifsStatus error;                     /* for composing DOS-style error */
    const CSShare* pShare;                  /* pointer to the share */
    NQ_WCHAR* pFileName;                    /* filename to search */
    CSTid tid;                              /* required tree ID */
    CSUid uid;                              /* required user ID */
    NQ_UINT16 attributes;                   /* required file attributes */
    NQ_BYTE* pEntry;                        /* file record pointer */
    NQ_BYTE* pLastEntry = NULL;             /* pointer to the last record */
    NQ_BYTE* pNextEntryOffset = NULL;       /* pointer to nextEntryOffset field in the entry */
    NQ_UINT entryCount;                     /* number of entries in the response */
    NQ_UINT maxCount;                       /* limit for the number of entries in response */
    NQ_UINT16 level;                        /* required detalization - information level */
    CSSearch* pSearch;                      /* search operation descriptor */
    const CSTree* pTree;                    /* master tree pointer */
    NQ_UINT16 flags;                        /* request flags */
    static const NQ_CHAR allFilesAscii[] = "*";     /* empty pattern will replaced by this */
    static const NQ_WCHAR allFilesUnicode[] = {(NQ_WCHAR)'*', 0};   /* empty pattern will replaced by this */
    NQ_BYTE* pPattern;                      /* pointer to the pattern */
    CSUser* pUser;                          /* pointer to the user descriptor */
    NQ_UINT maxLength;                      /* max response length */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    NQ_UINT length;                         /* entry length */
#ifdef UD_NQ_INCLUDEEVENTLOG
	UDFileAccessEvent eventInfo;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */

    findRequest = (CMCifsFindFirst2Request*)(
                          (NQ_BYTE*)descriptor->requestData
                        + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.parameterOffset))
                        - sizeof(CMCifsHeader)
                        );

    findResponse = (CMCifsFindFirst2Response*)descriptor->pParams;

    /* read request flags */

    flags = cmLtoh16(cmGetSUint16(findRequest->flags));

    /* withdraw UID and TID */

    uid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid));

    /* check access to share */

    if ((returnValue = csCanReadShare(tid)) != NQ_SUCCESS)
    {
        TRCERR("Access denied");
        TRCE();
        return returnValue;
    }

    pUser = csGetUserByUid(uid);
    if (pUser == NULL)
    {
        TRCERR("Illegal UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

    pShare = csGetShareByUidTid(uid, tid);
    if (pShare == NULL)
    {
        TRCERR("Illegal TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
    }

    /* withdraw the request parameters */

    attributes = cmLtoh16(cmGetSUint16(findRequest->searchAttributes));
    level = cmLtoh16(cmGetSUint16(findRequest->informationLevel));

    pPattern = (NQ_BYTE*)(findRequest + 1);
    if (unicodeRequired)
    {
        if (*(NQ_BYTE*)(findRequest + 1) == 0 && *((NQ_BYTE*)(findRequest + 1) + 1) == 0)
        {
            pPattern = (NQ_BYTE*)allFilesUnicode;
        }
    }
    else
    {
        if (*(NQ_BYTE*)(findRequest + 1) == 0)
        {
            pPattern = (NQ_BYTE*)allFilesAscii;
        }
    }

    /* convert filename to host filename */

    if ((pFileName = cmCifsNtohFilename(
    						fileNameBuff,
                            pShare->map,
                            (const NQ_WCHAR*)pPattern,
                            unicodeRequired,
							TRUE
                            )
        ) == NULL
       )
    {
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = pFileName;
	eventInfo.rid = csGetUserRid(pUser);
	eventInfo.tid = tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    if (!csCheckPath(pShare, pFileName, (NQ_UINT)syWStrlen(pShare->map), pUser->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
        TRCERR("Path does not exists");
        TRC1P(" path: %s", cmWDump(pFileName));
        return csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    /* allocate SID (we will release it immediatelly if this search is over) */

    if ((pTree = csGetTreeByTid(tid)) == NULL)
    {
        TRCERR("illegal TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }
    if ((pSearch = csGetNewSearch(pTree)) == NULL)
    {
        TRCERR("SID overflow");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }
    pSearch->attributes = attributes;
    pSearch->resumeKey = (flags & SMB_FINDFIRST2_RESUMEKEY) != 0;

    /* mark data area for entries - CIFS expects entries to be on a double
       word boundary */

    entryCount = 0;
    descriptor->pData = (NQ_BYTE*)(findResponse + 1);
    descriptor->pData = cmAllignFour(descriptor->pData);
    descriptor->parameterCount = sizeof(*findResponse);
    pEntry = descriptor->pData;     /* start writing entries from here */

    /* prepare counts: use the least of 1) required limit 2) number of entries fitting
       in the buffer */

    {
        NQ_UINT maxFittingCount;   /* maximum number of directory entries that fits the buffer */

        maxLength = cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.maxDataCount));
        if (maxLength > CS_MAXBUFFERSIZE)
        {
            maxLength = CS_MAXBUFFERSIZE;
        }
        maxCount = cmLtoh16(cmGetSUint16(findRequest->searchCount));
        maxFittingCount =   (NQ_UINT)(maxLength - (NQ_UINT)((NQ_BYTE*)pEntry - (NQ_BYTE*)descriptor->pHeaderOut))
                          / sizeof(*pEntry);

        if (maxFittingCount < maxCount)
        {
            maxCount = maxFittingCount;
        }
    }

    /* start searching files */

    TRC1P("Find operation on %s", cmWDump(pFileName));

    csEnumerateSourceName(&pSearch->enumeration, pFileName, pUser->preservesCase);
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = pSearch->enumeration.name;
	eventInfo.before = TRUE;
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    while ((pFileName = csNextSourceName(&pSearch->enumeration)) != NULL)
    {
        SYFileInformation fileInfo; /* for querying file information */
        NQ_BYTE* pLastEntryCandidate;  /* temporary pointer to the last entry */

#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_QUERYDIRECTORY,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        /* file candidate found - compare attributes */
#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		eventInfo.fileName = pFileName;
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorGetLast(),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
            /* set default info details for corruped file */
            syMemset(&fileInfo, 0, sizeof(fileInfo));
        }
#ifdef UD_NQ_INCLUDEEVENTLOG
        else
        {
        	udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
        }
#endif /* UD_NQ_INCLUDEEVENTLOG */
         
        /* match files as usual and also match directories */
        if (   csMatchFileAttributes(attributes, (NQ_UINT16)fileInfo.attributes)
            && (   (attributes & SMB_ATTR_DIRECTORY)
                || !(fileInfo.attributes & SMB_ATTR_DIRECTORY)
               )
           )
        {
            /* fill file information */

            pLastEntryCandidate = pEntry;
            length = maxLength;

            error = csFillFindEntry(
                                pFileName,
                                &fileInfo,
                                &pEntry,
                                level,
                                entryCount,
                                unicodeRequired,
                                (NQ_BYTE*)descriptor->pData,
                                &length,
                                pSearch->resumeKey,
                                &pNextEntryOffset
                                );

            if (error == INTERNAL_ERROR)
            {
                csRollbackEnumeration(pSearch->enumeration);
                break;
            }
            if (error != 0)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE *)&eventInfo
					);
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                csReleaseSearch(pSearch->sid);
#ifdef UD_NQ_INCLUDEEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE *)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                TRCERR("Unable to read file information");
                TRCE();
                return error;
            }
            pLastEntry = pLastEntryCandidate;

            if (++entryCount >= maxCount)
                break;

        }
#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.fileName = pSearch->enumeration.name;
		eventInfo.before = TRUE;
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_QUERYDIRECTORY,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* set zero for nextEntryOffset of last entry */

    if (pNextEntryOffset != NULL)
    {
        CMCifsFileDirectoryInformation* pFindFirstLastEntry = (CMCifsFileDirectoryInformation*)pLastEntry;
        cmPutSUint32(pFindFirstLastEntry->nextEntryOffset, 0);
    }

    /* return error if no files was found */

    if (entryCount == 0)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_CLOSE,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
		csReleaseSearch(pSearch->sid);
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_CLOSE,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }

    /* release SID if required */

    if (   (flags & SMB_FINDFIRST2_CLOSE)
        || ((pFileName == NULL) && (flags & SMB_FINDFIRST2_CLOSEIF)))
    {
        /* end of search reached or client requested to close search */
#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_CLOSE,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
		csReleaseSearch(pSearch->sid);
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_CLOSE,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        cmPutSUint16(findResponse->lastNameOffset, 0);
    }
    else
    {
        /* search continuation expected */

        cmPutSUint16(findResponse->sid, cmHtol16(pSearch->sid));
        cmPutSUint16(findResponse->lastNameOffset, cmHtol16((NQ_UINT16)(pLastEntry - descriptor->pData)));
    }

    cmPutSUint16(findResponse->endOfSearch, pFileName == NULL? cmHtol16(1) : 0);

    /* continue composing the response message */

    cmPutSUint16(findResponse->searchCount, cmHtol16((NQ_UINT16)entryCount));
    cmPutSUint16(findResponse->eaErrorOffset, 0);

    /* count the length of the data area */

    descriptor->dataCount = (NQ_UINT16)(pEntry - descriptor->pData);

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: Perform FindNext2 subcommand
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT structure with subcommand parameters:
 *              IN pointer to the CIFS header
 *              IN pointer to the parameter area
 *              OUT pointer to the data area
 *              OUT length of the parameter area
 *              OUT length of the data area
 *
 * RETURNS: SMB error or 0 on success
 *
 * NOTES:   This command is a continuation of a previous FindFirst2. Tt
 *          uses a search descriptor identified by SID and created in FindFirst2.
 *          Search descriptor contains also search context structure used for
 *          enumerating file names (see file CSFNAMES.C for more). This command
 *          continues the search.
 *====================================================================
 */

NQ_UINT32
csTransaction2FindNext(
    CSTransaction2Descriptor* descriptor
    )
{
    CMCifsFindNext2Request* findRequest;    /* casted request */
    CMCifsFindNext2Response* findResponse;  /* casted response */
    NQ_BOOL unicodeRequired;                /* whether client requires UNICODE */
    CMCifsStatus error;                     /* for composing DOS-style error */
    const CSShare* pShare;                  /* pointer to the share */
    CSTid tid;                              /* required tree ID */
    CSUid uid;                              /* required user ID */
    NQ_BYTE* pEntry;                        /* file record pointer */
    NQ_BYTE* pLastEntry = NULL;             /* pointer to the last record */
    NQ_BYTE* pNextEntryOffset = NULL;       /* pointer to nextEntryOffset field in the entry */
    NQ_UINT entryCount;                     /* number of entries in the response */
    NQ_UINT maxCount;                       /* limit for the number of entries in response */
    NQ_UINT16 level;                        /* required detalization - information level */
    CSSearch* pSearch;                      /* search operation descriptor */
    NQ_UINT16 flags;                        /* request flags */
    NQ_WCHAR* pFileName;                    /* filename to search */
    NQ_UINT maxLength;                      /* max response length */
    NQ_UINT length;                         /* entry length */
#ifdef UD_NQ_INCLUDEEVENTLOG
	UDFileAccessEvent eventInfo;
	CSUser	* 	pUser;
	NQ_WCHAR noName[] = CM_WCHAR_NULL_STRING;
	NQ_IPADDRESS noIP = CM_IPADDR_ZERO;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */

    findRequest = (CMCifsFindNext2Request*)(
                          (NQ_BYTE*)descriptor->requestData
                        + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.parameterOffset))
                        - sizeof(CMCifsHeader)
                        );

    findResponse = (CMCifsFindNext2Response*) descriptor->pParams;

    /* withdraw UID and TID */

    uid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid));

    if (csGetUserByUid(uid) == NULL)
    {
        TRCERR("Illegal UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

    pShare = csGetShareByUidTid(uid, tid);
    if (pShare == NULL)
    {
        TRCERR("Illegal UID or TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
    }

    /* withdraw the request parameters */

    level = cmLtoh16(cmGetSUint16(findRequest->informationLevel));

    /* find SID */

    if ((pSearch = csGetSearchBySid(cmLtoh16(cmGetSUint16(findRequest->sid)))) == NULL)
    {
        TRCERR("Illegal SID");
        TRC1P(" value: %d", cmLtoh16(cmGetSUint16(findRequest->sid)));
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    /* start or continue search according to the request */

    flags = cmLtoh16(cmGetSUint16(findRequest->flags));

    /* resume search by name cannot be implemented on some OS-es */

    /* mark data area for entries - CIFS expects entries to be on a double
       word boundary */

    entryCount = 0;
    descriptor->pData = (NQ_BYTE*)(findResponse + 1);
    /*descriptor->pData = cmAllignTwo(descriptor->pData);*/
    descriptor->parameterCount = sizeof(*findResponse);
    pEntry = descriptor->pData;     /* start writing entries from here */

    /* prepare counts: use the least of 1) required limit 2) number of entries fitting
       in the buffer */

    {
        NQ_UINT maxFittingCount;   /* maximum number of directory entries that fits the buffer */

        maxLength = cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.maxDataCount));
        if (maxLength > CS_MAXBUFFERSIZE)
        {
            maxLength = CS_MAXBUFFERSIZE;
        }
        maxCount = cmLtoh16(cmGetSUint16(findRequest->searchCount));
        maxFittingCount =   (NQ_UINT16)(maxLength - (NQ_UINT)((NQ_BYTE*)pEntry - (NQ_BYTE*)descriptor->pHeaderOut))
                          / sizeof(*pEntry);
        if (maxFittingCount < maxCount)
        {
            maxCount = maxFittingCount;
        }
    }

    /* continue searching files */
#ifdef UD_NQ_INCLUDEEVENTLOG
	pUser = csGetUserByUid(uid);
	eventInfo.rid = csGetUserRid(pUser);
	eventInfo.tid = tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = pSearch->enumeration.name;
	eventInfo.before = TRUE;
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			pUser? pUser->name : noName,
			pUser? pUser->ip : &noIP,
			0,
			(const NQ_BYTE *)&eventInfo
			);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    while ((pFileName = csNextSourceName(&pSearch->enumeration)) != NULL)
    {
        SYFileInformation fileInfo; /* for querying file information */
        NQ_BYTE* pLastEntryCandidate;  /* temporary pointer to the last entry */
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_QUERYDIRECTORY,
				pUser? pUser->name : noName,
				pUser? pUser->ip : &noIP,
				0,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        /* file candidate found - compare attributes */

#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		eventInfo.fileName = pFileName;
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser? pUser->name : noName,
				pUser? pUser->ip : &noIP,
				0,
				(const NQ_BYTE *)&eventInfo
				);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					pUser? pUser->name : noName,
					pUser? pUser->ip : &noIP,
					csErrorGetLast(),
					(const NQ_BYTE *)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
            /* set default info details for corruped file */
            syMemset(&fileInfo, 0, sizeof(fileInfo));
        }
#ifdef UD_NQ_INCLUDEEVENTLOG
        else
        {
        	udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser? pUser->name : noName,
				pUser? pUser->ip : &noIP,
				0,
				(const NQ_BYTE *)&eventInfo
				);
        }
#endif /* UD_NQ_INCLUDEEVENTLOG */

        if (csMatchFileAttributes(pSearch->attributes, (NQ_UINT16)fileInfo.attributes)
            && ((pSearch->attributes & SMB_ATTR_DIRECTORY) || !(fileInfo.attributes & SMB_ATTR_DIRECTORY)))
        {
            /* fill file information */

            pLastEntryCandidate = pEntry;
            length = maxLength;

            error = csFillFindEntry(
                                pFileName,
                                &fileInfo,
                                &pEntry,
                                level,
                                entryCount,
                                unicodeRequired,
                                (NQ_BYTE*)descriptor->pData,
                                &length,
                                pSearch->resumeKey,
                                &pNextEntryOffset
                                );
            if (error == INTERNAL_ERROR)
            {
                csRollbackEnumeration(pSearch->enumeration);
                break;
            }

            if (error != 0)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser? pUser->name : noName,
					pUser? pUser->ip : &noIP,
					0,
					(const NQ_BYTE *)&eventInfo
					);
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                csReleaseSearch(pSearch->sid);
#ifdef UD_NQ_INCLUDEEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser? pUser->name : noName,
					pUser? pUser->ip : &noIP,
					0,
					(const NQ_BYTE *)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                TRCERR("Unable to read file information");

                TRCE();
                return error;
            }
            pLastEntry = pLastEntryCandidate;

            if (++entryCount >= maxCount)
                break;
        }
#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.before = TRUE;
        eventInfo.fileName = pSearch->enumeration.name;
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_QUERYDIRECTORY,
				pUser? pUser->name : noName,
				pUser? pUser->ip : &noIP,
				0,
				(const NQ_BYTE *)&eventInfo
				);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    }

    /* set zero for nextEntryOffset of last entry */

    if (pNextEntryOffset != NULL)
    {
        CMCifsFileDirectoryInformation* pFindFirstLastEntry = (CMCifsFileDirectoryInformation*)pLastEntry;
        cmPutSUint32(pFindFirstLastEntry->nextEntryOffset, 0);
    }
    
    /* release SID if required */

    if (   (flags & SMB_FINDFIRST2_CLOSE)
        || ((pFileName == NULL) && (flags & SMB_FINDFIRST2_CLOSEIF)))
    {
        /* end of search reached or client requested to close search */

#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_CLOSE,
			pUser? pUser->name : noName,
			pUser? pUser->ip : &noIP,
			0,
			(const NQ_BYTE *)&eventInfo
			);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
		csReleaseSearch(pSearch->sid);
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_CLOSE,
			pUser? pUser->name : noName,
			pUser? pUser->ip : &noIP,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        cmPutSUint16(findResponse->lastNameOffset, 0);
    }
    else
    {
        /* search continuation expected */

        cmPutSUint16(findResponse->lastNameOffset, cmHtol16((NQ_UINT16)(pLastEntry - (NQ_BYTE*) (findResponse + 1))));
    }
    cmPutSUint16(findResponse->endOfSearch, pFileName == NULL? cmHtol16(1) : 0);

    /* continue composing the response message */

    cmPutSUint16(findResponse->searchCount, cmHtol16((NQ_UINT16)entryCount));
    cmPutSUint16(findResponse->eaErrorOffset, 0);

    /* count the length of the data area */

    descriptor->dataCount = (NQ_UINT16)(pEntry - descriptor->pData);

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: fill directory entry for CIFS search
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          OUT directory entry
 *
 * RETURNS: SNB error or 0
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
fillSearchEntry(
    const NQ_WCHAR* pFileName,
    CMCifsSearchDirectoryEntry* entry
    )
{
    SYFileInformation fileInfo;                 /* buffer for file information */
    NQ_STATIC NQ_CHAR fileName[CM_BUFFERLENGTH(NQ_CHAR, UD_FS_FILENAMELEN)]; /* for converting name to ANSI */

    TRCB();
    
    if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
    {
        /* set default info details for corruped file */
        syMemset(&fileInfo, 0, sizeof(fileInfo));
    }

    /* fix file size for directories */

    if (0 != (fileInfo.attributes & SMB_ATTR_DIRECTORY))
    {
        fileInfo.sizeHigh = 0;
        fileInfo.sizeLow = 0;
    }

    /* fill file information */

    entry->fileAttributes = (NQ_BYTE)cmHtol16((NQ_UINT16)fileInfo.attributes);
    {
        NQ_UINT16 smbTime;     /* temporary time in SMB_TIME format */
        NQ_UINT16 smbDate;     /* temporary date in SMB_DATE format */

        cmCifsTimeToSmbTime(fileInfo.lastWriteTime, &smbTime, &smbDate);
        cmPutSUint16(entry->lastWriteTime, cmHtol16(smbTime));
        cmPutSUint16(entry->lastWriteDate, cmHtol16(smbDate));
    }

    cmPutSUint32(entry->fileSize, cmHtol32(fileInfo.sizeLow));

    /* convert name to ANSII uppercase and place into the entry, padding by spaces */

    syMemset(fileName, ' ', sizeof(entry->fileName));
    syUnicodeToAnsi(fileName, cmCifsExtractFilenameFromFullName(pFileName));
    syMemcpy(entry->fileName, fileName, sizeof(entry->fileName));
    
    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: fill a directory entry for NT search (FindFirst, FindNext)
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN file information structure
 *          IN/OUT IN: double pointer to the entry
 *                 OUT: double pointer to the next entry
 *          IN information level as required by FIND
 *          IN file index in search
 *          IN whether UNICODE names ought to be returned
 *          IN pointer to the beginning of the SMB message
 *          IN/OUT IN: max response length
 *                 OUT: entry length without alignment
 *          IN whether to return resume key for particular levels
 *          IN/OUT double pointer to nextEntryOffset field in the entry
 *
 * RETURNS: SMB error or 0
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csFillFindEntry(
    const NQ_WCHAR* pFileName,
    SYFileInformation* fileInfo,
    NQ_BYTE** pEntry,
    NQ_UINT16 level,
    NQ_UINT32 fileIndex,
    NQ_BOOL unicodeRequired,
    const NQ_BYTE* messageStart,
    NQ_UINT* length,
    NQ_BOOL resumeKey,
    NQ_BYTE** pNextEntryOffset
    )
{
    NQ_UINT32 nameLength = 0;       /* file name length in bytes */
    NQ_BYTE* pData;                 /* pointer to various data fragments */
    NQ_UINT32 entryLength;          /* the entire length of the entry */
    NQ_BOOL isNt;                   /* TRUE when the detail level is NT-style ( > 0x100) */
    NQ_UINT maxLength = *length;    /* max length for response */

    TRCB();

    /* fix file size for directories */

    if (0 != (fileInfo->attributes & SMB_ATTR_DIRECTORY))
    {
        fileInfo->sizeHigh = 0;
        fileInfo->sizeLow = 0;
    }

    /* calculate entry length */

    switch (level)
    {
    case SMB_FINDFIRST2_INFOQUERYEASFROMLIST:
    case SMB_FINDFIRST2_INFOQUERYEASIZE:
        entryLength = sizeof(CMCifsFileInformationEaSize) + ((unicodeRequired)? 2:1);
        if (resumeKey)
            entryLength += 4;
        isNt = FALSE;
        break;
    case SMB_FINDFIRST2_INFOSTANDARD:
        entryLength = sizeof(CMCifsFileInformationStandard) + ((unicodeRequired)? 2:1);      /* 1 for file name length + 1 alignment*/
        if (resumeKey)
            entryLength += 4;
        isNt = FALSE;
        break;
    case SMB_PASSTHRU_FILE_BOTH_DIR_INFO:    
    case SMB_FINDFIRST2_FINDFILEBOTHDIRECTORYINFO:
        entryLength = sizeof(CMCifsFileBothDirectoryInformation);
        isNt = TRUE;
        break;
    case SMB_PASSTHRU_FILE_DIR_FULL_INFO:    
    case SMB_FINDFIRST2_FINDFILEFULLDIRECTORYINFO:
        entryLength = sizeof(CMCifsFileFullDirectoryInformation);
        isNt = TRUE;
        break;
    case SMB_PASSTHRU_FILE_ID_BOTH_DIR_INFO:    
    case SMB_FINDFIRST2_FINDIDBOTHDIRECTORYINFO:
        entryLength = sizeof(CMCifsIdBothDirectoryInformation);
        isNt = TRUE;
        break;
    case SMB_PASSTHRU_FILE_ID_FULL_DIR_INFO:    
    case SMB_FINDFIRST2_FINDIDFULLDIRECTORYINFO:
        entryLength = sizeof(CMCifsIdFullDirectoryInformation);
        isNt = TRUE;
        break;
    case SMB_PASSTHRU_FILE_DIR_INFO:    
    case SMB_FINDFIRST2_FINDFILEDIRECTORYINFO:
        entryLength = sizeof(CMCifsFileDirectoryInformation);
        isNt = TRUE;
        break;
    case SMB_PASSTHRU_FILE_NAMES_INFO:    
    case SMB_FINDFIRST2_FINDFILENAMESINFO:
        entryLength = sizeof(CMCifsFileNamesInformation);
        isNt = TRUE;
        break;
    default:
        TRCERR("Illegal information level");
        TRC1P("  value: %d", level);
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    pFileName = cmCifsExtractFilenameFromFullName(pFileName);

    if (isNt)
    {
        /* NT formats include the terminating zero */
        if (!unicodeRequired)
            nameLength += (NQ_UINT32)sizeof(NQ_CHAR);
    }

    if (unicodeRequired)
    {
        /* temporary convert to unicode */

        if ((*pEntry + syWStrlen(pFileName) + sizeof(NQ_WCHAR)) > (messageStart + maxLength))
        {
            /* name does not fit into the message - this not an error but an indication for
               the caller*/
            return INTERNAL_ERROR;
        }
        syWStrcpy((NQ_WCHAR*)*pEntry, pFileName);
        nameLength += (NQ_UINT32)(cmWStrlen((NQ_WCHAR*)*pEntry) * sizeof(NQ_WCHAR));
        entryLength += (NQ_UINT32)nameLength;
    }
    else
    {
        nameLength += (NQ_UINT32)syWStrlen(pFileName);
        entryLength += nameLength + 1;
    }

    /* calculate entry length aligning it to 8 byte boundary (smb2 requires)*/
    
    {
        NQ_UINT padd;

        *length = (NQ_UINT)entryLength;
        padd = (8 - (entryLength % 8)) % 8;
        entryLength += padd;
    }

    if ((*pEntry + entryLength + sizeof(NQ_WCHAR)) > (messageStart + maxLength))
    {
        /* entry does not fit into the message - this not an error but an indication for
           the caller */
        return INTERNAL_ERROR;
    }

    /* fill file information according to information level
       note: no 'break' is some 'case'-s is by intention - continues with the next 'case' */

    pData = *pEntry;

    switch (level)
    {

    /* the following three cases are cumulative: each one adds some information */

    case SMB_FINDFIRST2_INFOQUERYEASFROMLIST:
    case SMB_FINDFIRST2_INFOQUERYEASIZE:
        {
            CMCifsFileInformationEaSize* pResponse;

            if (resumeKey)
                pResponse = (CMCifsFileInformationEaSize*) (*pEntry + 4);
            else
                pResponse = (CMCifsFileInformationEaSize*) *pEntry;
            cmPutSUint32(pResponse->eaSize, 0);
            pData +=    sizeof(CMCifsFileInformationEaSize)
                      - sizeof(CMCifsFileInformationStandard);
        }
    case SMB_FINDFIRST2_INFOSTANDARD:
        {
            CMCifsFileInformationStandard* pResponse;
            NQ_UINT16 smbTime;     /* temporary time in SMB_TIME format */
            NQ_UINT16 smbDate;     /* temporary date in SMB_DATE format */

            if (resumeKey)
            {
                *(NQ_UINT32*)(*pEntry) = fileIndex;     /* resume key */
                pResponse = (CMCifsFileInformationStandard*) (*pEntry + 4);
                pData += 4;
            }
            else
                pResponse = (CMCifsFileInformationStandard*) *pEntry;
            cmCifsTimeToSmbTime(fileInfo->creationTime, &smbTime, &smbDate);
            cmPutSUint16(pResponse->creationDate, cmHtol16(smbDate));
            cmPutSUint16(pResponse->creationTime, cmHtol16(smbTime));
            cmCifsTimeToSmbTime(fileInfo->lastAccessTime, &smbTime, &smbDate);
            cmPutSUint16(pResponse->lastAccessDate, cmHtol16(smbDate));
            cmPutSUint16(pResponse->lastAccessTime, cmHtol16(smbTime));
            cmCifsTimeToSmbTime(fileInfo->lastWriteTime, &smbTime, &smbDate);
            cmPutSUint16(pResponse->lastWriteDate, cmHtol16(smbDate));
            cmPutSUint16(pResponse->lastWriteTime, cmHtol16(smbTime));
            cmPutSUint32(pResponse->dataSize, cmHtol32(fileInfo->sizeLow));
            cmPutSUint32(pResponse->allocationSize, cmHtol32(fileInfo->allocSizeLow));
            cmPutSUint16(pResponse->attributes, cmHtol16((NQ_UINT16)fileInfo->attributes));
            pData += sizeof(CMCifsFileInformationStandard);
            *pData++ = (NQ_BYTE)nameLength;
            if (unicodeRequired)
                pData++;    /* alignment */
        }
        break;

    /* the following three cases are cumulative: each one adds some information */
    case SMB_PASSTHRU_FILE_BOTH_DIR_INFO:
    case SMB_PASSTHRU_FILE_ID_BOTH_DIR_INFO:
    case SMB_FINDFIRST2_FINDFILEBOTHDIRECTORYINFO:
    case SMB_FINDFIRST2_FINDIDBOTHDIRECTORYINFO:
        {
            CMCifsFileBothDirectoryInformation* pResponse;

            pResponse = (CMCifsFileBothDirectoryInformation*) *pEntry;
            pResponse->shortNameLength = 0;
            pResponse->reserved = 0;

            if (level == SMB_FINDFIRST2_FINDIDBOTHDIRECTORYINFO || level == SMB_PASSTHRU_FILE_ID_BOTH_DIR_INFO)
            {
                CMCifsIdBothDirectoryInformation* pResponse;
                pResponse = (CMCifsIdBothDirectoryInformation*) *pEntry;
                cmPutSUint32(pResponse->fileIndex.low, cmHtol32(fileInfo->fileIdLow));
                cmPutSUint32(pResponse->fileIndex.high, cmHtol32(fileInfo->fileIdHigh));
                cmPutSUint16(pResponse->reserved0, 0);
            }

            pData +=    (level == SMB_FINDFIRST2_FINDIDBOTHDIRECTORYINFO || level == SMB_PASSTHRU_FILE_ID_BOTH_DIR_INFO ?
                                 sizeof(CMCifsIdBothDirectoryInformation):
                                 sizeof(CMCifsFileBothDirectoryInformation)
                        )
                      - sizeof(CMCifsFileFullDirectoryInformation);
            syMemset(pResponse->shortName, 0, sizeof(pResponse->shortName));
        }
    case SMB_PASSTHRU_FILE_DIR_FULL_INFO:
    case SMB_PASSTHRU_FILE_ID_FULL_DIR_INFO:
    case SMB_FINDFIRST2_FINDFILEFULLDIRECTORYINFO:
    case SMB_FINDFIRST2_FINDIDFULLDIRECTORYINFO:
        {
            CMCifsFileFullDirectoryInformation* pResponse;

            pResponse = (CMCifsFileFullDirectoryInformation*) *pEntry;
            cmPutSUint32(pResponse->eaSize, 0L);
            if (level == SMB_FINDFIRST2_FINDIDFULLDIRECTORYINFO || level == SMB_PASSTHRU_FILE_ID_FULL_DIR_INFO)
            {
                CMCifsIdFullDirectoryInformation* pResponse;
                pResponse = (CMCifsIdFullDirectoryInformation*) *pEntry;
                cmPutSUint32(pResponse->fileIndex.low, cmHtol32(fileInfo->fileIdLow));
                cmPutSUint32(pResponse->fileIndex.high, cmHtol32(fileInfo->fileIdHigh));
                cmPutSUint32(pResponse->reserved0, 0);
            }

            pData +=    (level == SMB_FINDFIRST2_FINDIDFULLDIRECTORYINFO || level == SMB_PASSTHRU_FILE_ID_FULL_DIR_INFO ?
                                 sizeof(CMCifsIdFullDirectoryInformation):
                                 sizeof(CMCifsFileFullDirectoryInformation)
                        )
                      - sizeof(CMCifsFileDirectoryInformation);
        }
    case SMB_PASSTHRU_FILE_DIR_INFO:    
    case SMB_FINDFIRST2_FINDFILEDIRECTORYINFO:
        {
            NQ_UINT32 timeLow;     /* low part of UTC time */
            NQ_UINT32 timeHigh;    /* high part of UTC time */

            CMCifsFileDirectoryInformation* pResponse;

            pResponse = (CMCifsFileDirectoryInformation*) *pEntry;
            cmPutSUint32(pResponse->fileIndex, 0);
            cmCifsTimeToUTC(
                fileInfo->creationTime,
                &timeLow,
                &timeHigh
                );
            cmPutSUint32(pResponse->creationTime.low, cmHtol32(timeLow));
            cmPutSUint32(pResponse->creationTime.high, cmHtol32(timeHigh));
            cmCifsTimeToUTC(
                fileInfo->lastChangeTime,
                &timeLow,
                &timeHigh
                );
            cmPutSUint32(pResponse->lastChangeTime.low, cmHtol32(timeLow));
            cmPutSUint32(pResponse->lastChangeTime.high, cmHtol32(timeHigh));
            cmCifsTimeToUTC(
                fileInfo->lastAccessTime,
                &timeLow,
                &timeHigh
                );
            cmPutSUint32(pResponse->lastAccessTime.low, cmHtol32(timeLow));
            cmPutSUint32(pResponse->lastAccessTime.high, cmHtol32(timeHigh));
            cmCifsTimeToUTC(
                fileInfo->lastWriteTime,
                &timeLow,
                &timeHigh
                );
            cmPutSUint32(pResponse->lastWriteTime.low, cmHtol32(timeLow));
            cmPutSUint32(pResponse->lastWriteTime.high, cmHtol32(timeHigh));

            cmPutSUint32(pResponse->nextEntryOffset, cmHtol32(entryLength));
            *pNextEntryOffset = (NQ_BYTE *)&pResponse->nextEntryOffset;
            cmPutSUint32(pResponse->allocationSize.low, cmHtol32(fileInfo->allocSizeLow));
            cmPutSUint32(pResponse->allocationSize.high, cmHtol32(fileInfo->allocSizeHigh));
            cmPutSUint32(pResponse->endOfFile.low, cmHtol32(fileInfo->sizeLow));
            cmPutSUint32(pResponse->endOfFile.high, cmHtol32(fileInfo->sizeHigh));
            cmPutSUint32(pResponse->fileAttributes, cmHtol32(fileInfo->attributes));
            cmPutSUint32(pResponse->fileNameLength,  cmHtol32(nameLength));
            pData += sizeof(CMCifsFileDirectoryInformation);
        }
        break;

    /* the last one is separate */
    case SMB_PASSTHRU_FILE_NAMES_INFO:
    case SMB_FINDFIRST2_FINDFILENAMESINFO:
        {
            CMCifsFileNamesInformation* pResponse;

            pResponse = (CMCifsFileNamesInformation*) *pEntry;
            cmPutSUint32(pResponse->nextEntryOffset, cmHtol32(entryLength));
            *pNextEntryOffset = (NQ_BYTE *)&pResponse->nextEntryOffset;
            cmPutSUint32(pResponse->fileIndex, 0);
            cmPutSUint32(pResponse->fileNameLength, cmHtol32(nameLength));
            pData += sizeof(CMCifsFileNamesInformation);
        }
        break;
    default:
        break;  /* never here */
    }

    /* place the name */

    if (unicodeRequired)
    {
        syWStrcpy((NQ_WCHAR*)pData, pFileName);
    }
    else
    {
        syUnicodeToAnsi((NQ_CHAR*)pData, pFileName);
    }

    /* calculate next entry address */

    *pEntry += entryLength;

    TRCE();
    return 0;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

