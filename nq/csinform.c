/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of file information command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 30-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "csutils.h"
#include "cstrans2.h"
#include "csnotify.h"
#ifdef UD_CS_INCLUDERPC
#include "csdcerpc.h"
#endif
#include "csinform.h"
#include "csdelete.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements information commands and subcommands */

static NQ_UINT32 convertNqAccessToNtAccess(NQ_UINT16 nqAccess);

/* The following value is used in NOTIFY CHANGE as a completion filter for file information */

#define COMPLETION_FILTER   \
          SMB_NOTIFYCHANGE_ATTRIBUTES \
        | SMB_NOTIFYCHANGE_LAST_WRITE \
        | SMB_NOTIFYCHANGE_LAST_ACCESS \
        | SMB_NOTIFYCHANGE_CREATION \
        | SMB_NOTIFYCHANGE_SIZE


/*====================================================================
 * PURPOSE: Perform QUERY INFORMATION DISK command
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
csComQueryInformationDisk(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsQueryInformationDiskRequest* queryRequest;   /* casted request */
    CMCifsQueryInformationDiskResponse* queryResponse; /* casted response */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    const CSShare* pShare;                  /* pointer to the share */
    NQ_TCHAR* pVolumeName;                  /* pointer to the volume name */
    CSUid uid;                              /* required UID */
    CSTid tid;                              /* required TID */
    SYVolumeInformation volumeInfo;         /* buffer for the volume information */
    static const NQ_TCHAR noName[] = {(NQ_TCHAR)0};   /* empty name for file */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent		eventInfo;
    CSUser *				pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    
    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*queryResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
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

#ifdef UD_NQ_INCLUDEEVENTLOG
    pUser = csGetUserByUid(uid);
    eventInfo.before = TRUE;
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = tid;
    eventInfo.fileName = noName;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* cast pointers */

    queryRequest = (CMCifsQueryInformationDiskRequest*) pRequest;
    queryResponse = (CMCifsQueryInformationDiskResponse*) *pResponse;

    /* check format */

    if (   queryRequest->wordCount != 0
        || cmGetSUint16(queryRequest->byteCount) != 0
       )
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* convert filename to host filename, simulating empty file name in ANSI */

    if ((pVolumeName = cmCifsNtohFilename(
                        pShare->map,
                        noName,
                        FALSE
                        )
        ) == NULL
       )
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
    }

    /* query information */
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = pVolumeName;
    eventInfo.before = TRUE;
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
    if (syGetVolumeInformation(pVolumeName, &volumeInfo))
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unable to read file information");
        TRCE();
        return error;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* adjust totalUnitsLow, freeUnitsLow and blocksPerUnit to fit into NQ_UINT16 */
 
    if (volumeInfo.totalUnitsLow > 65535)
    {
        int i;
        NQ_UINT32 totalUnits = volumeInfo.totalUnitsLow;
        
        /* find optimal coefficient */
        for (i = 1; totalUnits > 65535; i++)
        { 
            totalUnits = volumeInfo.totalUnitsLow;
            totalUnits >>= i;
        }

        volumeInfo.blocksPerUnit <<= --i;
        volumeInfo.totalUnitsLow >>= i;     
        volumeInfo.freeUnitsLow >>= i;     
    }
  
    /* compose the response */

    queryResponse->wordCount = SMB_QUERYINFORMATIONDISK_RESPONSE_WORDCOUNT;
    cmPutSUint16(queryResponse->totalUnits, cmHtol16((NQ_UINT16)volumeInfo.totalUnitsLow));
    cmPutSUint16(queryResponse->blocksPerUnit, cmHtol16((NQ_UINT16)volumeInfo.blocksPerUnit));
    cmPutSUint16(queryResponse->blockSize, cmHtol16((NQ_UINT16)volumeInfo.blockSize));
    cmPutSUint16(queryResponse->freeUnits, cmHtol16((NQ_UINT16)volumeInfo.freeUnitsLow));
    cmPutSUint16(queryResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*queryResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform QUERY INFORMATION command
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
csComQueryInformation(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsQueryInformationRequest* queryRequest;   /* casted request */
    CMCifsQueryInformationResponse* queryResponse; /* casted response */
    NQ_BOOL unicodeRequired;                    /* whether client requires UNICODE */
    NQ_UINT32 returnValue;                      /* error code in NT format or 0 for no error */
    CMCifsStatus error;                         /* for composing DOS-style error */
    const CSShare* pShare;                      /* pointer to the share */
    NQ_TCHAR* pFileName;                        /* filename to open */
    CSUid uid;                                  /* required UID */
    CSTid tid;                                  /* required TID */
    SYFileInformation fileInfo;                 /* buffer for file information */
    CSUser* pUser;                              /* pointer to the user descriptor */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent		eventInfo;
    const NQ_TCHAR noName[] = {(NQ_TCHAR)0};   /* empty name for file */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*queryResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

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

    if ((pUser = csGetUserByUid(uid)) == NULL)
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

#ifdef UD_NQ_INCLUDEEVENTLOG
    pUser = csGetUserByUid(uid);
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = tid;
    eventInfo.fileName = noName;
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* cast pointers */

    queryRequest = (CMCifsQueryInformationRequest*) pRequest;
    queryResponse = (CMCifsQueryInformationResponse*) *pResponse;

    /* check format */

    if (   queryRequest->wordCount != 0
        || cmGetSUint16(queryRequest->byteCount) < SMB_QUERYINFORMATION_REQUEST_MINBYTES
        || queryRequest->bufferFormat < SMB_FIELD_ASCII
       )
    {
        TRCERR("Illegal WordCount, ByteCount or BufferFormat");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* convert filename to host filename */

    if ((pFileName = cmCifsNtohFilename(
                        pShare->map,
                        (NQ_TCHAR*)(queryRequest + 1),
                        unicodeRequired
                        )
        ) == NULL
       )
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.fileName = pFileName;
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    if (!csCheckPathAndFile(pShare, pFileName, (NQ_UINT)cmTStrlen(pShare->map), pUser->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			csErrorReturn(SMB_STATUS_OBJECT_NAME_NOT_FOUND, DOS_ERRbadfile),
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
        TRCERR("Path does not exists");
        TRC1P(" path: %s", cmTDump(pFileName));
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_NOT_FOUND, DOS_ERRbadfile);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    /* check whether this file is opened by this or another client and is marked for deletion */

    if (csFileMarkedForDeletion(pFileName))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_DELETE_PENDING, DOS_ERRbadaccess),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("File is marked for deletion");
        TRC1P(" file name: %s", cmTDump(pFileName));
        TRCE();
        return csErrorReturn(SMB_STATUS_DELETE_PENDING, DOS_ERRbadaccess);
    }

    /* query information */
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.before = TRUE;
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
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unable to read file information");
        TRCE();
        return error;
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* compose the response */

    queryResponse->wordCount = SMB_QUERYINFORMATION_RESPONSE_WORDCOUNT;
	{
		NQ_UINT16	temp = fileInfo.attributes & 0x3F;
		
		cmPutSUint16(queryResponse->fileAttributes, cmHtol16(temp));
	}
    cmPutSUint32(queryResponse->lastWriteTime, cmHtol32(fileInfo.lastWriteTime));
    cmPutSUint32(queryResponse->fileSize, (fileInfo.attributes & SMB_ATTR_DIRECTORY) ? 0 : cmHtol32(fileInfo.sizeLow));
    cmPutSUint16(queryResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*queryResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform SET INFORMATION command
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
csComSetInformation(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsSetInformationRequest* setRequest;   /* casted request */
    CMCifsSetInformationResponse* setResponse; /* casted response */
    NQ_BOOL unicodeRequired;                   /* whether client requires UNICODE */
    NQ_UINT32 returnValue;                     /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    const CSShare* pShare;                  /* pointer to the share */
    NQ_TCHAR* pFileName;                    /* filename to open */
    CSUid uid;                              /* required UID */
    CSTid tid;                              /* required TID */
    SYFileInformation fileInfo;             /* buffer for file information */
    CSUser* pUser;                          /* pointer to the user descriptor */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;            /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();


    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*setResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* withdraw UID and TID */

    uid = cmLtoh16(cmGetSUint16(pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));

    if ((pUser = csGetUserByUid(uid)) == NULL)
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

    /* cast pointers */

    setRequest = (CMCifsSetInformationRequest*) pRequest;
    setResponse = (CMCifsSetInformationResponse*) *pResponse;

    /* check format */

    if (   setRequest->wordCount != SMB_SETINFORMATION_REQUEST_WORDCOUNT
        || cmGetSUint16(setRequest->byteCount) < SMB_SETINFORMATION_REQUEST_MINBYTES
        || setRequest->bufferFormat != SMB_FIELD_ASCII
       )
    {
        TRCERR("Illegal WordCount, ByteCount or BufferFormat");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.fileName = NULL;
	eventInfo.tid = tid;
	eventInfo.rid = csGetUserRid(pUser);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* convert filename to host filename */

    if ((pFileName = cmCifsNtohFilename(
                        pShare->map,
                        (NQ_TCHAR*)(setRequest + 1),
                        unicodeRequired
                        )
        ) == NULL
       )
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.fileName = pFileName;
	eventInfo.access = (NQ_UINT32)-1;
#endif /* UD_NQ_INCLUDEEVENTLOG */



    /* check access to share */

    if ((error = csCanWriteShare(tid)) != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            error,
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Access denied");
        TRCE();
        return error;
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    if (!csCheckPathAndFile(pShare, pFileName, (NQ_UINT)cmTStrlen(pShare->map), pUser->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Path does not exists");
        TRC1P(" path: %s", cmTDump(pFileName));
        return csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    /* check whether this file is opened by this or another client and is marked for deletion */

    if (csFileMarkedForDeletion(pFileName))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_DELETE_PENDING, DOS_ERRbadaccess),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("File is marked for deletion");
        TRC1P(" file name: %s", cmTDump(pFileName));
        TRCE();
        return csErrorReturn(SMB_STATUS_DELETE_PENDING, DOS_ERRbadaccess);
    }

    /* get information */
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_ATTRIBGET,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
	);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			error,
			(const NQ_BYTE*)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            error,
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unable to read file information");
        TRCE();
        return error;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_ATTRIBGET,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
	);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* update file information */

    if (cmGetSUint16(setRequest->fileAttributes) != 0xFFFF)
    {
        NQ_UINT32 attributes = cmLtoh16(cmGetSUint16(setRequest->fileAttributes));

        /* clear SMB_ATTR_READONLY for directory */
        if ((fileInfo.attributes & SMB_ATTR_DIRECTORY) && (attributes & SMB_ATTR_READONLY))
        {
            attributes &= (NQ_UINT32)(~SMB_ATTR_READONLY);
        }    
        fileInfo.attributes = attributes;
    }
    if (cmGetSUint32(setRequest->lastWriteTime) != 0)
    {
        fileInfo.lastWriteTime = cmLtoh32(cmGetSUint32(setRequest->lastWriteTime));
    }

    {
        SYFile nullHandle;  /* invalid handle to the file */

#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.access = fileInfo.attributes;
#endif /* UD_NQ_INCLUDEEVENTLOG */

        syInvalidateFile(&nullHandle);

#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE*)&eventInfo
		);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        if (sySetFileInformation(pFileName, nullHandle, &fileInfo))
        {
            error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_ATTRIBSET,
                pUser->name,
                pUser->ip,
                error,
                (const NQ_BYTE*)&eventInfo
            );
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Unable to update file information");
            TRCE();
            return error;
        }

#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            0,
            (const NQ_BYTE*)&eventInfo
        	);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        csNotifyImmediatelly(pFileName, SMB_NOTIFYCHANGE_MODIFIED, COMPLETION_FILTER);
    }

    /* compose the response */

    setResponse->wordCount = 0;
    cmPutSUint16(setResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*setResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform QUERY INFORMATION2 command
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
csComQueryInformation2(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsQueryInformation2Request* queryRequest;   /* casted request */
    CMCifsQueryInformation2Response* queryResponse; /* casted response */
    NQ_UINT32 returnValue;                          /* error code in NT format or 0 for no error */
    CMCifsStatus error;                             /* for composing DOS-style error */
    CSFile* pFile;                                  /* pointer to file descriptor */
    CSName* pName;                                  /* pointer to file name descriptor */
    SYFileInformation fileInfo;                     /* buffer for file information */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser * 			pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

#ifdef UD_NQ_INCLUDEEVENTLOG
    pUser = csGetUserByUid(cmGetSUint16(pHeaderOut->uid));
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = cmGetSUint16(pHeaderOut->tid);
    eventInfo.fileName = NULL;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*queryResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* cast pointers */

    queryRequest = (CMCifsQueryInformation2Request*) pRequest;
    queryResponse = (CMCifsQueryInformation2Response*) *pResponse;

    /* check format */

    if (   queryRequest->wordCount != SMB_QUERYINFORMATION2_REQUEST_WORDCOUNT
        || cmGetSUint16(queryRequest->byteCount) != 0
       )
    {
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* check access to share */

    if ((returnValue = csCanReadShare(cmLtoh16(cmGetSUint16(pHeaderOut->tid)))) != NQ_SUCCESS)
    {
        TRCERR("Access denied");
        TRCE();
        return returnValue;
    }

    /* find file descriptor(s) */

    pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(queryRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    if (pFile == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    /* check whether this file is opened by this or another client and is marked for deletion */

    pName = csGetNameByNid(pFile->nid);
    if (pName == NULL || pName->markedForDeletion)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	eventInfo.before = FALSE;
		eventInfo.fileName = (pName == NULL) ? NULL : pName->name;
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("File is marked for deletion");
        TRC1P(" file name: %s", cmTDump(pName->name));
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }

    /* query information */
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.fileName = pName->name;
    eventInfo.before = TRUE;
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
    if (syGetFileInformation(pFile->file, csGetFileName(pFile->fid), &fileInfo) != NQ_SUCCESS)
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unable to read file information");
        TRCE();
        return error;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* compose the response */

    queryResponse->wordCount = SMB_QUERYINFORMATION2_RESPONSE_WORDCOUNT;
    {
        NQ_UINT16 smbTime;     /* temporary time in SMB_TIME format */
        NQ_UINT16 smbDate;     /* temporary date in SMB_DATE format */

        cmCifsTimeToSmbTime(fileInfo.creationTime, &smbTime, &smbDate);
        cmPutSUint16(queryResponse->creationDate, cmHtol16(smbDate));
        cmPutSUint16(queryResponse->creationTime, cmHtol16(smbTime));
        cmCifsTimeToSmbTime(fileInfo.lastAccessTime, &smbTime, &smbDate);
        cmPutSUint16(queryResponse->lastAccessDate, cmHtol16(smbDate));
        cmPutSUint16(queryResponse->lastAccessTime, cmHtol16(smbTime));
        cmCifsTimeToSmbTime(fileInfo.lastWriteTime, &smbTime, &smbDate);
        cmPutSUint16(queryResponse->lastWriteDate, cmHtol16(smbDate));
        cmPutSUint16(queryResponse->lastWriteTime, cmHtol16(smbTime));
    }
    cmPutSUint32(queryResponse->fileDataSize,(fileInfo.attributes & SMB_ATTR_DIRECTORY) ? 0 : cmHtol32(fileInfo.sizeLow));   
    cmPutSUint32(queryResponse->fileAllocationSize, (fileInfo.attributes & SMB_ATTR_DIRECTORY) ? 0 : cmHtol32(fileInfo.allocSizeLow));
	{
		NQ_UINT16	temp = fileInfo.attributes & 0x3F;
		
		cmPutSUint16(queryResponse->fileAttributes, cmHtol16(temp)); 
	}
    cmPutSUint16(queryResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*queryResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform SET INFORMATION2 command
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
csComSetInformation2(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsSetInformation2Request* setRequest;   /* casted request */
    CMCifsSetInformation2Response* setResponse; /* casted response */
    NQ_UINT32 returnValue;                      /* error code in NT format or 0 for no error */
    CMCifsStatus error;                         /* for composing DOS-style error */
    CSName* pName;                              /* pointer to file name descriptor */
    CSFile* pFile;                              /* pointer to file descriptor */
    SYFileInformation fileInfo;                 /* buffer for file information */
    const NQ_TCHAR* pFileName;                  /* file name pointer */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser * 			pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*setResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    pUser = csGetUserByUid(cmGetSUint16(pHeaderOut->uid));
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = cmGetSUint16(pHeaderOut->tid);
	eventInfo.fileName = NULL;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* cast pointers */

    setRequest = (CMCifsSetInformation2Request*) pRequest;
    setResponse = (CMCifsSetInformation2Response*) *pResponse;

    /* check format */

    if (   setRequest->wordCount != SMB_SETINFORMATION2_REQUEST_WORDCOUNT
        || cmGetSUint16(setRequest->byteCount) != 0
       )
    {
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file descriptor(s) */

    pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(setRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    if (pFile == NULL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    pFileName = csGetFileName(pFile->fid);
    if (pFileName == NULL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("File name corrupted");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.fileName = pFileName;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* check access to share */

    if ((error = csCanWriteShare((cmLtoh16(cmGetSUint16(pHeaderOut->tid))))) != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Access denied");
        TRCE();
        return error;
    }

    /* check whether this file is opened by this or another client and is marked for deletion */

    pName = csGetNameByNid(pFile->nid);
    if (pName == NULL || pName->markedForDeletion)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("File is marked for deletion");
        TRC1P(" file name: %s", cmTDump(pFileName));
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }

    /* set information */
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.before = TRUE;
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
    if (syGetFileInformation(pFile->file, pFileName, &fileInfo) != NQ_SUCCESS)
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE *)&eventInfo
				);
	#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unable to read file information");
        TRCE();
        return error;
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* update information */

    fileInfo.creationTime = cmCifsSmbTimeToTime(
        cmLtoh16(cmGetSUint16(setRequest->creationTime)),
        cmLtoh16(cmGetSUint16(setRequest->creationDate))
        );
    fileInfo.lastAccessTime = cmCifsSmbTimeToTime(
        cmLtoh16(cmGetSUint16(setRequest->lastAccessTime)),
        cmLtoh16(cmGetSUint16(setRequest->lastAccessDate))
        );
    fileInfo.lastWriteTime = cmCifsSmbTimeToTime(
        cmLtoh16(cmGetSUint16(setRequest->lastWriteTime)),
        cmLtoh16(cmGetSUint16(setRequest->lastWriteDate))
        );

    {
        SYFile nullHandle;  /* invalid handle to the file */

        syInvalidateFile(&nullHandle);
#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        if (sySetFileInformation(pFileName, nullHandle, &fileInfo))
        {
            error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Unable to update file information");
            TRCE();
            return error;
        }
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    }

    /* compose the response */

    setResponse->wordCount = 0;
    cmPutSUint16(setResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*setResponse);

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: Perform QUERY_FS_INFORMATION2 subcommand of Transaction2 protocol
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
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csTransaction2QueryFsInformation(
    CSTransaction2Descriptor* descriptor
    )
{
    CMCifsQueryFsInformation2Request* infoRequest;    /* casted request */
    const CSShare* pShare;              /* pointer to the share */
    CSUid uid;                          /* required UID */
    CSTid tid;                          /* required TID */
    NQ_BOOL unicodeRequired;            /* whether client requires UNICODE */
    NQ_UINT32 returnValue;              /* error code in NT format or 0 for no error */
#ifdef UD_NQ_INCLUDEEVENTLOG
	CSTree		* pTree;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check unicode flag */
    
    unicodeRequired = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */
    
    infoRequest = (CMCifsQueryFsInformation2Request*) (
                          (NQ_BYTE*)descriptor->requestData
                        + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.parameterOffset))
                        - sizeof(CMCifsHeader)
                        );

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
#ifdef UD_NQ_INCLUDEEVENTLOG
	pTree = csGetTreeByTid(tid);
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* call common processing */

    returnValue = csQueryFsInformation(pShare, cmLtoh16(cmGetSUint16(infoRequest->informationLevel)), unicodeRequired, descriptor
#ifdef UD_NQ_INCLUDEEVENTLOG
																													,pTree
#endif /* UD_NQ_INCLUDEEVENTLOG */
	);

    TRCE();
    return returnValue;
}


/*
 *====================================================================
 * PURPOSE: query file system information providing share name
 *--------------------------------------------------------------------
 * PARAMS:  IN  name of the share to query on
 *          IN information level required
 *          IN whether the client asks for UNICODE names
 *          IN/OUT subcommand parameters structure:
 *              IN pointer to the CIFS header
 *              IN pointer to the parameter area
 *              OUT pointer to the data area
 *              OUT length of the parameter area
 *              OUT length of the data area
 *
 * RETURNS: SMB error or 0 on success
 *
 * NOTES:
 *====================================================================
 */
 
NQ_UINT32
csQueryFsInformation(
    const CSShare* pShare,
    NQ_UINT informationLevel,
    NQ_BOOL unicodeRequired,
    CSTransaction2Descriptor* descriptor
#ifdef UD_NQ_INCLUDEEVENTLOG
	,CSTree * pTree
#endif /* UD_NQ_INCLUDEEVENTLOG */
    )
{
    CMCifsStatus error;                 /* for composing DOS-style error */
    NQ_UINT responseLength;             /* response lengths according to the required level */
    NQ_TCHAR* pVolumeName;              /* pointer to the volume name */
    SYVolumeInformation volumeInfo;     /* buffer for the volume information */
    static const NQ_TCHAR noName[] = {(NQ_TCHAR)0};   /* empty name for file */
    NQ_UINT labelLength;                /* volume label length, 0 if not required */
    const NQ_TCHAR* pLabel;             /* pointer to a name to add to response */
    NQ_BOOL tcharLabel = TRUE;          /* whether label is in TCHAR or in CHAR */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent		eventInfo;
    CSUser *				pUser;
    CSUid					uid = pTree->uid;
    CSTid					tid = pTree->tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();
    
    /* convert filename to host filename, simulating empty file name in ANSI */
    
#ifdef UD_NQ_INCLUDEEVENTLOG
    pUser = csGetUserByUid(uid);
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = tid;
    eventInfo.fileName = noName;
    eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    if ((pVolumeName = cmCifsNtohFilename(
                        pShare->map,
                        noName,
                        FALSE
                        )
        ) == NULL
       )
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
    }



    /* query information */
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before = TRUE;
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
    if (syGetVolumeInformation(pVolumeName, &volumeInfo))
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unable to read file information");
        TRCE();
        return error;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    
    switch (informationLevel)
    {
    case SMB_QUERYFS_INFOALLOCATION:
        responseLength = sizeof(CMCifsQueryFsInfoAllocationResponse);
        pLabel = NULL;
        break;
    case SMB_QUERYFS_INFOVOLUME:
        responseLength = sizeof(CMCifsQueryFsInfoVolumeResponse);
        pLabel = pShare->name;
        break;
    case SMB_QUERYFS_NT_VOLUMEINFO:
        responseLength = sizeof(CMCifsQueryFsInfoNtVolumeResponse);
        pLabel = pShare->name;
        break;
    case SMB_QUERYFS_NT_SIZEINFO:
        responseLength = sizeof(CMCifsQueryFsInfoNtSizeResponse);
        pLabel = NULL;
        break;
    case SMB_QUERYFS_NT_DEVICEINFO:
        responseLength = sizeof(CMCifsQueryFsInfoNtDeviceResponse);
        pLabel = NULL;
        break;
    case SMB_QUERYFS_NT_ATTRIBUTEINFO:
        responseLength = sizeof(CMCifsQueryFsInfoNtAttributeResponse);
        pLabel = (NQ_TCHAR*)UD_FS_FILESYSTEMNAME;
        tcharLabel = FALSE;
        break;
    case SMB_QUERYFS_NT_FULLSIZEINFO:
        responseLength = sizeof(CMCifsQueryFsInfoNtFullSizeResponse);
        pLabel = NULL;
        break;
    default:
        TRCERR("Illegal information level %d", informationLevel);
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    /* prepare pointers */
    
    descriptor->parameterCount = 0;
    descriptor->pData = descriptor->pParams;
    descriptor->dataCount = 0;

    if (pLabel != NULL)
    {
        if (unicodeRequired)
        {
            if (tcharLabel)
                cmTcharToUnicode((NQ_WCHAR*)(descriptor->pData + responseLength), pLabel);
            else
                syAnsiToUnicode((NQ_WCHAR*)(descriptor->pData + responseLength), (NQ_CHAR*)pLabel);
            labelLength = (NQ_UINT)((cmWStrlen((const NQ_WCHAR*)(descriptor->pData + responseLength))) * sizeof(NQ_WCHAR));
        }
        else
        {
            if (tcharLabel)
                cmTcharToAnsi((NQ_CHAR*)(descriptor->pData + responseLength), pLabel);
            else
                syStrcpy((NQ_CHAR*)(descriptor->pData + responseLength), (NQ_CHAR*)pLabel);
            labelLength = (NQ_UINT)syStrlen((NQ_CHAR*)pLabel);
        }
        descriptor->dataCount = (NQ_UINT16)(descriptor->dataCount + labelLength);
    }
    else
        labelLength = 0;
    
    responseLength += labelLength;

    /* check available space */
    
    error = csDispatchCheckSpace(descriptor->pHeaderOut, (NQ_BYTE*)descriptor->pData, responseLength + labelLength);
    if (error != 0)
    {
        TRCERR("No buffer space available");
        TRCE();
        return error;
    }

    /* fill information - switch according to the information level */
    
    switch (informationLevel)
    {
    case SMB_QUERYFS_INFOALLOCATION:
        {
            CMCifsQueryFsInfoAllocationResponse* infoResponse;  /* casted response */

            infoResponse = (CMCifsQueryFsInfoAllocationResponse*)descriptor->pData;

            cmPutSUint32(infoResponse->idFileSystem, cmHtol32(volumeInfo.fileSystemId));
            cmPutSUint32(infoResponse->sectorsPerUnit, cmHtol32(volumeInfo.blocksPerUnit));
            cmPutSUint32(infoResponse->totalUnits, cmHtol32(volumeInfo.totalUnitsLow));
            cmPutSUint32(infoResponse->freeUnits, cmHtol32(volumeInfo.freeUnitsLow));
            cmPutSUint16(infoResponse->sectorSize, cmHtol16((NQ_UINT16)volumeInfo.blockSize));
        }
        break;
    case SMB_QUERYFS_INFOVOLUME:
        {
            CMCifsQueryFsInfoVolumeResponse* infoResponse; /* casted response */

            infoResponse = (CMCifsQueryFsInfoVolumeResponse*)descriptor->pData;

            cmPutSUint32(infoResponse->serialNumber, cmHtol32(volumeInfo.serialNumber));
            infoResponse->labelLength = (NQ_BYTE)labelLength;
        }
        break;
    case SMB_QUERYFS_NT_VOLUMEINFO:
        {
            CMCifsQueryFsInfoNtVolumeResponse* infoResponse; /* casted response */
            NQ_UINT32 timeLow;     /* low part of UTC time */
            NQ_UINT32 timeHigh;    /* high part of UTC time */

            infoResponse = (CMCifsQueryFsInfoNtVolumeResponse*)descriptor->pData;
            cmCifsTimeToUTC(volumeInfo.creationTime, &timeLow, &timeHigh);
            cmPutSUint32(infoResponse->creationTime.low, cmHtol32(timeLow));
            cmPutSUint32(infoResponse->creationTime.high, cmHtol32(timeHigh));
            cmPutSUint32(infoResponse->serialNumber, cmHtol32(volumeInfo.serialNumber));
            cmPutSUint32(infoResponse->labelLength, cmHtol32(labelLength));
            infoResponse->reserved[0] = infoResponse->reserved[1] = 0; 
        }
        break;
    case SMB_QUERYFS_NT_SIZEINFO:
        {
            CMCifsQueryFsInfoNtSizeResponse* infoResponse; /* casted response */

            infoResponse = (CMCifsQueryFsInfoNtSizeResponse*)descriptor->pData;

            cmPutSUint32(infoResponse->sectorsPerUnit, cmHtol32(volumeInfo.blocksPerUnit));
            cmPutSUint32(infoResponse->totalUnits.high, cmHtol32(volumeInfo.totalUnitsHigh));
            cmPutSUint32(infoResponse->totalUnits.low, cmHtol32(volumeInfo.totalUnitsLow));
            cmPutSUint32(infoResponse->freeUnits.high, cmHtol32(volumeInfo.freeUnitsHigh));
            cmPutSUint32(infoResponse->freeUnits.low, cmHtol32(volumeInfo.freeUnitsLow));
            cmPutSUint32(infoResponse->sectorSize, cmHtol32(volumeInfo.blockSize));
        }
        break;
    case SMB_QUERYFS_NT_DEVICEINFO:
        {
            CMCifsQueryFsInfoNtDeviceResponse* infoResponse; /* casted response */

            infoResponse = (CMCifsQueryFsInfoNtDeviceResponse*)descriptor->pData;

            cmPutSUint32(infoResponse->deviceType, 0);               /* no response */
            cmPutSUint32(infoResponse->deviceCharacteristics, 0);    /* no response */
        }
        break;
    case SMB_QUERYFS_NT_ATTRIBUTEINFO:
        {
            CMCifsQueryFsInfoNtAttributeResponse* infoResponse; /* casted response */

            infoResponse = (CMCifsQueryFsInfoNtAttributeResponse*)descriptor->pData;

            cmPutSUint32(infoResponse->attributes, cmHtol32(UD_FS_FILESYSTEMATTRIBUTES));
            cmPutSUint32(infoResponse->maxNameLength, cmHtol32(UD_FS_FILENAMECOMPONENTLEN));
            cmPutSUint32(infoResponse->fileSystemNameLength, cmHtol32(labelLength));
        }
        break;
    case SMB_QUERYFS_NT_FULLSIZEINFO:
        {
            CMCifsQueryFsInfoNtFullSizeResponse* infoResponse; /* casted response */

            infoResponse = (CMCifsQueryFsInfoNtFullSizeResponse*)descriptor->pData;
            
            cmPutSUint32(infoResponse->totalUnits.high, cmHtol32(volumeInfo.totalUnitsHigh));
            cmPutSUint32(infoResponse->totalUnits.low, cmHtol32(volumeInfo.totalUnitsLow));
            cmPutSUint32(infoResponse->callerTotalUnits.high, cmHtol32(volumeInfo.freeUnitsHigh));
            cmPutSUint32(infoResponse->callerTotalUnits.low, cmHtol32(volumeInfo.freeUnitsLow));
            cmPutSUint32(infoResponse->freeUnits.high, cmHtol32(volumeInfo.freeUnitsHigh));
            cmPutSUint32(infoResponse->freeUnits.low, cmHtol32(volumeInfo.freeUnitsLow));
            cmPutSUint32(infoResponse->sectorsPerUnit, cmHtol32(volumeInfo.blocksPerUnit));
            cmPutSUint32(infoResponse->sectorSize, cmHtol32(volumeInfo.blockSize));
        }
        break;
    }

    /* place label whether required and advance the response pointer*/
    
    descriptor->dataCount = (NQ_UINT16)(descriptor->dataCount + responseLength);
    
    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Perform QUERY_PATH_INFORMATION2 subcommand of Transaction2 protocol
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
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csTransaction2QueryPathInformation(
    CSTransaction2Descriptor* descriptor
    )
{
    CMCifsPathInformation2Request* infoRequest;    /* casted request */
    NQ_BOOL unicodeRequired;            /* whether client requires UNICODE */
    const CSShare* pShare;              /* pointer to the share */
    NQ_TCHAR* pFileName;                /* pointer to the volume name */
    CSUid uid;                          /* required UID */
    CSTid tid;                          /* required TID */
    CSUser *pUser;
    NQ_UINT32 returnValue;              /* error code in NT format or 0 for no error */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent 	eventInfo;
    CSFile				fakeFile;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    TRCB();

    /* check unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */

    infoRequest = (CMCifsPathInformation2Request*) (
                          (NQ_BYTE*)descriptor->requestData
                        + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.parameterOffset))
                        - sizeof(CMCifsHeader)
                        );

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
        TRCERR("Illegal UID or TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
    }

    /* convert filename to host filename */

    if ((pFileName = cmCifsNtohFilename(
                        pShare->map,
                        (NQ_TCHAR*)(infoRequest + 1),
                        unicodeRequired
                        )
        ) == NULL
       )
    {
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = tid;
    eventInfo.fileName = pFileName;
	syMemset(&fakeFile, 0, sizeof(fakeFile));
    fakeFile.uid = pUser->uid;
    fakeFile.tid = tid;
    eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    if (!csCheckPathAndFile(pShare, pFileName, (NQ_UINT)cmTStrlen(pShare->map), pUser->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			csErrorReturn(SMB_STATUS_OBJECT_NAME_NOT_FOUND, DOS_ERRbadfile),
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
        TRCERR("File does not exists");
        TRC1P(" path: %s", cmTDump(pFileName));
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_NOT_FOUND, DOS_ERRbadfile);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		pUser->preservesCase ? UD_LOG_FILE_ATTRIBGET : (pShare != NULL && cmTStrcmp(pShare->map , pFileName) == 0) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    /* check whether this file is opened by this or another client and is marked for deletion */

    if (csFileMarkedForDeletion(pFileName))
    {
        TRCERR("File is marked for deletion");
        TRC1P(" file name: %s", cmTDump(pFileName));
        TRCE();
        return csErrorReturn(SMB_STATUS_DELETE_PENDING, DOS_ERRbadaccess);
    }

    /* call common processing */
 
    returnValue = csQueryFileInformationByName(
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    				&fakeFile,
#else
                    NULL,
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                    pFileName,
                    (NQ_COUNT)cmTStrlen(pShare->map),
                    cmLtoh16(cmGetSUint16(infoRequest->informationLevel)),
                    unicodeRequired,
                    (NQ_UINT)(CS_MAXBUFFERSIZE - (NQ_UINT)(descriptor->pParams - (NQ_BYTE*)descriptor->pHeaderOut)),
                    descriptor
                    );

    TRCE();
    return returnValue;
}

/*
 *====================================================================
 * PURPOSE: Perform QUERY_FILE_INFORMATION2 subcommand of Transaction2 protocol
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
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csTransaction2QueryFileInformation(
    CSTransaction2Descriptor* descriptor
    )
{
    CMCifsFileInformation2Request* infoRequest; /* casted request */
    CSUid uid;                                  /* required UID */
    CSTid tid;                                  /* required TID */
    const CSShare* pShare;                      /* pointer to the share */
    NQ_UINT16 informationLevel;                 /* required information level */
    NQ_BOOL unicodeRequired;                    /* whether client requires UNICODE */
    NQ_UINT32 returnValue;                      /* error code in NT format or 0 for no error */
    CSFile* pFile;                              /* pointer to the file descriptor */
    CSName* pName;                              /* pointer to file name descriptor */
    const NQ_TCHAR* pFileName;                  /* file name pointer */

    TRCB();

    /* check unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */

    infoRequest = (CMCifsFileInformation2Request*) (
                          (NQ_BYTE*)descriptor->requestData
                        + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.parameterOffset))
                        - sizeof(CMCifsHeader)
                        );

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

    /* find file descriptor(s) */

    pFile = csGetFileByFid(
        cmLtoh16(cmGetSUint16(infoRequest->fid)),
        cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid)),
        cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid))
        );
    if (pFile == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    /* check whether this file is opened by this or another client and is marked for deletion */

    pName = csGetNameByNid(pFile->nid);
    if (pName == NULL || pName->markedForDeletion)
    {
        TRCERR("File is marked for deletion");
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }

    /* find file name */

    pFileName = csGetFileName(pFile->fid);
    if (pFileName == NULL)
    {
        TRCERR("File name corrupted");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* call common processing */

    informationLevel = cmLtoh16(cmGetSUint16(infoRequest->informationLevel));
    descriptor->parameterCount = 0;

    returnValue = csQueryFileInformationByName(
                    pFile,
                    pFileName,
                    (NQ_COUNT)cmTStrlen(pShare->map),
                    (NQ_UINT)informationLevel,
                    unicodeRequired,
                    (NQ_UINT)(CS_MAXBUFFERSIZE - (NQ_UINT)(descriptor->pParams - (NQ_BYTE*)descriptor->pHeaderOut)),
                    descriptor
                    );

    TRCE();
    return returnValue;
}

/*
 *====================================================================
 * PURPOSE: Perform SET_PATH_INFORMATION2 subcommand of Transaction2 protocol
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
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csTransaction2SetPathInformation(
    CSTransaction2Descriptor* descriptor
    )
{
    CMCifsPathInformation2Request* infoRequest;    /* casted request */
    const CSShare* pShare;              /* pointer to the share */
    NQ_UINT32 returnValue;              /* error code in NT format or 0 for no error */
    NQ_BOOL unicodeRequired;            /* TRUE for unicode names */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;        /* share event information */
    const CSUser* pUser;                /* user structure pointer */
#endif /* UD_NQ_INCLUDEEVENTLOG */
    InfoContext ctx;                    /* info context */ 

    TRCB();

    /* cast pointers */

    infoRequest = (CMCifsPathInformation2Request*) (
                          (NQ_BYTE*)descriptor->requestData
                        + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.parameterOffset))
                        - sizeof(CMCifsHeader)
                        );

    /* withdraw UID and TID */

    ctx.uid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid));
    ctx.tid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid));
    unicodeRequired = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

#ifdef UD_NQ_INCLUDEEVENTLOG
    if (NULL == (pUser = csGetUserByUid(ctx.uid)))
#else /* UD_NQ_INCLUDEEVENTLOG */
    if (csGetUserByUid(ctx.uid) == NULL)
#endif /* UD_NQ_INCLUDEEVENTLOG */
    {
        TRCERR("Illegal UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

    pShare = csGetShareByUidTid(ctx.uid, ctx.tid);
    if (pShare == NULL)
    {
        TRCERR("Illegal UID or TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
    }

    /* convert filename to host filename, simulating empty file name in ANSI */

    if ((ctx.pFileName = cmCifsNtohFilename(
                        pShare->map,
                        (NQ_TCHAR*)(infoRequest + 1),
                        unicodeRequired
                        )
        ) == NULL
       )
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.fileName = NULL;
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.fileName = ctx.pFileName;
        eventInfo.access = (NQ_UINT32)-1;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* check access to share */

    if ((returnValue = csCanWriteShare(ctx.tid)) != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            returnValue,
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Access denied");
        TRCE();
        return returnValue;
    }

    /* check whether this file is opened by this or another client and is marked for deletion */

    if (csFileMarkedForDeletion(ctx.pFileName))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_ATTRIBSET,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("File is marked for deletion");
        TRC1P(" file name: %s", cmTDump(ctx.pFileName));
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }

    /* call common processing */

    ctx.level = cmLtoh16(cmGetSUint16(infoRequest->informationLevel));

    descriptor->parameterCount = 2;
    descriptor->pData = descriptor->pParams + descriptor->parameterCount;
    descriptor->pData = cmAllignTwo(descriptor->pData);
    descriptor->dataCount = 0;
    syMemset(descriptor->pParams, 0, descriptor->parameterCount);
    ctx.pData = (NQ_BYTE*)descriptor->requestData
                    + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.dataOffset))
                    - sizeof(CMCifsHeader);

    returnValue = csSetFileInformationByName(
                    NULL,
#ifdef UD_NQ_INCLUDEEVENTLOG
                    pUser,
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    &ctx
                    );
    TRCE();
    return returnValue;
}

/*
 *====================================================================
 * PURPOSE: Perform SET_FILE_INFORMATION2 subcommand of Transaction2 protocol
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
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csTransaction2SetFileInformation(
    CSTransaction2Descriptor* descriptor
    )
{
    CMCifsFileInformation2Request* infoRequest;    /* casted request */
    NQ_UINT32 returnValue;              /* error code in NT format or 0 for no error */
    CSFile* pFile;                      /* pointer to the file descriptor */
#ifdef UD_NQ_INCLUDEEVENTLOG   
    const CSUser* pUser;                /* user name structure */
    UDFileAccessEvent eventInfo;        /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */
    InfoContext ctx;

    TRCB();

    /* cast pointers */

    infoRequest = (CMCifsFileInformation2Request*) (
                          (NQ_BYTE*)descriptor->requestData
                        + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.parameterOffset))
                        - sizeof(CMCifsHeader)
                        );

    /* find file descriptor(s) */

    pFile = csGetFileByFid(
        cmLtoh16(cmGetSUint16(infoRequest->fid)),
        cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid)),
        cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid))
        );
    if (pFile == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    pUser = csGetUserByUid(pFile->uid);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    ctx.pFileName = csGetFileName(pFile->fid);
    TRC1P(" file name: %s", cmTDump(ctx.pFileName));
    if (ctx.pFileName == NULL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        if (NULL != pUser)
        {
            eventInfo.fileName = NULL;
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_ATTRIBSET,
                pUser->name,
                pUser->ip,
                csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror),
                (const NQ_BYTE*)&eventInfo
            );
        }
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("File name corrupted");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = ctx.pFileName;
    eventInfo.access = (NQ_UINT32)-1;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* check access to share */

    if ((returnValue = csCanWriteShare(cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid)))) != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        if (NULL != pUser)
        {
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_ATTRIBSET,
                pUser->name,
                pUser->ip,
                returnValue,
                (const NQ_BYTE*)&eventInfo
            );
        }
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Access denied");
        TRCE();
        return returnValue;
    }

    /* call common processing */

    ctx.level = cmLtoh16(cmGetSUint16(infoRequest->informationLevel));

    descriptor->parameterCount = (ctx.level > 0x100)? 2 : 0;
    descriptor->pData = descriptor->pParams + descriptor->parameterCount;
    descriptor->pData = cmAllignTwo(descriptor->pData);
    descriptor->dataCount = 0;

    ctx.pData = (NQ_BYTE*)descriptor->requestData
                + cmLtoh16(cmGetSUint16(descriptor->requestData->transHeader.dataOffset))
                - sizeof(CMCifsHeader);
    ctx.uid = pFile->uid;
    ctx.tid = pFile->tid;

    returnValue = csSetFileInformationByName(
                        pFile,
#ifdef UD_NQ_INCLUDEEVENTLOG
                        pUser,
#endif /* UD_NQ_INCLUDEEVENTLOG */
                        &ctx
                        );
   
    TRCE();
    return returnValue;
}

/*
 *====================================================================
 * PURPOSE: query file information providing file name
 *--------------------------------------------------------------------
 * PARAMS:  IN file descriptor (may be NULL)
 *          IN  name of the file to query on
 *          IN length of the share map name
 *          IN information level required
 *          IN whether the client asks for UNICODE names
 *          IN available space in the buffer
 *          IN/OUT subcommand parameters structure:
 *              IN pointer to the CIFS header
 *              IN pointer to the parameter area
 *              OUT pointer to the data area
 *              OUT length of the parameter area
 *              OUT length of the data area
 *
 * RETURNS: error in NT format or 0 on success
 *
 * NOTES:   1) calculates required space
 *          2) composes the response
 *====================================================================
 */

NQ_UINT32
csQueryFileInformationByName(
    const CSFile* pFile,
    const NQ_TCHAR* pFileName,
    NQ_COUNT shareNameLen,
    NQ_UINT level,
    NQ_BOOL unicodeRequired,
    NQ_UINT spaceAvailable,
    CSTransaction2Descriptor* descriptor
    )
{
    NQ_STATUS status;                   /* generic return code */
    SYFileInformation fileInfo;         /* buffer for file information */
    NQ_UINT dataLength;                 /* length of the data area */
    CMCifsStatus error;                 /* for composing error code */
    NQ_UINT nameLength = 0;             /* length of the file name */
    const NQ_TCHAR* pActualName;        /* file name */
    NQ_STATIC NQ_TCHAR tempName[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_FILENAMELEN)];
                                        /* buffer for converting names */
    NQ_INT charLen;                     /* character length in required encoding */
    static const NQ_TCHAR rootName[] = { cmTChar('\\'), 0 };
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;        /* share event information */
    CSUser	*			pUser = NULL;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    TRC1P("file name: %s", cmTDump(pFileName));
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.access = 0;
    eventInfo.before = TRUE;
    eventInfo.fileName = pFileName;
    if (pFile != NULL)
    {
    	eventInfo.tid = pFile->tid;
    	pUser = csGetUserByUid(pFile->uid);
    	if (pUser != NULL)
    		eventInfo.rid = csGetUserRid((CSUser *)pUser);
    }
#endif /* UD_NQ_INCLUDEEVENTLOG */
    charLen = unicodeRequired? sizeof(NQ_WCHAR) : sizeof(NQ_CHAR);

#ifdef UD_CS_INCLUDERPC
    if (NULL != pFile && pFile->isPipe)
    {
        status = csDcerpcGetPipeInformation(pFile, &fileInfo);
    }
    else
    {
#endif /* UD_CS_INCLUDERPC */
#ifdef UD_NQ_INCLUDEEVENTLOG
		if (pUser != NULL)
		{
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
				);
		}
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        status = syGetFileInformationByName(pFileName, &fileInfo);
#ifdef UD_NQ_INCLUDEEVENTLOG
        if (pUser != NULL)
        {
    		udEventLog(
    				UD_LOG_MODULE_CS,
    				UD_LOG_CLASS_FILE,
    				UD_LOG_FILE_ATTRIBGET,
    				pUser->name,
    				pUser->ip,
    				(status == NQ_SUCCESS) ? 0 :csErrorGetLast(),
    				(const NQ_BYTE*)&eventInfo
    			);
        }
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_CS_INCLUDERPC
    }
#endif /* UD_CS_INCLUDERPC */
    if (NQ_SUCCESS != status)
    {
    	error = csErrorGetLast();

        TRCERR("Unable to read file/pipe information");
        TRCE();
        return error;
    }

    /* fix file size for directories */

    if (0 != (fileInfo.attributes & SMB_ATTR_DIRECTORY))
    {
        fileInfo.sizeHigh = 0;
        fileInfo.sizeLow = 0;
    }

    /* find the file name without the share */

    pActualName = pFileName + shareNameLen + 1;   /* including path separator */

    /* check available space */
    
    descriptor->parameterCount = 0;
    
    switch (level)
    {
    case SMB_QUERYPATH2_EASIZE:
        dataLength = sizeof(CMCifsFileInformation2EaSize);
        break;
    case SMB_QUERYPATH2_STANDARD:
        dataLength = sizeof(CMCifsFileInformation2Standard);
        break;
    case SMB_QUERYPATH2_EASFROMLIST:
    case SMB_QUERYPATH2_ALLEAS:
        dataLength = sizeof(CMCifsFileInformation2Eas);
        break;
    case SMB_QUERYPATH2_ISNAMEVALID:
        dataLength = 0;
        break;
    case SMB_PASSTHRU_FILE_BASICINFO:
    case SMB_QUERYPATH2_NT_BASICINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtBasic);
        break;
    case SMB_PASSTHRU_FILE_STANDARDINFO:
    case SMB_QUERYPATH2_NT_STANDARDINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtStandard);
        break;
    case SMB_PASSTHRU_FILE_EAINFO:
    case SMB_QUERYPATH2_NT_EAINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtEaSize);
        break;
    case SMB_PASSTHRU_FILE_NAMEINFO:    
    case SMB_QUERYPATH2_NT_NAMEINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtFileName);
        pActualName--;    /* include separator into the path */
        nameLength = (NQ_UINT)(cmTStrlen(pActualName) * sizeof(NQ_WCHAR));
        if (nameLength == 0)
        {
            pActualName = rootName;
            nameLength = (NQ_UINT)(cmTStrlen(pActualName) * sizeof(NQ_WCHAR));
        }
        dataLength += nameLength;
        break;
    case SMB_PASSTHRU_FILE_ALTNAMEINFO:    
    case SMB_QUERYPATH2_NT_ALTNAMEINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtFileName);
        pActualName = cmTStrrchr(pFileName, cmTChar(SY_PATHSEPARATOR));
        if (pActualName == NULL)
            pActualName = pFileName;
        else
            pActualName++;
        nameLength = (NQ_UINT)(cmTStrlen(pActualName) * sizeof(NQ_WCHAR));    /* force unicode */
        unicodeRequired = TRUE;
        dataLength += nameLength + (NQ_UINT)charLen;
        break;
    case SMB_PASSTHRU_FILE_ALLINFO:    
    case SMB_QUERYPATH2_NT_ALLINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtAll);
        nameLength = (NQ_UINT)(cmTStrlen(pActualName) * sizeof(NQ_WCHAR));    /* force unicode */
        unicodeRequired = TRUE;
        dataLength += nameLength;
        break;
    case SMB_QUERYPATH2_NT_ALLOCATIONINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtAllocation);
        break;
    case SMB_QUERYPATH2_NT_ENDOFFILEINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInformation2NtEndOfFile);
        break;
    case SMB_PASSTHRU_FILE_NETWORKINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileNetworkOpenInformation);
        break;
    case SMB_PASSTHRU_FILE_INTERNALINFO:
        descriptor->parameterCount = 2;
        dataLength = sizeof(CMCifsFileInternalInformation);
        break;
    default:
        TRCERR("Illegal information level: %d", level);
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    /* Undocumented feature
       --------------------
       I didn't find this in any CIFS-related document...
       A TRANSACT2 response with the QUERY_FILE_INFORMATION command is expected to have
       2-byte long parameter area (this IS documented). This word should be zero (this is
       NOT documented). There should be another two bytes after parameters and before the
       data area with a value of 1 (NOT documented as well).

       Maybe for a 4-byte alignment (?) */

    syMemset(descriptor->pParams, 0, descriptor->parameterCount);
    descriptor->pData = descriptor->pParams + descriptor->parameterCount;
    cmPutUint16(descriptor->pData, cmHtol16((NQ_UINT16)0x100));  /* undocumented CIFS feature */
    descriptor->pData += 2;                                      /* undocumented CIFS feature */

    descriptor->dataCount = (NQ_UINT16)dataLength;
    if ((descriptor->parameterCount + (NQ_UINT)2 + dataLength) > spaceAvailable)
    {
        TRCERR("Buffer overflow");
        TRC2P(" available: %d, required %d", spaceAvailable, descriptor->parameterCount + dataLength);
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* fill information according to the information level */

    switch (level)
    {
    case SMB_QUERYPATH2_EASIZE:
        {
            CMCifsFileInformation2EaSize* infoResponse;  /* casted response */
            infoResponse = (CMCifsFileInformation2EaSize*)descriptor->pData;
            cmPutSUint32(infoResponse->eaSize, 0L);
            /* continue to the next case */
        }
    case SMB_QUERYPATH2_STANDARD:
        {
            NQ_UINT16 smbTime;     /* temporary time in SMB_TIME format */
            NQ_UINT16 smbDate;     /* temporary date in SMB_DATE format */
            CMCifsFileInformation2Standard* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2Standard*)descriptor->pData;

            cmCifsTimeToSmbTime(fileInfo.creationTime, &smbTime, &smbDate);
            cmPutSUint16(infoResponse->creationTime, cmHtol16(smbTime));
            cmPutSUint16(infoResponse->creationDate, cmHtol16(smbDate));
            cmCifsTimeToSmbTime(fileInfo.lastAccessTime, &smbTime, &smbDate);
            cmPutSUint16(infoResponse->lastAccessTime, cmHtol16(smbTime));
            cmPutSUint16(infoResponse->lastAccessDate, cmHtol16(smbDate));
            cmCifsTimeToSmbTime(fileInfo.lastWriteTime, &smbTime, &smbDate);
            cmPutSUint16(infoResponse->lastWriteTime, cmHtol16(smbTime));
            cmPutSUint16(infoResponse->lastWriteDate, cmHtol16(smbDate));
            cmPutSUint32(infoResponse->dataSize, cmHtol32(fileInfo.sizeLow));
            cmPutSUint32(infoResponse->allocationSize, cmHtol32(fileInfo.allocSizeLow));
            cmPutSUint16(infoResponse->attributes, cmHtol16((NQ_UINT16)fileInfo.attributes));
        }
        break;
    case SMB_QUERYPATH2_EASFROMLIST:
    case SMB_QUERYPATH2_ALLEAS:
        {
            CMCifsFileInformation2Eas* infoResponse;  /* casted response */

            cmPutUint16(descriptor->pData, (NQ_UINT16)0);         /* parameters */
            descriptor->pData += 2;

            infoResponse = (CMCifsFileInformation2Eas*)descriptor->pData;  /* data */
            cmPutSUint32(infoResponse->listLength, 0);
        }
        break;
    case SMB_QUERYPATH2_ISNAMEVALID:
        break;
    case SMB_PASSTHRU_FILE_BASICINFO:    
    case SMB_QUERYPATH2_NT_BASICINFO:
        {
            CMCifsFileInformation2NtBasic* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2NtBasic*)descriptor->pData;

            csWriteFileTimes(&fileInfo, csGetNameByName(pFileName), descriptor->pData);
            cmPutSUint32(infoResponse->attributes, cmHtol32(fileInfo.attributes));
            cmPutSUint32(infoResponse->pad, cmHtol32(0));  /* undocumented */
        }
        break;
    case SMB_PASSTHRU_FILE_STANDARDINFO:    
    case SMB_QUERYPATH2_NT_STANDARDINFO:
        {
            CMCifsFileInformation2NtStandard* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2NtStandard*)descriptor->pData;

            cmPutSUint32(infoResponse->allocationSize.low, cmHtol32(fileInfo.allocSizeLow));
            cmPutSUint32(infoResponse->allocationSize.high, cmHtol32(fileInfo.allocSizeHigh));
            cmPutSUint32(infoResponse->endOfFile.low, cmHtol32(fileInfo.sizeLow));
            cmPutSUint32(infoResponse->endOfFile.high, cmHtol32(fileInfo.sizeHigh));
            cmPutSUint32(infoResponse->numberOfLinks, cmHtol32(fileInfo.numLinks));
            infoResponse->deletePending = (NQ_BYTE)fileInfo.isDeleted;
            infoResponse->directory = (fileInfo.attributes & SY_ATTR_DIRECTORY) != 0;
            cmPutSUint16(infoResponse->unknown, cmHtol16(0));
        }
        break;
    case SMB_PASSTHRU_FILE_EAINFO:    
    case SMB_QUERYPATH2_NT_EAINFO:
        {
            CMCifsFileInformation2NtEaSize* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2NtEaSize*)descriptor->pData;

            cmPutSUint32(infoResponse->eaSize, 0);
        }
        break;
    case SMB_PASSTHRU_FILE_NAMEINFO:
    case SMB_PASSTHRU_FILE_ALTNAMEINFO:
    case SMB_QUERYPATH2_NT_NAMEINFO:
    case SMB_QUERYPATH2_NT_ALTNAMEINFO:
        {
            CMCifsFileInformation2NtFileName* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2NtFileName*)descriptor->pData;

            cmPutSUint32(infoResponse->fileNameLength, cmHtol32(nameLength));
            cmTStrcpy(tempName, pActualName);
            cmCifsHtonFilename(tempName);
            cmTcharToUnicode((NQ_WCHAR*)(infoResponse + 1), tempName);
        }
        break;
    case SMB_PASSTHRU_FILE_ALLINFO:    
    case SMB_QUERYPATH2_NT_ALLINFO:
        {
            CMCifsFileInformation2NtAll* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2NtAll*)descriptor->pData;

            csWriteFileTimes(&fileInfo, csGetNameByName(pFileName), descriptor->pData);
            cmPutSUint32(infoResponse->attributes, cmHtol32(fileInfo.attributes));
            cmPutSUint32(infoResponse->pad1, 0);
            cmPutSUint32(infoResponse->allocationSize.low, cmHtol32(fileInfo.allocSizeLow));
            cmPutSUint32(infoResponse->allocationSize.high, cmHtol32(fileInfo.allocSizeHigh));
            cmPutSUint32(infoResponse->endOfFile.low, cmHtol32(fileInfo.sizeLow));
            cmPutSUint32(infoResponse->endOfFile.high, cmHtol32(fileInfo.sizeHigh));
            cmPutSUint32(infoResponse->numberOfLinks, cmHtol32(fileInfo.numLinks));
            infoResponse->deletePending = (NQ_BYTE)fileInfo.isDeleted;
            infoResponse->directory = ((NQ_UINT16)fileInfo.attributes & SY_ATTR_DIRECTORY) != 0;
            cmPutSUint16(infoResponse->pad2, 0);
            cmPutSUint32(infoResponse->fileIndex.low, 0);
            cmPutSUint32(infoResponse->fileIndex.high, 0);
            cmPutSUint32(infoResponse->eaSize, 0L);
            cmPutSUint32(infoResponse->accessFlags, pFile ? cmHtol32(convertNqAccessToNtAccess(pFile->access)): 0);
            cmPutSUint32(infoResponse->byteOffset.low, pFile ? cmHtol32(pFile->offsetLow) : 0);
            cmPutSUint32(infoResponse->byteOffset.high, pFile ? cmHtol32(pFile->offsetHigh) : 0);
            cmPutSUint32(infoResponse->mode, 0);
            cmPutSUint32(infoResponse->alignment, 0);
            cmPutSUint32(infoResponse->fileNameLength, cmHtol32(nameLength));
            cmTStrcpy(tempName, pActualName);
            cmCifsHtonFilename(tempName);
            cmTcharToUnicode((NQ_WCHAR*)(infoResponse + 1), tempName);
        }
        break;
    case SMB_QUERYPATH2_NT_ALLOCATIONINFO:
        {
            CMCifsFileInformation2NtAllocation* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2NtAllocation*)descriptor->pData;

            cmPutSUint32(infoResponse->allocationSize.low, cmHtol32(fileInfo.allocSizeLow));
            cmPutSUint32(infoResponse->allocationSize.high, cmHtol32(fileInfo.allocSizeHigh));
        }
        break;
    case SMB_QUERYPATH2_NT_ENDOFFILEINFO:
        {
            CMCifsFileInformation2NtEndOfFile* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInformation2NtEndOfFile*)descriptor->pData;

            cmPutSUint32(infoResponse->endOfFile.low, cmHtol32(fileInfo.sizeLow));
            cmPutSUint32(infoResponse->endOfFile.high, cmHtol32(fileInfo.sizeHigh));
        }
        break;
    case SMB_PASSTHRU_FILE_NETWORKINFO:
        {
            CMCifsFileNetworkOpenInformation* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileNetworkOpenInformation*)descriptor->pData;
            
            csWriteFileTimes(&fileInfo, csGetNameByName(pFileName), descriptor->pData);
            cmPutSUint32(infoResponse->allocationSize.low, cmHtol32(fileInfo.allocSizeLow));
            cmPutSUint32(infoResponse->allocationSize.high, cmHtol32(fileInfo.allocSizeHigh));
            cmPutSUint32(infoResponse->endOfFile.low, cmHtol32(fileInfo.sizeLow));
            cmPutSUint32(infoResponse->endOfFile.high, cmHtol32(fileInfo.sizeHigh));            
            cmPutSUint32(infoResponse->attributes, cmHtol32(fileInfo.attributes));
            cmPutSUint32(infoResponse->reserved, 0);
        }
        break;
    case SMB_PASSTHRU_FILE_INTERNALINFO:
        {
            CMCifsFileInternalInformation* infoResponse;  /* casted response */

            infoResponse = (CMCifsFileInternalInformation*)descriptor->pData;

            cmPutSUint32(infoResponse->fileIndex.low, 0);
            cmPutSUint32(infoResponse->fileIndex.high, 0);
        }
        break;
    }

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: query file information providing file name
 *--------------------------------------------------------------------
 * PARAMS:  IN optional file descriptor pointer
 *          IN name of the file to query on
 *          IN user structure pointer
 *          IN pointer to information context
 *
 * RETURNS: error in NT format or 0 on success
 *
 * NOTES:   writes file information according to information level
 *====================================================================
 */

NQ_UINT32
csSetFileInformationByName(
    CSFile* pFile,
#ifdef UD_NQ_INCLUDEEVENTLOG
    const CSUser* pUser,
#endif /* UD_NQ_INCLUDEEVENTLOG */
    const InfoContext* ctx
    )
{
    SYFileInformation fileInfo;         /* buffer for file information */
    SYFileInformation oldFileInfo;      /* saved file information before change */
    CMCifsStatus error;                 /* for composing error code */
    CSName* pName;                      /* file name pointer */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;        /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */
            
    TRCB();

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before = TRUE;
    eventInfo.rid = csGetUserRid((CSUser *)pUser);
    eventInfo.tid = pFile != NULL ? pFile->tid : ctx->tid;
    eventInfo.fileName = ctx->pFileName;
    eventInfo.infoLevel = ctx->level;
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before = TRUE;
    if (NULL != pUser)
    {
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE*)&eventInfo
			);
    }
    eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    if (syGetFileInformationByName(ctx->pFileName, &fileInfo) != NQ_SUCCESS)
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
        if (NULL != pUser)
        {
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_ATTRIBGET,
                pUser->name,
                pUser->ip,
                error,
                (const NQ_BYTE*)&eventInfo
            );
        }
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Unable to read file information");
        TRCE();
        return error;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	if (NULL != pUser)
	{
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE*)&eventInfo
		);
	}
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* get pointer to Name slot */
    pName = csGetNameByName(ctx->pFileName);

    syMemcpy(&oldFileInfo, &fileInfo, sizeof(fileInfo));

    /* fill information according to the information level */

    switch (ctx->level)
    {
    case SMB_PASSTHRU_FILE_DISPOSITIONINFO:
    case SMB_SETPATH2_NT_DISPOSITIONINFO:
        {
            NQ_BOOL markedForDeletion;      /* whether this file should be marked for deletion */

            if (pFile == NULL)
            {
                TRCERR("Unable to set file information");
                TRCE();
                return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
            }

            markedForDeletion = *ctx->pData != 0; 
         
            if (pName == NULL)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (NULL != pUser)
                {
                    udEventLog(
                        UD_LOG_MODULE_CS,
                        UD_LOG_CLASS_FILE,
                        UD_LOG_FILE_ATTRIBSET,
                        pUser->name,
                        pUser->ip,
                        csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror),
                        (const NQ_BYTE*)&eventInfo
                    );
                }
#endif /* UD_NQ_INCLUDEEVENTLOG */
                TRCERR("Unable to get file handle from open handle - probably the internal database is corrupted");
                TRCE();
                return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
            }

            if (!(pName->first->access & SMB_ACCESS_A_DELETE))
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (NULL != pUser)
                {
                    udEventLog(
                        UD_LOG_MODULE_CS,
                        UD_LOG_CLASS_FILE,
                        UD_LOG_FILE_ATTRIBSET,
                        pUser->name,
                        pUser->ip,
                        csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess),
                        (const NQ_BYTE*)&eventInfo
                    );
                }
#endif /* UD_NQ_INCLUDEEVENTLOG */
                TRCERR("Unable to mark file for deletion because of insufficient access");
                TRCE();
                return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
            }

            /* mark for deletion of read only file is not allowed */
            if (0 != (fileInfo.attributes & SMB_ATTR_READONLY))
            {
                TRCERR("Unable to mark file for deletion read only file");
                TRCE();
                return csErrorReturn(SMB_STATUS_CANNOT_DELETE, DOS_ERRnoaccess);
            }

            /* mark for deletion on non empty directory is not allowed */
            if (markedForDeletion && (fileInfo.attributes & SMB_ATTR_DIRECTORY))
            {
                CSFileEnumeration fileEnumeration;
                NQ_TCHAR fileName[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_FILENAMELEN)];
                NQ_TCHAR pattern[] = {cmTChar(SY_PATHSEPARATOR), cmTChar('*'), cmTChar(0)};

                cmTStrcpy(fileName, ctx->pFileName);
                cmTStrcat(fileName, pattern);

                csEnumerateSourceName(&fileEnumeration, fileName, csGetUserByUid(pFile->uid)->preservesCase);
                fileEnumeration.bringLinks = FALSE;
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
				if (NULL != pUser)
				{
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_QUERYDIRECTORY,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				}
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                if (csNextSourceName(&fileEnumeration) != NULL)
                {
#ifdef UD_NQ_INCLUDEEVENTLOG
					if (NULL != pUser)
					{
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_QUERYDIRECTORY,
							pUser->name,
							pUser->ip,
							csErrorReturn(SMB_STATUS_DIRECTORY_NOT_EMPTY, DOS_ERRdirnotempty),
							(const NQ_BYTE*)&eventInfo
							);
					}
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
					eventInfo.before = TRUE;
					if (NULL != pUser && syIsValidDirectory(fileEnumeration.directory))
					{
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
					}
					eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    csCancelEnumeration(&fileEnumeration);
#ifdef UD_NQ_INCLUDEEVENTLOG
					if (NULL != pUser && syIsValidDirectory(fileEnumeration.directory))
					{
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							csErrorReturn(SMB_STATUS_DIRECTORY_NOT_EMPTY, DOS_ERRdirnotempty),
							(const NQ_BYTE*)&eventInfo
							);
					}
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    TRCERR("Unable to set mark for deletion on full directory");
                    TRCE();
                    return csErrorReturn(SMB_STATUS_DIRECTORY_NOT_EMPTY, DOS_ERRdirnotempty);                   
                }
#ifdef UD_NQ_INCLUDEEVENTLOG
				if (NULL != pUser)
				{
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_QUERYDIRECTORY,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				}
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
				if (NULL != pUser && syIsValidDirectory(fileEnumeration.directory))
				{
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_CLOSE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				}
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                csCancelEnumeration(&fileEnumeration);
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (NULL != pUser && syIsValidDirectory(fileEnumeration.directory))
				{
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_CLOSE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				}
#endif /* UD_NQ_INCLUDEEVENTLOG */

            }
            if (markedForDeletion)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
				if (pName->deletingUserRid == CS_ILLEGALID)
				{
	                NQ_IPADDRESS zeroIP = CM_IPADDR_ZERO;

					pName->deletingUserRid = pUser ? csGetUserRid(pUser) : CS_ILLEGALID;
					pName->deletingTid = pFile ? pFile->tid : CS_ILLEGALID;
					cmIpToAscii(pName->deletingIP, pUser ? pUser->ip : &zeroIP);
				}
#endif /* UD_NQ_INCLUDEEVENTLOG */				

				pFile->options |= SMB_NTCREATEANDX_DELETEONCLOSE;
            }
            else
            {
                pFile->options = pFile->options & (NQ_UINT32)~SMB_NTCREATEANDX_DELETEONCLOSE;
           	}
            pName->markedForDeletion = markedForDeletion;
        }

        TRCE();
        return 0;
    case SMB_SETPATH2_EASIZE:
    case SMB_SETPATH2_STANDARD:
        {
            CMCifsFileInformation2Standard* infoRequest;  /* casted request */

            infoRequest = (CMCifsFileInformation2Standard*)ctx->pData;

            if (   (cmGetSUint16(infoRequest->creationTime) != 0xFFFF && cmGetSUint16(infoRequest->creationDate) != 0xFFFF)
                && (cmGetSUint16(infoRequest->creationTime) != 0x0000 && cmGetSUint16(infoRequest->creationDate) != 0x0000)
               )
            {
                fileInfo.creationTime = cmCifsSmbTimeToTime(
                                            cmLtoh16(cmGetSUint16(infoRequest->creationTime)),
                                            cmLtoh16(cmGetSUint16(infoRequest->creationDate))
                                            );
            }
            if (   (cmGetSUint16(infoRequest->lastAccessTime) != 0xFFFF && cmGetSUint16(infoRequest->lastAccessDate) != 0xFFFF)
                && (cmGetSUint16(infoRequest->lastAccessTime) != 0x0000 && cmGetSUint16(infoRequest->lastAccessDate) != 0x0000)
               )
            {
                fileInfo.lastAccessTime = cmCifsSmbTimeToTime(
                                            cmLtoh16(cmGetSUint16(infoRequest->lastAccessTime)),
                                            cmLtoh16(cmGetSUint16(infoRequest->lastAccessDate))
                                            );
            }
            if (   (cmGetSUint16(infoRequest->lastWriteTime) != 0xFFFF && cmGetSUint16(infoRequest->lastWriteDate) != 0xFFFF)
                && (cmGetSUint16(infoRequest->lastWriteTime) != 0xFFFF && cmGetSUint16(infoRequest->lastWriteDate) != 0xFFFF)
               )
            {
                fileInfo.lastWriteTime = cmCifsSmbTimeToTime(
                                            cmLtoh16(cmGetSUint16(infoRequest->lastWriteTime)),
                                            cmLtoh16(cmGetSUint16(infoRequest->lastWriteDate))
                                            );
            }
            if (cmGetSUint32(infoRequest->dataSize) != 0)
            {
                fileInfo.sizeLow = cmLtoh32(cmGetSUint32(infoRequest->dataSize));
                fileInfo.sizeHigh = 0L;
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
				if (NULL != pUser && pFile == NULL)
				{
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_OPEN,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
					);
				}
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                if ((error = csTruncateFile(pFile, ctx->pFileName, fileInfo.sizeLow, fileInfo.sizeHigh)) != NQ_SUCCESS)
                {
                    TRCERR("Unable to truncate file");
                    TRCE();
                    return error;
                }
            }
            if (cmGetSUint32(infoRequest->allocationSize) != 0)
            {
                fileInfo.allocSizeLow = cmLtoh32(cmGetSUint32(infoRequest->allocationSize));
                fileInfo.allocSizeHigh = 0L;
            }

            if (cmGetSUint16(infoRequest->attributes) != 0)
            {
                fileInfo.attributes = csChangeFileAttributes(fileInfo.attributes, cmLtoh16(cmGetSUint16(infoRequest->attributes)));
            }
        }
        break;
    case SMB_PASSTHRU_FILE_BASICINFO:    
    case SMB_SETPATH2_NT_BASICINFO:
        {
            CMCifsFileInformation2NtBasic* infoRequest;  /* casted request */

            infoRequest = (CMCifsFileInformation2NtBasic*)ctx->pData;

            if (   (cmGetSUint32(infoRequest->creationTime.low) != 0xFFFFFFFF || cmGetSUint32(infoRequest->creationTime.high) != 0xFFFFFFFF)
                && (cmGetSUint32(infoRequest->creationTime.low) != 0x00000000 || cmGetSUint32(infoRequest->creationTime.high) != 0x00000000)
               )
            {
                fileInfo.creationTime = cmCifsUTCToTime(
                    cmLtoh32(cmGetSUint32(infoRequest->creationTime.low)),
                    cmLtoh32(cmGetSUint32(infoRequest->creationTime.high))
                    );
                if (pName)
                {
                    pName->time.creationTimeLow = cmLtoh32(cmGetSUint32(infoRequest->creationTime.low));
                    pName->time.creationTimeHigh = cmLtoh32(cmGetSUint32(infoRequest->creationTime.high));
                }
            }
            if (   (cmGetSUint32(infoRequest->lastAccessTime.low) != 0xFFFFFFFF || cmGetSUint32(infoRequest->lastAccessTime.high) != 0xFFFFFFFF)
                && (cmGetSUint32(infoRequest->lastAccessTime.low) != 0x00000000 || cmGetSUint32(infoRequest->lastAccessTime.high) != 0x00000000)
               )
            {
                fileInfo.lastAccessTime = cmCifsUTCToTime(
                    cmLtoh32(cmGetSUint32(infoRequest->lastAccessTime.low)),
                    cmLtoh32(cmGetSUint32(infoRequest->lastAccessTime.high))
                    );
                if (pName)
                {
                    pName->time.lastAccessTimeLow = cmLtoh32(cmGetSUint32(infoRequest->lastAccessTime.low));
                    pName->time.lastAccessTimeHigh = cmLtoh32(cmGetSUint32(infoRequest->lastAccessTime.high));
                }
            }
            if (   (cmGetSUint32(infoRequest->lastWriteTime.low) != 0xFFFFFFFF || cmGetSUint32(infoRequest->lastWriteTime.high) != 0xFFFFFFFF)
                && (cmGetSUint32(infoRequest->lastWriteTime.low) != 0x00000000 || cmGetSUint32(infoRequest->lastWriteTime.high) != 0x00000000)
               )
            {
                fileInfo.lastWriteTime = cmCifsUTCToTime(
                    cmLtoh32(cmGetSUint32(infoRequest->lastWriteTime.low)),
                    cmLtoh32(cmGetSUint32(infoRequest->lastWriteTime.high))
                    );
                if (pName)
                {
                    pName->time.lastWriteTimeLow = cmLtoh32(cmGetSUint32(infoRequest->lastWriteTime.low));
                    pName->time.lastWriteTimeHigh = cmLtoh32(cmGetSUint32(infoRequest->lastWriteTime.high));
                    pName->time.lastChangeTimeLow = pName->time.lastWriteTimeLow;
                    pName->time.lastChangeTimeHigh = pName->time.lastWriteTimeHigh;
                }
            }
            if (   (cmGetSUint32(infoRequest->lastChangeTime.low) != 0xFFFFFFFF || cmGetSUint32(infoRequest->lastChangeTime.high) != 0xFFFFFFFF)
                && (cmGetSUint32(infoRequest->lastChangeTime.low) != 0x00000000 || cmGetSUint32(infoRequest->lastChangeTime.high) != 0x00000000)
               )
            {
                fileInfo.lastChangeTime = cmCifsUTCToTime(
                    cmLtoh32(cmGetSUint32(infoRequest->lastChangeTime.low)),
                    cmLtoh32(cmGetSUint32(infoRequest->lastChangeTime.high))
                    );
                if (pName)
                {
                    pName->time.lastChangeTimeLow = cmLtoh32(cmGetSUint32(infoRequest->lastChangeTime.low));
                    pName->time.lastChangeTimeHigh = cmLtoh32(cmGetSUint32(infoRequest->lastChangeTime.high));
                }
            }
            if (cmGetSUint32(infoRequest->attributes) != 0)
            {
                fileInfo.attributes = csChangeFileAttributes(fileInfo.attributes, cmLtoh32(cmGetSUint32(infoRequest->attributes)));
            }
        }
        break;
    case SMB_PASSTHRU_FILE_ALLOCATIONINFO:
    case SMB_SETPATH2_NT_ALLOCATIONINFO:
        {
            CMCifsFileInformation2NtAllocation* infoRequest;  /* casted request */
            
            infoRequest = (CMCifsFileInformation2NtAllocation*)ctx->pData;
            
            fileInfo.allocSizeLow = cmLtoh32(cmGetSUint32(infoRequest->allocationSize.low));
            fileInfo.allocSizeHigh = cmLtoh32(cmGetSUint32(infoRequest->allocationSize.high));   
            if (fileInfo.allocSizeLow == 0 && fileInfo.allocSizeHigh == 0)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
				if (NULL != pUser && pFile == NULL)
				{
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_OPEN,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
					);
				}
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                if ((error = csTruncateFile(pFile, ctx->pFileName, fileInfo.allocSizeLow, fileInfo.allocSizeHigh)) != NQ_SUCCESS)
                {
                    TRCERR("Unable to truncate file");
                    TRCE();
                    return error;
                }
            }
            else 
            {
                NQ_TCHAR* pVolumeName = NULL;                     /* pointer to the volume name */
                SYVolumeInformation volumeInfo;                   /* volume info */ 
                static const NQ_TCHAR noName[] = {(NQ_TCHAR)0};   /* empty name for file */
                const CSShare *pShare = NULL;                     /* pointer to share */
                NQ_UINT64 lowTotalSpace, highTotalSpace, allocSize, freeUnits, unitSize;

                if ((pShare = csGetShareByUidTid(ctx->uid, ctx->tid)) == NULL || 
                     (pVolumeName = cmCifsNtohFilename(pShare->map, noName, FALSE)) == NULL)
                {
                    TRCERR("Illegal filename");
                    TRCE();
                    return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
                }

                /* query volume information */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
			if (NULL != pUser)
			{
				const NQ_TCHAR * tempName = eventInfo.fileName;

				eventInfo.fileName = pVolumeName;
				eventInfo.before = TRUE;
				udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_ATTRIBGET,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				eventInfo.before = FALSE;
				eventInfo.fileName = tempName;
			}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

                if (syGetVolumeInformation(pVolumeName, &volumeInfo))
                {
                    error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
					if (NULL != pUser)
					{
						const NQ_TCHAR * tempName = eventInfo.fileName;

						eventInfo.fileName = pVolumeName;
						udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_ATTRIBGET,
								pUser->name,
								pUser->ip,
								error,
								(const NQ_BYTE*)&eventInfo
								);
						eventInfo.fileName = tempName;
					}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                    TRCERR("Unable to read volume information");
                    TRCE();
                    return error;
                }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
				if (NULL != pUser)
				{
					const NQ_TCHAR * tempName = eventInfo.fileName;

					eventInfo.fileName = pVolumeName;
					udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_ATTRIBGET,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
					eventInfo.fileName = tempName;
				}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                /* verify there is enough disk space for required operation */
                /* free space = freeUnits * blockSize * blocksPerUnit */
                
                cmU64MultU32U32(&unitSize, volumeInfo.blockSize, volumeInfo.blocksPerUnit);
                freeUnits.low = volumeInfo.freeUnitsLow;
                freeUnits.high = volumeInfo.freeUnitsHigh;
                cmU128MultU64U64(&lowTotalSpace, &highTotalSpace, &freeUnits, &unitSize);
                allocSize.low = fileInfo.allocSizeLow;
                allocSize.high = fileInfo.allocSizeHigh;
                if (highTotalSpace.high == 0 && highTotalSpace.low == 0 && cmU64Cmp(&allocSize, &lowTotalSpace) == 1)
                {
#ifdef UD_NQ_INCLUDEEVENTLOG
					if (NULL != pUser)
					{
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_ATTRIBSET,
							pUser->name,
							pUser->ip,
							csErrorReturn(SMB_STATUS_DISK_FULL, HRD_ERRdiskfull),
							(const NQ_BYTE*)&eventInfo
						);
					}
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    TRCERR("Disk is full");
                    TRCE();
                    return csErrorReturn(SMB_STATUS_DISK_FULL, HRD_ERRdiskfull);
                }
            }               
        }
        break;
    case SMB_PASSTHRU_FILE_ENDOFFILEINFO:    
    case SMB_SETPATH2_NT_ENDOFFILEINFO:
        {
            CMCifsFileInformation2NtEndOfFile* infoRequest;  /* casted request */

            infoRequest = (CMCifsFileInformation2NtEndOfFile*)ctx->pData;
     
            fileInfo.sizeLow = cmLtoh32(cmGetSUint32(infoRequest->endOfFile.low));
            fileInfo.sizeHigh = cmLtoh32(cmGetSUint32(infoRequest->endOfFile.high));
#ifdef UD_NQ_INCLUDEEVENTLOG
			eventInfo.before = TRUE;
			if (NULL != pUser && pFile == NULL)
			{
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_OPEN,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
				);
			}
			eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
            if ((error = csTruncateFile(pFile, ctx->pFileName, fileInfo.sizeLow, fileInfo.sizeHigh)) != NQ_SUCCESS)
            {
                TRCERR("Unable to truncate file");
                TRCE();
                return error;
            } 
        }
        break;
    case SMB_PASSTHRU_FILE_RENAMEINFO:
        {
            CMCifsFileRenameInformation* infoRequest;       /* casted request SMB */
#ifdef UD_NQ_INCLUDESMB2
            CMSmb2FileRenameInformation* infoRequestSmb2;   /* casted request SMB2 */
            CSSession* pSession;                            /* pointer to session structure */
#endif /* UD_NQ_INCLUDESMB2 */
            const CSShare* pShare;                          /* pointer to share descriptor */ 
            CSUser* pUser;                                  /* pointer to user descriptor */
            NQ_TCHAR* pDestFileName;                        /* destination file name in host filesystem format */
            NQ_STATIC NQ_WCHAR destName[UD_FS_FILENAMELEN]; /* buffer for destination file name */
            NQ_UINT32 nameLength;                           /* new name length */ 
            const NQ_WCHAR* pNameW;                         /* offset to file name */
            NQ_BOOL replaceIfExists;                        /* replace flag */

            pShare = csGetShareByUidTid(ctx->uid, ctx->tid);
            pUser = csGetUserByUid(ctx->uid);

#ifdef UD_NQ_INCLUDESMB2
            pSession = csGetSessionById(pUser->session);
            if (pSession->smb2)
            {
                infoRequestSmb2 = (CMSmb2FileRenameInformation*)ctx->pData; 
                nameLength = cmLtoh32(cmGetSUint32(infoRequestSmb2->nameLength));
                pNameW = (const NQ_WCHAR *)(infoRequestSmb2 + 1);
                replaceIfExists = infoRequestSmb2->replaceIfExists;
            }
            else
#endif /* UD_NQ_INCLUDESMB2 */
            {
                infoRequest = (CMCifsFileRenameInformation*)ctx->pData; 
                nameLength = cmLtoh32(cmGetSUint32(infoRequest->nameLength));
                pNameW = (const NQ_WCHAR *)(infoRequest + 1);
                replaceIfExists = infoRequest->replaceIfExists;
            }

            if (nameLength > 0)
            {
                cmWStrncpy(destName, pNameW, (NQ_UINT)(nameLength / sizeof(NQ_WCHAR))); 
                destName[nameLength / sizeof(NQ_WCHAR)] = 0;
            }
            else
            {
                TRCERR("Empty filename");
                TRCE();
                return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
            }

            if ((pDestFileName = cmCifsNtohFilename(pShare->map, (NQ_TCHAR*)destName, TRUE)) == NULL)
            {                
                TRCERR("Illegal filename");
                TRCE();
                return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
            }
            
            /* treat 'replace if exists' flag */
            if (replaceIfExists && 
                NQ_SUCCESS == csGetFileInformationByName(pShare, pDestFileName, &fileInfo
#ifdef UD_NQ_INCLUDEEVENTLOG
					,pUser
#endif /* UD_NQ_INCLUDEEVENTLOG */
                	)
               )
            {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
			if (NULL != pUser)
			{
				eventInfo.before = TRUE;
				udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_DELETE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				eventInfo.before = FALSE;
			}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                if (NQ_SUCCESS != syDeleteFile(pDestFileName))
                {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
					if (NULL != pUser)
					{
						udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_DELETE,
								pUser->name,
								pUser->ip,
								csErrorGetLast(),
								(const NQ_BYTE*)&eventInfo
								);
					}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                    TRCERR("Destination exists and replace required, but NQ failed to delete it");
                    TRCE();
                    return csErrorGetLast();
                }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
			if (NULL != pUser)
			{
				udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_DELETE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
			}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
            }
            if ((error = csRenameFile(pUser, pShare, TRUE, (NQ_UINT16)fileInfo.attributes, (NQ_TCHAR*)ctx->pFileName, pDestFileName)) != NQ_SUCCESS)    
            {
                TRCERR("Unable to rename file");
                TRCE();
                return error;
            }

            /* modify file name in the CSName structure */
            if (NULL == pName)
            {
                TRCERR("Illegal NID - internal error");
                TRCE();
                return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRinvalidname);
            }
            cmTStrncpy(pName->name, pDestFileName, sizeof(pName->name)/sizeof(NQ_TCHAR));
        }
        break;
    default:
        TRCERR("Illegal information level: %d", ctx->level);
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    /* if something was changed - write information to the file */

    if (syMemcmp(&oldFileInfo, &fileInfo, sizeof(fileInfo)) != 0)
    {
        SYFile nullHandle;  /* invalid handle to the file */

        syInvalidateFile(&nullHandle);
#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.before = TRUE;
        if (NULL != pUser)
        {
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_ATTRIBSET,
                pUser->name,
                pUser->ip,
                0,
                (const NQ_BYTE*)&eventInfo
            );
        }
        eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        if (sySetFileInformation(ctx->pFileName, nullHandle, &fileInfo))
        {
            error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
			if (NULL != pUser)
			{
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBSET,
					pUser->name,
					pUser->ip,
					error,
					(const NQ_BYTE*)&eventInfo
				);
			}
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Unable to change file information");
            TRCE();
            return error;
        }
#ifdef UD_NQ_INCLUDEEVENTLOG
        if (NULL != pUser)
        {
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_ATTRIBSET,
                pUser->name,
                pUser->ip,
                0,
                (const NQ_BYTE*)&eventInfo
            );
        }
#endif /* UD_NQ_INCLUDEEVENTLOG */


        csNotifyImmediatelly(ctx->pFileName, SMB_NOTIFYCHANGE_MODIFIED, COMPLETION_FILTER);
    }

    TRCE();
    return 0;
}

static NQ_UINT32
convertNqAccessToNtAccess(
    NQ_UINT16 nqAccess
    )
{
	NQ_UINT32 ntAccess = 0;

	switch (nqAccess & (
						SMB_ACCESS_A_READ |
						SMB_ACCESS_A_WRITE |
						SMB_ACCESS_A_READWRITE |
						SMB_ACCESS_A_NONE
						))
	{
		case SMB_ACCESS_A_READ:
			ntAccess = SMB_DESIREDACCESS_READDATA | SMB_DESIREDACCESS_GENREAD;
			break;
		case SMB_ACCESS_A_WRITE:
		    ntAccess = SMB_DESIREDACCESS_WRITEDATA | SMB_DESIREDACCESS_GENWRITE;
		    break;
		case SMB_ACCESS_A_READWRITE:
			ntAccess =  SMB_DESIREDACCESS_READDATA | SMB_DESIREDACCESS_GENREAD | SMB_DESIREDACCESS_WRITEDATA | SMB_DESIREDACCESS_GENWRITE;
		    break;
		case SMB_ACCESS_A_NONE:
			ntAccess = SMB_DESIREDACCESS_SYNCHRONISE | SMB_DESIREDACCESS_READATTRIBUTES | SMB_DESIREDACCESS_WRITEATTRIBUTES;
			break;
		default:
			ntAccess = 0;
			break;
	}
	return ntAccess;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

