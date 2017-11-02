/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of directory control commands
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
#include "csnotify.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements special directory commands */

/*====================================================================
 * PURPOSE: Perform CHECK DIRECTORY command
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
csComCheckDirectory(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsCheckDirectoryRequest* checkRequest;  /* casted request */
    CMCifsCheckDirectoryResponse* checkResponse;/* casted response */
    NQ_BOOL unicodeRequired;                    /* whether client requires UNICODE */
    NQ_UINT32 returnValue;                      /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    const CSShare* pShare;                  /* pointer to the share */
    NQ_TCHAR* pFileName;                    /* filename to open */
    SYFileInformation fileInfo;             /* buffer for file information */
    CSTid tid;                              /* required tree ID */
    CSUid uid;                              /* required user ID */
    const CSUser* pUser;                    /* user structure pointer */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;            /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */


    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*checkResponse))
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

    /* cast pointers */

    checkRequest = (CMCifsCheckDirectoryRequest*) pRequest;
    checkResponse = (CMCifsCheckDirectoryResponse*) *pResponse;

    /* check format */

    if (   checkRequest->wordCount != 0
        || cmGetSUint16(checkRequest->byteCount) < SMB_CHECKDIRECTORY_REQUEST_MINBYTES
        || checkRequest->bufferFormat < SMB_FIELD_ASCII
       )
    {
        TRCERR("Illegal WordCount, ByteCount or BufferFormat");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* convert filename to host filename */

    if ((pFileName = cmCifsNtohFilename(
                        pShare->map,
                        (NQ_TCHAR*)(checkRequest + 1),
                        unicodeRequired
                        )
        ) == NULL
       )
    {
        TRCERR("Illegal filename");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath);
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = pFileName;
    eventInfo.access = 0;
    eventInfo.rid = csGetUserRid((CSUser *)pUser);
    eventInfo.tid = tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* check name */
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
    if (!csCheckPath(pShare, pFileName, (NQ_UINT)cmTStrlen(pShare->map), pUser->preservesCase))
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
        TRCERR("No such path");
        TRCE();
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
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		(pUser->preservesCase || (pShare != NULL && cmTStrcmp( pShare->map , pFileName) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
        );
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    if (!csCheckFile(pShare, pFileName, pUser->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			(pUser->preservesCase || (pShare != NULL && cmTStrcmp( pShare->map , pFileName) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile),
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
        TRCERR("No such file");
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		(pUser->preservesCase || (pShare != NULL && cmTStrcmp( pShare->map , pFileName) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

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
    if (!(fileInfo.attributes & SMB_ATTR_DIRECTORY))  /* not a directory */
    {
        TRCERR("Not a directory");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_NAME_INVALID, DOS_ERRbadpath);  
    }

    /* compose the response */

    checkResponse->wordCount = 0;
    cmPutSUint16(checkResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*checkResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform DELETE DIRECTORY command
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
csComDeleteDirectory(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsDeleteDirectoryRequest* deleteRequest;   /* casted request */
    CMCifsDeleteDirectoryResponse* deleteResponse; /* casted response */
    NQ_BOOL unicodeRequired;                /* whether client requires UNICODE */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    const CSShare* pShare;                  /* pointer to the share */
    NQ_TCHAR* pFileName;                    /* filename to open */
    SYFileInformation fileInfo;             /* buffer for file information */
    CSTid tid;                              /* required tree ID */
    CSUid uid;                              /* required user ID */
    const CSUser* pUser;                    /* user structure pointer */
    CSName * pName;                         /* check if this file is open */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;            /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* delete space in output buffer and setup response flags */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*deleteResponse))
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


    if ((pUser= csGetUserByUid(uid)) == NULL)
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

    deleteRequest = (CMCifsDeleteDirectoryRequest*) pRequest;
    deleteResponse = (CMCifsDeleteDirectoryResponse*) *pResponse;

    /* delete format */

    if (   deleteRequest->wordCount != 0
        || cmGetSUint16(deleteRequest->byteCount) < SMB_CHECKDIRECTORY_REQUEST_MINBYTES
        || deleteRequest->bufferFormat < SMB_FIELD_ASCII
       )
    {
        TRCERR("Illegal WordCount, ByteCount or BufferFormat");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* convert filename to host filename */

    if ((pFileName = cmCifsNtohFilename(
                        pShare->map,
                        (NQ_TCHAR*)(deleteRequest + 1),
                        unicodeRequired
                        )
        ) == NULL
       )
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	eventInfo.before = FALSE;
        eventInfo.fileName = NULL;
        eventInfo.access = 0;
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
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
    eventInfo.access = 0;
    eventInfo.rid = csGetUserRid((CSUser *)pUser);
    eventInfo.tid = tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */


    /* check if the attempt is to delete the share */

    if (cmTStrlen(pShare->map) == cmTStrlen(pFileName))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	eventInfo.before = FALSE;
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_DIRECTORY_NOT_EMPTY, DOS_ERRremcd),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("An attempt to delete the share");
        TRCE();
        return csErrorReturn(SMB_STATUS_DIRECTORY_NOT_EMPTY, DOS_ERRremcd);
    }

    /* check access to share */

    if ((error = csCanWriteShare(tid)) != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	eventInfo.before = FALSE;
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
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

    /* check name */
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
    if (!csCheckPath(pShare, pFileName, (NQ_UINT)cmTStrlen(pShare->map), pUser->preservesCase))
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
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("No such path");
        TRCE();
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
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		(pUser->preservesCase || (pShare != NULL && cmTStrcmp( pShare->map , pFileName) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
        );
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    if (!csCheckFile(pShare, pFileName, pUser->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			(pUser->preservesCase || (pShare != NULL && cmTStrcmp( pShare->map , pFileName) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile),
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("No such file");
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		(pUser->preservesCase || (pShare != NULL && cmTStrcmp( pShare->map , pFileName) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
	/* get information */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
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
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			error,
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
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
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    if (!(fileInfo.attributes & SMB_ATTR_DIRECTORY))  /* not a directory */
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRnoaccess),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Not a directory");
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRnoaccess);
    }

    pName = csGetNameByName(pFileName);
    if (pName != NULL)
    {
        pName->markedForDeletion = TRUE;
#ifdef UD_NQ_INCLUDEEVENTLOG
		if (pName->markedForDeletion && pName->deletingUserRid == CS_ILLEGALID)
		{				
			pName->deletingUserRid = csGetUserRid(pUser);
			pName->deletingTid = tid;
			cmIpToAscii(pName->deletingIP, pUser->ip);
		}		
#endif /* UD_NQ_INCLUDEEVENTLOG */			
    }
    else
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
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
#endif /* UD_NQ_INCLUDEEVENTLOG */
        if (syDeleteDirectory(pFileName) == NQ_FAIL)
        {
            error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_DELETE,
                pUser->name,
                pUser->ip,
                error,
                (const NQ_BYTE*)&eventInfo
            );
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Unable to delete directory");
            TRCE();
            return csErrorReturn(error ==  SMB_STATUS_DIRECTORY_NOT_EMPTY? error: SMB_STATUS_CANNOT_DELETE, error);
        }

#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
            pUser->name,
            pUser->ip,
            0,
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
    }
    /* compose the response */

    csNotifyImmediatelly(pFileName, SMB_NOTIFYCHANGE_REMOVED | SMB_NOTIFYCHANGE_ISDIRECTORY, SMB_NOTIFYCHANGE_NAME);
    deleteResponse->wordCount = 0;
    cmPutSUint16(deleteResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*deleteResponse);

    TRCE();
    return 0;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

