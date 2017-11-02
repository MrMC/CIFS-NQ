/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of CLOSE, RENAME, DELETE commands
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
#include "csfnames.h"
#include "csnotify.h"
#include "csdelete.h"
#include "csbreak.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements file close, delete and rename commands
*/

/*====================================================================
 * PURPOSE: Perform CLOSE command
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
csComClose(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsCloseFileRequest* closeRequest;   /* casted request */
    CMCifsCloseFileResponse* closeResponse; /* casted response */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    CSFile* pFile;                          /* pointer to file descriptor */
    SYFileInformation fileInfo;             /* for changing file information */
    const NQ_TCHAR *pFileName;              /* file name pointer */
#ifdef UD_NQ_INCLUDEEVENTLOG
    const CSUser* pUser;                    /* user structure pointer */
    UDFileAccessEvent eventInfo;            /* share event information */
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

    closeRequest = (CMCifsCloseFileRequest*) pRequest;
    closeResponse = (CMCifsCloseFileResponse*) *pResponse;

    /* check format */

    if (   closeRequest->wordCount != SMB_CLOSEFILE_REQUEST_WORDCOUNT
        || cmGetSUint16(closeRequest->byteCount) != 0
       )
    {
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file descriptor */

    pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(closeRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    if (pFile == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    pFileName = csGetFileName(pFile->fid);
    if (pFileName == NULL)
    {
        TRCERR("File name corrupted");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = pFileName;
    eventInfo.access = 0;
    pUser = csGetUserByUid(pFile->uid);
#endif /* UD_NQ_INCLUDEEVENTLOG */

#ifdef UD_CS_INCLUDERPC_SPOOLSS
    if (pFile->isPrint)
    {
        if (syEndPrintJob(pFile->printerHandle, (NQ_UINT32)pFile->file) != NQ_SUCCESS)
        {
            csReleaseFile(pFile->fid);
            TRCERR("Failed to end print job");
            TRCE();
            return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
        }
    }
    else
#endif      
    {
        /* we may be required to change file last write time */

        {
            NQ_UINT32 writeTime;        /* required last write time */

            writeTime = cmLtoh32(cmGetSUint32(closeRequest->lastWriteTime));

            if (!pFile->isDirectory && writeTime != 0xFFFFFFFF && writeTime != 0)
            {
                if (csGetFileInformation(pFile, pFileName, &fileInfo) != NQ_SUCCESS)
                {
                    error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
                    if (NULL != pUser)
                    {
                      udEventLog(
                          UD_LOG_MODULE_CS,
                          UD_LOG_CLASS_FILE,
                          UD_LOG_FILE_CLOSE,
                          pUser->name,
                          pUser->ip,
                          error,
                          (const NQ_BYTE*)&eventInfo
                      );
                    }
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    csReleaseFile(pFile->fid);      /* also closes the file */
                    TRCERR("Unable to read file information");
                    TRCE();
                    return error;
                }

                fileInfo.lastAccessTime = writeTime;
                csSetFileInformation(pFile, pFileName, &fileInfo);

                /* errors are ignored as required by CIFS */
            }
        }

        /* if delete on close was requested - mark this file for deletion */

        if (pFile->options & SMB_NTCREATEANDX_DELETEONCLOSE)
        {
            CSName* pName;          /* pointer to the file name descriptor */

            pName = csGetNameByNid(pFile->nid);
            if (pName == NULL)
            {
                TRCERR("Internal error: file name descriptor not found");
                csReleaseFile(pFile->fid);      /* also closes the file */
                TRCE();
                return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
            }
            pName->markedForDeletion = TRUE;
#ifdef UD_NQ_INCLUDEEVENTLOG
			if (pName->markedForDeletion && pName->deletingUserRid == CS_ILLEGALID)
			{				
				NQ_IPADDRESS zeroIP = CM_IPADDR_ZERO;
				
				pName->deletingUserRid = pUser ? csGetUserRid(pUser) : CS_ILLEGALID;
				pName->deletingTid = pFile->tid;
				cmIpToAscii(pName->deletingIP, pUser ? pUser->ip : &zeroIP);
			}
#endif /* UD_NQ_INCLUDEEVENTLOG */				
        }
    } 

    /* compose the response */

    closeResponse->wordCount = 0;
    cmPutSUint16(closeResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*closeResponse);

    /* complete oplock break operation (send late response) if required */

    if (pFile->oplockGranted && pFile->pFileOplockBreaker)
    {
        csBreakComplete(&pFile->pFileOplockBreaker->breakContext, pHeaderOut);
        csReleaseFile(pFile->fid);
        TRC("Oplock break completed");
        TRCE();
        return SMB_STATUS_NORESPONSE;
    }

    /* release the descriptor and close the file */

    csReleaseFile(pFile->fid);      /* also closes the file */

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform PROCESS_EXIT command
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
csComProcessExit(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    CSFile* pFile;                          /* pointer to file descriptor */
    CSPid pid;                              /* requested process ID */
    CSUid uid;                              /* requested user ID */
    CSFid fid;                              /* next file ID */
    CMCifsCloseFileResponse* closeResponse; /* casted response */

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

    closeResponse = (CMCifsCloseFileResponse*) *pResponse;

    /* withdraw PID and UID */

    pid = csGetPidFromHeader(pHeaderOut);
    uid = cmLtoh16(cmGetSUint16(pHeaderOut->uid));

    if (csGetUserByUid(uid) == NULL)
    {
        TRCERR("Illegal UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

    fid = CS_ILLEGALID;

    /* cycle by all files of the same PID and close them */

    while ((pFile = csGetNextFileByPid(pid, fid)) != NULL)
    {
        fid = pFile->fid;
        csReleaseFile(pFile->fid);      /* also closes the file */
        /* even on error continue closing */
    }

    /* compose the response */

    closeResponse->wordCount = 0;
    cmPutSUint16(closeResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*closeResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform DELETE command
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
 *          This function works for both CREATE and CREATE_NEW commands
 *====================================================================
 */

NQ_UINT32
csComDelete(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsDeleteFileRequest* deleteRequest;     /* casted request */
    CMCifsDeleteFileResponse* deleteResponse;   /* casted response */
    NQ_UINT32 returnValue;                      /* error code in NT format or 0 for no error */
    NQ_BOOL unicodeRequired;                    /* whether client requires UNICODE */
    CMCifsStatus error;                         /* for composing DOS-style error */
    const CSShare* pShare;                      /* pointer to the share */
    NQ_TCHAR* pFileName;                        /* filename to delete */
    CSTid tid;                                  /* tree ID for access check */
    CSUid uid;                                  /* user ID for access check */
    NQ_UINT16 searchAttributes;                 /* allowed attributes of the file */
    SYFileInformation fileInfo;                 /* for querying file information */
    CSFileEnumeration fileEnumeration;          /* for enumerating wild card filenames */
    NQ_COUNT delCount;                          /* number of deleted files */
    CSUser* pUser;                              /* pointer to the user descriptor */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;                /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*deleteResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */

    deleteRequest = (CMCifsDeleteFileRequest*) pRequest;
    deleteResponse = (CMCifsDeleteFileResponse*) *pResponse;

    /* check counts */

    if (   deleteRequest->wordCount != SMB_DELETEFILE_REQUEST_WORDCOUNT
        || cmLtoh16(cmGetSUint16(deleteRequest->byteCount)) < SMB_DELETEFILE_REQUEST_MINBYTES
        || deleteRequest->bufferFormat != SMB_FIELD_ASCII
       )
    {
        TRCERR("Illegal WordCount or ByteCount ");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* withdraw TID */

    tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    uid = cmLtoh16(cmGetSUint16(pHeaderOut->uid));

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
    	eventInfo.before = TRUE;
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
	eventInfo.rid = csGetUserRid(pUser);
	eventInfo.tid = tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* check access to share */

    if ((returnValue = csCanWriteShare(tid)) != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_DELETE,
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
        TRCERR("Path does not exists");
        TRC1P(" path: %s", cmTDump(pFileName));
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
    /* enumerate and delete file(s) */

    delCount = 0;

    TRC1P("Required to delete: %s", cmTDump(pFileName));

    searchAttributes = cmLtoh16(cmGetSUint16(deleteRequest->searchAttributes));

    {
        const NQ_TCHAR* nextFile;   /* next file name to delete */

        csEnumerateSourceName(&fileEnumeration, pFileName, pUser->preservesCase);
        fileEnumeration.bringLinks = FALSE;
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
        while ((nextFile = csNextSourceName(&fileEnumeration)) != NULL)
        {
            TRC1P("next file to delete: %s", cmTDump(nextFile));
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
#ifdef UD_NQ_INCLUDEEVENTLOG
            eventInfo.fileName = nextFile;
#endif /* UD_NQ_INCLUDEEVENTLOG */

            /* check whether we may delete this file */

            if (csGetNameByName(nextFile) != NULL)    /* file opened */
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_DELETE,
                    pUser->name,
                    pUser->ip,
                    csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess),
                    (const NQ_BYTE*)&eventInfo
                );
#endif /* UD_NQ_INCLUDEEVENTLOG */
                csCancelEnumeration(&fileEnumeration);
                TRCERR("File is opened and cannot be deleted");
                return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
            }

            /* file candidate found - compare attributes */
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
            if (syGetFileInformationByName(nextFile, &fileInfo) != NQ_SUCCESS)
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
                    UD_LOG_FILE_DELETE,
                    pUser->name,
                    pUser->ip,
                    error,
                    (const NQ_BYTE*)&eventInfo
                );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
                eventInfo.before = TRUE;
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                csCancelEnumeration(&fileEnumeration);
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
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
            if (fileInfo.attributes & (SMB_ATTR_DIRECTORY | SMB_ATTR_READONLY))
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_DELETE,
                    pUser->name,
                    pUser->ip,
                    csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess),
                    (const NQ_BYTE*)&eventInfo
                );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
                eventInfo.before = TRUE;
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                csCancelEnumeration(&fileEnumeration);
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                TRCERR("Unable to delete a directory or readonly file");
                TRC1P(" file name: %s", cmTDump(nextFile));
                TRCE();
                return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
            }

            TRC2P("match attributes: %0x with file's: %0lx", searchAttributes, fileInfo.attributes);

            if (csMatchFileAttributes(searchAttributes, (NQ_UINT16)fileInfo.attributes))
            {
                TRC1P("deleting file: %s", cmTDump(nextFile));

                /* check whether this file is opened by this or another client and is marked for
                   deletion. If so, do nothing, else - delete it now */

                if (!csFileMarkedForDeletion(nextFile))
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
                    if (syDeleteFile(nextFile) == NQ_FAIL)
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
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
                eventInfo.before = TRUE;
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                csCancelEnumeration(&fileEnumeration);
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                        TRCERR("Unable to delete file");
                        TRC1P(" file name: %s", cmTDump(nextFile));
                        TRCE();
                        return error;
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
                    csNotifyImmediatelly(nextFile, SMB_NOTIFYCHANGE_REMOVED, SMB_NOTIFYCHANGE_NAME);
                }

                delCount++;
            }
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
        }
    }

    if (delCount == 0)
    {
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
        TRCERR("No files deleted");
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);

    }

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*deleteResponse);

    /* compose the response */

    deleteResponse->wordCount = 0;
    cmPutSUint16(deleteResponse->byteCount, 0);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform RENAME command
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
 *          This function works for both CREATE and CREATE_NEW commands
 *====================================================================
 */

NQ_UINT32
csComRename(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsRenameFileRequest* renameRequest;     /* casted request */
    CMCifsRenameFileResponse* renameResponse;   /* casted response */
    NQ_UINT32 returnValue;                      /* error code in NT format or 0 for no error */
    NQ_BOOL unicodeRequired;                    /* whether client requires UNICODE */
    const CSShare* pShare;                      /* pointer to the share */
    NQ_TCHAR* pFileName;                        /* filename pointer */
    CSTid tid;                                  /* tree ID for access check */
    CSUid uid;                                  /* user ID for access check */
    CSUser* pUser;                              /* pointer to the user descriptor */
    NQ_STATIC NQ_TCHAR srcName[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_FILENAMELEN + 1)];
                                                /* source file name */
    NQ_STATIC NQ_TCHAR dstName[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_FILENAMELEN + 1)];
                                                /* destination file name */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;                /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*renameResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */

    renameRequest = (CMCifsRenameFileRequest*) pRequest;
    renameResponse = (CMCifsRenameFileResponse*) *pResponse;

    /* check counts */

    if (   renameRequest->wordCount != SMB_RENAMEFILE_REQUEST_WORDCOUNT
        || cmLtoh16(cmGetSUint16(renameRequest->byteCount)) < SMB_RENAMEFILE_REQUEST_MINBYTES
        || renameRequest->bufferFormat != SMB_FIELD_ASCII
       )
    {
        TRCERR("Illegal WordCount or ByteCount ");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* withdraw TID */

    tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    uid = cmLtoh16(cmGetSUint16(pHeaderOut->uid));

    pUser = csGetUserByUid(uid);
    if (pUser == NULL)
    {
        TRCERR("Illegal UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before = TRUE;
    eventInfo.rid = csGetUserRid(pUser);
    eventInfo.tid = tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    pShare = csGetShareByUidTid(uid, tid);
    if (pShare == NULL)
    {
        TRCERR("Illegal TID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvtid);
    }

    /* check access to share */

    if ((returnValue = csCanWriteShare(tid)) != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(
            UD_LOG_MODULE_CS,
            UD_LOG_CLASS_FILE,
            UD_LOG_FILE_RENAME,
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

    /* convert filenames to host filename format */

    {
        NQ_BYTE* msgPtr;   /* pointer to names in the message */

        msgPtr = (NQ_BYTE*)(renameRequest + 1);
        pFileName = cmCifsNtohFilename(
                            pShare->map,
                            (NQ_TCHAR*)msgPtr,
                            unicodeRequired
                            );
        if (pFileName == NULL)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
            eventInfo.fileName = NULL;
            eventInfo.newName = NULL;
            eventInfo.access = 0;
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_RENAME,
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
        cmTStrcpy(srcName, pFileName);
#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.fileName = srcName;
        eventInfo.access = 0;
#endif /* UD_NQ_INCLUDEEVENTLOG */

        if (unicodeRequired)
        {
            msgPtr = cmAllignTwo(msgPtr);
            msgPtr += (cmWStrlen((NQ_WCHAR*)msgPtr) + 1) * sizeof(NQ_WCHAR);
        }
        else
        {
            msgPtr += syStrlen((NQ_CHAR*)msgPtr) + 1;
        }
        if (*msgPtr++ != SMB_FIELD_ASCII)
        {
            TRCERR("Illegal BufferFormat ");
            TRCE();
            return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
        }
        pFileName = cmCifsNtohFilename(
                            pShare->map,
                            (NQ_TCHAR*)msgPtr,
                            unicodeRequired
                            );
        if (pFileName == NULL)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog(
                UD_LOG_MODULE_CS,
                UD_LOG_CLASS_FILE,
                UD_LOG_FILE_RENAME,
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
        cmTStrcpy(dstName, pFileName);
#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.newName = dstName;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    }
    
    /* rename file */
    
    returnValue = csRenameFile(pUser, pShare, unicodeRequired, cmLtoh16(cmGetSUint16(renameRequest->searchAttributes)), srcName, dstName);
    if (returnValue != NQ_SUCCESS)
    {
        TRCERR("Failed to rename");
        TRCE();
        return returnValue;     
    }

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*renameResponse);

    /* compose the response */

    renameResponse->wordCount = 0;
    cmPutSUint16(renameResponse->byteCount, 0);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform rename
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the user descriptor
 *          IN pointer to the share
 *          IN whether client requires UNICODE
 *          IN allowed attributes of the file
 *          IN source file name in host filename format
 *          IN destination file name in host filename format
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   
 *====================================================================
 */
NQ_UINT32
csRenameFile( 
    CSUser* pUser,                              
    const CSShare* pShare,                      
    NQ_BOOL unicodeRequired,                    
    NQ_UINT16 searchAttributes,                 
    NQ_TCHAR* srcName,                        
    NQ_TCHAR* dstName                         
    )
{
    SYFileInformation fileInfo;                 /* for querying file information */
    NQ_COUNT renameCount;                       /* number of renamed files */
    CMCifsStatus error;                         /* for composing DOS-style error */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;                /* share event information */
    CSTree	*		  pTree;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();
    
    /* check situation where source and destination are identical */
    
    if (0 == cmTStrcmp(srcName, dstName))
    {
        TRCE();
        return NQ_SUCCESS;
    }
    
#ifdef UD_NQ_INCLUDEEVENTLOG
    pTree = csGetNextTreeByShare(pShare , CS_ILLEGALID);
    while (pTree->uid != pUser->uid)
	{
		pTree = csGetNextTreeByShare(pShare, pTree->tid);
	}
    eventInfo.tid = (pTree != NULL) ? pTree->tid : CS_ILLEGALID;
	eventInfo.rid = csGetUserRid(pUser);
    eventInfo.fileName = srcName;
    eventInfo.newName = dstName;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* check source path */
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
    if (!csCheckPath(pShare, srcName, (NQ_UINT)cmTStrlen(pShare->map), pUser->preservesCase))
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
            UD_LOG_FILE_RENAME,
            pUser->name,
            pUser->ip,
            csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
            (const NQ_BYTE*)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Source path does not exist: %s", cmTDump(srcName));
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

    /* check destination path */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	{
		NQ_TCHAR * tempName;

		tempName = (NQ_TCHAR *)eventInfo.fileName;
		eventInfo.fileName = eventInfo.newName;
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
		eventInfo.fileName = tempName;
	}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    if (!csCheckPath(pShare, dstName, (NQ_UINT)cmTStrlen(pShare->map), pUser->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    	{
			NQ_TCHAR * tempName;

			tempName = (NQ_TCHAR *)eventInfo.fileName;
			eventInfo.fileName = eventInfo.newName;
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_QUERYDIRECTORY,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
				(const NQ_BYTE*)&eventInfo
				);
			eventInfo.fileName = tempName;
    	}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
		{
			eventInfo.fileName = eventInfo.newName;
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_RENAME,
				pUser->name,
				pUser->ip,
				csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
				(const NQ_BYTE*)&eventInfo
			);
		}
#endif /* UD_NQ_INCLUDEEVENTLOG */
        TRCERR("Destination path does not exist: %s", cmTDump(dstName));
        TRCE();
        return csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    {
		NQ_TCHAR * tempName;

		tempName = (NQ_TCHAR *)eventInfo.fileName;
		eventInfo.fileName = eventInfo.newName;
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE*)&eventInfo
			);
		eventInfo.fileName = tempName;
    }
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
    /* enumerate and rename file(s) */

    TRC1P("Start enumerating rename op from %s, to %s", cmTDump(srcName), cmTDump(dstName));

    {
        NQ_TCHAR* nextSrcFile;  /* next file name to rename */
        NQ_TCHAR* nextDstFile;  /* new file name */

        renameCount = 0;

        csEnumerateSourceAndDestinationName(srcName, dstName, pUser->preservesCase);
#ifdef UD_NQ_INCLUDEEVENTLOG
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
#endif /* UD_NQ_INCLUDEEVENTLOG */
        while (csNextSourceAndDestinationName(&nextSrcFile, &nextDstFile))
        {

            CSName* pName;  /* pointer to file name descriptor */
#ifdef UD_NQ_INCLUDESMB2
            CSSession* pSession; /* pointer to the session structure */
#endif /* UD_NQ_INCLUDESMB2 */
#ifdef UD_NQ_INCLUDEEVENTLOG
            eventInfo.fileName = nextSrcFile;
            eventInfo.newName = nextDstFile;
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_QUERYDIRECTORY,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
            /* check whether we may rename the file 
             * this check is done for SMB(1) only since for SMB2 this is done 
             * for an open file
             * */
            
#ifdef UD_NQ_INCLUDESMB2
            pSession = csGetSessionById(pUser->session);
            if (NULL == pSession)
            {
                TRCERR("Unknown session");
                TRCE();
                return csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath);
            }
#endif /* UD_NQ_INCLUDESMB2 */
            if (
#ifdef UD_NQ_INCLUDESMB2
                !pSession->smb2 &&
#endif /* UD_NQ_INCLUDESMB2 */
                (pName = csGetNameByName(nextSrcFile)) != NULL
               ) /* SMB(1) file opened */
            {
                /* may be opened but shared for delete */

                if (!(pName->first->access & SMB_ACCESS_S_DELETE))
                {
#ifdef UD_NQ_INCLUDEEVENTLOG
                    udEventLog(
                        UD_LOG_MODULE_CS,
                        UD_LOG_CLASS_FILE,
                        UD_LOG_FILE_RENAME,
                        pUser->name,
                        pUser->ip,
                        csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess),
                        (const NQ_BYTE*)&eventInfo
                    );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
					eventInfo.before = TRUE;
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
					eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    csCancelDefaultEnumeration();
#ifdef UD_NQ_INCLUDEEVENTLOG
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_CLOSE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    TRCE();
                    return csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
                }
            }

            /* file candidate found - compare attributes */
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
#endif /* UD_NQ_INCLUDEEVENTLOG */
            if (syGetFileInformationByName(nextSrcFile, &fileInfo) != NQ_SUCCESS)
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
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
                udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_RENAME,
                    pUser->name,
                    pUser->ip,
                    error,
                    (const NQ_BYTE*)&eventInfo
                );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_CLOSE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
				csCancelDefaultEnumeration();
#ifdef UD_NQ_INCLUDEEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                TRCERR("Old file does not exist");
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
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRC1P("About to rename file: %s to %s", cmTDump(nextSrcFile), cmTDump(nextDstFile));

            if (csMatchFileAttributes(searchAttributes, (NQ_UINT16)fileInfo.attributes))
            {
                /* the destination file name may be in different case letters */
                if (cmTStricmp(nextSrcFile, nextDstFile) == 0)
                {
                    /* renaming file to the same name with difference in case */
                    if (!(UD_FS_FILESYSTEMATTRIBUTES & CM_FS_CASESENSITIVESEARCH))
                    {
                        renameCount++;
                        continue; 
                    }
                }
                else
                {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
                	{
                		NQ_TCHAR * tempName;

                		tempName = (NQ_TCHAR *)eventInfo.fileName;
                		eventInfo.fileName = eventInfo.newName;
						eventInfo.before = TRUE;
						udEventLog(
									UD_LOG_MODULE_CS,
									UD_LOG_CLASS_FILE,
									(pUser->preservesCase || (pShare != NULL && cmTStrcmp(pShare->map , nextDstFile) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
									pUser->name,
									pUser->ip,
									0,
									(const NQ_BYTE*)&eventInfo
								);
						eventInfo.before = FALSE;
						eventInfo.fileName = tempName;
                	}
#endif
                    /* destination file should not exist */
                    if (csCheckFile(pShare, nextDstFile, pUser->preservesCase))
                    {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
                    	{
                    		NQ_TCHAR * tempName;

							tempName = (NQ_TCHAR *)eventInfo.fileName;
							eventInfo.fileName = eventInfo.newName;
							udEventLog(
										UD_LOG_MODULE_CS,
										UD_LOG_CLASS_FILE,
										(pUser->preservesCase || (pShare != NULL && cmTStrcmp( pShare->map , nextDstFile) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
										pUser->name,
										pUser->ip,
										csErrorReturn(SMB_STATUS_OBJECT_NAME_COLLISION, DOS_ERRalreadyexists),
										(const NQ_BYTE*)&eventInfo
									);
							eventInfo.fileName = tempName;
                    	}
#endif
#ifdef UD_NQ_INCLUDEEVENTLOG
                        udEventLog(
                            UD_LOG_MODULE_CS,
                            UD_LOG_CLASS_FILE,
                            UD_LOG_FILE_RENAME,
                            pUser->name,
                            pUser->ip,
                            csErrorReturn(SMB_STATUS_OBJECT_NAME_COLLISION, DOS_ERRalreadyexists),
                            (const NQ_BYTE*)&eventInfo
                        );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
						eventInfo.before = TRUE;
							udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_CLOSE,
								pUser->name,
								pUser->ip,
								0,
								(const NQ_BYTE*)&eventInfo
								);
						eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    	csCancelDefaultEnumeration();
#ifdef UD_NQ_INCLUDEEVENTLOG
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                        TRCERR("Destination file already exists");
                        TRCE();
                        return csErrorReturn(SMB_STATUS_OBJECT_NAME_COLLISION, DOS_ERRalreadyexists);
                    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
                	{
                		NQ_TCHAR * tempName;

                		tempName = (NQ_TCHAR *)eventInfo.fileName;
                		eventInfo.fileName = eventInfo.newName;
						udEventLog(
									UD_LOG_MODULE_CS,
									UD_LOG_CLASS_FILE,
									(pUser->preservesCase || (pShare != NULL && cmTStrcmp(pShare->map , nextDstFile) == 0)) ? UD_LOG_FILE_ATTRIBGET : UD_LOG_FILE_QUERYDIRECTORY,
									pUser->name,
									pUser->ip,
									0,
									(const NQ_BYTE*)&eventInfo
								);
						eventInfo.fileName = tempName;
                	}
#endif
                }   

                /* destination file name should not be too long */
                if (cmTStrlen(nextDstFile) >= UD_FS_FILENAMELEN)
                {
#ifdef UD_NQ_INCLUDEEVENTLOG
                    udEventLog(
                        UD_LOG_MODULE_CS,
                        UD_LOG_CLASS_FILE,
                        UD_LOG_FILE_RENAME,
                        pUser->name,
                        pUser->ip,
                        csErrorReturn(SMB_STATUS_OBJECT_NAME_COLLISION, DOS_ERRalreadyexists),
                        (const NQ_BYTE*)&eventInfo
                    );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
					eventInfo.before = TRUE;
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
					eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    csCancelDefaultEnumeration();
#ifdef UD_NQ_INCLUDEEVENTLOG
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    TRCERR("Destination file already exists");
                    TRCE();
                    return csErrorReturn(SMB_STATUS_NAME_TOO_LONG, DOS_ERRinvalidname);
                }
                
                /* check whether the source file is opened by this or another client and
                   is marked for deletion */

                if (csFileMarkedForDeletion(nextSrcFile))
                {
#ifdef UD_NQ_INCLUDEEVENTLOG
                    udEventLog(
                        UD_LOG_MODULE_CS,
                        UD_LOG_CLASS_FILE,
                        UD_LOG_FILE_RENAME,
                        pUser->name,
                        pUser->ip,
                        csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile),
                        (const NQ_BYTE*)&eventInfo
                    );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
					eventInfo.before = TRUE;
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
					eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    csCancelDefaultEnumeration();
#ifdef UD_NQ_INCLUDEEVENTLOG
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    TRCERR("File is marked for deletion: %s", cmTDump(nextSrcFile));
                    TRCE();
                    return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
                }

                TRC1P("Renaming file: %s to: %s", cmTDump(nextSrcFile), cmTDump(nextDstFile));
#ifdef UD_NQ_INCLUDEEVENTLOG
                eventInfo.before = TRUE;
                udEventLog(
            			UD_LOG_MODULE_CS,
            			UD_LOG_CLASS_FILE,
            			UD_LOG_FILE_RENAME,
            			pUser->name,
            			pUser->ip,
            			0,
            			(const NQ_BYTE*)&eventInfo
            		);
                eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                if (syRenameFile(nextSrcFile, nextDstFile) == NQ_FAIL)
                {
                    error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
                    udEventLog(
                        UD_LOG_MODULE_CS,
                        UD_LOG_CLASS_FILE,
                        UD_LOG_FILE_RENAME,
                        pUser->name,
                        pUser->ip,
                        error,
                        (const NQ_BYTE*)&eventInfo
                    );
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
					eventInfo.before = TRUE;
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
					eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    csCancelDefaultEnumeration();
#ifdef UD_NQ_INCLUDEEVENTLOG
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_CLOSE,
							pUser->name,
							pUser->ip,
							0,
							(const NQ_BYTE*)&eventInfo
							);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    TRCERR("Unable to rename file");
                    TRCE();
                    return error;
                }
#ifdef UD_NQ_INCLUDEEVENTLOG
                udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_RENAME,
                    pUser->name,
                    pUser->ip,
                    0,
                    (const NQ_BYTE*)&eventInfo
                );
#endif /* UD_NQ_INCLUDEEVENTLOG */
                csNotifyImmediatelly(nextSrcFile, SMB_NOTIFYCHANGE_RENAMEDOLDNAME, SMB_NOTIFYCHANGE_NAME);
                csNotifyImmediatelly(nextDstFile, SMB_NOTIFYCHANGE_RENAMEDNEWNAME, SMB_NOTIFYCHANGE_NAME);
                renameCount++;
            }
#ifdef UD_NQ_INCLUDEEVENTLOG
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
#endif /* UD_NQ_INCLUDEEVENTLOG */

        }
    }
    
    if (renameCount == 0)
    {
        TRCERR("No files renamed");
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfile);
    }

    TRCE();
    return NQ_SUCCESS;
}

#ifdef UD_CS_INCLUDERPC_SPOOLSS

/*====================================================================
 * PURPOSE: Perform CLOSE_PRINT_FILE command
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
csComClosePrintFile(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsClosePrintRequest* closeRequest;   /* casted request */
    CMCifsClosePrintResponse* closeResponse; /* casted response */
    CSFile* pFile;                           /* pointer to file descriptor */
    NQ_UINT32 returnValue;
    
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

    closeRequest = (CMCifsClosePrintRequest*) pRequest;
    closeResponse = (CMCifsClosePrintResponse*) *pResponse;

    /* check format */

    if (   closeRequest->wordCount != SMB_CLOSEPRINT_REQUEST_WORDCOUNT
        || cmGetSUint16(closeRequest->byteCount) != SMB_CLOSEPRINT_REQUEST_BYTECOUNT
       )
    {
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file descriptor */

    pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(closeRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    if (pFile == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_NO_SUCH_FILE, DOS_ERRbadfid);
    }

    /* release the descriptor and close the file */

    csReleaseFile(pFile->fid);      /* also closes the file */

    /* compose the response */

    closeResponse->wordCount = SMB_CLOSEPRINT_RESPONSE_WORDCOUNT;
    cmPutSUint16(closeResponse->byteCount, cmHtol16(SMB_CLOSEPRINT_RESPONSE_BYTECOUNT));

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*closeResponse);

    TRCE();
    return 0;
}
#endif /* UD_CS_INCLUDERPC_SPOOLSS */


#endif /* UD_NQ_INCLUDECIFSSERVER */
