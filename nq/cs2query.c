/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 QUERY INFO command dispatcher
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 12-Feb-2008
 ********************************************************************/

#include "csdcerpc.h"
#include "csinform.h"
#include "csutils.h"
#include "csparams.h"
#include "cssearch.h"
#include "cs2disp.h"
#include "csnttran.h"
#include "csnotify.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

#define SMB2_QUERY_INFO_RESPONSE_DATASIZE   9
#define SMB2_SET_INFO_RESPONSE_DATASIZE     2

/* Query Directory flags */
#define SMB2_RESTART_SCANS                  0x01    /* Restart the enumeration from the beginning, but the search pattern is not changed. */
#define SMB2_RETURN_SINGLE_ENTRY            0x02    /* Return only the first entry of the search results. */
#define SMB2_INDEX_SPECIFIED                0x04    /* Return entries beginning at the byte number specified by FileIndex. */
#define SMB2_REOPEN                         0x10    /* Restart the enumeration from the beginning, the search pattern must be changed. */


 /*====================================================================
 * PURPOSE: Perform Query Info processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Query Info command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnQueryInfo(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    NQ_BYTE infoType;                       /* info type */
    NQ_BYTE infoClass;                      /* info class */
    NQ_UINT32 outputBufferLength;           /* maximum permitted response size */
    NQ_UINT16 inputBufferOffset;            /* offset to the input buffer (relevant for SMB2_INFO_QUOTA only)*/
    NQ_UINT32 inputBufferLength;            /* length of the input buffer (relevant for SMB2_INFO_QUOTA only)*/
    NQ_UINT32 additionalInformation;        /* relevant for SMB2_INFO_SECURITY and SMB2_INFO_FILE:FileFullEaInformation only */
    CSFid fid;                              /* file ID */
    CSFile* pFile;                          /* pointer to file descriptor */
    const NQ_TCHAR* pFileName;              /* file name pointer */
    CMBufferWriter outBuffWriter;           /* writer for response info buffer */  
    CSTransaction2Descriptor descriptor;    /* descriptor */
    NQ_UINT32 result = NQ_SUCCESS;          /* for result of query operation */   
    const CSShare* pShare;                  /* pointer to the share */
    CSName* pName;                          /* pointer to file name descriptor */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* read the request */
    cmBufferReadByte(reader, &infoType);  
    cmBufferReadByte(reader, &infoClass);
    cmBufferReadUint32(reader, &outputBufferLength); 
    cmBufferReadUint16(reader, &inputBufferOffset);
    cmBufferReaderSkip(reader, 2);  /* reserved */
    cmBufferReadUint32(reader, &inputBufferLength);    
    cmBufferReadUint32(reader, &additionalInformation); 
    cmBufferReaderSkip(reader, 4);  /* reserved */
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Info Type: %d, Info Class: %d, fid: 0x%x", infoType, infoClass, fid);

    /* check access to share */
    if ((result = csCanReadShare(tree->tid)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Access to share denied");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return result; 
    }

    /* find share */
    pShare = csGetShareByUidTid(session->uid, tree->tid);
    if (pShare == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal UID or TID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER;
    }

    /* create writer for output buffer */
    cmBufferWriterBranch(writer, &outBuffWriter, 8); /* structure size (2) + buffer offset (2) + buffer length (4) */

    syMemset(&descriptor, 0, sizeof(descriptor));
    
    /* process by info type code */
    switch (infoType)
    {
        case SMB2_INFO_FILE:
            /* find file descriptor(s) */
            pFile = csGetFileByFid(fid, tree->tid, session->uid);
            if (pFile == NULL)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return SMB_STATUS_FILE_CLOSED;
            }

            /* check whether this file is opened by this or another client and is marked for deletion */
            pName = csGetNameByNid(pFile->nid);
            if (pName == NULL || pName->markedForDeletion)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "File is marked for deletion");
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return SMB_STATUS_NO_SUCH_FILE;
            }

            /* find file name */
            pFileName = csGetFileName(pFile->fid);
            if (pFileName == NULL)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "File name corrupted");
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return SMB_STATUS_UNSUCCESSFUL;
            }
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "File name: %s", cmTDump(pFileName));

            /* get file information */
            descriptor.pParams = cmBufferWriterGetPosition(&outBuffWriter) - 4; /* extra 4 bytes required by csQueryFileInformationByName() */
            result = csQueryFileInformationByName(pFile, pFileName, (NQ_COUNT)cmTStrlen(pShare->map), (NQ_UINT)(infoClass + 1000), TRUE, CS_MAXBUFFERSIZE - SMB2_HEADERSIZE - 8, &descriptor);
            break;
        case SMB2_INFO_FILESYSTEM:
        {
            /* get file system information */
            descriptor.pParams = cmBufferWriterGetPosition(&outBuffWriter);
			descriptor.pHeaderOut = (const CMCifsHeader *)(cmBufferWriterGetStart(writer) - SMB2_HEADERSIZE);
            result = csQueryFsInformation(pShare, (NQ_UINT)(infoClass == 1 ? 0x102 : (infoClass | 0x100)), TRUE, &descriptor
#ifdef UD_NQ_INCLUDEEVENTLOG
																													,tree
#endif /* UD_NQ_INCLUDEEVENTLOG */
			);
            break;
        }
        case SMB2_INFO_SECURITY:
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS   
            {
                NQ_UINT32 sdLength;                     /* security descriptor length */

                /* find file descriptor(s) */
                pFile = csGetFileByFid(fid, tree->tid, session->uid);
                if (pFile == NULL)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return SMB_STATUS_FILE_CLOSED;
                }

                /* get security descriptor */
                sdLength = (NQ_UINT32)syGetSecurityDescriptor(pFile->file, additionalInformation, cmBufferWriterGetPosition(&outBuffWriter));
                if (NQ_FAIL == sdLength)
                {
    /*                LOGERR(CM_TRC_LEVEL_ERROR, "SD not supported");
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return SMB_STATUS_NOT_SUPPORTED;
    */
                	CMSdSecurityDescriptor sd;
                    CMRpcPacketDescriptor temp;

                	cmSdGetNoneSecurityDescriptor(&sd);
                    cmRpcSetDescriptor(&temp, cmBufferWriterGetPosition(&outBuffWriter), FALSE);
                	cmSdPackSecurityDescriptor(&temp, &sd);
                    cmBufferWriterSetPosition(&outBuffWriter, temp.current);
                    sdLength = sd.length;
                }
                else
                {
                    cmBufferWriterSetPosition(&outBuffWriter, cmBufferWriterGetStart(&outBuffWriter) + sdLength);
                }

                /* compose error response specifying required buffer size */
                if (outputBufferLength < sdLength)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Requested output buffer size is too small, requested: %d, required: %d", outputBufferLength, sdLength);
                    out->status = SMB_STATUS_BUFFER_TOO_SMALL;
                    cmBufferWriteUint16(writer, 9);
                    cmBufferWriteUint16(writer, 0);
                    cmBufferWriteUint32(writer, 4);
                    cmBufferWriteUint32(writer, sdLength);
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return SMB_STATUS_CUSTOM_ERROR_RESPONSE;
                }         
             
                descriptor.dataCount = (NQ_UINT16)sdLength;
            }
            break;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */                       
        case SMB2_INFO_QUOTA:
        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Unsupported info type");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_NOT_SUPPORTED;
    }
    
    /* write the response */
    cmBufferWriteUint16(writer, SMB2_QUERY_INFO_RESPONSE_DATASIZE);                       /* constant response size */  
    cmBufferWriteUint16(writer, SMB2_HEADERSIZE + SMB2_QUERY_INFO_RESPONSE_DATASIZE - 1); /* output buffer offset   */
    cmBufferWriterSetPosition(&outBuffWriter, cmBufferWriterGetStart(&outBuffWriter) + descriptor.dataCount);
    cmBufferWriteUint32(writer, cmBufferWriterGetDataCount(&outBuffWriter));              /* output buffer length   */
    cmBufferWriterSync(writer, &outBuffWriter);

    if (cmBufferWriterGetDataCount(&outBuffWriter) > outputBufferLength)
    	result = SMB_STATUS_BUFFER_OVERFLOW;

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return result;
}

/*====================================================================
 * PURPOSE: Perform Set Info processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Set Info command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnSetInfo(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    NQ_BYTE infoType;                       /* info type */
    NQ_BYTE infoClass;                      /* info class */
    NQ_UINT32 inputBufferLength;            /* input buffer length */
    NQ_UINT16 inputBufferOffset;            /* offset to the input buffer */
    NQ_UINT32 additionalInformation;        /* relevant for SMB2_INFO_SECURITY and SMB2_INFO_FILE:FileFullEaInformation only */
    CSFid fid;                              /* file ID */
    NQ_UINT32 result = NQ_SUCCESS;          /* for result of query operation */   
    CSFile* pFile;                          /* pointer to file descriptor */
    NQ_UINT32 sdLength;                     /* security descriptor length */
    InfoContext ctx;                        /* information context */
#ifdef UD_CS_FORCEINTERIMRESPONSES
    NQ_UINT32 asyncId = 0;                  /* generated Async ID */
#endif /* UD_CS_FORCEINTERIMRESPONSES */
    
    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* read the request */
    cmBufferReadByte(reader, &infoType);  
    cmBufferReadByte(reader, &infoClass);
    cmBufferReadUint32(reader, &inputBufferLength); 
    cmBufferReadUint16(reader, &inputBufferOffset);
    cmBufferReaderSkip(reader, 2);  /* reserved */
    cmBufferReadUint32(reader, &additionalInformation); 
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);
    cmBufferReaderSkip(reader, 14); /* the rest of the file ID */
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Info Type: %d, Info Class: %d, fid: 0x%x", infoType, infoClass, fid);

    /* check access to share */
    if ((result = csCanWriteShare(tree->tid)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Access to share denied");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return result; 
    }

    /* find file descriptor(s) */
    pFile = csGetFileByFid(fid, tree->tid, session->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_FILE_CLOSED;
    }

    /* find file name */
    ctx.pFileName = csGetFileName(pFile->fid);
    if (ctx.pFileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "File name corrupted");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_UNSUCCESSFUL;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "File name: %s", cmTDump(ctx.pFileName));
            
    /* process by info type code */
    switch (infoType)
    {
        case SMB2_INFO_FILE:
            /* set file information by info class code */
            ctx.uid = session->uid;
            ctx.tid = tree->tid;
            ctx.level = (NQ_UINT)infoClass + 1000; /* passthru level */
            ctx.pData = cmBufferReaderGetPosition(reader);
            /* send interim response on file extension */
#ifdef UD_CS_FORCEINTERIMRESPONSES
            if (ctx.level == SMB_PASSTHRU_FILE_ALLOCATIONINFO || ctx.level ==  SMB_PASSTHRU_FILE_ENDOFFILEINFO)
            {
                asyncId = csSmb2SendInterimResponse(in);
                if (0 == asyncId)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "error sending interim write response");
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return SMB_STATUS_INVALID;
                }
                out->flags |= SMB2_FLAG_ASYNC_COMMAND;
                out->aid.low = asyncId;
                out->aid.high = 0;
            }
#endif /* UD_CS_FORCEINTERIMRESPONSES */

            result = csSetFileInformationByName(pFile, 
#ifdef UD_NQ_INCLUDEEVENTLOG
                                                session,       
#endif /* UD_NQ_INCLUDEEVENTLOG */
                                                &ctx);
            break;
        case SMB2_INFO_FILESYSTEM:
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_INVALID_INFO_CLASS;
        case SMB2_INFO_SECURITY:
            /* set security descriptor */
            csGetEmptySd(additionalInformation, &sdLength);
            if (NQ_FAIL == sySetSecurityDescriptor(pFile->file, additionalInformation, cmBufferReaderGetPosition(reader), inputBufferLength)
                        && 0 != syMemcmp(cmBufferReaderGetPosition(reader), csGetEmptySd(additionalInformation, &sdLength), sdLength))
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Unable to set security descriptor");
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return SMB_STATUS_NOT_SUPPORTED;
            }
            csNotifyImmediatelly(ctx.pFileName, SMB_NOTIFYCHANGE_MODIFIED, SMB_NOTIFYCHANGE_SECURITY);
            break;
        case SMB2_INFO_QUOTA:
        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Unsupported info type");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_NOT_SUPPORTED;
    }

    /* write the response */
    cmBufferWriteUint16(writer, SMB2_SET_INFO_RESPONSE_DATASIZE);   /* constant response size */  

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return result;
}


/*====================================================================
 * PURPOSE: Perform Query Directory processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Query Directory command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnQueryDirectory(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    NQ_BYTE infoClass;                      /* query info class */
    NQ_BYTE flags;                          /* query flags */
    NQ_UINT32 fileIndex;                    /* file index */
    CSFid fid;                              /* file ID */
    NQ_UINT16 searchPatternOffset;          /* offset to search pattern in request */
    NQ_UINT16 searchPatternLength;          /* search pattern length */
    NQ_UINT32 maxOutBufferLength;           /* maximal output buffer length */
    NQ_STATIC NQ_WCHAR searchPattern[UD_FS_FILENAMELEN]; /* search pattern buffer */
    NQ_UINT32 result = NQ_SUCCESS;          /* for result of query operation */   
    const CSShare* pShare;                  /* pointer to the share */
    CSFile* pFile;                          /* pointer to file descriptor */
    NQ_TCHAR* pFileName;                    /* filename to search */
    CSSearch* pSearch;                      /* search operation descriptor */
    NQ_BYTE* pEntry;                        /* file record pointer */
    NQ_BYTE* pLastEntry = NULL;             /* pointer to the last record */
    NQ_BYTE* pNextEntryOffset = NULL;       /* pointer to nextEntryOffset field in the entry */
    NQ_UINT entryCount = 0;                 /* number of entries in the response */
    CMCifsStatus error;                     /* for composing DOS-style error */
    NQ_UINT maxLength;                      /* max response length */
    NQ_BYTE* pBuffer;                       /* pointer to the start of the entries */
    NQ_BOOL isFindFirst = FALSE;            /* whether it's 'find first' request */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent	eventInfo;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* read the request */
    cmBufferReadByte(reader, &infoClass);  
    cmBufferReadByte(reader, &flags);
    cmBufferReadUint32(reader, &fileIndex);
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid); 
    cmBufferReaderSkip(reader, 14); /* the rest of the file ID */
    cmBufferReadUint16(reader, &searchPatternOffset);
    cmBufferReadUint16(reader, &searchPatternLength);    
    cmBufferReadUint32(reader, &maxOutBufferLength); 

    /* null-terminate search pattern */
    if (searchPatternLength > 0)
    {
        cmWStrncpy(searchPattern, (const NQ_WCHAR *)cmBufferReaderGetPosition(reader), searchPatternLength / sizeof(NQ_WCHAR));
        searchPattern[searchPatternLength / sizeof(NQ_WCHAR)] = 0;
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Empty search pattern");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER; 
    }
    
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Info class: %d, flags: %d, fid: 0x%x, fileIndex: %d, pattern: %s", 
                                     infoClass, flags, fid, fileIndex, cmWDump(searchPattern));

    /* check access to share */
    if ((result = csCanReadShare(tree->tid)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Access denied");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return result; 
    }

    /* find share */
    pShare = csGetShareByUidTid(session->uid, tree->tid);
    if (pShare == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal UID or TID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER;
    }

    /* find file descriptor(s) */
    pFile = csGetFileByFid(fid, tree->tid, session->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID: 0x%x", fid);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_FILE_CLOSED;
    }

    /* verify supplied fid is a directory */
    if (!pFile->isDirectory)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Supplied FID is not a directory");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_NOT_SUPPORTED;
    }
 
    /* convert filename to host filename */
    if ((pFileName = cmCifsNtohFilename(csGetNameByNid(pFile->nid)->name, (NQ_TCHAR*)searchPattern, TRUE)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal filename");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_OBJECT_NAME_INVALID;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.tid = tree->tid;
    eventInfo.rid = csGetUserRid(session);
    eventInfo.fileName = pFileName;
#endif /* UD_NQ_INCLUDEEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before = TRUE;
    udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_QUERYDIRECTORY,
		session->name,
		session->ip,
		0,
		(const NQ_BYTE *)&eventInfo
		);
    eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* check path */
    if (!csCheckPath(pShare, pFileName, (NQ_UINT)cmTStrlen(pShare->map), session->preservesCase))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			session->name,
			session->ip,
			csErrorReturn(SMB_STATUS_OBJECT_PATH_NOT_FOUND, DOS_ERRbadpath),
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        LOGERR(CM_TRC_LEVEL_ERROR, "Path does not exist: %s", cmTDump(pFileName));
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_OBJECT_PATH_NOT_FOUND;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_QUERYDIRECTORY,
		session->name,
		session->ip,
		0,
		(const NQ_BYTE *)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* allocate SID if not allocated yet */
    if ((pSearch = csGetSearchBySid(pFile->sid)) == NULL)
    {
        if ((pSearch = csGetNewSearch(tree)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "SID overflow");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_UNSUCCESSFUL;
        }
        pFile->sid = pSearch->sid;
        isFindFirst = TRUE;
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Allocated new SID %d", pFile->sid);
    }

    /* consider search flags */
    isFindFirst = ((flags & SMB2_RESTART_SCANS) != 0) || ((flags & SMB2_REOPEN) != 0) ? TRUE : isFindFirst;
    
    /* structure size (2) + buffer offset (2) + buffer length (4) */
    pEntry = pBuffer = cmBufferWriterGetPosition(writer) + 8;  /* start writing entries from here */

    /* use the least of 1) required limit 
                        2) max size of internal buffer */
    {
        maxLength = (NQ_UINT)(maxOutBufferLength > CS_MAXBUFFERSIZE ? CS_MAXBUFFERSIZE : maxOutBufferLength);
        maxLength -= 8 + SMB2_HEADERSIZE;
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Requested max buffer length %d, got %d", maxOutBufferLength, maxLength);
    }
    
    /* determine whether it's a 'find first' or 'find next' request */
    if (isFindFirst)
    {
         csEnumerateSourceName(&pSearch->enumeration, pFileName, session->preservesCase);
         LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Starting search on %s", cmTDump(pFileName));
    }
    else
    {
         LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Continuing search on %s", cmTDump(pFileName));
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before = TRUE;
    udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_QUERYDIRECTORY,
		session->name,
		session->ip,
		0,
		(const NQ_BYTE *)&eventInfo
		);
    eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* search files */
    while ((pFileName = csNextSourceName(&pSearch->enumeration)) != NULL)
    {
        SYFileInformation fileInfo;    	/* for querying file information */
        NQ_BYTE* pLastEntryCandidate;  	/* temporary pointer to the last entry */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			session->name,
			session->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
        {
        	NQ_TCHAR * oldName;

        	oldName = (NQ_TCHAR *)eventInfo.fileName;
			eventInfo.before = TRUE;
			eventInfo.fileName = pFileName;
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				session->name,
				session->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
			eventInfo.fileName = oldName;
			eventInfo.before = FALSE;
        }
#endif
        /* set default info details for corrupted file */
        if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
        {
            syMemset(&fileInfo, 0, sizeof(fileInfo));
        }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
        {
        	NQ_TCHAR * oldName;

        	oldName = (NQ_TCHAR *)eventInfo.fileName;
			eventInfo.fileName = pFileName;
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				session->name,
				session->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
			eventInfo.fileName = oldName;
        }
#endif
    
        /* fill file information */
        pLastEntryCandidate = pEntry;

        error = csFillFindEntry(
                            pFileName,
                            &fileInfo,
                            &pEntry,
                            (NQ_UINT16)(infoClass + 1000), /* passthru level */
                            entryCount,
                            TRUE,
                            pBuffer,
                            maxLength,
                            FALSE,
                            &pNextEntryOffset
                            );

        if (error == INTERNAL_ERROR)
        {
            if (entryCount == 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Requested buffer too small");
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
#ifdef UD_NQ_INCLUDEEVENTLOG
				eventInfo.before = TRUE;
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					session->name,
					session->ip,
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
					session->name,
					session->ip,
					0,
					(const NQ_BYTE *)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                pFile->sid = (CSSid)CS_ILLEGALID;
                return SMB_STATUS_BUFFER_TOO_SMALL;
            }

            LOGERR(CM_TRC_LEVEL_ERROR, "Max buffer length reached");
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
				session->name,
				session->ip,
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
				session->name,
				session->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to read file information");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return error;
        }
        entryCount++;
        pLastEntry = pLastEntryCandidate;

        if ((flags & SMB2_RETURN_SINGLE_ENTRY) != 0)
            break;

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
        eventInfo.before = TRUE;
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_QUERYDIRECTORY,
			session->name,
			session->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
		eventInfo.before = FALSE;
#endif
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_QUERYDIRECTORY,
		session->name,
		session->ip,
		0,
		(const NQ_BYTE *)&eventInfo
		);
#endif
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "entryCount = %d", entryCount);
    
    /* return error if no files were found or end of search reached */
    if (entryCount == 0)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "%s", isFindFirst ? "No such file" : "No more files");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
#ifdef UD_NQ_INCLUDEEVENTLOG
		eventInfo.before = TRUE;
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_CLOSE,
			session->name,
			session->ip,
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
			session->name,
			session->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        pFile->sid = (CSSid)CS_ILLEGALID;
        return isFindFirst ? SMB_STATUS_NO_SUCH_FILE : SMB_STATUS_NO_MORE_FILES;
    }
    
    /* set zero for nextEntryOffset of last entry */
    if (pNextEntryOffset != NULL)
    {
        NQ_BYTE* position = cmBufferWriterGetPosition(writer);
        
        cmBufferWriterSetPosition(writer, pLastEntry);
        cmBufferWriteUint32(writer, 0);
        cmBufferWriterSetPosition(writer, position);
    }
    
    /* write the response */
    cmBufferWriteUint16(writer, SMB2_QUERY_INFO_RESPONSE_DATASIZE);                       /* constant response size */  
    cmBufferWriteUint16(writer, SMB2_HEADERSIZE + SMB2_QUERY_INFO_RESPONSE_DATASIZE - 1); /* output buffer offset   */
    cmBufferWriteUint32(writer, (NQ_UINT32)(pEntry - pBuffer));                           /* output buffer length   */
    cmBufferWriterSetPosition(writer, pEntry);
 
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}



#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */
