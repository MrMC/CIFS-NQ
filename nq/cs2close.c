/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Close command handler
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Jan-2009
 ********************************************************************/

#include "csutils.h"
#include "csnotify.h"
#include "cs2disp.h"
#include "csbreak.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/*====================================================================
 * PURPOSE: Perform Close processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN user - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Create command.
 *====================================================================
 */

NQ_UINT32 csSmb2OnClose(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    CSFile* pFile;                          /* pointer to file descriptor */
    CSFid fid;                              /* fid of the file to close */
    NQ_UINT16 flags;                        /* close flags */
    const NQ_TCHAR *pFileName;              /* file name pointer */
    const CSShare* pShare;                  /* pointer to share descriptor */
    SYFileInformation fileInfo;             /* buffer for file information */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;            /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* parse request */
    cmBufferReadUint16(reader, &flags);
    cmBufferReaderSkip(reader, 4);
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);

    if ((pShare = csGetShareByUidTid(user->uid, tree->tid)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal TID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER;
    }
    
    /* find file descriptor */
    pFile = csGetFileByFid(fid, tree->tid, user->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_HANDLE;
    }

    pFileName = csGetFileName(pFile->fid);
    if (pFileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "File name corrupted");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_UNSUCCESSFUL;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.tid = tree->tid;
    eventInfo.rid = csGetUserRid(user);
    eventInfo.fileName = pFileName;
    eventInfo.access = 0;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "File name: %s", cmTDump(pFileName));   

#ifdef UD_CS_INCLUDERPC_SPOOLSS
    if (pFile->isPrint)
    {
    }
    else
#endif
    {
        /* if delete on close was requested - mark this file for deletion */
        if (pFile->options & SMB_NTCREATEANDX_DELETEONCLOSE)
        {
            CSName* pName;          /* pointer to the file name descriptor */
#ifdef UD_CS_FORCEINTERIMRESPONSES
            NQ_UINT32 asyncId = 0;                  /* generated Async ID */
#endif /* UD_CS_FORCEINTERIMRESPONSES */
    
#ifdef UD_CS_FORCEINTERIMRESPONSES
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
#endif /* UD_CS_FORCEINTERIMRESPONSES */
            pName = csGetNameByNid(pFile->nid);
            if (pName == NULL)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Internal error: file name descriptor not found");
                csReleaseFile(pFile->fid);      /* also closes the file */
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return SMB_STATUS_UNSUCCESSFUL;
            }
            pName->markedForDeletion = TRUE;
#ifdef UD_NQ_INCLUDEEVENTLOG
			if (pName->markedForDeletion && pName->deletingUserRid == CS_ILLEGALID)
			{				
				pName->deletingUserRid = csGetUserRid(user);
				pName->deletingTid = pFile->tid;
				cmIpToAscii(pName->deletingIP, user->ip);
			}
#endif /* UD_NQ_INCLUDEEVENTLOG */		
        }
        /* read file information */
#ifdef UD_CS_INCLUDERPC 
        if (pFile->isPipe)
        {
            syMemset(&fileInfo, 0, sizeof(fileInfo));
        }
        else
        {
#endif /* UD_CS_INCLUDERPC */   
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
        	eventInfo.before = TRUE;
        	udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				user->name,
				user->ip,
				0,
				(const NQ_BYTE*)&eventInfo
				);
        	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
            if (syGetFileInformationByName(pFileName, &fileInfo) != NQ_SUCCESS)
            {
                NQ_UINT32 error;
                
                error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					user->name,
					user->ip,
					error,
					(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
#ifdef UD_NQ_INCLUDEEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					user->name,
					user->ip,
					error,
					(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                csReleaseFile(pFile->fid);      /* also closes the file */
                LOGERR(CM_TRC_LEVEL_ERROR, "Unable to read file information: %d", error);
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return error;
            }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				user->name,
				user->ip,
				0,
				(const NQ_BYTE*)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
#ifdef UD_CS_INCLUDERPC 
        }
#endif /* UD_CS_INCLUDERPC */           
    }

    /* compose the response */
    cmBufferWriteUint16(writer, 60);    /* structure size */
    cmBufferWriteUint16(writer, 0);     /* client should not use file attributes */
    cmBufferWriteUint32(writer, 0);     /* reserved */
    if (flags & 1)    
    {
        NQ_UINT64 time;         /* utc time */
        
        cmCifsTimeToUTC(fileInfo.creationTime, &time.low, &time.high);
        cmBufferWriteUint64(writer, &time);
        cmCifsTimeToUTC(fileInfo.lastAccessTime, &time.low, &time.high);
        cmBufferWriteUint64(writer, &time);
        cmCifsTimeToUTC(fileInfo.lastWriteTime, &time.low, &time.high);
        cmBufferWriteUint64(writer, &time);
        cmCifsTimeToUTC(fileInfo.lastChangeTime, &time.low, &time.high);
        cmBufferWriteUint64(writer, &time);
        cmBufferWriteUint32(writer, fileInfo.allocSizeLow);   /* allocation size */
        cmBufferWriteUint32(writer, fileInfo.allocSizeHigh);
        cmBufferWriteUint32(writer, fileInfo.sizeLow);        /* EOF */
        cmBufferWriteUint32(writer, fileInfo.sizeHigh);
        cmBufferWriteUint32(writer, fileInfo.attributes);
    }
    else
    	cmBufferWriteZeroes(writer, 52);
    

    /* complete oplock break operation (send late response) if required */

    if (pFile->oplockGranted && pFile->pFileOplockBreaker)
    {
        CMBufferWriter packet;

        out->status = 0;
        cmBufferWriterInit(&packet, cmBufferWriterGetStart(writer) - SMB2_HEADERSIZE , 124);
        cmSmb2HeaderWrite(out, &packet);
        csBreakComplete(&pFile->pFileOplockBreaker->breakContext, cmBufferWriterGetStart(&packet));
        csReleaseFile(pFile->fid);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Oplock break completed");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_NORESPONSE;
    }

    /* release the descriptor and close the file */
    csReleaseFile(pFile->fid);          /* also closes the file */

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);

    return 0;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

