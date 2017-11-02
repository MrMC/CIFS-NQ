/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Flush command handler
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Jan-2009
 ********************************************************************/

#include "csutils.h"
#include "csnotify.h"
#include "cs2disp.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)


/*====================================================================
 * PURPOSE: Perform Flush processing
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

NQ_UINT32 csSmb2OnFlush(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    CSFile* pFile;                          /* pointer to file descriptor */
    CSFid fid;                              /* fid of the file to close */
    CMCifsStatus error;                     /* for composing DOS-style error */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;            /* share event information */
    const NQ_TCHAR *pFileName;              /* file name pointer */
#endif /* UD_NQ_INCLUDEEVENTLOG */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* parse request */
    cmBufferReaderSkip(reader, 2);  /* reserved 1 */
    cmBufferReaderSkip(reader, 4);  /* reserved 2 */
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);
    
    /* find file descriptor */
    pFile = csGetFileByFid(fid, tree->tid, user->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_HANDLE;
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    pFileName = csGetFileName(pFile->fid);
    if (pFileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "File name corrupted");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_UNSUCCESSFUL;
    }
    eventInfo.tid = tree->tid;
    eventInfo.rid = csGetUserRid(user);
    eventInfo.before = TRUE;
    eventInfo.fileName = pFileName;
    eventInfo.access = 0;
    udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_CLOSE,
		user->name,
		user->ip,
		0,
		(const NQ_BYTE*)&eventInfo
	);
    eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* flush the file */
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    if (!pFile->isPrint)
    { 
#endif /* UD_CS_INCLUDERPC_SPOOLSS */
    if (NQ_SUCCESS != syFlushFile(pFile->file))
    {
        error = csErrorGetLast();
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Internal error: unable to flush file information");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return error;
    }
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    }
#endif /* UD_CS_INCLUDERPC_SPOOLSS */
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_CLOSE,
		user->name,
		user->ip,
		0,
		(const NQ_BYTE*)&eventInfo
	);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    /* compose response */
    cmBufferWriteUint16(writer, 1);   /* structure size */
    cmBufferWriteUint16(writer, 0);   /* reserved */
    
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

