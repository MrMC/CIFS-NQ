/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Lock command handler
 *--------------------------------------------------------------------
 * MODULE        : CS
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 02-Dec-2008
 ********************************************************************/

#include "csparams.h"
#include "csutils.h"
#include "csdcerpc.h"
#include "cs2disp.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/* 
    Local functions, definitions and data
    -------------------------------------
 */

/* lock element flags */
#define FLAG_SHARED_LOCK 0x1
#define FLAG_EXCLUSIVE_LOCK 0x2
#define FLAG_UNLOCK 0x4
#define FLAG_FAIL_IMMEDIATELY 0x10

/*====================================================================
 * PURPOSE: Perform Lock processing
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

NQ_UINT32 csSmb2OnLock(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    CSFile* pFile;                          /* pointer to file descriptor */
    CSFid fid;                              /* fid of the file to close */
    NQ_UINT16 lockCount;                    /* number of lock entries */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* parse request */
    cmBufferReadUint16(reader, &lockCount);
    cmBufferReaderSkip(reader, 4); /* reserved */
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);
    cmBufferReaderSkip(reader, 14); /* the rest of the file ID */

    /* find file descriptor */
    pFile = csGetFileByFid(fid, tree->tid, user->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_HANDLE;
    }

    /* process lock elements */
    for (; lockCount > 0; lockCount--)
    {
        NQ_UINT64 offset;   /* lock offset */
        NQ_UINT64 length;   /* lock range length */
        NQ_UINT32 flags;    /* lock flags */
        NQ_STATUS status;   /* lock/unlock result status */        
        NQ_UINT32 lockType = 0;    /* lock type as in SMB1 */

        cmBufferReadUint64(reader, &offset);
        cmBufferReadUint64(reader, &length);
        cmBufferReadUint32(reader, &flags);
        cmBufferReaderSkip(reader, 4); /* reserved */

        if (flags & FLAG_SHARED_LOCK)
        {
            lockType |= SMB_LOCKINGANDX_SHAREDLOCK;
        }

        if (flags & (FLAG_SHARED_LOCK | FLAG_EXCLUSIVE_LOCK))
        {
            status = syLockFile(
                pFile->file, 
                offset.high, offset.low, 
                length.high, length.low,  
                lockType,
                0
                );
        }
        else
        {
            status = syUnlockFile(
                pFile->file, 
                offset.high, offset.low, 
                length.high, length.low,  
                0
                );
        }
        if (NQ_SUCCESS != status)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Lock/Uplock operation failed");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return csErrorGetLast();
        }
    }

    /* compose positive response */
    cmBufferWriteUint16(writer, 4);             /* structure length */
    cmBufferWriteUint16(writer, 0);             /* reserved */
    
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

