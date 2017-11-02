/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#include "ccfile.h"
#include "ccmount.h"
#include "ccserver.h"
#include "ccutils.h"
#include "ccconfig.h"
#include "cmfscifs.h"
#include "ccdfs.h"
#include "cmlist.h"
#include "ccsmb10.h"
#include "ccinfo.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Constants -- */

#define ACCESSMASKDEFAULT (       \
    SMB_DESIREDACCESS_SYNCHRONISE |   \
    SMB_DESIREDACCESS_READCONTROL |   \
    SMB_DESIREDACCESS_READATTRIBUTES)

/* -- Static functions --- */

/*
 * Explicitly close and dispose file:
 *  - disconnects from the share
 *  - disposes private data  
 */
static void disposeFile(CCFile * pFile)
{
    CCServer * pServer;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose file %s", cmWDump(pFile->item.name));

    pServer = pFile->share->user->server;
    if (NULL!= pServer->smb && pFile->open)
        pServer->smb->doClose(pFile);
    cmListItemRemoveAndDispose((CMItem *)pFile);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 * Callback for file unlock and disposal:
 *  - disconnects from the share
 *  - disposes private data  
 */
static NQ_BOOL unlockCallback(CMItem * pItem)
{
    CCFile  *   pFile = (CCFile *)pItem;

    disposeFile(pFile);
    return TRUE;
}

#ifdef UD_CC_INCLUDEDFS  
static void cloneFileData(CCFile *from, CCFile *to)
{
    if (from && to)
    {
        to->accessMask = from->accessMask;
        to->attributes = from->attributes;
        to->disposition = from->disposition;
        to->open = from->open;
        to->options = from->options;
        to->sharedAccess = from->sharedAccess;
    }
}
#endif /* UD_CC_INCLUDEDFS */

/*
 * Print share-specific information 
 */
#if SY_DEBUGMODE
static void dumpOne(CMItem * pItem)
{
#ifdef UD_NQ_INCLUDETRACE
    CCFile * pFile = (CCFile *)pItem;
    NQ_BYTE * fid = pFile->fid;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  File:: FID: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x access: %08x", \
          fid[0], fid[1], fid[2], fid[3],   \
          fid[4], fid[5], fid[6], fid[7],   \
          fid[8], fid[9], fid[10], fid[11], \
          fid[12], fid[13], fid[14], fid[15], \
          pFile->accessMask             \
           );
#endif /* UD_NQ_INCLUDETRACE */
}
#endif /* SY_DEBUGMODE */

/* -- API Functions */

NQ_BOOL ccFileStart(void)
{
    return TRUE;
}

void ccFileShutdown(void)
{
  
}

CCFile * ccFileFind(CCShare * pShare, const NQ_WCHAR * path)
{
    return NULL;  /* this call is not expected */
}

CCFile * ccFileFindById(CCServer * pServer, const NQ_BYTE * id)
{
    CMIterator userIterator;        /* user iterator */
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    ccServerIterateUsers(pServer, &userIterator);
    while (cmListIteratorHasNext(&userIterator))
    {
        CCUser * pUser;                 /* next user pointer */
        CMIterator shareIterator;       /* share iterator */

        pUser = (CCUser *)cmListIteratorNext(&userIterator);
        ccUserIterateShares(pUser, &shareIterator);
        while (cmListIteratorHasNext(&shareIterator))
        {
            CCShare * pShare;               /* next share pointer */
            CMIterator  fileIterator;       /* file Iterator*/
			
            pShare = (CCShare *)cmListIteratorNext(&shareIterator);
            cmListIteratorStart(&pShare->files, &fileIterator);
            if (cmListIteratorHasNext(&fileIterator))
            {
                CCFile * pFile;               /* next file pointer */
    			
                pFile = (CCFile *)cmListIteratorNext(&fileIterator);
                if (0 == syMemcmp(id, pFile->fid, sizeof(pFile->fid)))
                {
                    cmListIteratorTerminate(&userIterator);
                    cmListIteratorTerminate(&shareIterator);
                    cmListIteratorTerminate(&fileIterator);
	                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	                return pFile;
                }
            }
            cmListIteratorTerminate(&fileIterator);
        }
        cmListIteratorTerminate(&shareIterator);
    }
    cmListIteratorTerminate(&userIterator);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return NULL;
}

CCFile * ccFileCreate(CCShare * pShare, const NQ_WCHAR * path)
{
    CCFile * pFile;       /* File pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "path: %s", cmWDump(path));
    
    /* we do not care of another file with the same name */
    pFile = (CCFile *)cmListItemCreateAndAdd(&pShare->files, sizeof(CCFile), path, unlockCallback , TRUE);
    if (NULL == pFile)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        cmListItemCheck((CMItem *)pShare);    /* try disposal */
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pFile: %s", cmWDump(pFile->item.name));
    pFile->oplockLevel = 0;
    pFile->open = FALSE;
    pFile->share = pShare;
    cmListItemAddReference((CMItem *)pFile, (CMItem *)pShare);
#if SY_DEBUGMODE
    pFile->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pFile;
}

NQ_HANDLE ccCreateFileA(
    const NQ_CHAR *fileName, 
    NQ_INT access, 
    NQ_INT shareMode,
    NQ_INT locality, 
    NQ_BOOL writeThrough, 
    NQ_UINT16 attributes, 
    NQ_INT createAction, 
    NQ_INT openAction
    )
{
    NQ_WCHAR * fileNameW; /* name in Unicode */
    NQ_HANDLE res;        /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (fileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL == fileNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    res = ccCreateFileW(fileNameW, access, shareMode, locality, writeThrough, attributes, createAction, openAction); 
    cmMemoryFree(fileNameW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_HANDLE ccCreateFileW(
    const NQ_WCHAR * fileName, 
    NQ_INT access, 
    NQ_INT shareMode,
    NQ_INT locality, 
    NQ_BOOL writeThrough, 
    NQ_UINT16 attributes, 
    NQ_INT createAction, 
    NQ_INT openAction
    )
{
    CCMount * pMount;   /* mount point descriptor */
    CCFile * pFile;     /* file handle */
    CCShare * pShare;   /* pointer to the hosting share */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fileName: %s", cmWDump(fileName));

    if (fileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    if (ccUtilsPathIsLocal(fileName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR,"Cannot open mount point");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    pMount = ccMountFind(fileName);
    if (NULL == pMount)
    {
        sySetLastError(NQ_ERR_BADPATH);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    pShare = pMount->share;
    pFile = ccFileCreateOnServer(
            pShare, 
            fileName, 
            TRUE,
            access, 
            shareMode, 
            locality, 
            writeThrough,
            attributes,
            createAction,
            openAction,
            FALSE
            );
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_HANDLE)pFile;
}

NQ_BOOL ccCloseHandle(NQ_HANDLE handle)
{
    CCFile *    pFile = (CCFile *)handle;   /* casted pointer to file */
    NQ_STATUS   res;                        /* exchange status */
    NQ_INT      counter;                    /* simple counter*/

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (handle == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    
	if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }

    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT ; counter++)
    {
        res = pFile->share->user->server->smb->doClose(pFile);
        if (res == NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else
            break;
    }
    pFile->open = FALSE;

    cmListItemUnlock((CMItem *)pFile);
    sySetLastError((NQ_UINT32)res);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res == NQ_SUCCESS;
}

CCFile * ccFileCreateOnServer(
    CCShare * pShare, 
    const NQ_WCHAR * path, 
    NQ_BOOL pathIsLocal,
    NQ_INT access, 
    NQ_INT shareMode,
    NQ_INT locality, 
    NQ_BOOL writeThrough, 
    NQ_UINT16 attributes, 
    NQ_INT createAction, 
    NQ_INT openAction,
    NQ_BOOL isPipe
    )
{
    CCFile * pFile = NULL;  /* file handle */
    NQ_BOOL res;            /* exchange status */
    NQ_INT counter;         /* operation attempts counter */
    const NQ_WCHAR * filePath = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pShare: %s", cmWDump(pShare->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "path: %s", cmWDump(path));

    if (path != NULL)
    {
        filePath = pathIsLocal ? ccUtilsFilePathFromLocalPath(path) : cmMemoryCloneWString(path);
        if (NULL == filePath)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
    }

	if (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
    }

#ifdef UD_CC_INCLUDEDFS
    if (!isPipe && (pShare->flags & CC_SHARE_IN_DFS))
    {
        NQ_WCHAR *dfsFullPath;
        CCMount *pMount;

        pMount = ccMountFind(path);
        if (NULL != pMount)
        { 
            if (NULL != filePath)
            {
                dfsFullPath = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, filePath);
                if (NULL == dfsFullPath)
                {
                    cmMemoryFree(filePath);
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }
                pFile = ccFileCreate(pShare, dfsFullPath);
                cmMemoryFree(dfsFullPath);
            }
        }
    }
    else
#endif  /* UD_CC_INCLUDEDFS */   
    {
        pFile = ccFileCreate(pShare, filePath);
    }
    if (NULL == pFile)
    {
        cmMemoryFree(filePath);
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    pFile->isPipe = isPipe;

    /* convert parameters */
    switch (access)
    {
        case FILE_AM_READ:
            pFile->accessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_READDATA;
            break;
        case FILE_AM_WRITE:
            if (attributes & SMB_ATTR_DIRECTORY)
            pFile->accessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES; 
            else
            pFile->accessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES + SMB_DESIREDACCESS_WRITEDATA; 
            break;
        case FILE_AM_READ_WRITE:
            if (attributes & SMB_ATTR_DIRECTORY)
            pFile->accessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES; 
            else
            pFile->accessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES + SMB_DESIREDACCESS_READDATA + SMB_DESIREDACCESS_WRITEDATA;
            break;
        default:
            pFile->accessMask = (NQ_UINT32)(access & ~CCFILE_ACCESSMASK_SPECIAL); 
            break;
    }
    switch (shareMode)
    {
        case FILE_SM_COMPAT:
            pFile->sharedAccess = SMB_SHAREACCESS_READ;
            if (!(pFile->accessMask & SMB_DESIREDACCESS_WRITEDATA))
                pFile->sharedAccess |= SMB_SHAREACCESS_WRITE;
            if (!(pFile->accessMask & SMB_DESIREDACCESS_DELETE))
                pFile->sharedAccess |= SMB_SHAREACCESS_DELETE;
            break;
        case FILE_SM_DENY_NONE:
            pFile->sharedAccess = SMB_SHAREACCESS_WRITE | SMB_SHAREACCESS_READ | SMB_SHAREACCESS_DELETE;
            break;
        case FILE_SM_DENY_READ:
            pFile->sharedAccess = SMB_SHAREACCESS_WRITE | SMB_SHAREACCESS_DELETE;
            break;
        case FILE_SM_DENY_WRITE:
            pFile->sharedAccess = SMB_SHAREACCESS_READ | SMB_SHAREACCESS_DELETE;
            break;
        case FILE_SM_EXCLUSIVE:
            pFile->sharedAccess = SMB_SHAREACCESS_NONE;
            break;
        default:
            cmMemoryFree(filePath);
            cmListItemUnlock((CMItem *)pFile);
            LOGERR(CM_TRC_LEVEL_ERROR, "Illegal share mode value %d", shareMode);
            sySetLastError(NQ_ERR_BADPARAM);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
    }
    pFile->attributes = 0;
    pFile->disposition = 0;
        
    if (openAction == FILE_OA_FAIL && createAction == FILE_CA_FAIL)
    {
        cmMemoryFree(filePath);
        cmListItemUnlock((CMItem *)pFile);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal combination of action values %d %d", createAction, openAction);
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
        
    switch (createAction)
    {
        case FILE_CA_CREATE:
            pFile->disposition = openAction == FILE_OA_FAIL? 
        SMB_NTCREATEANDX_FILECREATE : openAction == FILE_OA_OPEN? 
        SMB_NTCREATEANDX_FILEOPENIF : SMB_NTCREATEANDX_FILEOVERWRITEIF;
            break;
        case FILE_CA_FAIL:
            pFile->disposition = openAction == FILE_OA_FAIL? 
        SMB_NTCREATEANDX_SUPERSEDE : openAction == FILE_OA_OPEN? 
        SMB_NTCREATEANDX_FILEOPEN : SMB_NTCREATEANDX_FILEOVERWRITE;
            break;
        default:
            cmMemoryFree(filePath);
            cmListItemUnlock((CMItem *)pFile);
            LOGERR(CM_TRC_LEVEL_ERROR, "Illegal combination of action values %d %d", createAction, openAction);
            sySetLastError(NQ_ERR_BADPARAM);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
    }
    pFile->options = 0x0;
    if (attributes & SMB_ATTR_DIRECTORY)
    {
        pFile->options |= SMB_NTCREATEANDX_DIRECTORY;
        pFile->options &= ~(NQ_UINT32)SMB_NTCREATEANDX_NONDIRECTORY;
    }
    if (writeThrough)
        pFile->options |= SMB_NTCREATEANDX_WRITETHROUGH;
    if (locality == FILE_LCL_SEQUENTIAL)
        pFile->options |= SMB_NTCREATEANDX_SEQUENTIAL;
    if (locality == FILE_LCL_RANDOM)
        pFile->options |= SMB_NTCREATEANDX_RANDOMACCESS;       
 
    /* delegate to the protocol */
    pFile->open = FALSE;
    for (counter = CC_CONFIG_RETRYCOUNT ; counter > 0; counter--)
    {
        res = pShare->user->server->smb->doCreate(pFile);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "res: 0x%x", res);
#ifdef UD_CC_INCLUDEDFS        
        if (res == NQ_ERR_PATHNOTCOVERED && !isPipe)
        {
            CCDfsResult dfsResult;  /* result of DFS resolution */

            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "NQ_ERR_PATHNOTCOVERED");
            dfsResult = ccDfsResolvePath(pShare, filePath);
            if (dfsResult.path)
            {
                NQ_WCHAR *pTempPath;
                CCFile *pTempFile;                

                cmMemoryFree(filePath);
                pShare = dfsResult.share;

                pTempPath = dfsResult.share->flags & CC_SHARE_IN_DFS ? cmMemoryCloneWString(dfsResult.path) : ccUtilsFilePathFromRemotePath(dfsResult.path, FALSE);    
                if (NULL == pTempPath)
                {
                    ccDfsResolveDispose(&dfsResult);
                    cmListItemUnlock((CMItem *)pFile);
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }

                pTempFile = ccFileCreate(dfsResult.share, pTempPath);
                cmMemoryFree(pTempPath);                
                if (NULL == pTempFile)
                {
                    ccDfsResolveDispose(&dfsResult);
                    cmListItemUnlock((CMItem *)pFile);
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }
                cloneFileData(pFile, pTempFile);
                cmListItemUnlock((CMItem *)pFile);
                pFile = pTempFile;                
                
                filePath = ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                ccDfsResolveDispose(&dfsResult);
                if (NULL == filePath)
                {
                    cmListItemUnlock((CMItem *)pFile);
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pFile: %s", cmWDump(pFile->item.name));

                counter++;
                continue;
            }         
        }
#endif /* UD_CC_INCLUDEDFS */
        cmMemoryFree(filePath);
        if (res == NQ_SUCCESS)
        {
            pFile->open = TRUE;
            cmU64Zero(&pFile->offset);

            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return pFile;
        }
        if (res == NQ_ERR_RECONNECTREQUIRED)
        {
            
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else
            break;
    }

    cmListItemUnlock((CMItem *)pFile);
    sySetLastError((NQ_UINT32)res);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NULL;
}

NQ_BOOL ccCreateDirectoryA(const NQ_CHAR *pathName)
{
    NQ_WCHAR * pathNameW; /* name in Unicode */
    NQ_BOOL res;          /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (pathName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Path");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    pathNameW = cmMemoryCloneAString(pathName);
    if (NULL == pathNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    res = ccCreateDirectoryW(pathNameW); 
    cmMemoryFree(pathNameW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_BOOL ccCreateDirectoryW(const NQ_WCHAR * remotePath)
{
    CCMount *   pMount;     /* mount point descriptor */
    CCFile      file;       /* file structure */
    NQ_WCHAR *  localPath;  /* path component local to remote share */
    CCShare *   pShare;     /* pointer to the hosting share */
    NQ_BOOL     res;        /* operation result */
    NQ_INT      counter;    /* simple counter */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (remotePath == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Path");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    pMount = ccMountFind(remotePath);
    if (NULL == pMount)
    {
        sySetLastError(NQ_ERR_BADPATH);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    
    pShare = pMount->share;

	if (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }

    file.accessMask = 0x13019b;
    file.attributes = 0;
    file.disposition = 2;
    file.options = 0x1;
    file.share = pShare;
    file.sharedAccess = 0;

#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
    {
        file.item.name = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, remotePath);
    }
    else
#endif  /* UD_CC_INCLUDEDFS */  
    {
        file.item.name = ccUtilsFilePathFromLocalPath(remotePath);
    }
    if (NULL == file.item.name)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    localPath = ccUtilsFilePathFromLocalPath(remotePath);
    if (NULL == localPath)
    {
        cmMemoryFree(file.item.name);
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "file.item.name: %s", cmWDump(file.item.name));

    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        res = pShare->user->server->smb->doCreate(&file);
#ifdef UD_CC_INCLUDEDFS        
        if (res == NQ_ERR_PATHNOTCOVERED)
        {
            CCDfsResult dfsResult;  /* result of DFS resolution */

            dfsResult = ccDfsResolvePath(pShare, localPath);
            cmMemoryFree(localPath);
            if (dfsResult.path)
            {
                file.share = pShare = dfsResult.share;

                cmMemoryFree(file.item.name);
                file.item.name = dfsResult.share->flags & CC_SHARE_IN_DFS ? 
                                    cmMemoryCloneWString(dfsResult.path) : 
                                    ccUtilsFilePathFromRemotePath(dfsResult.path, FALSE); 
                if (NULL == file.item.name)
                {
                    ccDfsResolveDispose(&dfsResult);                    
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return FALSE;
                }
                
                localPath = ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                ccDfsResolveDispose(&dfsResult);                    
                if (NULL == localPath)
                {
                    cmMemoryFree(file.item.name);
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return FALSE;
                }

                counter++;
                continue;
            }
        }
#endif        
        if (NQ_ERR_RECONNECTREQUIRED == res)
        {
            pShare->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pShare->user->server))
                break;
        }
        else
            break;
    }
    if (NQ_SUCCESS != res)
    {
        sySetLastError((NQ_UINT32)res);
        cmMemoryFree(file.item.name);
        cmMemoryFree(localPath);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    pShare->user->server->smb->doClose(&file);
    cmMemoryFree(file.item.name);
    cmMemoryFree(localPath);
      
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_BOOL ccRemoveDirectoryA(const NQ_CHAR * remotePath)
{
    return ccDeleteFileA(remotePath);
}

NQ_BOOL ccRemoveDirectoryW(const NQ_WCHAR * remotePath)
{
    return ccDeleteFileW(remotePath);
}

NQ_BOOL ccDeleteFileA(const NQ_CHAR * fileName)
{
    NQ_WCHAR * fileNameW; /* name in Unicode */
    NQ_BOOL res;          /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (fileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid File Name");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL == fileNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    res = ccDeleteFileW(fileNameW); 
    cmMemoryFree(fileNameW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_BOOL ccDeleteFileW(const NQ_WCHAR * fileName)
{
    CCFile *    pFile;      /* open file handle */
    NQ_STATUS   res;        /* operation result */
    NQ_UINT32   attributes; /* file attributes */
    NQ_INT      counter;    /* simple counter*/

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (fileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid File Name");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    attributes = ccGetFileAttributesW(fileName);
    pFile = ccCreateFileW(
            fileName, 
            CCFILE_ACCESSMASK_SPECIAL | SMB_DESIREDACCESS_DELETE | SMB_DESIREDACCESS_READATTRIBUTES, 
            FILE_SM_DENY_NONE, 
            FILE_LCL_UNKNOWN, 
            FALSE, 
            (NQ_UINT16)attributes, 
            FILE_CA_FAIL, 
            FILE_OA_OPEN
            );
    if (NULL == pFile)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileDeleteOnClose(pFile);
        if (NQ_ERR_RECONNECTREQUIRED == res)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else
        {
            ccCloseHandle(pFile);
            break;
        }
    }
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to write file information");
        sySetLastError((NQ_UINT32)res);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_BOOL ccMoveFileA(const NQ_CHAR * oldFileName, const NQ_CHAR * newFileName)
{
    NQ_WCHAR * oldFileNameW;  /* name in Unicode */
    NQ_WCHAR * newFileNameW;  /* name in Unicode */
    NQ_BOOL res;        /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (oldFileName == NULL || newFileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    oldFileNameW = cmMemoryCloneAString(oldFileName);
    if (NULL == oldFileNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    newFileNameW = cmMemoryCloneAString(newFileName);
    if (NULL == newFileNameW)
    {
        cmMemoryFree(oldFileNameW);
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    res = ccMoveFileW(oldFileNameW, newFileNameW); 
    cmMemoryFree(oldFileNameW);
    cmMemoryFree(newFileNameW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_BOOL ccMoveFileW(const NQ_WCHAR * oldFileName, const NQ_WCHAR * newFileName)
{
    CCMount *   pMount;                 /* mount point descriptor */
    CCFile *    pFile;                  /* open file handle */
    NQ_WCHAR *  newLocalPath = NULL;    /* path component local to remote share */
    NQ_STATUS   res;                    /* operation result */
    NQ_INT      counter;                /* simple counter */
    NQ_BOOL     createBeforeMove;       /* saved dialect flag */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"from: %s", cmWDump(oldFileName));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"to: %s", cmWDump(newFileName));

    if (oldFileName == NULL || newFileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    
    /* rename to itself should always succeed */
    if (0 == cmWStrcmp(oldFileName, newFileName))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }
    pMount = ccMountFind(oldFileName);
    if (NULL == pMount)
    {
        sySetLastError(NQ_ERR_BADPATH);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    if (pMount != ccMountFind(newFileName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot move files between different trees");
        sySetLastError(NQ_ERR_DIFFDEVICE);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    /*  SMB does need file to be open. It is good to open it anyway to just check access 
        rights for deletion. 
        Then, SMB will close file inside.
    */
    pFile = ccCreateFileW(
            oldFileName, 
            CCFILE_ACCESSMASK_SPECIAL | SMB_DESIREDACCESS_DELETE,  
            FILE_SM_DENY_NONE, 
            FILE_LCL_UNKNOWN, 
            FALSE, 
            0, 
            FILE_CA_FAIL, 
            FILE_OA_OPEN
            );
    if (NULL == pFile)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }   

#ifdef UD_CC_INCLUDEDFS  
    {  
        NQ_WCHAR *resolvedPath = NULL;

        ccCheckPath(newFileName, FALSE, &resolvedPath);
        if (NULL != resolvedPath)
        {
            /* SMB1 requires full path for a new name, while SMB2 requires relative path */
            if (pFile->share->user->server->smb->useFullPath)
            {
                newLocalPath = cmMemoryCloneWString(resolvedPath);
            }
            else
            {
                if (pFile->share->flags & CC_SHARE_IN_DFS)
                    newLocalPath = ccUtilsFilePathFromRemotePath(resolvedPath, TRUE);  
                else
                    newLocalPath = (*resolvedPath == cmWChar('\\')) ? 
                                    cmMemoryCloneWString(resolvedPath + 1) : 
                                    cmMemoryCloneWString(resolvedPath);
             }
            cmMemoryFree(resolvedPath);
        }
    }   
#endif /* UD_CC_INCLUDEDFS */

    if (NULL == newLocalPath)
    {
        newLocalPath = ccUtilsFilePathFromLocalPath(newFileName);
        if (NULL == newLocalPath)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return FALSE;
        }
    }

    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"pFile: %s", cmWDump(pFile->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"pFile->share: %s", cmWDump(pFile->share->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"newLocalPath: %s", cmWDump(newLocalPath));

    /* save the dialect flag since it may be not available after rename */
    createBeforeMove = pFile->share->user->server->smb->createBeforeMove;
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doRename(pFile, newLocalPath);
        if (NQ_ERR_RECONNECTREQUIRED == res)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
            {
                cmMemoryFree(newLocalPath);
                LOGERR(CM_TRC_LEVEL_ERROR, "Unable to write file information (Connection Lost)");
                sySetLastError((NQ_UINT32)res);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return FALSE;
            }
        }
        else
            break;
    }
    /* SMB may close file inside so that the next call will fail. We do not check its status anyway */
    if (createBeforeMove)
        ccCloseHandle(pFile);
    cmMemoryFree(newLocalPath);
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to write file information");
        sySetLastError((NQ_UINT32)res);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_UINT64 ccGetFilePointer(NQ_HANDLE handle)
{
    CCFile * pFile = (CCFile *)handle;  /* casted file pointer */
    const NQ_UINT64 none = {(NQ_UINT32)-1, (NQ_UINT32)-1};      /* none offset */


    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (handle == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return none;
    }

    /* Check CIFS Client is initialized */
    if (ccIsInitialized())
    {
        if (!pFile->open)
        {
            sySetLastError(NQ_ERR_INVALIDHANDLE);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return none;
        }
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return pFile->offset; 
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return none; 
    }
}

NQ_UINT32 ccSetFilePointer(NQ_HANDLE handle, NQ_INT32 lowOffset, NQ_INT32 * highOffset, NQ_INT moveMethod)
{
    CCFile * pFile = (CCFile *)handle;  /* casted file pointer */
    NQ_INT64 offset;          /* required offset in a civilized form */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "handle: %p", handle);

    if (handle == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_INVALIDHANDLE;
    }
    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_SEEKERROR;
    }
    if (!pFile->open)
    {
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_SEEKERROR;
    }
    if (highOffset == NULL)
    {
        offset.high = 0;

        if (lowOffset < 0)
        {
            offset.low = (NQ_UINT32)(-lowOffset);
            offset.sign = -1;
        }
        else
        {
            offset.low = (NQ_UINT32)lowOffset;
            offset.sign = 1;
        }
    }
    else
    {
        offset.low = (NQ_UINT32)lowOffset;

        if (*highOffset < 0)
        {
            offset.high = (NQ_UINT32)(-*highOffset - 1);
            offset.low = (NQ_UINT32)(-(NQ_INT32)offset.low);
            offset.sign = -1;
        }
        else
        {
            offset.high = (NQ_UINT32)*highOffset;
            offset.sign = 1;
        }
    }

    cmListItemTake((CMItem *)pFile);

    switch (moveMethod)
    {
        case SEEK_FILE_BEGIN:
            pFile->offset.low = offset.low;
            pFile->offset.high = offset.high;
            break;

        case SEEK_FILE_CURRENT:
            cmU64AddS64(&pFile->offset, &offset);
            break;

        case SEEK_FILE_END:
            pFile->offset.low = ccGetFileSize(pFile, &pFile->offset.high);
            cmU64AddS64(&pFile->offset, &offset);
            break;

        default:
            cmListItemGive((CMItem *)pFile);
            LOGERR(CM_TRC_LEVEL_ERROR, "Invalid move metod: %d", moveMethod);
            sySetLastError(NQ_ERR_BADPARAM);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_ERR_SEEKERROR;
    }
    cmListItemGive((CMItem *)pFile);

    if (highOffset != NULL)
        *highOffset = (NQ_INT32)pFile->offset.high;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pFile->offset.low;
}

NQ_BOOL ccFlushFile(NQ_HANDLE handle)
{
    CCFile *            pFile;				        /* casted file pointer */
    NQ_STATUS           res;                        /* operation result */
    NQ_INT              counter;                    /* simple counter*/

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (handle == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    pFile = (CCFile *)handle;
    if (!pFile->open)
	{
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }

    for (counter = 0 ; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doFlush(pFile);
        if (NQ_ERR_RECONNECTREQUIRED == res)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else
            break;
    }
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to flush file");
        sySetLastError((NQ_UINT32)res);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_BOOL ccFileReportDisconnect(CCFile * pFile)
{
    NQ_BOOL res;    /* call result */ 

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    /* We reconnect the entire server, including all its users, shares. files.
    * If after reconnect this file becomes connected - we succeeded.
    */ 
    pFile->open = FALSE;
    res = ccServerReconnect(pFile->share->user->server);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res && pFile->open;
}

NQ_BOOL ccFileRestore(CCFile * pFile)
{
    NQ_BOOL res;    /* call result */ 

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    res = pFile->share->user->server->smb->doRestoreHandle(pFile);
    pFile->open = res == NQ_SUCCESS;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS == res;
}


#endif /* UD_NQ_INCLUDECIFSCLIENT */

