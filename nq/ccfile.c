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
#include "ccparams.h"
#include "cmfscifs.h"
#include "ccdfs.h"
#include "cmlist.h"
#include "ccsmb10.h"
#include "ccinfo.h"
#include "cmsmb2.h"

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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p", pFile);
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
#if defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE)
    CCFile * pFile = (CCFile *)pItem;
    NQ_BYTE * fid = pFile->fid;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  File:: FID: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x access: %08x", \
          fid[0], fid[1], fid[2], fid[3],   \
          fid[4], fid[5], fid[6], fid[7],   \
          fid[8], fid[9], fid[10], fid[11], \
          fid[12], fid[13], fid[14], fid[15], \
          pFile->accessMask             \
           );
#endif /* defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE) */
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
    CCFile * pFile;                 /* next file pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p id:%p", pServer, id);

    cmListItemTake((CMItem *)pServer);    /* MR - Roseville July 7, 2014 */
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
            while (cmListIteratorHasNext(&fileIterator))
            {
                pFile = (CCFile *)cmListIteratorNext(&fileIterator);
                if (0 == syMemcmp(id, pFile->fid, sizeof(pFile->fid)))
                {
                    cmListIteratorTerminate(&shareIterator);
                    cmListIteratorTerminate(&fileIterator);
                    goto Exit;
                }
            }
            cmListIteratorTerminate(&fileIterator);
        }
        cmListIteratorTerminate(&shareIterator);
    }
    pFile = NULL;

Exit:
    cmListIteratorTerminate(&userIterator);
    cmListItemGive((CMItem *)pServer);    /* MR - Roseville July 7, 2014 */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pFile);
    return pFile;
}

NQ_HANDLE ccGetFileHandleByName(const NQ_CHAR *path, NQ_INT desiredAccess, NQ_UINT32 desiredSharedAccess, NQ_BYTE desiredOpLock, NQ_UINT16 attributes)
{
    CCFile 	*pFile = NULL;                 /* next file pointer */
    CCMount *pMount;
    CMIterator iterator;
    NQ_UINT32 desiredAccessMask;
    NQ_UINT32 requiredShareAccess;
    NQ_WCHAR *pathW = NULL;
    NQ_WCHAR *filePath = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s ", path);
    if (NULL == path)
	{
		LOGERR(CM_TRC_LEVEL_ERROR , "Invalid path");
		sySetLastError(NQ_ERR_BADPARAM);
		goto Exit1;
	}

	pathW = cmMemoryCloneAString(path);

    if (NULL == pathW)
    {
    	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Out of memory.");
    	sySetLastError(NQ_ERR_NOMEM);
    	goto Exit1;
    }

    if (ccUtilsPathIsLocal(pathW))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open mount point");
		sySetLastError(NQ_ERR_BADPARAM);
		goto Exit1;
	}

    pMount = ccMountFind(pathW);
    if (NULL == pMount)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Cannot find mount point");
    	goto Exit1;
    }

    filePath = ccUtilsFilePathFromLocalPath(pathW, pMount->pathPrefix, pMount->share->user->server->smb->revision == CCCIFS_ILLEGALSMBREVISION, TRUE);
	if (NULL == filePath)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		goto Exit1;
	}

    cmListIteratorStart(&(pMount->share->files), &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		pFile = (CCFile *)cmListIteratorNext(&iterator);
		if (NULL != pFile->item.name && 0 == cmWStricmp(filePath, pFile->item.name))
		{
			if (!pFile->item.findable)
			{
				continue;
			}

			/* check this item had desired properties */
			if (desiredOpLock > pFile->grantedOplock)
			{
				continue;
			}

			switch (desiredAccess)
			{
				case FILE_AM_READ:
					desiredAccessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_READDATA;
					break;
				case FILE_AM_WRITE:
					if (attributes & SMB_ATTR_DIRECTORY)
						desiredAccessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES;
					else
						desiredAccessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES + SMB_DESIREDACCESS_WRITEDATA;
					break;
				case FILE_AM_READ_WRITE:
					if (attributes & SMB_ATTR_DIRECTORY)
						desiredAccessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES;
					else
						desiredAccessMask = ACCESSMASKDEFAULT + SMB_DESIREDACCESS_WRITEATTRIBUTES + SMB_DESIREDACCESS_READDATA + SMB_DESIREDACCESS_WRITEDATA;
					break;
				default:
						desiredAccessMask = ACCESSMASKDEFAULT;
					break;
			}

			if ((pFile->accessMask & desiredAccessMask) != desiredAccessMask)
			{
				continue;
			}

			switch (desiredSharedAccess)
			{
			case FILE_SM_COMPAT:
				{
					requiredShareAccess = SMB_SHAREACCESS_READ;
					if (!(desiredAccessMask & SMB_DESIREDACCESS_WRITEDATA))
						requiredShareAccess |= SMB_SHAREACCESS_WRITE;
					if (!(desiredAccessMask & SMB_DESIREDACCESS_DELETE))
						requiredShareAccess |= SMB_SHAREACCESS_DELETE;
				}
				break;
			case FILE_SM_DENY_NONE:
				requiredShareAccess = SMB_SHAREACCESS_WRITE | SMB_SHAREACCESS_READ | SMB_SHAREACCESS_DELETE;
				break;
			case FILE_SM_DENY_READ:
				requiredShareAccess = SMB_SHAREACCESS_WRITE | SMB_SHAREACCESS_DELETE;
				break;
			case FILE_SM_DENY_WRITE:
				requiredShareAccess = SMB_SHAREACCESS_READ | SMB_SHAREACCESS_DELETE;
				break;
			case FILE_SM_EXCLUSIVE:
				/* no break */
			default:
				requiredShareAccess = SMB_SHAREACCESS_NONE;
				break;
			}
			if ((pFile->sharedAccess & requiredShareAccess) != requiredShareAccess)
			{
				continue;
			}

			goto Exit;

		}
	}
    pFile = NULL;


Exit:
	cmListIteratorTerminate(&iterator);
Exit1:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pFile);
    cmMemoryFree(pathW);
    cmMemoryFree(filePath);
    return (NQ_HANDLE)pFile;
}


CCFile * ccFileCreate(CCShare * pShare, const NQ_WCHAR * path)
{
    CCFile * pFile;       /* File pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p path:%s", pShare, cmWDump(path));

    /* we do not care of another file with the same name */
    pFile = (CCFile *)cmListItemCreateAndAdd(&pShare->files, sizeof(CCFile), path, unlockCallback, CM_LISTITEM_LOCK);
    if (NULL == pFile)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        cmListItemCheck((CMItem *)pShare);    /* try disposal */
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pFile: %s", cmWDump(pFile->item.name));
    pFile->grantedOplock = SMB2_OPLOCK_LEVEL_NONE;
    pFile->open = FALSE;
    pFile->share = pShare;
    pFile->disconnected = FALSE;
#ifdef UD_NQ_INCLUDESMB2
    pFile->durableState = DURABLE_REQUIRED;
    pFile->durableFlags = 0;
    pFile->durableTimeout = 0;
    cmGenerateUuid(&pFile->durableHandle);
#endif /* UD_NQ_INCLUDESMB2 */
    cmListItemAddReference((CMItem *)pFile, (CMItem *)pShare);
#if SY_DEBUGMODE
    pFile->item.dump = dumpOne;
#endif /* SY_DEBUGMODE */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pFile);
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
    NQ_WCHAR * fileNameW = NULL; /* name in Unicode */
    NQ_HANDLE res = NULL;        /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (NULL == fileName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL == fileNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = ccCreateFileW(fileNameW, access, shareMode, locality, writeThrough, attributes, createAction, openAction);

Exit:
    cmMemoryFree(fileNameW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", res);
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
    CCMount * pMount;      /* mount point descriptor */
    CCFile * pFile = NULL; /* file handle */
    CCShare * pShare;      /* pointer to the hosting share */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s access:%d mode:%d local:%d write:%s attr:0x%x create:%d open:%d", cmWDump(fileName), access, shareMode, locality, writeThrough ? "TRUE" : "FALSE", attributes, createAction, openAction);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fileName: %s", cmWDump(fileName));

    if (NULL == fileName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    if (ccUtilsPathIsLocal(fileName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open mount point");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    pMount = ccMountFind(fileName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot find mount point");
        sySetLastError(NQ_ERR_BADPATH);
        goto Exit;
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
            FALSE,
			FILE_OPLOCK_LEVEL_BATCH
            );

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pFile);
    return (NQ_HANDLE)pFile;
}

NQ_HANDLE ccCreateFileNoBatch(
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
    CCMount * pMount;      /* mount point descriptor */
    CCFile * pFile = NULL; /* file handle */
    CCShare * pShare;      /* pointer to the hosting share */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s access:%d mode:%d local:%d write:%s attr:0x%x create:%d open:%d", cmWDump(fileName), access, shareMode, locality, writeThrough ? "TRUE" : "FALSE", attributes, createAction, openAction);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fileName: %s", cmWDump(fileName));

    if (NULL == fileName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    if (ccUtilsPathIsLocal(fileName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open mount point");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    pMount = ccMountFind(fileName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot find mount point");
        sySetLastError(NQ_ERR_BADPATH);
        goto Exit;
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
            FALSE,
			FILE_OPLOCK_LEVEL_NONE
            );

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pFile);
    return (NQ_HANDLE)pFile;
}

NQ_BOOL ccCloseHandle(NQ_HANDLE handle)
{
    CCFile *    pFile = (CCFile *)handle;   /* casted pointer to file */
    NQ_STATUS   res;                        /* exchange status */
    NQ_INT      counter;                    /* simple counter*/
    NQ_BOOL     result = FALSE;             /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);

    if (NULL == handle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "NULL Handle");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    if (!ccValidateFileHandle(handle))
    {
    	cmListItemUnlock((CMItem *)pFile); /* remove one lock for one use*/
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }

    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT ; counter++)
    {
        res = pFile->share->user->server->smb->doClose(pFile);
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else if ((NQ_STATUS)NQ_ERR_TRYAGAIN == res)
		{
			/* possible reconnect caused a wrong user session or wrong FID */
        	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "operation failed. Try again");
			continue;
		}
		else
		{
			break;
		}
    }
    pFile->open = FALSE;

    cmListItemUnlock((CMItem *)pFile);
    sySetLastError((NQ_UINT32)res);
    result = (res == NQ_SUCCESS);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
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
    NQ_BOOL isPipe,
	NQ_INT oplockLevel
    )
{
    CCFile * pFile = NULL;  /* file handle */
    NQ_BOOL res = TRUE;            /* exchange status */
    NQ_INT counter;         /* operation attempts counter */
    const NQ_WCHAR * filePath = NULL;
#ifdef UD_CC_INCLUDEDFS
    CCDfsContext dfsContext = {CC_DFS_NUMOFRETRIES, 0, NULL}; /* DFS operations context */
    CCDfsResult dfsResult = {NULL, NULL, NULL};  /* result of DFS resolution */
#endif /* UD_CC_INCLUDEDFS */
    CCMount *pMount = NULL; /* pointer to mount point */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pShare:%s path:%s", cmWDump(pShare->item.name), path ? cmWDump(path) : "");
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pShare: %s", cmWDump(pShare->item.name));*/
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "path: %s", path ? cmWDump(path) : "");*/

    if (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }

    if (path != NULL)
    {
        pMount = ccMountFind(path);
        filePath = ccUtilsFilePathFromLocalPath(path, pMount ? pMount->pathPrefix : NULL, pShare->user->server->smb->revision == CCCIFS_ILLEGALSMBREVISION, pathIsLocal);
        if (NULL == filePath)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }
    }

#ifdef UD_CC_INCLUDEDFS
    if (!isPipe && !pShare->isPrinter && (pShare->flags & CC_SHARE_IN_DFS))
    {
        NQ_WCHAR *dfsFullPath;

        if (NULL != pMount)
        {
            if (NULL != filePath)
            {
                dfsFullPath = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, filePath, FALSE);
                if (NULL == dfsFullPath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
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
            LOGERR(CM_TRC_LEVEL_ERROR, "Illegal share mode value %d", shareMode);
            sySetLastError(NQ_ERR_BADPARAM);
            goto Error;
    }
    pFile->attributes = 0;
    pFile->disposition = SMB2_CREATEDISPOSITION_SUPERSEDE;

    if (openAction == FILE_OA_FAIL && createAction == FILE_CA_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal combination of action values %d %d", createAction, openAction);
        sySetLastError(NQ_ERR_BADPARAM);
        goto Error;
    }

    switch (oplockLevel)
    {
    	case FILE_OPLOCK_LEVEL_NONE:
    		pFile->grantedOplock = SMB2_OPLOCK_LEVEL_NONE;
    		break;
    	case FILE_OPLOCK_LEVEL_II:
    		pFile->grantedOplock = SMB2_OPLOCK_LEVEL_II;
    		break;
    	case FILE_OPLOCK_LEVEL_BATCH:
    	default:
    		pFile->grantedOplock = SMB2_OPLOCK_LEVEL_BATCH;
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
			SMB_NTCREATEANDX_FILESUPERSEDE : openAction == FILE_OA_OPEN ?
        SMB_NTCREATEANDX_FILEOPEN : SMB_NTCREATEANDX_FILEOVERWRITE;
            break;
        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Illegal combination of action values %d %d", createAction, openAction);
            sySetLastError(NQ_ERR_BADPARAM);
            goto Error;
    }

    pFile->options = SMB2_CREATEOPTIONS_NONE;
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

    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        res = pShare->user->server->smb->doCreate(pFile);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "doCreate result: 0x%x", res);
#ifdef UD_CC_INCLUDEDFS
        if (ccDfsIsError(dfsContext.lastError = res) && !isPipe)
        {
            dfsResult.path = NULL;

            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "DFS related error %s", res == NQ_ERR_PATHNOTCOVERED ? ": NQ_ERR_PATHNOTCOVERED" : "");

            if (--dfsContext.counter < 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "DFS failed to resolve path: too many attempts");
                break;
            }
            dfsResult = ccDfsResolvePath(pMount, pShare, filePath, &dfsContext);
            if (dfsResult.path)
            {
                NQ_WCHAR *pTempPath;
                CCFile *pTempFile;

                cmMemoryFree(filePath);
                filePath = NULL;

                pShare = dfsResult.share;

                pTempPath = dfsResult.share->flags & CC_SHARE_IN_DFS ? cmMemoryCloneWString(dfsResult.path) : ccUtilsFilePathFromRemotePath(dfsResult.path, FALSE);
                if (NULL == pTempPath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Error;
                }

                pTempFile = ccFileCreate(dfsResult.share, pTempPath);
                cmMemoryFree(pTempPath);
                if (NULL == pTempFile)
                {
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Error;
                }
                cloneFileData(pFile, pTempFile);
                cmListItemUnlock((CMItem *)pFile);
                pFile = pTempFile;

                filePath = ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                ccDfsResolveDispose(&dfsResult);
                dfsResult.path = NULL;
                if (NULL == filePath)
                {
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Error;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pFile: %s", cmWDump(pFile->item.name));

                counter++;
                continue;
            }
        }
#endif /* UD_CC_INCLUDEDFS */
        cmMemoryFree(filePath);
        filePath = NULL;
        if (res == NQ_SUCCESS)
        {
            pFile->open = TRUE;
            cmU64Zero(&pFile->offset);
            pShare->user->server->smb->handleWaitingNotifyResponses(pShare->user->server, pFile);
            goto Exit;
        }
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else if ((NQ_STATUS)NQ_ERR_TRYAGAIN == res)
		{
			/* possible reconnect caused a wrong user session */
        	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "operation failed. Try again");
        	continue;
		}
        else
            break;
    }

Error:
    if (NULL != pFile)
    {
        cmListItemUnlock((CMItem *)pFile);
        pFile = NULL;
    }
#ifdef UD_CC_INCLUDEDFS
    if (NULL != dfsResult.path)
        ccDfsResolveDispose(&dfsResult);
#endif /* UD_CC_INCLUDEDFS */
    sySetLastError((NQ_UINT32)res);

Exit:
    cmMemoryFree(filePath);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pFile);
    return pFile;
}

NQ_BOOL ccCreateDirectoryA(const NQ_CHAR *pathName)
{
    NQ_WCHAR * pathNameW; /* name in Unicode */
    NQ_BOOL res = FALSE;  /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (NULL == pathName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Path");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pathNameW = cmMemoryCloneAString(pathName);
    if (NULL == pathNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = ccCreateDirectoryW(pathNameW);
    cmMemoryFree(pathNameW);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccCreateDirectoryW(const NQ_WCHAR * remotePath)
{
    CCMount *   pMount;            /* mount point descriptor */
    CCFile      file;              /* file structure */
    NQ_WCHAR *  localPath = NULL;  /* path component local to remote share */
    CCShare *   pShare;            /* pointer to the hosting share */
    NQ_BOOL     res;               /* operation result */
    NQ_INT      counter;           /* simple counter */
#ifdef UD_CC_INCLUDEDFS
    CCDfsContext dfsContext = {CC_DFS_NUMOFRETRIES, 0, NULL}; /* DFS operations context */
    CCDfsResult dfsResult = {NULL, NULL, NULL};               /* result of DFS resolution */
#endif /* UD_CC_INCLUDEDFS */
    NQ_BOOL     result = FALSE;    /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s", cmWDump(remotePath));

    /* for error handling */
    file.item.name = NULL;

    if (NULL == remotePath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Path");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pMount = ccMountFind(remotePath);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot find mount point");
        sySetLastError(NQ_ERR_BADPATH);
        goto Exit;
    }

    pShare = pMount->share;

    if (pShare->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot create directory on a printer share");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    if (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }

    file.grantedOplock = SMB2_OPLOCK_LEVEL_BATCH;
    file.accessMask = SMB_DESIREDACCESS_SYNCHRONISE | SMB_DESIREDACCESS_READCONTROL| SMB_DESIREDACCESS_DELETE |
    				  SMB_DESIREDACCESS_WRITEATTRIBUTES| SMB_DESIREDACCESS_READATTRIBUTES | SMB_DESIREDACCESS_WRITEEA |
    				  SMB_DESIREDACCESS_READDATA | SMB_DESIREDACCESS_WRITEDATA | SMB_DESIREDACCESS_READEA; /*0x13019b*/
    file.attributes = CIFS_ATTR_DIR;
    file.disposition = SMB2_CREATEDISPOSITION_CREATE;
    file.options = SMB2_CREATEOPTIONS_DIRECTORY_FILE;
    file.share = pShare;
    file.sharedAccess = SMB_SHAREACCESS_NONE;
#ifdef UD_NQ_INCLUDESMB2
    file.durableState = DURABLE_REQUIRED;
    file.durableFlags = 0;
    file.durableTimeout = 0;
#endif /* UD_NQ_INCLUDESMB2 */
#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
    {
        file.item.name = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, remotePath, TRUE);
    }
    else
#endif  /* UD_CC_INCLUDEDFS */
    {
        file.item.name = ccUtilsFilePathFromLocalPath(remotePath, pMount->pathPrefix, pShare->user->server->smb->revision == CCCIFS_ILLEGALSMBREVISION, TRUE);
    }
    if (NULL == file.item.name)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "file portion of the path: %s", cmWDump(file.item.name));
    localPath = ccUtilsFilePathFromLocalPath(remotePath, pMount->pathPrefix, pShare->user->server->smb->revision == 1, TRUE);
    if (NULL == localPath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        res = pShare->user->server->smb->doCreate(&file);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "doCreate result: 0x%x", res);
#ifdef UD_CC_INCLUDEDFS
        if (ccDfsIsError(dfsContext.lastError = res))
        {
            dfsResult.path = NULL;

            if (--dfsContext.counter < 0)
            {
                LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "DFS related error %s", res == NQ_ERR_PATHNOTCOVERED ? ": NQ_ERR_PATHNOTCOVERED" : "");
                break;
            }
            dfsResult = ccDfsResolvePath(pMount, pShare, localPath, &dfsContext);
            if (dfsResult.path)
            {
                file.share = pShare = dfsResult.share;

                cmMemoryFree(file.item.name);
                file.item.name = dfsResult.share->flags & CC_SHARE_IN_DFS ?
                                    cmMemoryCloneWString(dfsResult.path) :
                                    ccUtilsFilePathFromRemotePath(dfsResult.path, FALSE);
                if (NULL == file.item.name)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memoroy");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
                }
                cmMemoryFree(localPath);
                localPath = ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                ccDfsResolveDispose(&dfsResult);
                dfsResult.path = NULL;
                if (NULL == localPath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memoroy");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
                }

                counter++;
                continue;
            }
        }
#endif
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
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
        LOGERR(CM_TRC_LEVEL_ERROR, "status:%d", res);
        sySetLastError((NQ_UINT32)res);
        goto Exit;
    }
    pShare->user->server->smb->doClose(&file);
    result = TRUE;

Exit:
    cmMemoryFree(file.item.name);
    cmMemoryFree(localPath);
#ifdef UD_CC_INCLUDEDFS
    if (dfsResult.path)
        ccDfsResolveDispose(&dfsResult);
#endif /* UD_CC_INCLUDEDFS */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
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
    NQ_WCHAR * fileNameW = NULL; /* name in Unicode */
    NQ_BOOL res = FALSE;  /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (NULL == fileName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid File Name");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL == fileNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = ccDeleteFileW(fileNameW);

Exit:
    cmMemoryFree(fileNameW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccDeleteFileW(const NQ_WCHAR * fileName)
{
    CCFile *    pFile = NULL;       /* open file handle */
    NQ_STATUS   res = NQ_SUCCESS;   /* operation result */
    NQ_UINT32   attributes;         /* file attributes */
    NQ_INT      counter;            /* simple counter*/
    NQ_BOOL     result = FALSE;     /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s", cmWDump(fileName));

    if (NULL == fileName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid File Name");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    attributes = ccGetFileAttributesW(fileName);

    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fileName: %s, attributes: 0x%x", cmWDump(fileName), attributes);

    pFile = (CCFile *)ccCreateFileW(
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
        LOGERR(CM_TRC_LEVEL_ERROR , "File was not created");
        goto Exit;
    }
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot delete on a printer share");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileDeleteOnClose(pFile);
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else if ((NQ_STATUS)NQ_ERR_TRYAGAIN == res)
		{
			/* possible reconnect caused a wrong user session or wrong FID */
        	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "operation failed. Try again");
			continue;
		}
		else
		{
			break;
		}
    }
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to delete file or directory");
        goto Exit;
    }

    result = TRUE;

Exit:
    if (NULL != pFile)
        ccCloseHandle(pFile);
    if (NQ_SUCCESS != res)
        sySetLastError((NQ_UINT32)res);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccMoveFileA(const NQ_CHAR * oldFileName, const NQ_CHAR * newFileName)
{
    NQ_WCHAR * oldFileNameW = NULL;  /* name in Unicode */
    NQ_WCHAR * newFileNameW = NULL;  /* name in Unicode */
    NQ_BOOL    res = FALSE;          /* delegated call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (oldFileName == NULL || newFileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    oldFileNameW = cmMemoryCloneAString(oldFileName);
    if (NULL == oldFileNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    newFileNameW = cmMemoryCloneAString(newFileName);
    if (NULL == newFileNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = ccMoveFileW(oldFileNameW, newFileNameW);

Exit:
    cmMemoryFree(oldFileNameW);
    cmMemoryFree(newFileNameW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccMoveFileW(const NQ_WCHAR * oldFileName, const NQ_WCHAR * newFileName)
{
    CCMount *   pMount;                   /* mount point descriptor */
    CCFile *    pFile;                    /* open file handle */
    NQ_WCHAR *  newLocalPath = NULL;      /* path component local to remote share */
    NQ_STATUS   res = NQ_SUCCESS;         /* operation result */
    NQ_INT      counter;                  /* simple counter */
    NQ_BOOL     createBeforeMove = FALSE; /* saved dialect flag */
    NQ_BOOL     result = FALSE;           /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "from:%s to:%s", cmWDump(oldFileName), cmWDump(newFileName));
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"from: %s", cmWDump(oldFileName));*/
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"to: %s", cmWDump(newFileName));*/

    if (oldFileName == NULL || newFileName == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid FileName");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    /* rename to itself should always succeed */
    if (0 == cmWStrcmp(oldFileName, newFileName))
    {
        result = TRUE;
        goto Exit;
    }
    pMount = ccMountFind(oldFileName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot find mount point");
        sySetLastError(NQ_ERR_BADPATH);
        goto Exit;
    }
    if (pMount->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot move files on a printer share");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (pMount != ccMountFind(newFileName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot move files between different trees");
        sySetLastError(NQ_ERR_DIFFDEVICE);
        goto Exit;
    }

    /*  SMB does not need file to be open. It is good to open it anyway to just check access
        rights for deletion.
        Then, SMB will close file inside.
    */
    pFile = (CCFile *)ccCreateFileW(
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot create file");
        goto Exit;
    }

    /* save the dialect flag since it may be not available after rename */
    createBeforeMove = pFile->share->user->server->smb->createBeforeMove;

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
            if (NULL == newLocalPath)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                sySetLastError(NQ_ERR_OUTOFMEMORY);
                goto Exit;
            }
        }
    }
#endif /* UD_CC_INCLUDEDFS */

    if (NULL == newLocalPath)
    {
        newLocalPath = ccUtilsFilePathFromLocalPath(newFileName, pMount->pathPrefix, pFile->share->user->server->smb->revision == CCCIFS_ILLEGALSMBREVISION, TRUE);
        if (NULL == newLocalPath)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }
    }

    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"pFile: %s", cmWDump(pFile->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"pFile->share: %s", cmWDump(pFile->share->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS,"newLocalPath: %s", cmWDump(newLocalPath));

    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doRename(pFile, newLocalPath);
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
            {
                /* reconnection cleans up everything, so doesn't need to close pFile anymore */
                createBeforeMove = FALSE;
                LOGERR(CM_TRC_LEVEL_ERROR, "Unable to rename file (Connection Lost)");
                sySetLastError((NQ_UINT32)res);
                goto Exit;
            }
        }
        else
            break;
    }
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to rename file");
        sySetLastError((NQ_UINT32)res);
        goto Exit;
    }

    result = TRUE;

Exit:
    /* SMB2 (TRUE) requires to create the file before moving it but SMB1 (FALSE) doesn't. */
    if (TRUE == createBeforeMove)
    {
        ccCloseHandle(pFile);
        if (TRUE != result)
            sySetLastError((NQ_UINT32)res);
    }
    cmMemoryFree(newLocalPath);    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_UINT64 ccGetFilePointer(NQ_HANDLE handle)
{
    CCFile * pFile = (CCFile *)handle;                      /* casted file pointer */
    const NQ_UINT64 none = {(NQ_UINT32)-1, (NQ_UINT32)-1};  /* none offset */
    NQ_UINT64 result = none;                                /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "handle: %p", handle);*/

    if (handle == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    /* Check CIFS Client is initialized */
    if (ccIsInitialized())
    {

        if (!ccValidateFileHandle(handle))
        {
            LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
            sySetLastError(NQ_ERR_INVALIDHANDLE);
            goto Exit;
        }

        if (!pFile->open)
        {
            LOGERR(CM_TRC_LEVEL_ERROR , "Not Opened");
            sySetLastError(NQ_ERR_INVALIDHANDLE);
        }
        result = pFile->offset;
        goto Exit;
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        goto Exit;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result(low,high):%u,%u", result.low, result.high);
    return result;
}

NQ_UINT32 ccSetFilePointer(NQ_HANDLE handle, NQ_INT32 lowOffset, NQ_INT32 * highOffset, NQ_INT moveMethod)
{
    CCFile * pFile = (CCFile *)handle;  /* casted file pointer */
    NQ_INT64 offset;                    /* required offset in a civilized form */
    NQ_UINT32 result = NQ_ERR_INVALIDHANDLE; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p low:%d high:%p move:%d", handle, lowOffset, highOffset, moveMethod);
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "handle: %p", handle);*/

    if (handle == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        goto Exit;
    }

    /* Check CIFS Client is initialized */
    if (!ccIsInitialized())
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "CIFS Client is not ready");
        sySetLastError(NQ_ERR_NOTREADY);
        result = NQ_ERR_NOTREADY;
        goto Exit;
    }

    if (!ccValidateFileHandle(handle))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        result = NQ_ERR_INVALIDHANDLE;
        goto Exit;
    }

    if (!pFile->open)
    {
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        result = NQ_ERR_INVALIDHANDLE;
        goto Exit;
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
    	/*we assume negative offset will not be received in high value. */
    	offset.low = (NQ_UINT32)lowOffset;
        offset.high = (NQ_UINT32)*highOffset;
        offset.sign = 1;
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
            result = NQ_ERR_SEEKERROR;
            goto Exit;

    }
    cmListItemGive((CMItem *)pFile);

    if (highOffset != NULL)
        *highOffset = (NQ_INT32)pFile->offset.high;

    result = pFile->offset.low;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%u", result);
    return result;
}

NQ_BOOL ccFlushFile(NQ_HANDLE handle)
{
    CCFile *            pFile;                      /* casted file pointer */
    NQ_STATUS           res;                        /* operation result */
    NQ_INT              counter;                    /* simple counter*/
    NQ_BOOL             result = FALSE;             /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);

    if (NULL == handle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    if (!ccValidateFileHandle(handle))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    pFile = (CCFile *)handle;
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot flush to a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (!pFile->open)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }

    for (counter = 0 ; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doFlush(pFile);
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else if ((NQ_STATUS)NQ_ERR_TRYAGAIN == res)
        {
        	/* possible reconnect caused a wrong user session or wrong FID */
        	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "operation failed. Try again");
        	continue;
        }
        else
        {
            break;
        }
    }
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to flush file");
        sySetLastError((NQ_UINT32)res);
        goto Exit;
    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccFileReportDisconnect(CCFile * pFile)
{
    NQ_BOOL res = FALSE; /* call result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p", pFile);

    if (pFile == NULL || !ccValidateFileHandle((NQ_HANDLE)pFile))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    /* We reconnect the entire server, including all its users, shares. files.
    * If after reconnect this file becomes connected - we succeeded.
    */

    res = ccServerReconnect(pFile->share->user->server);
    res = (res && pFile->open);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccFileRestore(CCFile * pFile)
{
    NQ_STATUS res = FALSE;    /* call result */
    NQ_BOOL result = FALSE;
    NQ_COUNT counter;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p", pFile);

    if (pFile == NULL || !ccValidateFileHandle((NQ_HANDLE)pFile))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT ; counter++)
    {
    	res = pFile->share->user->server->smb->doRestoreHandle(pFile);
    	if ((NQ_STATUS)NQ_ERR_TRYAGAIN == res)
    	{
    		continue;
    	}
    	break;
    }
    result = (NQ_SUCCESS == res);
    pFile->open = result;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccValidateFileHandle(NQ_HANDLE handle)
{
    NQ_BOOL     result = FALSE;
    CCFile * pFile = (CCFile *)handle;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);

    if (NULL == handle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Null Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    if (pFile->disconnected)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR , "disconnected Handle");
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		goto Exit;
    }

    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

void ccFileTake(NQ_HANDLE handle)
{
    if (handle)
    {
        CCFile *    pFile = (CCFile *)handle;
        cmListItemTake((CMItem *)pFile);
    }
}

void ccFileGive(NQ_HANDLE handle)
{
    if (handle)
    {
        CCFile *    pFile = (CCFile *)handle;
        cmListItemGive((CMItem *)pFile);
    }
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
