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

#include "ccinfo.h"
#include "ccmount.h"
#include "ccfile.h"
#include "ccdfs.h"
#include "ccutils.h"
#include "ccparams.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions -- */

static NQ_STATUS getFileInformationByName(const NQ_WCHAR * fileName, CCFileInfo * pInfo, CCShare ** resolvedShare, NQ_WCHAR ** resolvedPath)
{
    CCMount * pMount;              /* mount point descriptor */
    NQ_WCHAR * filePath = NULL;    /* path component local to remote share or DFS full path */
    NQ_WCHAR * filePathFromLocalPath = NULL;    /* file path component */
    NQ_INT counter;                /* operation attempts counter */
    CCShare * pShare;              /* pointer to the hosting share */
    NQ_BOOL dfsResolved = FALSE;
#ifdef UD_CC_INCLUDEDFS
    CCDfsContext dfsContext = {CC_DFS_NUMOFRETRIES, 0, NULL}; /* DFS operations context */
    CCDfsResult dfsResult = {NULL, NULL, NULL};               /* result of DFS resolution */
#endif /* UD_CC_INCLUDEDFS */
    NQ_STATUS result = NQ_FAIL;                               /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s info:%p share:%p resolve:%p", cmWDump(fileName), pInfo, resolvedShare, resolvedPath);
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fileName: %s", cmWDump(fileName));*/

    pMount = ccMountFind(fileName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot find mount");
        result = (NQ_STATUS)NQ_ERR_BADPARAM;
        goto Exit;
    }
    pShare = pMount->share;
    if (pShare->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot get info from a print share");
        result = (NQ_STATUS)NQ_ERR_BADPARAM;
        goto Exit;
    }
    filePathFromLocalPath = ccUtilsFilePathFromLocalPath(fileName, pMount->pathPrefix, pShare->user->server->smb->revision == CCCIFS_ILLEGALSMBREVISION, TRUE);
    if (NULL == filePathFromLocalPath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        result = (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
        goto Exit;
    }

    if (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        result = (NQ_STATUS)NQ_ERR_NOTCONNECTED;
        goto Exit;
    }

#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
    {
        if (NULL != fileName)
        {
            filePath = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, filePathFromLocalPath, FALSE);
            if (NULL == filePath)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                result = (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
                goto Exit;
            }
        }
    }
    else
#endif /* UD_CC_INCLUDEDFS */
    {
        filePath = cmMemoryCloneWString(filePathFromLocalPath);
        cmMemoryFree(filePathFromLocalPath);
        filePathFromLocalPath = NULL;
    }
    if (NULL == filePath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        result = (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "filePath: %s", cmWDump(filePath));

    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        NQ_STATUS res = pShare->user->server->smb->doQueryFileInfoByName(
                    pShare,
                    filePath,
                    pInfo
                    );
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "doQueryFileInfoByName result: 0x%x", res);
#ifdef UD_CC_INCLUDEDFS
        if (ccDfsIsError(dfsContext.lastError = res))
        {
            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "DFS related error %s", res == NQ_ERR_PATHNOTCOVERED ? ": NQ_ERR_PATHNOTCOVERED" : "");

            if (--dfsContext.counter < 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "DFS failed to resolve path: too many attempts");
                result = (NQ_STATUS)res;
                goto Exit;
            }
            dfsResult = ccDfsResolvePath(pMount, pShare, filePathFromLocalPath, &dfsContext);
            cmMemoryFree(filePath);
            cmMemoryFree(filePathFromLocalPath);
            filePath = NULL;
            filePathFromLocalPath = NULL;
            if (dfsResult.path)
            {
                pShare = dfsResult.share;
                filePath = dfsResult.share->flags & CC_SHARE_IN_DFS ? cmMemoryCloneWString(dfsResult.path) : ccUtilsFilePathFromRemotePath(dfsResult.path, FALSE);
                if (NULL == filePath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    result = (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
                    goto Exit;
                }
                dfsResolved = TRUE;
                LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "resolved filePath: %s", cmWDump(filePath));
                filePathFromLocalPath = ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                if (NULL == filePathFromLocalPath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    result = (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
                    goto Exit;
                }

                ccDfsResolveDispose(&dfsResult);
                dfsResult.path = NULL;
                counter++;
                continue;
            }
       }
#endif /* UD_CC_INCLUDEDFS */
        cmMemoryFree(filePathFromLocalPath);
        filePathFromLocalPath = NULL;

        result = res;
        if (result == NQ_SUCCESS)
        {
            if (dfsResolved && resolvedShare != NULL)
            {
                *resolvedShare = pShare;
            }
            break;
        }
        if (result == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pShare->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pShare->user->server))
                break;
        }
        else
            break;
    }

    if (resolvedPath)
    {
        *resolvedPath = cmMemoryCloneWString(filePath);
    }

Exit:
    if (NQ_SUCCESS != result)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to withdraw file information: 0x%x", result);
        sySetLastError((NQ_UINT32)result);        
    }
    cmMemoryFree(filePathFromLocalPath);
    cmMemoryFree(filePath);
#ifdef UD_CC_INCLUDEDFS
    if (NULL != dfsResult.path)
    {
        ccDfsResolveDispose(&dfsResult);
    }
#endif /* UD_CC_INCLUDEDFS */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}


/* --- API functions --- */
NQ_BOOL ccGetDiskFreeSpaceExA(
    const NQ_CHAR * pathName,
    NQ_UINT * sectorsPerCluster,
    NQ_UINT * bytesPerSector,
    NQ_UINT64 * freeClusters,
    NQ_UINT64 * totalClusters,
    NQ_UINT * fsType,
    NQ_UINT * serialNumber
   )
{
    NQ_BOOL result = FALSE;    /* Unicode result */
    NQ_WCHAR * pathNameW;      /* the same in Unicode */

    pathNameW = (NQ_WCHAR *)cmMemoryCloneAString(pathName);
    if (NULL != pathNameW)
    {
        result = ccGetDiskFreeSpaceExW(pathNameW, sectorsPerCluster, bytesPerSector, freeClusters, totalClusters, fsType, serialNumber);
        cmMemoryFree(pathNameW);
    }
    return result;
}

NQ_BOOL ccGetDiskFreeSpaceA(
    const NQ_CHAR * pathName,
    NQ_UINT * sectorsPerCluster,
    NQ_UINT * bytesPerSector,
    NQ_UINT * freeClusters,
    NQ_UINT * totalClusters,
    NQ_UINT * fsType,
    NQ_UINT * serialNumber
   )
{
    NQ_BOOL result = FALSE;    /* Unicode result */
    NQ_UINT64 freeClusters64 = {0, 0}, totalClusters64 = {0, 0};
    NQ_WCHAR * pathNameW;      /* the same in Unicode */

    pathNameW = (NQ_WCHAR *)cmMemoryCloneAString(pathName);

    result = ccGetDiskFreeSpaceExW(pathNameW, sectorsPerCluster, bytesPerSector, &freeClusters64, &totalClusters64, fsType, serialNumber);

    if (NULL != freeClusters)
    	*freeClusters = cmNQ_UINT64toU32(freeClusters64);
    if (NULL != totalClusters)
    	*totalClusters = cmNQ_UINT64toU32(totalClusters64);

    cmMemoryFree(pathNameW);

    return result;
}

NQ_BOOL ccGetDiskFreeSpaceExW(
    const NQ_WCHAR * pathName,
    NQ_UINT * sectorsPerCluster,
    NQ_UINT * bytesPerSector,
    NQ_UINT64 * freeClusters,
    NQ_UINT64 * totalClusters,
    NQ_UINT * fsType,
    NQ_UINT * serialNumber
   )
{
    CCVolumeInfo    infoVolume;     /* volume information */
    CCMount *       pMount;         /* mount point descriptor */
    NQ_STATUS       res;            /* operation result */
    CCShare *       pShare;         /* resolved share (DFS) */
    CCFileInfo      infoFile;       /* file info */
    NQ_INT          counter;        /* simple counter */
    NQ_BOOL         result = FALSE; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s\n", cmWDump(pathName));

    if (ccUtilsPathIsLocal(pathName))
    {
        if (sectorsPerCluster != NULL)
           *sectorsPerCluster = 1;
        if (bytesPerSector != NULL)
            *bytesPerSector = 512;
        if (freeClusters != NULL)
        {
            freeClusters->low = 0;
            freeClusters->high = 0;
        }
        if (totalClusters != NULL)
        {
            totalClusters->low = 0;
            totalClusters->high = 0;
        }
        if (fsType != NULL)
            *fsType = 0;
        if (serialNumber != NULL)
            *serialNumber = 0;

        result = TRUE;
        goto Exit;
    }

    pMount = ccMountFind(pathName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot find mount point.");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pShare = pMount->share;
    res = getFileInformationByName(pathName, &infoFile, &pShare, NULL);
    if (NQ_SUCCESS != res || pShare == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to withdraw file information:%d", res);
        sySetLastError((NQ_UINT32)res);
        goto Exit;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pShare->user->server->smb->doQueryFsInfo(pShare, &infoVolume);
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to withdraw volume information:%d", res);
        sySetLastError((NQ_UINT32)res);
        goto Exit;
    }
    if (sectorsPerCluster != NULL)
        *sectorsPerCluster = infoVolume.sectorsPerCluster;

    if (bytesPerSector != NULL)
        *bytesPerSector = infoVolume.bytesPerSector;

    if (freeClusters != NULL)
    {
        freeClusters->high = infoVolume.freeClusters.high;
        freeClusters->low = infoVolume.freeClusters.low;
    }
    if (totalClusters != NULL)
    {
    	totalClusters->high = infoVolume.totalClusters.high;
        totalClusters->low = infoVolume.totalClusters.low;
    }

    if (fsType != NULL)
        *fsType = infoVolume.fsType;

    if (serialNumber != NULL)
        *serialNumber = infoVolume.serialNumber;

    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccGetDiskFreeSpaceW(
    const NQ_WCHAR * pathName,
    NQ_UINT * sectorsPerCluster,
    NQ_UINT * bytesPerSector,
    NQ_UINT * freeClusters,
    NQ_UINT * totalClusters,
    NQ_UINT * fsType,
    NQ_UINT * serialNumber
   )
{
	NQ_BOOL result;
	NQ_UINT64 freeClusters64 = {0, 0}, totalClusters64 = {0, 0};

	result = ccGetDiskFreeSpaceExW(pathName, sectorsPerCluster, bytesPerSector, &freeClusters64, &totalClusters64, fsType, serialNumber);

	*freeClusters = cmNQ_UINT64toU32(freeClusters64);
	*totalClusters = cmNQ_UINT64toU32(totalClusters64);

	return result;
}
NQ_UINT32 ccGetFileAttributesA(const NQ_CHAR * fileName)
{
    NQ_UINT32 status = NQ_ERR_ATTRERROR; /* NT status */
    NQ_WCHAR * fileNameW;                /* file Name in Unicode */

    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL != fileNameW)
    {
        status = ccGetFileAttributesW(fileNameW);
        cmMemoryFree(fileNameW);
    }
    return status;
}

NQ_UINT32 ccGetFileAttributesW(const NQ_WCHAR * fileName)
{
    CCFileInfo info;                     /* file info */
    NQ_STATUS res = NQ_SUCCESS;          /* operation result */
    NQ_UINT32 result = NQ_ERR_ATTRERROR; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON,  "file:%s", cmWDump(fileName));

    if (ccUtilsPathIsLocal(fileName))
    {
        info.attributes = CIFS_ATTR_DIR | CIFS_ATTR_READONLY;
    }
    else
    {
        res = getFileInformationByName(fileName , &info, NULL, NULL);
    }
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to withdraw file information:%d", res);
        goto Exit;
    }
    result = info.attributes;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%u", result);
    return result;
}

NQ_BOOL ccSetFileAttributesA(const NQ_CHAR * fileName,  NQ_UINT32 attributes)
{
    NQ_BOOL result = FALSE;    /* Unicode result */
    NQ_WCHAR * fileNameW;      /* the same in Unicode */

    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL != fileNameW)
    {
        result = ccSetFileAttributesW(fileNameW, attributes);
        cmMemoryFree(fileNameW);
    }
    return result;
}

NQ_BOOL ccSetFileAttributesW(const NQ_WCHAR * fileName, NQ_UINT32 attributes)
{
    CCFile *    pFile = NULL;   /* open file handle */
    NQ_STATUS   res;            /* operation result */
    NQ_INT      counter;        /* simple counter*/
    NQ_BOOL     result = FALSE; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%s attr:0x%x", cmWDump(fileName), attributes);

    if (0 == attributes)
    {
        attributes |= SMB_ATTR_NORMAL;
    }
    pFile = (CCFile *)ccCreateFileW(
            fileName,
            CCFILE_ACCESSMASK_SPECIAL | SMB_DESIREDACCESS_WRITEATTRIBUTES,
            FILE_SM_DENY_NONE,
            FILE_LCL_UNKNOWN,
            FALSE,
            0,
            FILE_CA_FAIL,
            FILE_OA_OPEN
            );
    if (NULL == pFile)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot set attributes for a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileAttributes(
                pFile,
                attributes
                );
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
            {
                break;
            }
        }
        else
            break;
    }

    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to write file information:%d", res);
        sySetLastError((NQ_UINT32)res);
        goto Exit;
    }
    result = TRUE;

Exit:
    if (NULL != pFile)
    {
        ccCloseHandle(pFile);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccGetFileInformationByNameA(const NQ_CHAR * fileName, FileInfo_t * fileInfo)
{
    NQ_BOOL result = FALSE;    /* Unicode result */
    NQ_WCHAR * fileNameW;      /* the same in Unicode */

    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL != fileNameW)
    {
        result = ccGetFileInformationByNameW(fileNameW, fileInfo);
        cmMemoryFree(fileNameW);
    }
    return result;
}

NQ_BOOL ccGetFileInformationByNameW(const NQ_WCHAR * fileName, FileInfo_t * fileInfo)
{
    CCFileInfo info;          /* file info */
    NQ_STATUS res;            /* operation result */
    NQ_BOOL result = TRUE;    /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%s info:%p", cmWDump(fileName), fileInfo);
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fileName: %s", cmWDump(fileName));*/
    if (ccUtilsPathIsLocal(fileName))
    {
        syMemset(fileInfo, 0, sizeof(FileInfo_t));
        fileInfo->attributes = CIFS_ATTR_DIR | CIFS_ATTR_READONLY;
        fileInfo->fileSizeLow = 512;
        goto Exit;
    }
    res = getFileInformationByName(fileName , &info, NULL, NULL);
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot get file information:%d", res);
        result = FALSE;
        goto Exit;
    }
    fileInfo->allocationSizeHigh = info.allocationSize.high;
    fileInfo->allocationSizeLow = info.allocationSize.low;
    fileInfo->attributes = info.attributes;
    fileInfo->creationTimeHigh = info.creationTime.high;
    fileInfo->creationTimeLow = info.creationTime.low;
    fileInfo->fileIndexHigh = info.fileIndex.high;
    fileInfo->fileIndexLow = info.fileIndex.low;
    fileInfo->fileSizeHigh = info.endOfFile.high;
    fileInfo->fileSizeLow = info.endOfFile.low;
    fileInfo->lastAccessTimeHigh = info.lastAccessTime.high;
    fileInfo->lastAccessTimeLow = info.lastAccessTime.low;
    fileInfo->lastWriteTimeHigh = info.lastWriteTime.high;
    fileInfo->lastWriteTimeLow = info.lastWriteTime.low;
    fileInfo->numberOfLinks = info.numberOfLinks;
    fileInfo->volumeSerialNumber = 0;

Exit:
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "result: %d", result);*/
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccGetFileTime(
    NQ_HANDLE handle,
    FileTime_t * creationTime,
    FileTime_t * lastAccessTime,
    FileTime_t * lastWriteTime
    )
{
    CCFile *        pFile = NULL;    /* open file handle */
    NQ_STATUS       res;             /* operation result */
    CCFileInfo      info;            /* file info */
    NQ_INT          counter;         /* simple counter*/
    NQ_BOOL         result = FALSE;  /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p creation:%p lastAccess:%p lastWrite:%p", handle, creationTime, lastAccessTime, lastWriteTime);

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
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot get file time for a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (!pFile->open)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "File not opened");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }

    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doQueryFileInfoByHandle(
                    pFile,
                    &info
                    );
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to query file:%d", res);
        goto Exit;
    }
    if (NULL != creationTime)
    {
        creationTime->timeHigh = info.creationTime.high;
        creationTime->timeLow = info.creationTime.low;
    }
    if (NULL != lastAccessTime)
    {
        lastAccessTime->timeHigh = info.lastAccessTime.high;
        lastAccessTime->timeLow = info.lastAccessTime.low;
    }
    if (NULL != lastWriteTime)
    {
        lastWriteTime->timeHigh = info.lastWriteTime.high;
        lastWriteTime->timeLow = info.lastWriteTime.low;

    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccSetFileTime(
    NQ_HANDLE handle,
    FileTime_t * creationTime,
    FileTime_t * lastAccessTime,
    FileTime_t * lastWriteTime
   )
{
    CCFile *    pFile;          /* open file handle */
    NQ_STATUS   res;            /* operation result */
    NQ_UINT64   creationT;      /* time copy */
    NQ_UINT64   lastAccessT;    /* time copy */
    NQ_UINT64   lastWriteT;     /* time copy */
    NQ_INT      counter;        /* simple counter*/
    NQ_BOOL     result = FALSE; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p creation:%p lastAccess:%p lastWrite:%p", handle, creationTime, lastAccessTime, lastWriteTime);

    if (NULL == handle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
        sySetLastError(NQ_ERR_BADPARAM);
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
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot set file time for a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (!pFile->open)
    {
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    if (NULL != creationTime)
    {
        creationT.low = creationTime->timeLow;
        creationT.high = creationTime->timeHigh;
    }
    else
    {
        creationT.low = 0;
        creationT.high = 0;
    }
    if (NULL != lastAccessTime)
    {
        lastAccessT.low = lastAccessTime->timeLow;
        lastAccessT.high = lastAccessTime->timeHigh;
    }
    else
    {
        lastAccessT.low = 0;
        lastAccessT.high = 0;
    }
    if (NULL != lastWriteTime)
    {
        lastWriteT.low = lastWriteTime->timeLow;
        lastWriteT.high = lastWriteTime->timeHigh;
    }
    else
    {
        lastWriteT.low = 0;
        lastWriteT.high = 0;
    }
    if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileTime(
                    pFile,
                    creationT,
                    lastAccessT,
                    lastWriteT
                    );
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
            {
                goto Exit;
            }
        }
        else
            break;
    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_UINT32 ccGetFileSize(NQ_HANDLE hndl, NQ_UINT32 *fileSizeHigh)
{
    CCFile *        pFile;          /* open file handle */
    NQ_STATUS       res;            /* operation result */
    CCFileInfo      info;           /* file info */
    NQ_INT          counter;        /* simple counter */
    NQ_UINT32       result = NQ_ERR_SIZEERROR; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p size:%p", hndl, fileSizeHigh);

    if (NULL == hndl)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    if (!ccValidateFileHandle(hndl))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    pFile = (CCFile *)hndl;
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot get file size for a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (!pFile->open)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "File not opened");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        result = NQ_ERR_NOTCONNECTED;
        goto Exit;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doQueryFileInfoByHandle(
                    pFile,
                    &info
                    );
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to query file:%d", res);
        goto Exit;
    }
    *fileSizeHigh = info.endOfFile.high;
    result = info.endOfFile.low;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%u", result);
    return result;
}

NQ_BOOL ccGetFileInformationByHandle(NQ_HANDLE hndl, FileInfo_t *fileInfo)
{
    CCFile *    pFile;          /* open file handle */
    NQ_STATUS   res;            /* operation result */
    CCFileInfo  info;           /* file info */
    NQ_INT      counter;        /* simple counter*/
    NQ_BOOL     result = FALSE; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p info:%p", hndl, fileInfo);

    if (NULL == hndl)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    if (!ccValidateFileHandle(hndl))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    pFile = (CCFile *)hndl;
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot get file info for a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (!pFile->open)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "File not opened");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doQueryFileInfoByHandle(
                    pFile,
                    &info
                    );
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
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
        LOGERR(CM_TRC_LEVEL_ERROR, "query file error: %d", res);
        goto Exit;
    }
    fileInfo->allocationSizeHigh = info.allocationSize.high;
    fileInfo->allocationSizeLow = info.allocationSize.low;
    fileInfo->attributes = info.attributes;
    fileInfo->creationTimeHigh = info.creationTime.high;
    fileInfo->creationTimeLow = info.creationTime.low;
    fileInfo->fileIndexHigh = info.fileIndex.high;
    fileInfo->fileIndexLow = info.fileIndex.low;
    fileInfo->fileSizeHigh = info.endOfFile.high;
    fileInfo->fileSizeLow = info.endOfFile.low;
    fileInfo->lastAccessTimeHigh = info.lastAccessTime.high;
    fileInfo->lastAccessTimeLow = info.lastAccessTime.low;
    fileInfo->lastWriteTimeHigh = info.lastWriteTime.high;
    fileInfo->lastWriteTimeLow = info.lastWriteTime.low;
    fileInfo->numberOfLinks = info.numberOfLinks;
    fileInfo->volumeSerialNumber = 0;

    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccSetFileSizeByNameA(const NQ_CHAR * fileName, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh)
{
    NQ_BOOL result = FALSE;    /* Unicode result */
    NQ_WCHAR * fileNameW;    /* the same in Unicode */

    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL != fileNameW)
    {
        result = ccSetFileSizeByNameW(fileNameW, sizeLow, sizeHigh);
        cmMemoryFree(fileNameW);
    }
    return result;
}

NQ_BOOL ccSetFileSizeByNameW(const NQ_WCHAR * fileName, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh)
{
    CCFile *        pFile = NULL;    /* open file handle */
    NQ_STATUS       res;             /* operation result */
    NQ_UINT64       size;            /* required size */
    NQ_INT          counter;         /* simple counter */
    NQ_BOOL         result = FALSE;  /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%s low:%u high:%u", cmWDump(fileName), sizeLow, sizeHigh);

    pFile = (CCFile *)ccCreateFileNoBatch(
            fileName,
            CCFILE_ACCESSMASK_SPECIAL | SMB_DESIREDACCESS_WRITEDATA,
            FILE_SM_DENY_NONE,
            FILE_LCL_UNKNOWN,
            FALSE,
            0,
            FILE_CA_FAIL,
            FILE_OA_OPEN
            );
    if (NULL == pFile)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot open file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot set file size for a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    size.low = sizeLow;
    size.high = sizeHigh;
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileSize(
                    pFile,
                    size
                    );
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
                break;
        }
        else
        {
            break;
        }
    }
    if (NQ_SUCCESS != res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to write file information:%d", res);
        sySetLastError((NQ_UINT32)res);
        goto Exit;
    }
    result = TRUE;

Exit:
    if (NULL != pFile)
        ccCloseHandle(pFile);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccSetFileSizeByHandle(NQ_HANDLE handle, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh)
{
    CCFile *        pFile;            /* open file handle */
    NQ_STATUS       res;              /* operation result */
    NQ_UINT64       size;             /* required size */
    NQ_INT          counter;          /* simple counter */
    NQ_BOOL         result = FALSE;   /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p low:%u high:%u", handle, sizeLow, sizeHigh);

    if (NULL == handle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
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
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot set file size for a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (!pFile->open)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "File not opened");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }
    size.low = sizeLow;
    size.high = sizeHigh;
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileSize(
                    pFile,
                    size
                    );
        if (res == (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED)
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to set file size:%d", res);
        goto Exit;
    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccCheckPath(const NQ_WCHAR * path, NQ_BOOL stripLast, NQ_WCHAR **resolvedPath)
{
    NQ_STATUS status;
    CCFileInfo fileInfo;
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s strip:%s resolve:%p", cmWDump(path), stripLast ? "TRUE" : "FALSE", resolvedPath);

    *resolvedPath = NULL;
    if (stripLast)
    {
        NQ_WCHAR * pathStripped;

        pathStripped = ccUtilsFilePathStripLastComponent(path);
        if (NULL == pathStripped)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }
        status = getFileInformationByName(pathStripped, &fileInfo, NULL, resolvedPath);
        cmMemoryFree(pathStripped);
    }
    else
    {
        status = getFileInformationByName(path, &fileInfo, NULL, resolvedPath);
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "resolvedPath: %s", (resolvedPath && *resolvedPath) ? cmWDump(*resolvedPath) : "");
    result = ( NQ_SUCCESS == status );

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
