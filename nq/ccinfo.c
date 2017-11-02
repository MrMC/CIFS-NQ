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
#include "ccconfig.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions -- */
static void fileInfoResponseCallback(CMBufferReader * pReader, void * context)
{
	CCFileInfo * pInfo = (CCFileInfo *)context;	/* target pointer */
	
	/* basic info */
	cmBufferReadUint64(pReader, &pInfo->creationTime);		/* creation time */
	cmBufferReadUint64(pReader, &pInfo->lastAccessTime);	/* last access time */
	cmBufferReadUint64(pReader, &pInfo->lastWriteTime);		/* last write time */
	cmBufferReadUint64(pReader, &pInfo->changeTime);		/* change time */
	cmBufferReadUint32(pReader, &pInfo->attributes);		/* file attributes */
	cmBufferReaderSkip(pReader, sizeof(NQ_UINT32));			/* reserved */
	/* standard info */
	cmBufferReadUint64(pReader, &pInfo->allocationSize);	/* file allocation size */
	cmBufferReadUint64(pReader, &pInfo->endOfFile);			/* file size */
	cmBufferReadUint32(pReader, &pInfo->numberOfLinks);		/* number of links */
	cmBufferReaderSkip(pReader, sizeof(NQ_UINT32));			/* delete pending + directory + reserved */
	/* internal info */
	cmBufferReadUint64(pReader, &pInfo->fileIndex);			/* file index */
}

static NQ_STATUS getFileInformationByName(const NQ_WCHAR * fileName, CCFileInfo * pInfo, CCShare ** resolvedShare, NQ_WCHAR ** resolvedPath)
{
	CCMount * pMount;		/* mount point descriptor */
	NQ_WCHAR * filePath = NULL;	/* path component local to remote share or DFS full path */
	NQ_WCHAR * filePathFromLocalPath = NULL;	/* file path component */
    NQ_INT counter;         /* operation attempts counter */
	NQ_STATUS res;			/* operation result */
	CCShare * pShare;		/* pointer to the hosting share */
    NQ_BOOL dfsResolved = FALSE;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fileName: %s", cmWDump(fileName));

	pMount = ccMountFind(fileName);
	if (NULL == pMount)
	{
        sySetLastError(NQ_ERR_BADPARAM);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)NQ_ERR_BADPARAM;
	}
    pShare = pMount->share;

    filePathFromLocalPath = ccUtilsFilePathFromLocalPath(fileName);
	if (NULL == filePathFromLocalPath)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
	}

	if (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)NQ_ERR_NOTCONNECTED;
    }

#ifdef UD_CC_INCLUDEDFS    
    if (pShare->flags & CC_SHARE_IN_DFS)
    {
        if (NULL != fileName)
        {
            filePath = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, filePathFromLocalPath);
            if (NULL == filePath)
            {
                cmMemoryFree(filePathFromLocalPath);
                sySetLastError(NQ_ERR_OUTOFMEMORY);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
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
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
	}
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "filePath: %s", cmWDump(filePath));

    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)    
    {       
    	res = pShare->user->server->smb->doQueryFileInfoByName(
    				pShare, 
    				filePath,
    				fileInfoResponseCallback,
    				pInfo
    				);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "res: 0x%x", res);
#ifdef UD_CC_INCLUDEDFS        
        if (res == NQ_ERR_PATHNOTCOVERED)
        {
            CCDfsResult dfsResult;  /* result of DFS resolution */

            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "NQ_ERR_PATHNOTCOVERED");
            dfsResult = ccDfsResolvePath(pShare, filePathFromLocalPath);
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
                    ccDfsResolveDispose(&dfsResult);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return (NQ_STATUS)NQ_ERR_OUTOFMEMORY;
                }
                dfsResolved = TRUE;
                LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "resolved filePath: %s", cmWDump(filePath));
                filePathFromLocalPath = ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                ccDfsResolveDispose(&dfsResult);

                counter++;
                continue;
            }         
       }
#endif  /* UD_CC_INCLUDEDFS */   
       cmMemoryFree(filePathFromLocalPath);

        if (res == NQ_SUCCESS)
        {
            if (dfsResolved)
            {
                if (resolvedShare)
                    *resolvedShare = pShare;
            }
            break;
        }    
        if (NQ_ERR_RECONNECTREQUIRED == res)
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
    cmMemoryFree(filePath);		

    if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to withdraw file information");
		sySetLastError((NQ_UINT32)res);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return (NQ_STATUS)res;
	}

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/* --- API functions --- */
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
    NQ_BOOL result = FALSE;	/* Unicode result */
    NQ_WCHAR * pathNameW;	/* the same in Unicode */

    pathNameW = (NQ_WCHAR *)cmMemoryCloneAString(pathName);
    if (NULL != pathNameW)
    {
        result = ccGetDiskFreeSpaceW(pathNameW, sectorsPerCluster, bytesPerSector, freeClusters, totalClusters, fsType, serialNumber);
    	cmMemoryFree(pathNameW);
    }
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
	CCVolumeInfo    infoVolume;     /* volume information */
	CCMount *       pMount;		    /* mount point descriptor */
	NQ_STATUS       res;			/* operation result */
	CCShare *       pShare;         /* resolved share (DFS) */
	CCFileInfo      infoFile;       /* file info */
    NQ_INT          counter;        /*simple counter*/
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (ccUtilsPathIsLocal(pathName))
    {
        if (sectorsPerCluster != NULL)
            *sectorsPerCluster = 1;
        if (bytesPerSector != NULL)
            *bytesPerSector = 512;
        if (freeClusters != NULL)
            *freeClusters = 0;
        if (totalClusters != NULL)
            *totalClusters = 0;
        if (fsType != NULL)
            *fsType = 0;
        if (serialNumber != NULL)
            *serialNumber = 0;

		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }

	pMount = ccMountFind(pathName);
	if (NULL == pMount)
	{
        sySetLastError(NQ_ERR_BADPARAM);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pShare = pMount->share;
    
    res = getFileInformationByName(pathName, &infoFile, &pShare, NULL);
    if (NQ_SUCCESS != res || pShare == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to withdraw file information");
        sySetLastError((NQ_UINT32)res);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pShare->user->server->smb->doQueryFsInfo(pShare, &infoVolume);
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
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to withdraw volume information");
		sySetLastError((NQ_UINT32)res);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    if (sectorsPerCluster != NULL)
        *sectorsPerCluster = infoVolume.sectorsPerCluster;
    
    if (bytesPerSector != NULL)
        *bytesPerSector = infoVolume.bytesPerSector;
    
    if (freeClusters != NULL)
        *freeClusters = infoVolume.freeClusters;
    
    if (totalClusters != NULL)
        *totalClusters = infoVolume.totalClusters;
    
    if (fsType != NULL)
        *fsType = infoVolume.fsType;
    
    if (serialNumber != NULL)
        *serialNumber = infoVolume.serialNumber;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_UINT32 ccGetFileAttributesA(const NQ_CHAR * fileName)
{
    NQ_UINT32 status;		/* NT status */
    NQ_WCHAR * fileNameW;	/* the same in Unicode */

    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL != fileNameW)
    {
        status = ccGetFileAttributesW(fileNameW);
    	cmMemoryFree(fileNameW);
        return status;
    }
    return NQ_ERR_ATTRERROR;
}

NQ_UINT32 ccGetFileAttributesW(const NQ_WCHAR * fileName)
{
    CCFileInfo info;		            /* file info */
	NQ_STATUS res = NQ_SUCCESS;			/* operation result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_ATTRERROR;
	}
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return info.attributes;
}

NQ_BOOL ccSetFileAttributesA(const NQ_CHAR * fileName,  NQ_UINT32 attributes)
{
    NQ_BOOL result = FALSE;	/* Unicode result */
    NQ_WCHAR * fileNameW;	/* the same in Unicode */

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
	CCFile *    pFile;	/* open file handle */
	NQ_STATUS   res;	/* operation result */
    NQ_INT      counter;      /* simple counter*/
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (0 == attributes)
	{
		attributes |= SMB_ATTR_NORMAL;
	}
	pFile = ccCreateFileW(
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
        sySetLastError(NQ_ERR_BADPARAM);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileAttributes(
                pFile, 
                attributes
                );
        if (NQ_ERR_RECONNECTREQUIRED == res)
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
	ccCloseHandle(pFile);
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

NQ_BOOL ccGetFileInformationByNameA(const NQ_CHAR * fileName, FileInfo_t * fileInfo)
{
	NQ_BOOL result = FALSE;	/* Unicode result */
    NQ_WCHAR * fileNameW;	/* the same in Unicode */

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
    CCFileInfo info;		/* file info */
	NQ_STATUS res;			/* operation result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (ccUtilsPathIsLocal(fileName))
    {
        fileInfo->attributes = CIFS_ATTR_DIR | CIFS_ATTR_READONLY;
        fileInfo->fileSizeLow = 512;
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }

	res = getFileInformationByName(fileName , &info, NULL, NULL);
    if (NQ_SUCCESS != res)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
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

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return TRUE;
}

NQ_BOOL ccGetFileTime(
	NQ_HANDLE handle, 
	FileTime_t * creationTime, 
	FileTime_t * lastAccessTime, 
	FileTime_t * lastWriteTime
	)
{
	CCFile *        pFile;      /* open file handle */
	NQ_STATUS       res;        /* operation result */
    CCFileInfo      info;       /* file info */
    NQ_INT          counter;    /* simple counter*/
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (handle == NULL)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

	pFile = (CCFile *)handle;
	if (!pFile->open)
	{
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

    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
	    res = pFile->share->user->server->smb->doQueryFileInfoByHandle(
                    pFile,
                    fileInfoResponseCallback,
                    &info
                    );
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
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
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
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
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
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	if (handle == NULL)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pFile = (CCFile *)handle;
	if (!pFile->open)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
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
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileTime(
                    pFile, 
                    creationT, 
                    lastAccessT,
                    lastWriteT
                    );
        if (NQ_ERR_RECONNECTREQUIRED == res)
        {
            pFile->share->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pFile->share->user->server))
            {
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return FALSE;            
            }
        }
        else
            break;
    }
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_UINT32 ccGetFileSize(NQ_HANDLE hndl, NQ_UINT32 *fileSizeHigh)
{
	CCFile *        pFile;          /* open file handle */
	NQ_STATUS       res;            /* operation result */
    CCFileInfo      info;           /* file info */
    NQ_INT          counter;        /* simple counter */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (hndl == NULL)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_SIZEERROR;
	}
	pFile = (CCFile *)hndl;
	if (!pFile->open)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_SIZEERROR;
	}
	if (!ccTransportIsConnected(&pFile->share->user->server->transport) && !ccServerReconnect(pFile->share->user->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_NOTCONNECTED;
    }
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doQueryFileInfoByHandle(
                    pFile,
                    fileInfoResponseCallback,
                    &info
                    );
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
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_SIZEERROR;
	}
    *fileSizeHigh = info.endOfFile.high;
    
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return info.endOfFile.low;
}

NQ_BOOL ccGetFileInformationByHandle(NQ_HANDLE hndl, FileInfo_t *fileInfo)
{
	CCFile *    pFile;			/* open file handle */
	NQ_STATUS   res;			/* operation result */
    CCFileInfo  info;		    /* file info */
    NQ_INT      counter;        /* simple counter*/
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (hndl == NULL)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pFile = (CCFile *)hndl;
	if (!pFile->open)
	{
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
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doQueryFileInfoByHandle(
                    pFile,
                    fileInfoResponseCallback,
                    &info
                    );
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
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
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
    
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

NQ_BOOL ccSetFileSizeByNameA(const NQ_CHAR * fileName, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh)
{
	NQ_BOOL result = FALSE;	/* Unicode result */
    NQ_WCHAR * fileNameW;	/* the same in Unicode */

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
	CCFile *        pFile;	/* open file handle */
	NQ_STATUS       res;	/* operation result */
	NQ_UINT64       size;	/* required size */
    NQ_INT          counter;/* simple counter */     
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	pFile = ccCreateFileW(
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
        sySetLastError(NQ_ERR_BADPARAM);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	
	size.low = sizeLow;
	size.high = sizeHigh;
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileSize(
                    pFile, 
                    size
                    );
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

NQ_BOOL ccSetFileSizeByHandle(NQ_HANDLE handle, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh)
{
	CCFile *        pFile;			/* open file handle */
	NQ_STATUS       res;			/* operation result */
	NQ_UINT64       size;	        /* required size */
    NQ_INT          counter;        /* simple counter */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (handle == NULL)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pFile = (CCFile *)handle;
	if (!pFile->open)
	{
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
	size.low = sizeLow;
	size.high = sizeHigh;
    for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
    {
        res = pFile->share->user->server->smb->doSetFileSize(
                    pFile, 
                    size
                    );
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
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return TRUE;
}

NQ_BOOL ccCheckPath(const NQ_WCHAR * path, NQ_BOOL stripLast, NQ_WCHAR **resolvedPath)
{
    NQ_STATUS status;
    CCFileInfo fileInfo;
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    *resolvedPath = NULL;
    if (stripLast)
    {
        NQ_WCHAR * pathStripped;

        pathStripped = ccUtilsFilePathStripLastComponent(path);
        if (NULL == pathStripped)
        {
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return FALSE;
        }
        status = getFileInformationByName(pathStripped, &fileInfo, NULL, resolvedPath);
        cmMemoryFree(pathStripped);
    }
    else
    {
        status = getFileInformationByName(path, &fileInfo, NULL, resolvedPath);
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "resolvedPath: %s", (resolvedPath && *resolvedPath) ? cmWDump(*resolvedPath) : "");
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status == NQ_SUCCESS;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
