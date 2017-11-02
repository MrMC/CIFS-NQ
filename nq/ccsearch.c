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

#include "ccsearch.h"
#include "ccapi.h"
#include "cmbufman.h"
#include "ccdfs.h"
#include "ccmount.h"
#include "ccutils.h"
#include "ccconfig.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Definitions -- */

/* -- Static data -- */
static CMList localSearches;

/* -- Static functions -- */

/*
 * Explicitly dispose and disconnect search entry:
 *  - disposes private data  
 */
static void disposeSearch(CCSearch * pSearch)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose search %s", cmWDump(pSearch->item.name));

    if (pSearch->localFile)
        cmListIteratorTerminate((CMIterator *)pSearch->context);

    if (NULL != pSearch->server)
    {
        pSearch->server->smb->doFindClose(pSearch);
        pSearch->server = NULL; 
    }
    if (NULL != pSearch->context)
        cmMemoryFree(pSearch->context);
    if (NULL != pSearch->buffer)
        cmBufManGive(pSearch->buffer);
    cmListItemRemoveAndDispose((CMItem *)pSearch);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 * Callback for search unlock and disposal:
 *  - disposes private data  
 */
static NQ_BOOL unlockCallback(CMItem * pItem)
{
    disposeSearch((CCSearch *)pItem);
    return TRUE;
}

/* 
 * Setup search context 
 */
static void initializeSearchStructure(CCSearch * pSearch)
{
    cmBufferReaderInit(&pSearch->parser, NULL, 0);  /* set not valid */
    pSearch->context = NULL;
    pSearch->buffer = NULL;
    pSearch->lastFile.data = NULL;
}

static NQ_BOOL getDirPathAndWildCards (CCShare * pShare,  NQ_WCHAR * localPath, NQ_WCHAR ** dirPath, NQ_WCHAR ** wildcards, NQ_BOOL pathHasMountPoint)
{
    if (pathHasMountPoint || !(pShare->flags & CC_SHARE_IN_DFS))
    {
        *dirPath = ccUtilsFilePathStripWildcards(localPath);
        *wildcards = ccUtilsFilePathGetWildcards(localPath);
    }
    else
    {
        NQ_WCHAR * temp;

        temp = ccUtilsFilePathFromRemotePath(localPath, TRUE);
        if (NULL == temp)
        {
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return FALSE;
        }
        *dirPath = ccUtilsFilePathStripWildcards(temp);
        *wildcards = ccUtilsFilePathGetWildcards(temp);
        cmMemoryFree(temp);
    }
    
    if (NULL == *dirPath || NULL == *wildcards)
    {
        if (NULL != *dirPath)
            cmMemoryFree(*dirPath);
        if (NULL != *wildcards)
            cmMemoryFree(*wildcards);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    return TRUE;
}

/* 
 * Get new search : allocates search structure, resolves search path (in case of DFS + SMB2)
 */
static CCSearch *getNewSearch(const NQ_WCHAR * srchPath, CCShare * pShare, NQ_WCHAR ** dirPath, NQ_WCHAR ** wildcards, NQ_BOOL pathHasMountPoint)
{
    NQ_WCHAR * localPath; /* path component local to remote share */
    CCSearch * pSearch;   /* search descriptor */
    NQ_STATUS status;     /* SMB operation status */
    NQ_INT counter;       /* counter */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "srchPath: %s, pathHasMountPoint: %d", cmWDump(srchPath), pathHasMountPoint);

    if (pShare == NULL && dirPath == NULL && wildcards == NULL && !pathHasMountPoint && ccUtilsPathIsLocal(srchPath))
    {
        CMIterator  mntItr;
        
        ccMountIterateMounts(&mntItr);
        if (!cmListIteratorHasNext(&mntItr))
        {   
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        cmListIteratorTerminate(&mntItr);
        pSearch = (CCSearch *)cmListItemCreate(sizeof(CCSearch), srchPath , FALSE);
        initializeSearchStructure(pSearch);
        pSearch->context = (CMIterator *)cmMemoryAllocate(sizeof(CMIterator));
        ccMountIterateMounts((CMIterator *)pSearch->context);

        pSearch->share = NULL;
        pSearch->server = NULL;
        pSearch->isFirst = TRUE;
		pSearch->localFile = TRUE;
        cmListItemAdd(&localSearches, (CMItem *)pSearch, unlockCallback);

        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return pSearch;
    }

	if (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NULL;
    }

    localPath = pathHasMountPoint ? ccUtilsFilePathFromLocalPath(srchPath) : cmMemoryCloneWString(srchPath);
    if (NULL == localPath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    if (!getDirPathAndWildCards (pShare, localPath, dirPath, wildcards, pathHasMountPoint))
    {
        cmMemoryFree(localPath);
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
    {
        NQ_WCHAR *dfsFullPath;
        CCMount *pMount;

        pMount = ccMountFind(srchPath);
        if (NULL != pMount)
        { 
            dfsFullPath = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, localPath);
            if (NULL == dfsFullPath)
            {
                cmMemoryFree(localPath);
                sySetLastError(NQ_ERR_OUTOFMEMORY);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NULL;
            }
            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "dfsFullPath: %s", cmWDump(dfsFullPath));
            cmMemoryFree(localPath);
            localPath = dfsFullPath;
        }
    }
#endif   
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "localPath: %s", cmWDump((const NQ_WCHAR *) localPath));
    pSearch = (CCSearch *)cmListItemCreate(sizeof(CCSearch), localPath , FALSE);
    cmMemoryFree(localPath);
    if (NULL == pSearch)
    {
        cmMemoryFree(*dirPath);
        cmMemoryFree(*wildcards);
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    initializeSearchStructure(pSearch);
    pSearch->share = pShare;
    pSearch->server = pShare->user->server;
    pSearch->isFirst = TRUE;
	pSearch->localFile = FALSE;
    cmListItemAdd(&pShare->searches, (CMItem *)pSearch, unlockCallback);

    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        status = pSearch->server->smb->doFindOpen(pSearch);
#ifdef UD_CC_INCLUDEDFS      
        /* for SMB2 only */
        if (status == NQ_ERR_PATHNOTCOVERED)
        {
            CCDfsResult dfsResult;  /* result of DFS resolution */
            NQ_WCHAR * localPath;   /* path component local to remote share */

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NQ_ERR_PATHNOTCOVERED");
            dfsResult = ccDfsResolvePath(pShare, *dirPath);
            if (dfsResult.path)
            {   
                NQ_WCHAR *newPath;

                pShare = dfsResult.share;
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved: %s", cmWDump((const NQ_WCHAR *) dfsResult.path));
                
                localPath = ccUtilsComposePath(dfsResult.path, *wildcards);
                ccDfsResolveDispose(&dfsResult);
                cmMemoryFree(*dirPath);
                cmMemoryFree(*wildcards);
                if (NULL == localPath)
                {
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }               
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "srchPath: %s", cmWDump((const NQ_WCHAR *) localPath));
                
                newPath = (pShare->flags & CC_SHARE_IN_DFS) ? cmMemoryCloneWString(localPath) :
                                                              ccUtilsFilePathFromRemotePath(localPath, TRUE);
                cmMemoryFree(localPath);                                                               
                if (NULL == newPath)
                {
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "newPath: %s", cmWDump((const NQ_WCHAR *) newPath));
                
                if (!getDirPathAndWildCards(pShare, newPath, dirPath, wildcards, FALSE))
                {
                    cmMemoryFree(newPath);
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }
                cmMemoryFree(pSearch->item.name);
				cmMemoryFree(pSearch->context);
                pSearch->item.name = newPath;
                initializeSearchStructure(pSearch);
                pSearch->share = pShare;
                pSearch->server = pShare->user->server;
                pSearch->isFirst = TRUE;

                counter++;
                continue;
            }
        }
#endif /* UD_CC_INCLUDEDFS */          
        if (NQ_ERR_RECONNECTREQUIRED == status)
        {
            pShare->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pShare->user->server))
                break;
        }
        else
            break;
             
    }
    if (NQ_SUCCESS != status)
    {
            cmMemoryFree(*dirPath);
            cmMemoryFree(*wildcards);
            pSearch->server = NULL; /* to not close the search */
            disposeSearch(pSearch);
            sySetLastError((NQ_UINT32)status);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "*dirPath: %s", cmWDump(*dirPath));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "*wildcards: %s", cmWDump(*wildcards));
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pSearch;
}

/*
 * Check file name for . and ..
 */
NQ_BOOL isRealFile(const NQ_WCHAR * name)
{
    return !(
      (name[0] == cmWChar('.') && name[1] == 0) ||
      (name[0] == cmWChar('.') && name[1] == cmWChar('.') && name[2] == 0) 
      );
}

/* 
 * Continue scan 
 */
static NQ_STATUS findNextFile(NQ_HANDLE handle, FindFileDataW_t * findFileData)
{
    NQ_STATUS status = NQ_SUCCESS;              /* SMB operation status */
    CCSearch * pSearch = (CCSearch *)handle;    /* casted search handle */
    NQ_UINT32 nextOffset;                       /* offset to the next entry in the response */
    NQ_BYTE * pEntry;                           /* pointer to the current entry */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (pSearch->localFile)
    {
        NQ_UINT32 low , high;
        CCMount * pMount;
        CMIterator * mntItr;

        mntItr = pSearch->context;
        if (!cmListIteratorHasNext(mntItr))
        {
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_ERR_NOFILES;  
        }
        pMount = (CCMount *)cmListIteratorNext(mntItr);
        syWStrcpy((NQ_WCHAR *)&findFileData->fileName , pMount->item.name);
        findFileData->fileNameLength = syWStrlen(pMount->item.name);
        cmCifsTimeToUTC((NQ_UINT32)syGetTime(), &low, &high);
        findFileData->fileAttributes = CIFS_ATTR_DIR | CIFS_ATTR_ARCHIVE;
        findFileData->creationTimeLow = low;
        findFileData->creationTimeHigh = high;
        findFileData->lastAccessTimeLow = low;
        findFileData->lastAccessTimeHigh = high;
        findFileData->lastWriteTimeLow = low;
        findFileData->lastWriteTimeHigh = high;
        findFileData->fileSizeHigh = 0;
        findFileData->fileSizeLow = 0;
        findFileData->allocationSizeHigh = 0;
        findFileData->allocationSizeLow = 0;
        
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_SUCCESS; 
    }

    if (NULL == pSearch->buffer)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_NOFILES;            
    }

	if (!ccTransportIsConnected(&pSearch->server->transport) && !ccServerReconnect(pSearch->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_NOTCONNECTED;
    }

    do 
    {
        if (cmBufferReaderGetRemaining(&pSearch->parser) < (24 * sizeof(NQ_UINT32)))
        {
            const NQ_BYTE * pBuffer = pSearch->buffer;  /* pointer to the old buffer which is still used 
                                                           for the last file name */
            NQ_INT          counter;                                                    

            pSearch->buffer = NULL;

            for (counter = 0 ; counter < CC_CONFIG_RETRYCOUNT ; counter++)
            {
                status = pSearch->server->smb->doFindMore(pSearch);
                if (NQ_ERR_RECONNECTREQUIRED == status)
                {
                    pSearch->server->transport.connected = FALSE;
                    if (!ccServerReconnect(pSearch->server))
                        break;
                }
                else
                    break;
            }
            cmMemoryFree(pBuffer);
        }
        if (NQ_SUCCESS != status)
        {
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return status;            
        }
        pSearch->isFirst = FALSE;
        /* parse entry */
        pEntry = cmBufferReaderGetPosition(&pSearch->parser);
        cmBufferReadUint32(&pSearch->parser, &nextOffset);      /* next offset */
        cmBufferReaderSkip(&pSearch->parser, sizeof(NQ_UINT32));  /* file index */
        cmBufferReadUint32(&pSearch->parser, &findFileData->creationTimeLow); /* creation time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->creationTimeHigh);  /* creation time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastAccessTimeLow); /* last access time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastAccessTimeHigh);/* last access time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastWriteTimeLow);  /* last write time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastWriteTimeHigh); /* last write time */
        cmBufferReaderSkip(&pSearch->parser, 2 * sizeof(NQ_UINT32));      /* last change time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileSizeLow);   /* EOF */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileSizeHigh);    /* EOF */
        cmBufferReadUint32(&pSearch->parser, &findFileData->allocationSizeLow); /* allocation size */
        cmBufferReadUint32(&pSearch->parser, &findFileData->allocationSizeHigh);/* allocation size */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileAttributes);  /* attributes */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileNameLength);  /* file name length */
        cmBufferReaderSkip(&pSearch->parser, 30);               /* offset to name */
        pSearch->lastFile.data = cmBufferReaderGetPosition(&pSearch->parser);
        pSearch->lastFile.len = findFileData->fileNameLength;
        cmBufferReadBytes(&pSearch->parser, (NQ_BYTE *)findFileData->fileName, findFileData->fileNameLength); /* in bytes */
        findFileData->fileNameLength /= sizeof(NQ_WCHAR);           /* now - in characters */
        findFileData->fileName[findFileData->fileNameLength] = 0;       /* terminator */
        if (0 != nextOffset)
        {
            cmBufferReaderSetPosition(&pSearch->parser, pEntry + nextOffset);   /* prepare next entry */
        }
    }
    while (
        (findFileData->fileNameLength == 1 && findFileData->fileName[0] == cmWChar('.'))
        || (findFileData->fileNameLength == 2 && findFileData->fileName[0] == cmWChar('.') && findFileData->fileName[1] == cmWChar('.'))
        );

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return status;
}

/* -- API Functions */

NQ_BOOL ccSearchStart(void)
{
    cmListStart(&localSearches);
#if SY_DEBUGMODE
    localSearches.name = "localSearches";
#endif   
    return TRUE;
}

void ccSearchShutdown(void)
{
    CMIterator  iterator;

    cmListIteratorStart(&localSearches, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&iterator);
        cmListItemUnlock(pItem);
    }
    cmListIteratorTerminate(&iterator);
    cmListShutdown(&localSearches);
}

NQ_HANDLE ccFindFirstFileA(const NQ_CHAR * srchPath, FindFileDataA_t * findFileData, NQ_BOOL extractFirst)
{
    NQ_WCHAR * searchPathW;           /* the same in Unicode */
    FindFileDataW_t * findFileDataW;  /* file entry in Unicode */
    NQ_HANDLE res;                    /* Unicode operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    searchPathW = cmMemoryCloneAString(srchPath);
    if (NULL == searchPathW)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    findFileDataW = cmMemoryAllocate(sizeof(*findFileDataW));
    if (NULL == findFileDataW)
    {
        cmMemoryFree(searchPathW);
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    res = ccFindFirstFileW(searchPathW, findFileDataW, extractFirst);
    if (NULL != res)
    {
        syMemcpy(findFileData, findFileDataW, sizeof(*findFileData) - sizeof(findFileData->fileName));
        cmUnicodeToAnsiN(findFileData->fileName, findFileDataW->fileName, sizeof(findFileData->fileName));
    }
    cmMemoryFree(findFileDataW);
    cmMemoryFree(searchPathW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_BOOL ccFindNextFileA(NQ_HANDLE handle, FindFileDataA_t *findFileData)
{
    FindFileDataW_t * findFileDataW;  /* file entry in Unicode */
    NQ_BOOL res;                      /* Unicode operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    findFileDataW = cmMemoryAllocate(sizeof(*findFileDataW));
    if (NULL == findFileDataW)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    res = ccFindNextFileW(handle, findFileDataW);
    if (res)
    {
        syMemcpy(findFileData, findFileDataW, sizeof(*findFileData) - sizeof(findFileData->fileName));
        cmUnicodeToAnsiN(findFileData->fileName, findFileDataW->fileName, sizeof(findFileData->fileName));
    }
    cmMemoryFree(findFileDataW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

NQ_HANDLE ccFindFirstFileW(const NQ_WCHAR * srchPath, FindFileDataW_t * findFileData, NQ_BOOL extractFirst)
{
    CCMount * pMount;       /* mount point descriptor */
    NQ_WCHAR * dirPath;     /* path component local to remote share without widlcards */
    NQ_WCHAR * wildcards;   /* the last path component with (possible) wildcards */
    CCShare * pShare;       /* pointer to the hosting share */
    CCSearch * pSearch;     /* search descriptor */
    NQ_STATUS status;       /* SMB operation status */
    NQ_INT counter;         /* counter */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "srchPath: %s", cmWDump((const NQ_WCHAR *) srchPath));

    if (ccUtilsPathIsLocal(srchPath))
    {
    	NQ_CHAR * strA = "*";
		NQ_CHAR * strB = "*.*";
		NQ_CHAR * srchPathA = NULL;
		NQ_BOOL res = FALSE;
		CMIterator mntItr;

		/* checking if search path is mount point name if TRUE then return mount point list else fail */
		ccMountIterateMounts(&mntItr);
		while (cmListIteratorHasNext(&mntItr))
		{
			CMItem *	pItem = cmListIteratorNext(&mntItr);
			
			res = syWStrcmp(srchPath+1 , pItem->name) == 0 ? TRUE : FALSE;
		}
		cmListIteratorTerminate(&mntItr);

		/* checking if search path is '*' or '*.*'    if TRUE then return mount point list else fail */
		srchPathA = cmMemoryCloneWStringAsAscii(srchPath+1);
		if ( syStrcmp(srchPathA ,strA) == 0 ||
			 syStrcmp(srchPathA ,strB) == 0)
		{
		 	res = TRUE;
		}
		cmMemoryFree(srchPathA);

		if (!res)
		{
			sySetLastError(NQ_ERR_BADFILE);
			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return NULL;
		}
	
        pSearch = getNewSearch(srchPath, NULL, NULL, NULL, FALSE);
        if (pSearch == NULL)
        {
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        if (extractFirst)
        {
            findNextFile(pSearch,findFileData);
        }
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return (NQ_HANDLE)pSearch;
    }

    pMount = ccMountFind(srchPath);
    if (NULL == pMount)
    {
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    pShare = pMount->share;
    /* get new search (for SMB2 opens directory, DFS path is resolved at this point) 
       for SMB - just search structure is allocated */
    pSearch = getNewSearch(srchPath, pShare, &dirPath, &wildcards, TRUE);
    if (pSearch == NULL)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dirPath: %s", cmWDump((const NQ_WCHAR *) dirPath));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "wildcards: %s", cmWDump((const NQ_WCHAR *) wildcards));
    
    /* delegate to the protocol */
    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        status = pSearch->server->smb->doFindMore(pSearch);
#ifdef UD_CC_INCLUDEDFS        
        if (status == NQ_ERR_PATHNOTCOVERED)
        {
            /* SMB1 only */
            CCDfsResult dfsResult;           /* result of DFS resolution */

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NQ_ERR_PATHNOTCOVERED");
            dfsResult = ccDfsResolvePath(pShare, dirPath);
            if (dfsResult.path)
            {   
                NQ_WCHAR *newPath;
                NQ_WCHAR *localPathWildCards;   /* path component local to remote share */

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved path: %s", cmWDump((const NQ_WCHAR *) dfsResult.path));
                disposeSearch(pSearch);
                cmMemoryFree(dirPath);

                pShare = dfsResult.share;

                /* decide on full dfs path or just file path */
                newPath = (pShare->flags & CC_SHARE_IN_DFS) ? cmMemoryCloneWString(dfsResult.path) :
                                                              ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                ccDfsResolveDispose(&dfsResult);
                if (NULL == newPath)
                {
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }

                /* add wildcards */
                localPathWildCards = ccUtilsComposePath(newPath, wildcards);  
                cmMemoryFree(newPath); 
                cmMemoryFree(wildcards);
                if (NULL == localPathWildCards)
                {                    
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }                
              
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "new search path: %s", cmWDump((const NQ_WCHAR *) localPathWildCards));
                
                pSearch = getNewSearch(localPathWildCards, pShare, &dirPath, &wildcards, FALSE);
                cmMemoryFree(localPathWildCards); 
                if (NULL == pSearch)
                {
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dirPath: %s", cmWDump((const NQ_WCHAR *) dirPath));
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "wildcards: %s", cmWDump((const NQ_WCHAR *) wildcards));

                counter++;
                continue;
            }
        }
#endif /* UD_CC_INCLUDEDFS */        
        if (NQ_ERR_RECONNECTREQUIRED == status)
        {
            pShare->user->server->transport.connected = FALSE;
            if (!ccServerReconnect(pShare->user->server))
                break;
        }
        else
            break;
    }
    if (NQ_SUCCESS != status)
    {
            disposeSearch(pSearch);
            cmMemoryFree(dirPath);
            cmMemoryFree(wildcards);
            switch(status)
            {
            case NQ_ERR_NOFILES:
            case NQ_ERR_BADFILE:
                status = NQ_ERR_OK;
                break;
            default:
                break;
            }
            sySetLastError((NQ_UINT32)status);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;            
    }
    cmMemoryFree(dirPath);
    cmMemoryFree(wildcards);

    if (extractFirst)
    {
        status = findNextFile((NQ_HANDLE)pSearch, findFileData);
        if (NQ_SUCCESS != status)
        {
            disposeSearch(pSearch);
            switch(status)
            {
            case NQ_ERR_NOFILES:
            case NQ_ERR_BADFILE:
                status = NQ_ERR_OK;
                break;
            default:
                break;
            }
            sySetLastError((NQ_UINT32)status);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return (NQ_HANDLE)pSearch;
}

NQ_BOOL ccFindNextFileW(NQ_HANDLE handle, FindFileDataW_t * findFileData)
{
    NQ_STATUS status;   /* SMB status */

    do 
    {
        status = findNextFile(handle, findFileData);
        if (NQ_SUCCESS != status)
        {
            if (NQ_ERR_NOFILES == status)
            {
                sySetLastError(NQ_SUCCESS);
                return FALSE;
            }
            else
            {
                sySetLastError((NQ_UINT32)status);
            }
            return FALSE;
        }
    }
    while (!isRealFile(findFileData->fileName));
    return TRUE;
}

NQ_BOOL ccFindClose(NQ_HANDLE handle)
{
	if (NULL != handle)
	{
		CCSearch *pSearch = (CCSearch *)handle;
	  	if (!pSearch->localFile && !ccTransportIsConnected(&pSearch->server->transport) && !ccServerReconnect(pSearch->server))
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
			sySetLastError(NQ_ERR_NOTCONNECTED);
			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return FALSE;
		}
	  	disposeSearch(pSearch);
	}
    return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */

