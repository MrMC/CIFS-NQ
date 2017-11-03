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
#include "ccparams.h"
#include <assert.h>

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
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "search:%p", pSearch);

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
    pSearch->disconnected = FALSE;
}

static NQ_BOOL getDirPathAndWildCards (CCShare * pShare,  NQ_WCHAR * localPath, NQ_WCHAR ** dirPath, NQ_WCHAR ** wildcards, NQ_BOOL pathHasMountPoint)
{
    NQ_BOOL result = FALSE;

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
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }
        *dirPath = ccUtilsFilePathStripWildcards(temp);
        *wildcards = ccUtilsFilePathGetWildcards(temp);
        cmMemoryFree(temp);
    }
    
    if (NULL == *dirPath || NULL == *wildcards)
    {
        if (NULL != *dirPath)
        {
            cmMemoryFree(*dirPath);
            *dirPath = NULL;
        }
        if (NULL != *wildcards)
        {
            cmMemoryFree(*wildcards);
            *wildcards = NULL;
        }
        goto Exit;
    }
    result = TRUE;

Exit:
    return result;
}

/* 
 * Get new search : allocates search structure, resolves search path (in case of DFS + SMB2)
 */
static CCSearch *getNewSearch(const NQ_WCHAR * srchPath, CCShare * pShare, NQ_WCHAR ** dirPath, NQ_WCHAR ** wildcards, NQ_BOOL pathHasMountPoint)
{
    NQ_WCHAR * localPath = NULL; /* path component local to remote share */
    CCSearch * pSearch = NULL;   /* search descriptor */
    NQ_STATUS status;            /* SMB operation status */
    NQ_INT counter;              /* counter */
#ifdef UD_CC_INCLUDEDFS
    CCDfsContext dfsContext = {CC_DFS_NUMOFRETRIES, 0, NULL}; /* DFS operations context */
#endif /* UD_CC_INCLUDEDFS */
    CCMount * pMount = NULL;     /* pointer to mount point */
    CCSearch * pResult = NULL;   /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "srchPath:%s share:%p dirPath:%p wildcards:%p pathHasMountPoint:%s", cmWDump(srchPath), pShare, dirPath, wildcards, pathHasMountPoint ? "TRUE" : "FALSE");
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "srchPath: %s, pathHasMountPoint: %d", cmWDump(srchPath), pathHasMountPoint);*/

    if (pShare == NULL && dirPath == NULL && wildcards == NULL && !pathHasMountPoint && ccUtilsPathIsLocal(srchPath))
    {
        CMIterator  mntItr;
        
        ccMountIterateMounts(&mntItr);
        if (!cmListIteratorHasNext(&mntItr))
        {   
			LOGERR(CM_TRC_LEVEL_ERROR, "No mntItr");
			cmListIteratorTerminate(&mntItr);
            goto Exit;
        }
        cmListIteratorTerminate(&mntItr);
        pSearch = (CCSearch *)cmListItemCreate(sizeof(CCSearch), srchPath , CM_LISTITEM_NOLOCK);
        if (NULL != pSearch)
        {
        	initializeSearchStructure(pSearch);
            pSearch->context = (CMIterator *)cmMemoryAllocate(sizeof(CMIterator));
            ccMountIterateMounts((CMIterator *)pSearch->context);

            pSearch->share = NULL;
            pSearch->server = NULL;
            pSearch->isFirst = TRUE;
    		pSearch->localFile = TRUE;
            cmListItemAdd(&localSearches, (CMItem *)pSearch, unlockCallback);
        }
        pResult = pSearch;
        goto Exit;
    }

	if (NULL == pShare || (!ccTransportIsConnected(&pShare->user->server->transport) && !ccServerReconnect(pShare->user->server)))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }
    
    pMount = ccMountFind(srchPath);
    localPath = pathHasMountPoint ? 
            ccUtilsFilePathFromLocalPath(srchPath, pMount ? pMount->pathPrefix : NULL, pShare->user->server->smb->revision == CCCIFS_ILLEGALSMBREVISION, TRUE) :
            ccUtilsFilePathFromLocalPath(srchPath, NULL, pShare->user->server->smb->revision == CCCIFS_ILLEGALSMBREVISION, FALSE);
    if (NULL == localPath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "localPath: %s", cmWDump(localPath));

    if (!getDirPathAndWildCards (pShare, localPath, dirPath, wildcards, pathHasMountPoint))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
    {
        NQ_WCHAR *dfsFullPath;

        if (NULL != pMount)
        { 
            dfsFullPath = ccUtilsComposeRemotePathToFileByMountPath(pMount->path, localPath, FALSE);
            if (NULL == dfsFullPath)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                sySetLastError(NQ_ERR_OUTOFMEMORY);
                goto Exit;
            }
            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "dfsFullPath: %s", cmWDump(dfsFullPath));
            cmMemoryFree(localPath);
            localPath = dfsFullPath;
        }
    }
#endif   
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "localPath: %s", cmWDump((const NQ_WCHAR *) localPath));
    pSearch = (CCSearch *)cmListItemCreate(sizeof(CCSearch), localPath , CM_LISTITEM_NOLOCK);
    if (NULL == pSearch)
    {
        cmMemoryFree(*dirPath);
        cmMemoryFree(*wildcards);
        *dirPath = *wildcards = NULL;
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    initializeSearchStructure(pSearch);
    pSearch->share = pShare;
    pSearch->server = pShare->user->server;
    pSearch->isFirst = TRUE;
	pSearch->localFile = FALSE;
	pSearch->context = NULL;
	pSearch->isAscii = pShare->user->server->useAscii;
    cmListItemAdd(&pShare->searches, (CMItem *)pSearch, unlockCallback);
    cmListItemAddReference((CMItem *)pSearch, (CMItem *)pShare);

    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        status = pSearch->server->smb->doFindOpen(pSearch);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "doFindOpen result: 0x%x", status);
#ifdef UD_CC_INCLUDEDFS      
        /* for SMB2 only */
        if (ccDfsIsError(dfsContext.lastError = status))
        {
            CCDfsResult dfsResult;     /* result of DFS resolution */
            NQ_WCHAR * tmplocalPath;   /* path component local to remote share */

            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "DFS related error %s", status == NQ_ERR_PATHNOTCOVERED ? ": NQ_ERR_PATHNOTCOVERED" : "");
            
            if (--dfsContext.counter < 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "DFS failed to resolve path: too many attempts");
                break;
            }
            dfsResult = ccDfsResolvePath(pMount, pShare, *dirPath, &dfsContext);
            if (dfsResult.path)
            {   
                NQ_WCHAR *newPath;

                pShare = dfsResult.share;
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved: %s", cmWDump((const NQ_WCHAR *) dfsResult.path));
                
                tmplocalPath = ccUtilsComposePath(dfsResult.path, *wildcards);
                ccDfsResolveDispose(&dfsResult);
                cmMemoryFree(*dirPath);
                cmMemoryFree(*wildcards);
                *wildcards = *dirPath = NULL;
                if (NULL == tmplocalPath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
                }               
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "srchPath: %s", cmWDump((const NQ_WCHAR *) tmplocalPath));
                
                newPath = (pShare->flags & CC_SHARE_IN_DFS) ? cmMemoryCloneWString(tmplocalPath) :
                                                              ccUtilsFilePathFromRemotePath(tmplocalPath, TRUE);
                cmMemoryFree(tmplocalPath);                                                               
                if (NULL == newPath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "newPath: %s", cmWDump((const NQ_WCHAR *) newPath));
                
                if (!getDirPathAndWildCards(pShare, newPath, dirPath, wildcards, FALSE))
                {
                    cmMemoryFree(newPath);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
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
        if ((NQ_STATUS) NQ_ERR_RECONNECTREQUIRED == status)
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
        LOGERR(CM_TRC_LEVEL_ERROR, "status:%d", status);
		cmMemoryFree(*dirPath);
		cmMemoryFree(*wildcards);
		*dirPath = *wildcards = NULL;
		if (!ccValidateSearchHandle(pSearch))
		{
			pSearch->server = NULL; /* to not close the search */
			disposeSearch(pSearch);
		}
		sySetLastError((NQ_UINT32)status);
		goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "*dirPath: %s", cmWDump(*dirPath));
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "*wildcards: %s", cmWDump(*wildcards));
    pResult = pSearch;

Exit:
    cmMemoryFree(localPath);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

/* 
 * Continue scan 
 */
static NQ_STATUS findNextFile(NQ_HANDLE handle, FindFileDataW_t * findFileData)
{
    NQ_STATUS status = NQ_SUCCESS;              /* SMB operation status */
    CCSearch * pSearch = (CCSearch *)handle;    /* casted search handle */
    NQ_UINT32 nextOffset = 1;                   /* offset to the next entry in the response */
    NQ_BYTE * pEntry;                           /* pointer to the current entry */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p find:%p", handle, findFileData);

    if (NULL == handle)
	{
		LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		status = NQ_ERR_INVALIDHANDLE;
		goto Exit;
	}

    if (!ccValidateSearchHandle(handle))
	{
		LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		status = NQ_ERR_INVALIDHANDLE;
		goto Exit;
	}
     
    if (pSearch->localFile)
    {
        NQ_UINT32 low , high;
        CCMount * pMount;
        CMIterator * mntItr;

        mntItr = (CMIterator *)pSearch->context;
        if (!cmListIteratorHasNext(mntItr))
        {
			LOGERR(CM_TRC_LEVEL_ERROR , "No mntItr");
			status = NQ_ERR_NOFILES;
			goto Exit;
        }
        pMount = (CCMount *)cmListIteratorNext(mntItr);
        syWStrcpy((NQ_WCHAR *)&findFileData->fileName , pMount->item.name);
        findFileData->fileNameLength = syWStrlen(pMount->item.name);
        cmCifsTimeToUTC(syGetTimeInMsec(), &low, &high);
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
        goto Exit;
    }
    
    if (pSearch->share->isPrinter)
	{
		LOGERR(CM_TRC_LEVEL_ERROR , "Cannot search on a print share");
		sySetLastError(NQ_ERR_BADPARAM);
		status = NQ_ERR_BADPARAM;
		goto Exit;
	}

	if (NULL == pSearch->buffer)
	{
		sySetLastError(NQ_ERR_BADPARAM);
		status = NQ_ERR_BADPARAM;
		goto Exit;
	}
	
	if (!ccTransportIsConnected(&pSearch->server->transport) && !ccServerReconnect(pSearch->server))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		status = NQ_ERR_NOTCONNECTED;
		goto Exit;
    }

    do 
    {
        if (cmBufferReaderGetRemaining(&pSearch->parser) < (24 * sizeof(NQ_UINT32)))
        {
            NQ_INT          counter;                                                    

           	if (pSearch->buffer != NULL)
           	{
           		cmBufManGive(pSearch->buffer);
           		pSearch->buffer = NULL;
           	}

            for (counter = 0 ; counter < CC_CONFIG_RETRYCOUNT ; counter++)
            {
                status = pSearch->server->smb->doFindMore(pSearch);
                if ((NQ_STATUS) NQ_ERR_RECONNECTREQUIRED == status)
                {
                	pSearch->server->transport.connected = FALSE;
                    if (!ccServerReconnect(pSearch->server))
                        break;
                }
                else
                    break;
            }
            if (status != NQ_SUCCESS)
			{
				cmBufManGive(pSearch->buffer);
				pSearch->buffer = NULL;
				LOGERR(CM_TRC_LEVEL_ERROR, "status:%d", status);
				goto Exit;
			}
        }

        pSearch->isFirst = FALSE;
        /* parse entry */
        pEntry = cmBufferReaderGetPosition(&pSearch->parser);
        cmBufferReadUint32(&pSearch->parser, &nextOffset);      				/* next offset */
        cmBufferReaderSkip(&pSearch->parser, sizeof(NQ_UINT32));  				/* file index */
        cmBufferReadUint32(&pSearch->parser, &findFileData->creationTimeLow); 	/* creation time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->creationTimeHigh);  /* creation time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastAccessTimeLow); /* last access time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastAccessTimeHigh);/* last access time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastWriteTimeLow);  /* last write time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->lastWriteTimeHigh); /* last write time */
        cmBufferReaderSkip(&pSearch->parser, 2 * sizeof(NQ_UINT32));      		/* last change time */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileSizeLow);  		/* EOF */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileSizeHigh);    	/* EOF */
        cmBufferReadUint32(&pSearch->parser, &findFileData->allocationSizeLow); /* allocation size */
        cmBufferReadUint32(&pSearch->parser, &findFileData->allocationSizeHigh);/* allocation size */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileAttributes);  	/* attributes */
        cmBufferReadUint32(&pSearch->parser, &findFileData->fileNameLength);  	/* file name length in bytes */
        cmBufferReaderSkip(&pSearch->parser, 30);               				/* offset to name */
        pSearch->lastFile.data = cmBufferReaderGetPosition(&pSearch->parser);
        pSearch->lastFile.len = (NQ_COUNT)findFileData->fileNameLength;
        if (pSearch->isAscii)
        {
        	/* old SMB1 servers do not include null terminator in file name and correspondingly size */
            /* latest SMB1 servers can include null terminator */
            NQ_BYTE * pFileName = cmBufferReaderGetPosition(&pSearch->parser);	/* current position */
            NQ_BOOL isNullTerminated = pFileName[findFileData->fileNameLength - 1] == '\0';

            cmBufferReaderSkip(&pSearch->parser, (NQ_UINT)findFileData->fileNameLength);

            if (isNullTerminated)
                --findFileData->fileNameLength;

            cmAnsiToUnicodeN(findFileData->fileName, (const NQ_CHAR *)pFileName, findFileData->fileNameLength);
        }
        else
        {
        	cmBufferReadBytes(&pSearch->parser, (NQ_BYTE *)findFileData->fileName, (NQ_COUNT)findFileData->fileNameLength);
        	findFileData->fileNameLength /= sizeof(NQ_WCHAR);                           /* now - in characters */

        }
        findFileData->fileName[findFileData->fileNameLength] = cmWChar('\0');       	/* terminator */

       
        if (0 != nextOffset)
        {
            cmBufferReaderSetPosition(&pSearch->parser, pEntry + nextOffset);   /* prepare next entry */
        }
		else
		{
			/*
			 * if nextOffset is 0, "invalidate" additional usage of the parser by forwarding the parser to end of current buffer,
			 * will force us to get the next list of files if the application chooses to continue the search operation.
			 * this fixes a bug where extra garbage bytes exist in the file chain (while next offset is 0)
			 */
			if (cmBufferReaderGetRemaining(&pSearch->parser) > 0)
			{
				LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Trailing data left in search response, skipping to end");
				cmBufferReaderSkip(&pSearch->parser, cmBufferReaderGetRemaining(&pSearch->parser));
			}
        }
    }
    while ((findFileData->fileNameLength == 1 && findFileData->fileName[0] == cmWChar('.'))
        || (findFileData->fileNameLength == 2 && findFileData->fileName[0] == cmWChar('.') && findFileData->fileName[1] == cmWChar('.')));

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
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
    NQ_WCHAR * searchPathW = NULL;           /* the same in Unicode */
    FindFileDataW_t * findFileDataW = NULL;  /* file entry in Unicode */
    NQ_HANDLE res = NULL;                    /* Unicode operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    searchPathW = cmMemoryCloneAString(srchPath);
    if (NULL == searchPathW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    findFileDataW = (FindFileDataW_t *)cmMemoryAllocate(sizeof(*findFileDataW));
    if (NULL == findFileDataW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    res = ccFindFirstFileW(searchPathW, findFileDataW, extractFirst);
    if (NULL != res)
    {
        syMemcpy(findFileData, findFileDataW, sizeof(*findFileData) - sizeof(findFileData->fileName));
        cmUnicodeToAnsiN(findFileData->fileName, findFileDataW->fileName, sizeof(findFileData->fileName));
    }

Exit:
    cmMemoryFree(findFileDataW);
    cmMemoryFree(searchPathW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", res);
    return res;
}

NQ_BOOL ccFindNextFileA(NQ_HANDLE handle, FindFileDataA_t *findFileData)
{
    FindFileDataW_t * findFileDataW = NULL;  /* file entry in Unicode */
    NQ_BOOL res = FALSE;                     /* Unicode operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    findFileDataW = (FindFileDataW_t *)cmMemoryAllocate(sizeof(*findFileDataW));
    if (NULL == findFileDataW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    res = ccFindNextFileW(handle, findFileDataW);
    if (res)
    {
        syMemcpy(findFileData, findFileDataW, sizeof(*findFileData) - sizeof(findFileData->fileName));
        cmUnicodeToAnsiN(findFileData->fileName, findFileDataW->fileName, sizeof(findFileData->fileName));
    }

Exit:
    cmMemoryFree(findFileDataW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_HANDLE ccFindFirstFileW(const NQ_WCHAR * srchPath, FindFileDataW_t * findFileData, NQ_BOOL extractFirst)
{
    CCMount * pMount;              /* mount point descriptor */
    NQ_WCHAR * dirPath = NULL;     /* path component local to remote share without wild cards */
    NQ_WCHAR * wildcards = NULL;   /* the last path component with (possible) wild cards */
    CCShare * pShare;              /* pointer to the hosting share */
    CCSearch * pSearch;            /* search descriptor */
    NQ_STATUS status;              /* SMB operation status */
    NQ_INT counter;                /* counter */
#ifdef UD_CC_INCLUDEDFS
    CCDfsContext dfsContext = {CC_DFS_NUMOFRETRIES, 0, NULL}; /* DFS operations context */
#endif /* UD_CC_INCLUDEDFS */
    NQ_HANDLE result = NULL;       /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s find:%p extract:%s", cmWDump(srchPath), findFileData, extractFirst ? "TRUE" : "FALSE");
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "srchPath: %s", cmWDump((const NQ_WCHAR *) srchPath));*/

    if (ccUtilsPathIsLocal(srchPath))
    {
    	NQ_CHAR * strA = (NQ_CHAR *)"*";
		NQ_CHAR * strB = (NQ_CHAR *)"*.*";
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
	    if (NULL == srchPathA)
	    {
	        LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
	        sySetLastError(NQ_ERR_OUTOFMEMORY);
	        goto Exit;
	    }

		if ( syStrcmp(srchPathA ,strA) == 0 ||
			 syStrcmp(srchPathA ,strB) == 0)
		{
		 	res = TRUE;
		}
		cmMemoryFree(srchPathA);

		if (!res)
		{
	        LOGERR(CM_TRC_LEVEL_ERROR , "Bad file");
			sySetLastError(NQ_ERR_BADFILE);
			goto Exit;
		}
	
        pSearch = getNewSearch(srchPath, NULL, NULL, NULL, FALSE);
        if (pSearch == NULL)
        {
	        LOGERR(CM_TRC_LEVEL_ERROR , "getNewSearch() failed");
			goto Exit;
        }

        if (extractFirst)
        {
            findNextFile(pSearch, findFileData);
        }

        result = (NQ_HANDLE)pSearch;
        goto Exit;
    }

    pMount = ccMountFind(srchPath);
    if (NULL == pMount)
    {
		LOGERR(CM_TRC_LEVEL_ERROR , "pMount is NULL");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pShare = pMount->share;
    if (pShare->isPrinter)
    {
		LOGERR(CM_TRC_LEVEL_ERROR , "Cannot search on a print share");
		sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    /* get new search (for SMB2 opens directory, DFS path is resolved at this point) 
       for SMB - just search structure is allocated */

    pSearch = getNewSearch(srchPath, pShare, &dirPath, &wildcards, TRUE);
    if (pSearch == NULL)
    {
		LOGERR(CM_TRC_LEVEL_ERROR , "pSearch is NULL");
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dirPath: %s", cmWDump((const NQ_WCHAR *) dirPath));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "wildcards: %s", cmWDump((const NQ_WCHAR *) wildcards));

    /* delegate to the protocol */
    for (counter = CC_CONFIG_RETRYCOUNT; counter > 0; counter--)
    {
        status = pSearch->server->smb->doFindMore(pSearch);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "doFindMore result: 0x%x", status);
#ifdef UD_CC_INCLUDEDFS        
        if (ccDfsIsError(dfsContext.lastError = status))
        {
            /* SMB1 only */
            CCDfsResult dfsResult;           /* result of DFS resolution */

            LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "DFS related error %s", status == NQ_ERR_PATHNOTCOVERED ? ": NQ_ERR_PATHNOTCOVERED" : "");

            if (--dfsContext.counter < 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "DFS failed to resolve path: too many attempts");
                break;
            }
            dfsResult = ccDfsResolvePath(pMount, pShare, dirPath, &dfsContext);
            if (dfsResult.path)
            {   
                NQ_WCHAR *newPath;
                NQ_WCHAR *localPathWildCards;   /* path component local to remote share */

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "resolved path: %s", cmWDump((const NQ_WCHAR *) dfsResult.path));
                disposeSearch(pSearch);
                cmMemoryFree(dirPath);
                dirPath = NULL;

                pShare = dfsResult.share;

                /* decide on full dfs path or just file path */
                newPath = (pShare->flags & CC_SHARE_IN_DFS) ? cmMemoryCloneWString(dfsResult.path) :
                                                              ccUtilsFilePathFromRemotePath(dfsResult.path, TRUE);
                ccDfsResolveDispose(&dfsResult);
                if (NULL == newPath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
                }

                /* add wildcards */
                localPathWildCards = ccUtilsComposePath(newPath, wildcards);  
                cmMemoryFree(newPath); 
                if (NULL == localPathWildCards)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
                }
              
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "new search path: %s", cmWDump((const NQ_WCHAR *) localPathWildCards));
                cmMemoryFree(wildcards);
                wildcards = NULL;
                pSearch = getNewSearch(localPathWildCards, pShare, &dirPath, &wildcards, FALSE);
                cmMemoryFree(localPathWildCards);
                if (NULL == pSearch)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Exit;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dirPath: %s", cmWDump((const NQ_WCHAR *) dirPath));
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "wildcards: %s", cmWDump((const NQ_WCHAR *) wildcards));

                counter++;
                continue;
            }
        }
#endif /* UD_CC_INCLUDEDFS */        
        if ((NQ_STATUS)NQ_ERR_RECONNECTREQUIRED == status)
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
        goto Error;
    }

    if (extractFirst)
    {
		status = findNextFile((NQ_HANDLE)pSearch, findFileData);
        if (NQ_SUCCESS != status)
        {
			goto Error;
		}
    }

    result = (NQ_HANDLE)pSearch;
    goto Exit;

Error:
	switch(status)
	{
	case (NQ_STATUS)NQ_ERR_RECONNECTREQUIRED:
		break;
	case NQ_ERR_NOFILES:
	case NQ_ERR_BADFILE:
		status = NQ_ERR_OK;
		cmListItemUnlock((CMItem *)pSearch);
		break;
	default:
		LOGERR(CM_TRC_LEVEL_ERROR , "status:%d", status);
		cmListItemUnlock((CMItem *)pSearch);
		break;
	}
	sySetLastError((NQ_UINT32)status);
	
Exit:
    cmMemoryFree(dirPath);
    cmMemoryFree(wildcards);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", result);
    return result;
}

NQ_BOOL ccFindNextFileW(NQ_HANDLE handle, FindFileDataW_t * findFileData)
{
    NQ_STATUS status;       /* SMB status */
    NQ_BOOL result = FALSE; /* return value */
    do 
    {
        status = findNextFile(handle, findFileData);
        if (NQ_SUCCESS != status)
        {
            if (NQ_ERR_NOFILES == status)
            {
                sySetLastError(NQ_SUCCESS);
            }
            else
            {
                sySetLastError((NQ_UINT32)status);
            }
            goto Exit;
        }
    }
    while (NQ_SUCCESS != status);
    result = TRUE;

Exit:
    return result;
}

NQ_BOOL ccFindClose(NQ_HANDLE handle)
{
	NQ_BOOL result = FALSE;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);

	if (NULL != handle)
	{
		CCSearch *pSearch = (CCSearch *)handle;

		if (!ccValidateSearchHandle(handle))
		{
			if (syGetLastError() == NQ_ERR_NOTCONNECTED)
				disposeSearch(pSearch);
			LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
			sySetLastError(NQ_ERR_INVALIDHANDLE);
			goto Exit;
		}

	  	if (!pSearch->localFile && !ccTransportIsConnected(&pSearch->server->transport) && !ccServerReconnect(pSearch->server))
		{
	  		disposeSearch(pSearch);
			LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
			sySetLastError(NQ_ERR_NOTCONNECTED);
			goto Exit;
		}
	  	disposeSearch(pSearch);
		result = TRUE;
		goto Exit;
	}
	else
	{
		LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		goto Exit;
	}

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}


NQ_BOOL ccValidateSearchHandle(NQ_HANDLE handle)
{
	CMIterator serverItr;
	NQ_BOOL result = FALSE;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p", handle);

	if (NULL == handle)
	{
		LOGERR(CM_TRC_LEVEL_ERROR , "Null Handle");
		goto Exit;
	}

	ccServerIterateServers(&serverItr);
	while (cmListIteratorHasNext(&serverItr))
	{
		CMIterator  userItr;
		CCServer    *   pServer;

		pServer = (CCServer *)cmListIteratorNext(&serverItr);

		cmListIteratorStart(&pServer->users, &userItr);
		while (cmListIteratorHasNext(&userItr))
		{
			CMIterator  shareItr;
			CCUser  *   pUser;

			pUser = (CCUser *)cmListIteratorNext(&userItr);

			cmListIteratorStart(&pUser->shares, &shareItr);
			while (cmListIteratorHasNext(&shareItr))
			{
				CCShare *   pShare;
				CMIterator  searchItr;

				pShare = (CCShare *)cmListIteratorNext(&shareItr);

				cmListIteratorStart(&pShare->searches, &searchItr);
				while (cmListIteratorHasNext(&searchItr))
				{
					CCSearch * pSearch;

					pSearch = (CCSearch *)cmListIteratorNext(&searchItr);

					if (pSearch == handle)
					{
						cmListIteratorTerminate(&searchItr);
						cmListIteratorTerminate(&shareItr);
						cmListIteratorTerminate(&userItr);
						cmListIteratorTerminate(&serverItr);
						if (!pSearch->disconnected)
							result = TRUE;
						else
							sySetLastError(NQ_ERR_NOTCONNECTED);
						goto Exit;
					}
				}
				cmListIteratorTerminate(&searchItr);
			}
			cmListIteratorTerminate(&shareItr);
		}
		cmListIteratorTerminate(&userItr);
	}
	cmListIteratorTerminate(&serverItr);

	cmListIteratorStart(&localSearches, &serverItr);
	while (cmListIteratorHasNext(&serverItr))
	{
		CCSearch * pSearch;

		pSearch = (CCSearch *)cmListIteratorNext(&serverItr);
		if (pSearch == handle)
		{
			cmListIteratorTerminate(&serverItr);
			result = TRUE;
			goto Exit;
		}
	}
	cmListIteratorTerminate(&serverItr);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
