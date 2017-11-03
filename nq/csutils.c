/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Common functions
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csutils.h"
#include "cmbuf.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This file implements the most common functions that do not fit in other
   categories
 */

/* find file in a directory and change its name providing the request may have incorrect case */

static NQ_BOOL
findFileInPath(
    const NQ_WCHAR* path,       /* path to the containing directory (in correct case) */
    NQ_WCHAR* file              /* file name to look for (may have incorrect case) */
    );

/*
 *====================================================================
 * PURPOSE: create a socket and bind it to the host name
 *--------------------------------------------------------------------
 * PARAMS:  IN socket type (datagram or stream)
 *          IN socket transport (NetBIOS, TCPv4 or TCPv6)
 *
 * RETURNS: socket handle or NULL on error
 *
 * NOTES:   create socket, bind it to the host name and start listening
 *====================================================================
 */

NSSocketHandle
csPrepareSocket(
    NQ_UINT type,
    NQ_UINT transport
    )
{
    NSSocketHandle socket;      /* handle for the new socket */
    NQ_STATUS res;

    TRCB();

    /* create a socket */

    socket = nsSocket(type, transport);

    if (socket == NULL)
    {
        TRCERR("Unable to create server socket ");

        TRCE();
        return NULL;
    }

    /* bind it to NetBIOS Name */

    switch (transport)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
    case NS_TRANSPORT_NETBIOS:
        cmNetBiosNameFormat((NQ_CHAR*)cmNetBiosGetHostNameInfo()->name, CM_NB_POSTFIX_SERVER);
        res = nsBindNetBios(socket, cmNetBiosGetHostNameInfo(), NS_BIND_SERVER);
        break;
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_NQ_USETRANSPORTIPV4
    case NS_TRANSPORT_IPV4:
    {
        NQ_IPADDRESS any = CM_IPADDR_ANY4;
        res = nsBindInet(socket, &any, syHton16(CM_NB_SESSIONSERVICEPORTIP));
        break;
    }
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
    case NS_TRANSPORT_IPV6:
    {
        NQ_IPADDRESS any6 = CM_IPADDR_ANY6;
        res = nsBindInet(socket, &any6, syHton16(CM_NB_SESSIONSERVICEPORTIP));
        break;
    }
#endif /* UD_NQ_USETRANSPORTIPV6 */

    default:
        res = NQ_FAIL;
        break;
    };

    if (res == NQ_FAIL)
    {
        nsClose(socket);
        TRCERR("Unable to bind to port ");

        TRCE();
        return NULL;
    }

    /* start listening on the server
       even on fail we have a chance on a datagram port since DD is actually listening */

    if (nsListen(socket, UD_FS_LISTENQUEUELEN) == NQ_FAIL && type == NS_SOCKET_STREAM)
    {
        nsClose(socket);
        TRCERR("Unable to listen on port ");

        TRCE();
        return NULL;
    }

    TRCE();
    return socket;
}

/*
 *====================================================================
 * PURPOSE: check whether file attributes match the desired attributes
 *--------------------------------------------------------------------
 * PARAMS:  IN desired (requested) attributes
 *          IN file attributes
 *
 * RETURNS: TRUE on match, FALSE otherwise
 *
 * NOTES:   At least one file attribute should match the desired mask. Besides,
 *          a normal file always match and a directory match too.
 *====================================================================
 */

NQ_BOOL
csMatchFileAttributes(
    NQ_UINT16 searchAttributes,
    NQ_UINT16 fileAttributes
    )
{
    /* oocatinally returned volume labels are not reported */

    if (fileAttributes & SMB_ATTR_VOLUME)
    {
        return FALSE;
    }

    /* special file attributes (hidden, system, read-only) should match */

    if (fileAttributes & SMB_ATTR_SYSTEM)
    {
        if (!(searchAttributes & SMB_ATTR_SYSTEM))
            return FALSE;
    }

    if (fileAttributes & SMB_ATTR_HIDDEN)
    {
        if (!(searchAttributes & SMB_ATTR_HIDDEN))
            return FALSE;
    }

    /* archive files, normal files, readonly files and directories always match */

    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: Change file attributes
 *--------------------------------------------------------------------
 * PARAMS:  IN existing attributes
 *          IN desired attributes
 *
 * RETURNS: new file attributes
 *
 * NOTES:   The (bloody) Microsoft client does not care about preserving
 *          such attributes as Directory or Device. So, we need to preserve this attributes
 *          regradless of what MS client requires
 *====================================================================
 */

NQ_UINT32
csChangeFileAttributes(
    NQ_UINT32 oldAttributes,
    NQ_UINT32 desiredAttributes
    )
{
    if (desiredAttributes == 0)
    {
        return oldAttributes;       /* nothing to change */
    }

    return (NQ_UINT32)((oldAttributes & SMB_ATTR_FILETYPE) | (desiredAttributes & (NQ_UINT32)~SMB_ATTR_FILETYPE));
}

/*
 *====================================================================
 * PURPOSE: find the file (case insensitive) providing the path exists
 *--------------------------------------------------------------------
 * PARAMS:  IN share pointer or NULL if we do not care of share type
 *          IN/OUT pointer to the full path
 *          IN whether client file system is case preserving
 *
 * RETURNS: TRUE if the file exists
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csCheckFile(
    const CSShare* pShare,
    NQ_WCHAR* pName,
    NQ_BOOL preservesCase
    )
{
    NQ_WCHAR* pSeparator;    /* pointer to the separator before the file name in the path */
    NQ_BOOL resValue;       /* the result value */
    SYFileInformation fileInfo;     /* placeholder - value not used */

    TRCB();
    
    if (pShare != NULL && (pShare->ipcFlag || pShare->isPrintQueue))
    {
        TRCE();
        return TRUE;
    }
    if (preservesCase || (pShare != NULL && 0==syWStrcmp(pShare->map, pName)))
    {
        resValue =  syGetFileInformationByName(pName, &fileInfo) == NQ_SUCCESS;
    }
    else
    {
        if ((pSeparator = syWStrrchr(pName, cmWChar(SY_PATHSEPARATOR))) != NULL)
        {
            *pSeparator = cmWChar(0);
            resValue = findFileInPath(pName, pSeparator + 1);
            *pSeparator = cmWChar(SY_PATHSEPARATOR);
        }
        else
        {
            resValue = findFileInPath(NULL, pName);
        }
    }

    TRCE();
    return resValue;
}

/*
 *====================================================================
 * PURPOSE: find the path to a given file (case insensitive)
 *--------------------------------------------------------------------
 * PARAMS:  IN share pointer
 *          IN/OUT pointer to the full path
 *          IN length of the tree map
 *          IN whether client file system is case preserving
 *
 * RETURNS: TRUE if the path exists
 *
 * NOTES:   This function is essential for a case sensitive file systems
 *          It checks each component of a given file path using case insensitive
 *          comparison
 *====================================================================
 */

NQ_BOOL
csCheckPath(
    const CSShare* pShare,
    NQ_WCHAR* pName,
    NQ_UINT treeLen,
    NQ_BOOL preservesCase
    )
{
    NQ_WCHAR* pSeparator1;          /* pointer to the separator before the directory being checked */
    NQ_WCHAR* pSeparator2 = NULL;   /* pointer to the separator after the directory being checked */
    NQ_WCHAR* pFileSeparator;       /* pointer to the separator before the file name */
    NQ_BOOL resValue;               /* the result value */
    NQ_UINT relativePartsNum = 0;   /* number of relative parts of the path: '.' and '..' */
    NQ_UINT absolutePartsNum = 0;   /* number of absolute parts of the path */

    TRCB();

    TRC3P("  Share [%s], map [%s], name [%s]", cmWDump(pShare->name), cmWDump(pShare->map), cmWDump(pName));
    TRC2P("  tree length %d, preserves case %d", treeLen, preservesCase);
    
    if (pShare->ipcFlag)
    {
        TRCE();
        return TRUE;
    }
    if (    (pFileSeparator = syWStrrchr(pName, cmWChar(SY_PATHSEPARATOR))) == NULL
         || (NQ_UINT)(pFileSeparator - pName) < treeLen
        )
    {
        TRCE();
        return TRUE;
    }
    else
    {        
        /* check whether given path points above the shared directory */ 
        pSeparator1 = syWStrchr(pName + treeLen, cmWChar(SY_PATHSEPARATOR));
        for ( ; pSeparator1 != pFileSeparator; pSeparator1 = syWStrchr(pSeparator1 + 1, cmWChar(SY_PATHSEPARATOR)))
        {
        	if (NULL == pSeparator1)
        		break;

            if (*(pSeparator1 + 1) == cmWChar('.'))
            {
                if (*(pSeparator1 + 2) == cmWChar('.'))
                {
                    if (*(pSeparator1 + 3) == cmWChar(SY_PATHSEPARATOR))
                    {
                        relativePartsNum++;
                        continue;
                    }
                }
                if (*(pSeparator1 + 2) == cmWChar(SY_PATHSEPARATOR))
                    continue;
            }    
            absolutePartsNum++;
        }        
        if (relativePartsNum > absolutePartsNum)
        {
            TRCERR("illegal relative path");
            TRCE();
            return FALSE;
        }                    
        
        *pFileSeparator = cmWChar(0);

        resValue = TRUE;
        pSeparator1 = syWStrchr(pName + treeLen, cmWChar(SY_PATHSEPARATOR));

        if (preservesCase)
        {
            SYDirectory dir;            /* directory descriptor */
            NQ_STATUS status;           /* operation status */
            const NQ_WCHAR* nextName;   /* name in the next directory entry */

            status = syFirstDirectoryFile(
                pName,
                &dir,
                &nextName
            );

            if (status != NQ_SUCCESS)
            {
                TRCERR("syFirstDirectoryFile failed");
                TRCE();
                return FALSE;
            }

            syCloseDirectory(dir);
            *pFileSeparator = cmWChar(SY_PATHSEPARATOR);
            TRCE();
            return TRUE;
        }
        else
        {
            while (pSeparator1 != NULL)
            {
                *pSeparator1 = cmWChar(0);
                pSeparator2 = syWStrchr(pSeparator1 + 1, cmWChar(SY_PATHSEPARATOR));
                if (pSeparator2 != NULL)
                    *pSeparator2 = cmWChar(0);
                if (!findFileInPath(pName, pSeparator1 + 1))
                {
                    resValue = FALSE;
                    break;
                }
                *pSeparator1 = cmWChar(SY_PATHSEPARATOR);
                pSeparator1 = pSeparator2;
            }
            if (pSeparator1 != NULL)
                *pSeparator1 = cmWChar(SY_PATHSEPARATOR);
            if (pSeparator2 != NULL)
                *pSeparator2 = cmWChar(SY_PATHSEPARATOR);
            *pFileSeparator = cmWChar(SY_PATHSEPARATOR);
        }
    }

    TRCE();
    return resValue;
}

/*
 *====================================================================
 * PURPOSE: find the full path (case insensitive)
 *--------------------------------------------------------------------
 * PARAMS:  IN share pointer
 *          IN/OUT pointer to the full path
 *          IN length of the tree map
 *          IN whether client file system is case preserving
 *
 * RETURNS: TRUE if the full path exists
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csCheckPathAndFile(
    const CSShare* pShare,
    NQ_WCHAR* pName,
    NQ_UINT treeLen,
    NQ_BOOL preservesCase
    )
{
    NQ_BOOL resValue;           /* resulting value */
    SYFileInformation fileInfo; /* placeholder - value not used */

    TRCB();

    TRC3P("  Share [%s], map [%s], name [%s]", cmWDump(pShare->name), cmWDump(pShare->map), cmWDump(pName));
    
    if (pShare->ipcFlag)
    {
        TRCE();
        return TRUE;
    }
    if (preservesCase)
    {
        resValue = syGetFileInformationByName(pName, &fileInfo) == NQ_SUCCESS;
    }
    else
    {
        resValue = csCheckPath(pShare, pName, treeLen, preservesCase) && csCheckFile(pShare, pName, preservesCase);
    }

    TRCE();
    return resValue;
}

/*
 *====================================================================
 * PURPOSE: get file information according to the file type
 *          (file, share, etc.)
 *--------------------------------------------------------------------
 * PARAMS:  IN file structure pointer
 *          IN file name pointer
 *          OUT pointer to the file information structure
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   The file name is corrected to reflect the actual file name
 *====================================================================
 */

NQ_STATUS
csGetFileInformation(
    const CSFile* pFile,
    const NQ_WCHAR* pFileName,
    SYFileInformation* pFileInfo
    )
{
	NQ_BOOL				res;
#ifdef UD_NQ_INCLUDEEVENTLOG
	UDFileAccessEvent	eventInfo;
	CSUser	*			pUser = NULL;

	eventInfo.before = TRUE;
	eventInfo.fileName = pFileName != NULL ? pFileName : NULL;
	eventInfo.tid = pFile->tid;
	pUser = (pFile->user != NULL) ? pFile->user : csGetUserByUid(pFile->uid);
	eventInfo.rid = (pUser != NULL) ? csGetUserRid(pUser) : (NQ_UINT32)CS_ILLEGALID;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    if (syIsValidFile(pFile->file))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	if (pUser != NULL)
		{

			udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_ATTRIBGET,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE *)&eventInfo
						);
			eventInfo.before = FALSE;
		}
#endif /* UD_NQ_INCLUDEEVENTLOG */
    	res = syGetFileInformation(pFile->file, pFileName, pFileInfo);
#ifdef UD_NQ_INCLUDEEVENTLOG
    	if (pUser != NULL)
    	{
			eventInfo.sizeLow = pFileInfo->sizeLow;
			eventInfo.sizeHigh = pFileInfo->sizeHigh;
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					pUser->name,
					pUser->ip,
					(res == 0) ? 0 : csErrorGetLast(),
					(const NQ_BYTE *)&eventInfo
					);
    	}
#endif /* UD_NQ_INCLUDEEVENTLOG */
        return res;
    }
#ifdef UD_CS_INCLUDERPC
    else if (pFile->isPipe)
    {
    	NQ_TIME zero = {0, 0};

        pFileInfo->allocSizeHigh = 0;
        pFileInfo->allocSizeLow = 0;
        pFileInfo->attributes = 0;
        pFileInfo->isDeleted = FALSE;
        pFileInfo->creationTime = zero;
        pFileInfo->lastAccessTime = zero;
        pFileInfo->lastChangeTime = zero;
        pFileInfo->lastWriteTime = zero;
        pFileInfo->numLinks = 0;
        pFileInfo->sizeHigh = 0;
        pFileInfo->sizeLow = 0;

        return NQ_SUCCESS;
    }
#endif /* UD_CS_INCLUDERPC */
    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: get file by file name information according to the file type
 *          (file, share, etc.)
 *--------------------------------------------------------------------
 * PARAMS:  IN file structure pointer
 *          IN file name pointer
 *          OUT pointer to the share descriptor
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   The file name is corrected to reflect the actual file name
 *====================================================================
 */

NQ_STATUS
csGetFileInformationByName(
    const CSShare* pShare,
    const NQ_WCHAR* pFileName,
    SYFileInformation* pFileInfo
#ifdef UD_NQ_INCLUDEEVENTLOG
    ,const CSUser	*			pUser
#endif /* UD_NQ_INCLUDEEVENTLOG */
    )
{
	NQ_INT	res;
#ifdef UD_NQ_INCLUDEEVENTLOG
	UDFileAccessEvent	eventInfo;
	CSTree	*			pTree;


	pTree = csGetNextTreeByShare(pShare , CS_ILLEGALID);
	if (pUser != NULL)
	{
		while (pTree->uid != pUser->uid)
		{
			pTree = csGetNextTreeByShare(pShare, pTree->tid);
		}
		eventInfo.rid = csGetUserRid(pUser);
		eventInfo.tid = (NQ_UINT32)(pTree != NULL ? pTree->tid : CS_ILLEGALID);
		eventInfo.fileName = pFileName != NULL ? pFileName : NULL;
	}
#endif /* UD_NQ_INCLUDEEVENTLOG */

    if (!pShare->ipcFlag && !pShare->isPrintQueue)
    {

#ifdef UD_NQ_INCLUDEEVENTLOG
		if (pUser != NULL)
		{
			eventInfo.before = TRUE;
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE *)&eventInfo
					);
			eventInfo.before = FALSE;
		}
#endif /* UD_NQ_INCLUDEEVENTLOG */
    	res = syGetFileInformationByName(pFileName, pFileInfo);
#ifdef UD_NQ_INCLUDEEVENTLOG
    	if (pUser != NULL)
    	{
			eventInfo.sizeLow = pFileInfo->sizeLow;
			eventInfo.sizeHigh = pFileInfo->sizeHigh;
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					pUser->name,
					pUser->ip,
					(res == 0) ? 0 : csErrorGetLast(),
					(const NQ_BYTE *)&eventInfo
					);
    	}
#endif /* UD_NQ_INCLUDEEVENTLOG */
        return res;
    }
    else
    {
    	NQ_TIME zero = {0, 0};

        pFileInfo->allocSizeHigh = 0;
        pFileInfo->allocSizeLow = 0;
        pFileInfo->attributes = 0;
        pFileInfo->isDeleted = FALSE;
        pFileInfo->creationTime = zero;
        pFileInfo->lastAccessTime = zero;
        pFileInfo->lastChangeTime = zero;
        pFileInfo->lastWriteTime = zero;
        pFileInfo->numLinks = 0;
        pFileInfo->sizeHigh = 0;
        pFileInfo->sizeLow = 0;

        return NQ_SUCCESS;
    }
}

/*
 *====================================================================
 * PURPOSE: set file information according to the file type
 *          (file, share, etc.)
 *--------------------------------------------------------------------
 * PARAMS:  IN file structure pointer
 *          IN file name pointer
 *          OUT fpointer to the file information structure
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   The file name is corrected to reflect the actual file name
 *====================================================================
 */

NQ_STATUS
csSetFileInformation(
    const CSFile* pFile,
    const NQ_WCHAR* pFileName,
    const SYFileInformation* pFileInfo
    )
{
	NQ_STATUS res;
#ifdef UD_NQ_INCLUDEEVENTLOG
	UDFileAccessEvent	eventInfo;
	CSUser	*			pUser = NULL;

	eventInfo.before = TRUE;
	eventInfo.fileName = pFileName != NULL ? pFileName : NULL;
	eventInfo.tid = pFile->tid;
	pUser = (pFile->user != NULL) ? pFile->user : csGetUserByUid(pFile->uid);
	eventInfo.rid = (pUser != NULL) ? csGetUserRid(pUser) : (NQ_UINT32)CS_ILLEGALID;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    if (syIsValidFile(pFile->file))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		if (pUser != NULL)
		{
			eventInfo.before = TRUE;
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBSET,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE *)&eventInfo
					);
			eventInfo.before = FALSE;
		}
#endif /* UD_NQ_INCLUDEEVENTLOG */
        res = sySetFileInformation(pFileName,pFile->file, pFileInfo);
#ifdef UD_NQ_INCLUDEEVENTLOG
    	if (pUser != NULL)
    	{
			eventInfo.sizeLow = pFileInfo->sizeLow;
			eventInfo.sizeHigh = pFileInfo->sizeHigh;
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBSET,
					pUser->name,
					pUser->ip,
					(res == 0) ? 0 : csErrorGetLast(),
					(const NQ_BYTE *)&eventInfo
					);
    	}
#endif /* UD_NQ_INCLUDEEVENTLOG */
        return res;
    }
#ifdef UD_CS_INCLUDERPC
    else if (pFile->isPipe)
    {
        return NQ_SUCCESS;
    }
#endif
    return NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: Check whether this file can be deleted
 *--------------------------------------------------------------------
 * PARAMS:  IN file name pointer
 *
 * RETURNS: TRUE or FALSE
 *
 * NOTES:   The file name is corrected to reflect the actual file name
 *====================================================================
 */

NQ_BOOL
csCanDeleteFile(
    const NQ_WCHAR* pFileName
#ifdef UD_NQ_INCLUDEEVENTLOG
    ,const CSUser * pUser,
    const UDFileAccessEvent eventLogInfo
#endif /* UD_NQ_INCLUDEEVENTLOG */
    )
{
    SYFileInformation fileInfo;     /* file information structure */
    SYFile noFile;                  /* illegal file handle */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;
#endif /* UD_NQ_INCLUDEEVENTLOG */

#ifdef UD_NQ_INCLUDEEVENTLOG
    syMemcpy(&eventInfo , &eventLogInfo , sizeof(eventInfo));
	eventInfo.before = TRUE;
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    if (NQ_FAIL == syGetFileInformationByName(pFileName, &fileInfo))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBGET,
				pUser->name,
				pUser->ip,
				csErrorGetLast(),
				(const NQ_BYTE *)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        return FALSE;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBGET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEVENTLOG */
/*    if (fileInfo.attributes & SMB_ATTR_READONLY)
    {
        return FALSE;
    }*/


    syInvalidateFile(&noFile);
#ifdef UD_NQ_INCLUDEEVENTLOG
	eventInfo.before = TRUE;
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBSET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    if (NQ_FAIL == sySetFileInformation(pFileName, noFile, &fileInfo))
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_ATTRIBSET,
				pUser->name,
				pUser->ip,
				csErrorGetLast(),
				(const NQ_BYTE *)&eventInfo
				);
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
        return FALSE;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
	udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_ATTRIBSET,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE *)&eventInfo
			);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    return TRUE;
}

/*====================================================================
 * PURPOSE: Truncate file
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the file
 *          IN file name
 *          IN low 32 bits of the offset
 *          IN high 32 bits of the offset
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:
 *====================================================================
 */
 
NQ_UINT32
csTruncateFile(
    CSFile* pFile,
    const NQ_WCHAR* pFileName,
    NQ_UINT32 sizeLow,
    NQ_UINT32 sizeHigh
    )
{
    SYFile file;
    NQ_STATUS result;
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser	*	pUser = (pFile && pFile->user) ? pFile->user : NULL;
#endif /* UD_NQ_INCLUDEEVENTLOG*/

    TRCB();

    if (pFile == NULL)
    {      
        if (pFileName == NULL)
        {
            TRCERR("invalid file");
            TRCE();
            return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
        }      
        file = syOpenFileForReadWrite(pFileName, FALSE, FALSE, FALSE);
        if (!syIsValidFile(file))
        {
            TRCERR("invalid file");
            TRCE();
            return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
        }
    }
    else
    {
        file = pFile->file;
    }

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.before   = TRUE;
    eventInfo.fileName = pFileName;
    eventInfo.sizeHigh = sizeHigh;
    eventInfo.sizeLow  = sizeLow;
    if (pUser != NULL)
    {
    	eventInfo.tid  = (NQ_UINT32)((pFile != NULL) ? pFile->tid : CS_ILLEGALID);
    	eventInfo.rid  = csGetUserRid(pUser);
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_SIZESET,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
    }
    eventInfo.before   = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG*/

    result = syTruncateFile(file, sizeLow, sizeHigh);
    if (result != NQ_SUCCESS)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	if (pUser != NULL)
		{
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_SIZESET,
					pUser->name,
					pUser->ip,
					csErrorGetLast(),
					(const NQ_BYTE *)&eventInfo
					);
		}
#endif /* UD_NQ_INCLUDEEVENTLOG*/
		if (pFile == NULL)
		{
			result = syCloseFile(file);
		}
        TRCERR("unable to truncate file");
        TRCE();
        return csErrorGetLast();
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    if (pUser != NULL)
   	{
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_SIZESET,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE *)&eventInfo
				);
   	}
#endif /* UD_NQ_INCLUDEEVENTLOG*/
    if (pFile == NULL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		if (pUser != NULL)
		{
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE *)&eventInfo
					);
		}
#endif /* UD_NQ_INCLUDEEVENTLOG*/
        result = syCloseFile(file);
#ifdef UD_NQ_INCLUDEEVENTLOG
		if (pUser != NULL)
		{
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_CLOSE,
					pUser->name,
					pUser->ip,
					(result == NQ_SUCCESS) ? 0 : csErrorGetLast(),
					(const NQ_BYTE *)&eventInfo
					);
		}
#endif /* UD_NQ_INCLUDEEVENTLOG*/
    }
    else
    {
        pFile->offsetLow = 0;
        pFile->offsetHigh = 0;

        /* set file pointer on the underlying file system */
#ifdef UD_NQ_INCLUDEEVENTLOG
        eventInfo.offsetLow = pFile->offsetLow;
        eventInfo.offsetHigh = pFile->offsetHigh;
        eventInfo.before = TRUE;
		if (pUser != NULL)
		{
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_SEEK,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE *)&eventInfo
					);
		}
		eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG*/
        result = (NQ_STATUS)sySeekFileStart(pFile->file, (NQ_UINT32)pFile->offsetLow, (NQ_UINT32)pFile->offsetHigh);
#ifdef UD_NQ_INCLUDEEVENTLOG
		if (pUser != NULL)
		{
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_SEEK,
					pUser->name,
					pUser->ip,
					(result == NQ_FAIL) ? csErrorGetLast() : 0,
					(const NQ_BYTE *)&eventInfo
					);
		}
#endif /* UD_NQ_INCLUDEEVENTLOG*/
    }

    TRCE();
    return NQ_SUCCESS;
}


/*
 *====================================================================
 * PURPOSE: set file information according to the file type
 *          (file, share, etc.)
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: host type
 *
 * NOTES:   The file name is corrected to reflect the actual file name
 *====================================================================
 */

NQ_UINT32
csGetHostType(
    void
    )
{
    NQ_UINT32 hostType = 0;
    const CMNetBiosNameInfo* domainInfo = cmNetBiosGetDomain();

#ifdef UD_NQ_INCLUDECIFSSERVER
        hostType |= 0x00000002;    /* any server */
#if defined(UD_CS_INCLUDERPC_LSARPC) || defined (UD_CS_INCLUDERPC_SAMRPC)
        hostType |= 0x00008000;    /* NT server */
#endif
#endif
#ifdef UD_NQ_INCLUDECIFSCLIENT
        hostType |= 0x00000001;    /* workstation */
#if defined(UD_CS_INCLUDERPC_LSARPC) || defined (UD_CS_INCLUDERPC_SAMRPC)
        hostType |= 0x00001000;    /* NT workstation */
#endif
#endif
#ifdef UD_CS_INCLUDERPC_SPOOLSS
        hostType |= 0x00000200;
#endif
    if (!domainInfo->isGroup)
    {
        hostType |= 0x00000100;     /* domain member */
    }
    return hostType;
}

/*
 *====================================================================
 * PURPOSE: find file in a directory and change its name providing the
 *          request may have incorrect case
 *--------------------------------------------------------------------
 * PARAMS:  IN path to the containing directory (in correct case)
 *          IN/OUT file name to look for (may have incorrect case)
 *
 * RETURNS: TRUE if the file exists
 *
 * NOTES:   The file name is corrected to reflect the actual file name
 *====================================================================
 */

static NQ_BOOL
findFileInPath(
    const NQ_WCHAR* path,
    NQ_WCHAR* file
    )
{
    SYDirectory dir;            /* directory descriptor */
    NQ_STATUS status;           /* operation status */
    const NQ_WCHAR* nextName;   /* name in the next directory entry */

    TRCB();

    TRC2P("  Path [%s], file [%s]", cmWDump(path), cmWDump(file));
    
    status = syFirstDirectoryFile(
        path,
        &dir,
        &nextName
    );

    if (status != NQ_SUCCESS)
    {
        TRCERR("Cannot open directory for file path check");
        TRC1P(" path: %s", cmWDump(path));
        TRCE();
        return FALSE;
    }

    while (status == NQ_SUCCESS && nextName != NULL)
    {
        if (cmWStricmp(file, nextName) == 0)
        {
            cmWStrcpy(file, nextName);
            if (syCloseDirectory(dir) != NQ_SUCCESS)
            {
                TRCERR("Close directory failed");
            }
            TRCE();
            return TRUE;
        }
        status = syNextDirectoryFile(
            dir,
            &nextName
        );
    }
    if (syCloseDirectory(dir) != NQ_SUCCESS)
    {
        TRCERR("Close directory failed");
    }

    TRCERR("    File not found!");
    TRCE();
    return FALSE;
}

/*
 *====================================================================
 * PURPOSE: check if the given user can read from share
 *--------------------------------------------------------------------
 * PARAMS:  IN TID to use
 *
 * RETURNS: NQ_SUCCESS if access allowed or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csCanReadShare(
    CSTid tid
    )
{
    const CSTree* pTree;        /* tree structure pointer */
    const CSShare* pShare;      /* share structure pointer */
    const CSUser* pUser;        /* user structure pointer */

    pTree = csGetTreeByTid(tid);
    if (NULL == pTree)
        return csErrorReturn(0, SRV_ERRinvtid);
    
    pShare = pTree->share;
    pUser = csGetUserByUid(pTree->uid);

    if (NULL == pShare || NULL == pUser)
        return csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    return cmSdHasAccess(&pUser->token, pShare->sd.data, SMB_DESIREDACCESS_READDATA) ? 
                         NQ_SUCCESS : csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
#else
    return cmSdHasAccess(&pUser->token, NULL, SMB_DESIREDACCESS_READDATA) ?
                             NQ_SUCCESS : csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
#endif
}

/*
 *====================================================================
 * PURPOSE: check if the given user can write to share
 *--------------------------------------------------------------------
 * PARAMS:  IN TID to use
 *
 * RETURNS: NQ_SUCCESS if access allowed or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csCanWriteShare(
    CSTid tid
    )
{
    const CSTree* pTree;        /* tree structure pointer */
    const CSShare* pShare;      /* share structure pointer */
    const CSUser* pUser;        /* user structure pointer */

    pTree = csGetTreeByTid(tid);
    if (NULL == pTree)
        return csErrorReturn(0, SRV_ERRinvtid);
    pShare = pTree->share;
    pUser = csGetUserByUid(pTree->uid);

    if (NULL == pShare || NULL == pUser)
        return csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    return cmSdHasAccess(&pUser->token, pShare->sd.data, SMB_DESIREDACCESS_WRITEDATA) ? 
                         NQ_SUCCESS : csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
#else
    return cmSdHasAccess(&pUser->token, NULL, SMB_DESIREDACCESS_WRITEDATA) ?
                             NQ_SUCCESS : csErrorReturn(SMB_STATUS_ACCESS_VIOLATION, DOS_ERRbadaccess);
#endif
}


/*====================================================================
 * PURPOSE: check share mapping
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the share struct
 *
 * RETURNS: TRUE on success
 *
 * NOTES:   checks the existence of the underlying path
 *====================================================================
 */

NQ_BOOL
csCheckShareMapping(
    CSShare* pShare
    )
{
#ifndef UD_CS_AVOIDSHAREACCESSCHECK
    SYFileInformation fileInfo;
    const NQ_WCHAR rootDir[] = {SY_PATHSEPARATOR, cmWChar(0)};

    return pShare->ipcFlag || pShare->isPrintQueue ? 
        TRUE : NQ_SUCCESS == syGetFileInformationByName(
                                                        0 == syWStrlen(pShare->map)?
                                                            rootDir :
                                                            pShare->map, &fileInfo
                                                        );
#else
    return TRUE;
#endif /*UD_CS_AVOIDSHAREACCESSCHECK*/
}

/*====================================================================
 * PURPOSE: write file times in response packet
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to file info structure
 *          IN pointer to name structure
 *          IN/OUT pointer to response buffer
 *
 * RETURNS: 
 *
 * NOTES:   
 *====================================================================
 */

void
csWriteFileTimes(
    const SYFileInformation *fileInfo,
    const CSName *pName,
    NQ_BYTE *pResponse
    )
{
    NQ_UINT32 timeLow, timeHigh;
    CMBufferWriter writer;

    TRCB();

    cmBufferWriterInit(&writer, pResponse, 32); 
    
    /* creation time */
    if (pName && (pName->time.creationTimeLow != 0 || pName->time.creationTimeHigh != 0))
    {
        cmBufferWriteUint32(&writer, pName->time.creationTimeLow);
        cmBufferWriteUint32(&writer, pName->time.creationTimeHigh);
    }
    else
    {
        cmCifsTimeToUTC(fileInfo->creationTime, &timeLow, &timeHigh);
        cmBufferWriteUint32(&writer, timeLow);
        cmBufferWriteUint32(&writer, timeHigh);
    }

    /* last access time */
    if (pName && (pName->time.lastAccessTimeLow != 0 || pName->time.lastAccessTimeHigh != 0))
    {
        cmBufferWriteUint32(&writer, pName->time.lastAccessTimeLow);
        cmBufferWriteUint32(&writer, pName->time.lastAccessTimeHigh);
    }
    else
    {
        cmCifsTimeToUTC(fileInfo->lastAccessTime, &timeLow, &timeHigh);
        cmBufferWriteUint32(&writer, timeLow);
        cmBufferWriteUint32(&writer, timeHigh);
    }

    /* last write time */
    if (pName && (pName->time.lastWriteTimeLow != 0 || pName->time.lastWriteTimeHigh != 0))
    {
        cmBufferWriteUint32(&writer, pName->time.lastWriteTimeLow);
        cmBufferWriteUint32(&writer, pName->time.lastWriteTimeHigh);
    }
    else
    {
        cmCifsTimeToUTC(fileInfo->lastWriteTime, &timeLow, &timeHigh);
        cmBufferWriteUint32(&writer, timeLow);
        cmBufferWriteUint32(&writer, timeHigh);
    }

    /* last change time */
    if (pName && (pName->time.lastChangeTimeLow != 0 || pName->time.lastChangeTimeHigh != 0))
    {
        cmBufferWriteUint32(&writer, pName->time.lastChangeTimeLow);
        cmBufferWriteUint32(&writer, pName->time.lastChangeTimeHigh);
    }
    else
    {
        cmCifsTimeToUTC(fileInfo->lastChangeTime, &timeLow, &timeHigh);
        cmBufferWriteUint32(&writer, timeLow);
        cmBufferWriteUint32(&writer, timeHigh);
    }

    TRCE();
}

/*====================================================================
 * PURPOSE: reset file times in name structur
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to name structure
 *
 * RETURNS: 
 *
 * NOTES:   
 *====================================================================
 */

void
csResetFileTimes(
    CSName *pName
    )
{
    if (pName)
        syMemset(&pName->time, 0, sizeof(pName->time));
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

