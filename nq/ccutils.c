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

#include "ccutils.h"
#include "cmmemory.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- API Functions */

NQ_BOOL ccUtilsStart(void)
{
    return TRUE;
}

void ccUtilsShutdown(void)
{
  
}

NQ_BOOL ccUtilsNameToIp(const NQ_WCHAR * name, NQ_IPADDRESS * ip)
{
    NQ_CHAR * aName;     /* server host name in ASCII */
    NQ_BOOL res = FALSE; /* the result */

    aName = cmMemoryCloneWStringAsAscii(name);
    if (NULL == aName)
    {
        goto Exit;
    }
    res = (NQ_SUCCESS == cmAsciiToIp(aName, ip));
    cmMemoryFree(aName);

Exit:
    return res;
}

NQ_WCHAR * ccUtilsHostFromRemotePath(const NQ_WCHAR * path)
{
    const NQ_WCHAR *p, *t;  /* pointers in path */
    NQ_WCHAR * res;         /* pointer to result */
    NQ_COUNT len;           /* name length */

    for (t = (NQ_WCHAR *)path; *t && (*t == cmWChar('\\') || *t == cmWChar('/')); t++) /* skip path delimiters */
    {}

    for (p = t ; *p && *p != cmWChar('\\') && *p != cmWChar('/'); p++)
    {}

    len = (NQ_COUNT)(p - t + 1);
    if (len == 0)
    {
        res = (NQ_WCHAR *)cmMemoryAllocate(sizeof(NQ_WCHAR) * 1);
        if (NULL != res)
            *res = cmWChar('\0');
    }
    else
    {
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * len));
        if (NULL != res)
        {
            cmWStrncpy(res, (NQ_WCHAR *)t, len);
            res[len - 1] = cmWChar('\0');
        }
    }   
    return res;
}

NQ_WCHAR * ccUtilsShareFromRemotePath(const NQ_WCHAR * path)
{
    const NQ_WCHAR * p;     /* pointer in path */
    NQ_WCHAR * res = NULL;  /* pointer to result */ 
    NQ_WCHAR *pHostShare;   /* pointer host and share path */

    pHostShare = ccUtilsHostShareFromRemotePath(path);
    if (NULL != pHostShare)
    {
        p = cmWStrrchr(pHostShare, cmWChar('\\'));
        if (p)
            res = cmMemoryCloneWString(p + 1);
        cmMemoryFree(pHostShare);
    }
    return res;
}

NQ_WCHAR * ccUtilsHostShareFromRemotePath(const NQ_WCHAR * path)
{
    NQ_WCHAR *p, *t;        /* pointers in path */
    NQ_WCHAR *res = NULL, *temp = NULL;   /* pointer to result */
    NQ_COUNT i;             /* counter */
    NQ_WCHAR prefix [] = {cmWChar('\\'), cmWChar('\\'), cmWChar('\0')};

    temp = cmMemoryCloneWString(path);
    if (!temp)
    {
        goto Exit;
    }

    for (i = 0, p = (NQ_WCHAR *)temp; *p && *p == cmWChar('\\'); p++, i++) /* skip backslashes */
    {
    }

    for (i = 0, t = p; *t; t++) /* count path delimiters */
    {
        if (*t == cmWChar('\\'))
        {
            i++;
            if (i == 2) {*t = 0; break;}
        }
    }
    if (i == 0)
    {
        goto Exit;
    }
    res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(p)+ 3)));
    if (NULL != res)
    {
        cmWStrcpy(res, prefix);
        cmWStrcat(res, (NQ_WCHAR *)p);
    }

Exit:
    cmMemoryFree(temp);
    return res;
}


NQ_WCHAR * ccUtilsFilePathFromRemotePath(const NQ_WCHAR * path, NQ_BOOL stripBackslash)
{
    NQ_WCHAR *pTemp = NULL, *p = NULL, *pHostShare = NULL;
    NQ_WCHAR *res = NULL;
    NQ_WCHAR prefix [] = {cmWChar('\\'), cmWChar('\\'), cmWChar('\0')};

    pTemp = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((cmWStrlen(path) + 3) * sizeof(NQ_WCHAR)));
    if (NULL == pTemp)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }

    cmWStrcpy(pTemp, prefix);
    for (p = (NQ_WCHAR *)path; *p == cmWChar('\\'); p++)
    {}
    cmWStrcat(pTemp, p);
    pHostShare = ccUtilsHostShareFromRemotePath(pTemp);
    if (NULL != pHostShare)
    {
        if (cmWStrlen(pTemp) == cmWStrlen(pHostShare))
        {
            /* path doesn't contain file portion */
            res = (NQ_WCHAR *)cmMemoryAllocate(2 * sizeof(NQ_WCHAR));
            if (NULL != res)
            {
                res[0] = stripBackslash ? cmWChar('\0') : cmWChar('\\');
                res[1] = cmWChar('\0'); 
            }
        }
        else
        {
            res = cmMemoryCloneWString(pTemp + cmWStrlen(pHostShare) + 1 - (stripBackslash ? 0 : 1));
            if (NULL == res)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                goto Exit;
            }
        }
    }

Exit:
    cmMemoryFree(pHostShare);
    cmMemoryFree(pTemp);
    return res;
}

NQ_WCHAR * ccUtilsMountPointFromLocalPath(const NQ_WCHAR * path)
{
    const NQ_WCHAR * p;   /* pointer in path */
    NQ_WCHAR * res;       /* pointer to result */
    NQ_COUNT len;         /* name length */
    
    for (p = path + 1; *p != 0 && *p != cmWChar('\\') && *p != cmWChar('/'); p++)
    {}
    
    len = (NQ_COUNT)((p - path) - 1);
    if (len == 0)
    {
        res = (NQ_WCHAR *)cmMemoryAllocate(sizeof(NQ_WCHAR) * 1);
        if (NULL != res)
            *res = cmWChar('\0');
    }
    else
    {
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (len + 1)));
        if (NULL != res)
        {
            cmWStrncpy(res, (NQ_WCHAR *)(path + 1), len);
            res[len] = cmWChar('\0');
        }

    }
    return res;
}

NQ_WCHAR * ccUtilsFilePathFromLocalPath(const NQ_WCHAR * path, const NQ_WCHAR * pathPrefix, NQ_BOOL makeCanonic, NQ_BOOL isLocalPath)
{
    const NQ_WCHAR * p;         /* pointer in path */
    NQ_WCHAR * res = NULL;      /* pointer to result */
    NQ_COUNT lenPath;           /* path name length */
    NQ_COUNT lenPathPrefix;     /* path prefix name length */
    NQ_CHAR canonicString[] = {'\\', '\0'};
    NQ_BOOL isPathPrefix = pathPrefix ? (cmWStrlen(pathPrefix) != 0) : FALSE;
 
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s pathPrefix:%s makeCanonic:%s isLocalPath:%s", path ? cmWDump(path) : "null", pathPrefix ? cmWDump(pathPrefix) : "null", makeCanonic ? "TRUE" : "FALSE", isLocalPath ? "TRUE" : "FALSE");
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "path: %s", path ? cmWDump(path) : "null");*/
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "pathPrefix: %s", pathPrefix ? cmWDump(pathPrefix) : "null");*/
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "makeCanonic: %d, isLocalPath: %d, isPathPrefix: %d", makeCanonic, isLocalPath, isPathPrefix);*/
    if (!isLocalPath)
    {
        res = makeCanonic ? ccUtilsCanonicalizePath(path) : cmMemoryCloneWString(path);
        goto Exit;
    }

    for (p = path + 1; *p != 0 && *p != cmWChar('\\') && *p != cmWChar('/'); p++)
    {}
    lenPath = (NQ_COUNT)cmWStrlen(path) - (NQ_COUNT)(p - path);
    lenPathPrefix = isPathPrefix ? (NQ_COUNT)cmWStrlen(pathPrefix) : 0;

    res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((lenPathPrefix + lenPath + 2) * sizeof(NQ_WCHAR)));
    if (NULL == res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }

    *res = cmWChar('\0');

    if (lenPath == 0 && lenPathPrefix == 0)
	{
		goto Exit;
	}

    syMemset(res, 0, ((lenPathPrefix + lenPath + 2) * sizeof(NQ_WCHAR)));

    if (makeCanonic)    cmAnsiToUnicode(res, canonicString);
    if (isPathPrefix)   cmWStrcat(res, (pathPrefix[0] == cmWChar('\\')) ? pathPrefix + 1 : pathPrefix);
    if (p) cmWStrcat(res, isPathPrefix ? (NQ_WCHAR *)(p) : (NQ_WCHAR *)(p + 1));

Exit:
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "res: %s", res ? cmWDump(res) : "null");*/
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? cmWDump(res) : "null");
    return res;
}

NQ_WCHAR * ccUtilsComposeRemotePathToShare(const NQ_WCHAR * server, const NQ_WCHAR * share)
{
    const NQ_WCHAR oneSlash[] = { cmWChar('\\'), cmWChar('\0') };
    const NQ_WCHAR twoSlashes[] = { cmWChar('\\'), cmWChar('\\'), cmWChar('\0') };
    NQ_WCHAR * path;

    path = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + 3 + cmWStrlen(server) + cmWStrlen(share))));
    if (NULL != path)
    {
        cmWStrcpy(path, twoSlashes);
        cmWStrcat(path, server);
        cmWStrcat(path, oneSlash);
        cmWStrcat(path, share);
    }
    return path;
}

NQ_WCHAR * ccUtilsComposeRemotePathToFile(const NQ_WCHAR * server, const NQ_WCHAR * share, const NQ_WCHAR * file)
{
    const NQ_WCHAR oneSlash[] = { cmWChar('\\'), cmWChar('\0') };
    const NQ_WCHAR twoSlashes[] = { cmWChar('\\'), cmWChar('\\'), cmWChar('\0') };
    NQ_WCHAR * path;

    path = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + 4 + cmWStrlen(server) + cmWStrlen(share) + (file ? cmWStrlen(file) : 0))));
    if (NULL != path)
    {
        cmWStrcpy(path, twoSlashes);
        cmWStrcat(path, server);
        cmWStrcat(path, oneSlash);
        cmWStrcat(path, share);
        if (NULL != file)
        {
            cmWStrcat(path, oneSlash);
            cmWStrcat(path, file[0] == cmWChar('\\') ? file + 1 : file);
        }
    }
    return path;
}

NQ_WCHAR * ccUtilsComposeLocalPathToFileByMountPoint(const NQ_WCHAR * mountPoint, const NQ_WCHAR * file)
{
    const NQ_WCHAR oneSlash[] = {cmWChar('\\'), cmWChar('\0')};
    NQ_WCHAR * path;
    
    path = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (NULL == file ? 0 : (cmWStrlen(file)) + cmWStrlen(mountPoint) + 3))); 
    if (NULL != path)
    {
        cmWStrcpy(path, oneSlash);
        if (NULL != mountPoint)
            cmWStrcat(path, mountPoint);
        cmWStrcat(path, oneSlash);
        if (NULL != file)
            cmWStrcat(path, file);
    }
    return path;
}

NQ_WCHAR * ccUtilsComposeRemotePathToFileByMountPath(const NQ_WCHAR * mountPath, const NQ_WCHAR * file, NQ_BOOL isPathLocal)
{
    const NQ_WCHAR oneSlash[] = {cmWChar('\\'), cmWChar('\0')};
    NQ_WCHAR * path;

    path = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * ((NULL == file ? 0 : cmWStrlen(file)) + cmWStrlen(mountPath) + 6)));
    if (NULL != path)
    {
        cmWStrcpy(path, mountPath + 1);
        if (NULL != file)
        {
            cmWStrcat(path, oneSlash);
            if (isPathLocal)
            {
                if (file[0] == cmWChar('\\'))
                {
                    NQ_WCHAR *p;
                
                    /* skip mount point */
                    p = cmWStrchr(file + 1, cmWChar('\\'));
                    if (p)
                        cmWStrcat(path, p + 1);
                }
                else
                    cmWStrcat(path, file);
            }
            else
            {
                cmWStrcat(path, file[0] == cmWChar('\\') ? file + 1 : file);
            }            
        }
    }
    return path;
}    

NQ_BOOL ccUtilsFilePathHasWildcards(const NQ_WCHAR * origin)
{
    const NQ_WCHAR * p;   /* pointer in path */
    NQ_BOOL result = TRUE;

    for (p = origin + cmWStrlen(origin) - 1; p >= origin && *p != cmWChar('\\') && *p != cmWChar('/'); p--)
    {
        if (*p == cmWChar('*') || *p == cmWChar('?'))
            goto Exit;
    }
    result = FALSE;

Exit:
    return result;
}

NQ_WCHAR * ccUtilsFilePathStripWildcards(const NQ_WCHAR * origin)
{
    const NQ_WCHAR * p;   /* pointer in path */
    NQ_WCHAR * res;       /* pointer to result */
    NQ_INT len;           /* name length */
    NQ_BOOL hasWildCards = FALSE; /* wildcards flag */

    for (p = origin + cmWStrlen(origin) - 1; p >= origin && *p != cmWChar('\\') && *p != cmWChar('/'); p--)
    {
        if (*p == cmWChar('*') || *p == cmWChar('?'))
            hasWildCards = TRUE;
    }
    if (hasWildCards)
    {
        len = (NQ_INT)(p - origin);
        if (len > 0)
        {
            res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((NQ_INT)sizeof(NQ_WCHAR) * (len + 1)));
            if (NULL != res)
            {
            	*res = cmWChar('\0');
                cmWStrncpy(res, (NQ_WCHAR *)origin, (NQ_UINT)len);
                res[len] = cmWChar('\0');
            }
        }
        else
        {
            res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
            if (NULL != res)
            {
                *res = cmWChar('\0');
            }
        }
    }
    else
    {
        res =  cmMemoryCloneWString(origin);
    }
    return res;
}

NQ_WCHAR * ccUtilsFilePathStripLastComponent(const NQ_WCHAR * origin)
{
    const NQ_WCHAR * p;   /* pointer in path */
    NQ_WCHAR * res;       /* pointer to result */
    NQ_INT len;           /* name length */

    for (p = origin + cmWStrlen(origin) - 1; p >= origin && *p != cmWChar('\\') && *p != cmWChar('/'); p--)
    {}
    len = (NQ_INT)(p - origin);
    if (len > 0)
    {
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((NQ_INT)sizeof(NQ_WCHAR) * (len + 1)));
        if (NULL != res)
        {
        	*res = cmWChar('\0');
            cmWStrncpy(res, (NQ_WCHAR *)origin, (NQ_UINT)len);
            res[len] = cmWChar('\0');
        }
    }
    else
    {
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
        if (NULL != res)
        {
            *res = cmWChar('\0');
        }
    } 
    return res;
}


NQ_WCHAR * ccUtilsFilePathGetWildcards(const NQ_WCHAR * origin)
{
    const NQ_WCHAR * p;   /* pointer in path */
    NQ_WCHAR * res;       /* pointer to result */
    NQ_COUNT len;         /* name length */
    NQ_BOOL hasWildCards = FALSE; /* wildcards flag */

    for (p = origin + cmWStrlen(origin) - 1; p >= origin && *p != cmWChar('\\') && *p != cmWChar('/'); p--)
    {
        if (*p == cmWChar('*') || *p == cmWChar('?'))
            hasWildCards = TRUE;
    }
    if (hasWildCards)
    {
        len = (NQ_COUNT)syWStrlen(origin) - (NQ_COUNT)(p - origin) - 1;
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (len + 1)));
        if (NULL != res)
        {
        	*res = cmWChar('\0');
            cmWStrncpy(res, (NQ_WCHAR *)p + 1, len);
            res[len] = cmWChar('\0');
        }
    }
    else
    {
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
        if (NULL != res)
        {
            *res = cmWChar('\0');
        }
    }
    return res;
}

NQ_WCHAR * ccUtilsComposePath(const NQ_WCHAR * dir, const NQ_WCHAR * file)
{
    const NQ_WCHAR oneSlash[] = { cmWChar('\\'), cmWChar(0) };
    NQ_WCHAR * path;

    if ((NULL == file) || (0 == cmWStrlen(file)))
    {
        path = cmMemoryCloneWString(dir);
        goto Exit;
    }
    path = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + 1 + cmWStrlen(dir) + cmWStrlen(file))));
    if (NULL != path)
    {
        cmWStrcpy(path, dir);
        cmWStrcat(path, oneSlash);
        cmWStrcat(path, file);
    }

Exit:
    return path;
}

NQ_WCHAR * ccUtilsDirectoryFromPath(const NQ_WCHAR * path)
{
    NQ_WCHAR * res;         /* pointer to result */
    NQ_INT len;             /* name length */
    const NQ_WCHAR * p;     /* pointer in path */

    for (p = path + cmWStrlen(path) - 1; p >= path && *p != cmWChar('\\') && *p != cmWChar('/'); p--)
    {}

    len = (NQ_INT)(p - path);
    if (len > 0)
    {
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (NQ_UINT)(len + 1)));
        if (NULL != res)
        {
            cmWStrncpy(res, (NQ_WCHAR *)path, (NQ_UINT)len);
            res[len] = cmWChar('\0');
        }
    }
    else
    {
        res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
        if (NULL != res)
        {
            *res = cmWChar('\0');
        }
    }
    return res;
}

NQ_WCHAR * ccUtilsFileFromPath(const NQ_WCHAR * path)
{
    NQ_WCHAR * res;         /* pointer to result */
    NQ_INT len;             /* name length */
    const NQ_WCHAR * p;     /* pointer in path */

    for (p = path + cmWStrlen(path) - 1; p >= path && *p != cmWChar('\\') && *p != cmWChar('/'); p--)
    {}

    if (p >= path)
    {
        len = (NQ_INT)syWStrlen(path) - (NQ_INT)(p - path) - 1;
        if (len == 0)
        {
            res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
            if (NULL != res)
                *res = cmWChar('\0');
        }
        else
        {
            res = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((NQ_INT)sizeof(NQ_WCHAR) * (len + 1)));
            if (NULL != res)
            {
                cmWStrncpy(res, (NQ_WCHAR *)p + 1, (NQ_UINT)len);
                res[len] = cmWChar('\0');
            }

        }
    }
    else
    {
        res =  cmMemoryCloneWString(path);
    }
    return res;
}

NQ_BOOL ccUtilsPathIsLocal(const NQ_WCHAR * path)
{
    const NQ_WCHAR *p;         /* pointer in path */
    NQ_BOOL result = FALSE;

    if (path[0] != cmWChar('\0'))
    {
        for (p = (NQ_WCHAR *)&path[1]; *p != cmWChar('\0'); p++)
            if (*p == cmWChar('\\') || *p == cmWChar('/'))
                break;

        if (*p != cmWChar('\0'))
        {
            goto Exit;
        }
    }
    result = TRUE;

Exit:
    return result;
}


NQ_WCHAR * ccUtilsCanonicalizePath(const NQ_WCHAR * path)
{
    NQ_WCHAR *canonicalizedPath = (NQ_WCHAR *)path;

    if (path[0] != cmWChar('\\'))
    {
        canonicalizedPath = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)sizeof(NQ_WCHAR) * (cmWStrlen(path) + 2));
        if (NULL == canonicalizedPath)
            goto Exit;
        canonicalizedPath[0] = cmWChar('\\');
        canonicalizedPath[1] = cmWChar('\0');
        cmWStrcat(canonicalizedPath, path);
    }
    else
    {
        canonicalizedPath = cmMemoryCloneWString(path);
    }

Exit:
    return canonicalizedPath;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
