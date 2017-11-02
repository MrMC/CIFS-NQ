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
    NQ_CHAR * aName;    /* server host name in ASCII */
    NQ_BOOL res;        /* the result */

    aName = cmMemoryCloneWStringAsAscii(name);
    if (NULL == aName)
    {
        return FALSE;
    }
    res = (NQ_SUCCESS == cmAsciiToIp(aName, ip));
    cmMemoryFree(aName);
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
        res = cmMemoryAllocate(sizeof(NQ_WCHAR) * 1);
        if (NULL != res)
            *res = cmWChar('\0');
    }
    else
    {
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * len));
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
    NQ_WCHAR *res, *temp;   /* pointer to result */
    NQ_COUNT i;             /* counter */
    NQ_WCHAR prefix [] = {cmWChar('\\'), cmWChar('\\'), cmWChar(0)};

    temp = cmMemoryCloneWString(path);
    if (!temp)
    {
        return NULL;
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
        cmMemoryFree(temp);
        return NULL; 
    }
    res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(p)+ 3)));
    if (NULL != res)
    {
        cmWStrcpy(res, prefix);
        cmWStrcat(res, (NQ_WCHAR *)p);
    }
    cmMemoryFree(temp);    
    return res;   
}


NQ_WCHAR * ccUtilsFilePathFromRemotePath(const NQ_WCHAR * path, NQ_BOOL stripBackslash)
{
    NQ_WCHAR *pHostShare;
    NQ_WCHAR *res = NULL;

    pHostShare = ccUtilsHostShareFromRemotePath(path);
    if (NULL != pHostShare)
    {
        res = cmMemoryCloneWString(path + cmWStrlen(pHostShare) - (stripBackslash ? 0 : 1));
        cmMemoryFree(pHostShare);
    }
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
        res = cmMemoryAllocate(sizeof(NQ_WCHAR) * 1);
        if (NULL != res)
            *res = cmWChar('\0');
    }
    else
    {
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (len + 1)));
        if (NULL != res)
            cmWStrncpy(res, (NQ_WCHAR *)(path + 1), len);
    }
    return res;
}

NQ_WCHAR * ccUtilsFilePathFromLocalPath(const NQ_WCHAR * path)
{
    const NQ_WCHAR * p;   /* pointer in path */
    NQ_WCHAR * res;       /* pointer to result */
    NQ_COUNT len;         /* name length */
    
    for (p = path + 1; *p != 0 && *p != cmWChar('\\') && *p != cmWChar('/'); p++)
    {}
    
    len = (NQ_COUNT)(cmWStrlen(path) - (p - path));
    if (len == 0)
    {
        res = cmMemoryAllocate(sizeof(NQ_WCHAR) * 1);
        if (NULL != res)
            *res = cmWChar('\0');
    }
    else
    {   
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * len));
        if (NULL != res)
            cmWStrncpy(res, (NQ_WCHAR *)(p + 1), len);
    }
    return res;
}

NQ_WCHAR * ccUtilsComposeRemotePathToShare(const NQ_WCHAR * server, const NQ_WCHAR * share)
{
    const NQ_WCHAR oneSlash[] = { cmWChar('\\'), cmWChar(0) };
    const NQ_WCHAR twoSlashes[] = { cmWChar('\\'), cmWChar('\\'), cmWChar(0) };
    NQ_WCHAR * path;

    path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + 3 + cmWStrlen(server) + cmWStrlen(share))));
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
    const NQ_WCHAR oneSlash[] = { cmWChar('\\'), cmWChar(0) };
    const NQ_WCHAR twoSlashes[] = { cmWChar('\\'), cmWChar('\\'), cmWChar(0) };
    NQ_WCHAR * path;

    path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + 4 + cmWStrlen(server) + cmWStrlen(share) + (file ? cmWStrlen(file) : 0))));
    if (NULL != path)
    {
        cmWStrcpy(path, twoSlashes);
        cmWStrcat(path, server);
        cmWStrcat(path, oneSlash);
        cmWStrcat(path, share);
        if (NULL != file)
        {
            cmWStrcat(path, oneSlash);
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
    }
    return path;
}

NQ_WCHAR * ccUtilsComposeRemotePathToFileByMountPath(const NQ_WCHAR * mountPath, const NQ_WCHAR * file)
{
    const NQ_WCHAR oneSlash[] = {cmWChar('\\'), cmWChar(0)};
    NQ_WCHAR * path;

    path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (NULL==file? 0:(cmWStrlen(file)) + cmWStrlen(mountPath) + 2))); 
    if (NULL != path)
    {
        cmWStrcpy(path, mountPath + 1);
        if (NULL != file)
        {
            cmWStrcat(path, oneSlash);
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
    }
    return path;
}    

NQ_BOOL ccUtilsFilePathHasWildcards(const NQ_WCHAR * origin)
{
    const NQ_WCHAR * p;   /* pointer in path */
    
    for (p = origin + cmWStrlen(origin) - 1; p >= origin && *p != cmWChar('\\') && *p != cmWChar('/'); p--)
    {
        if (*p == cmWChar('*') || *p == cmWChar('?'))
            return TRUE;
    }
    return FALSE;
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
            res = cmMemoryAllocate((NQ_UINT)((NQ_INT)sizeof(NQ_WCHAR) * (len + 1)));
            if (NULL != res)
            {
                cmWStrncpy(res, (NQ_WCHAR *)origin, (NQ_UINT)len);
            }
        }
        else
        {
            res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
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
        res = cmMemoryAllocate((NQ_UINT)((NQ_INT)sizeof(NQ_WCHAR) * (len + 1)));
        if (NULL != res)
        {
            cmWStrncpy(res, (NQ_WCHAR *)origin, (NQ_UINT)len);
        }
    }
    else
    {
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
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
        len = (NQ_COUNT)(syWStrlen(origin) - (p - origin) - 1);
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (len + 1)));
        if (NULL != res)
        {
            cmWStrncpy(res, (NQ_WCHAR *)p + 1, len);
        }
    }
    else
    {
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
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

    if (0 == cmWStrlen(file))
    {
        return cmMemoryCloneWString(dir);
    }
    path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + 1 + cmWStrlen(dir) + cmWStrlen(file))));
    if (NULL != path)
    {
        cmWStrcpy(path, dir);
        cmWStrcat(path, oneSlash);
        cmWStrcat(path, file);
    }
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
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (NQ_UINT)(len + 1)));
        if (NULL != res)
        {
            cmWStrncpy(res, (NQ_WCHAR *)path, (NQ_UINT)len);
        }
    }
    else
    {
        res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
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
        len = (NQ_INT)(syWStrlen(path) - (p - path) - 1);
        if (len == 0)
        {
            res = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * 1));
            if (NULL != res)
                *res = cmWChar('\0');
        }
        else
        {
            res = cmMemoryAllocate((NQ_UINT)((NQ_INT)sizeof(NQ_WCHAR) * (len + 1)));
            if (NULL != res)
                cmWStrncpy(res, (NQ_WCHAR *)p + 1, (NQ_UINT)len);
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

    if (path[0] != cmWChar('\0'))
    {
        for (p = (NQ_WCHAR *)&path[1]; *p != cmWChar('\0'); p++)
            if (*p == cmWChar('\\') || *p == cmWChar('/'))
                break;

        if (*p != cmWChar('\0'))
        {
            return FALSE;
        }
    }
    return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
