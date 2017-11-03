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

#include "ccsdescr.h"
#include "ccapi.h"
#include "ccmount.h"
#include "cclsarpc.h"
#include "ccfile.h"
#include "cmapi.h"
#include "cmsdescr.h"
#include "cmfinddc.h"

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDESECURITYDESCRIPTORS)

/* -- Constants -- */
#define READ_ACCESSMASK \
    CCFILE_ACCESSMASK_SPECIAL | \
    SMB_DESIREDACCESS_READDATA | \
    SMB_DESIREDACCESS_READATTRIBUTES | \
    SMB_DESIREDACCESS_READCONTROL
#define WRITE_ACCESSMASK \
    CCFILE_ACCESSMASK_SPECIAL | \
    SMB_DESIREDACCESS_WRITEOWNER | \
    SMB_DESIREDACCESS_WRITEATTRIBUTES | \
    SMB_DESIREDACCESS_WRITEDAC | \
    SMB_DESIREDACCESS_READATTRIBUTES | \
    SMB_DESIREDACCESS_READCONTROL

/* -- Static functions and data -- */

static NQ_WCHAR * pDCName;    /* pointer to domain name */

/* fill user token for the user authenticated to a given file */
static NQ_STATUS lookupUserToken(CMSdAccessToken * token,  const NQ_WCHAR * fileName)
{
    NQ_STATUS status;                       /* generic status */
    NQ_HANDLE lsa;                          /* pipe handle for LSA */
    CCMount * pMount = NULL;                /* mount point */
    const NQ_WCHAR * userName = NULL;       /* user name */
    const NQ_WCHAR * domainName = NULL;     /* domain name */
    NQ_CHAR * dcNameA = NULL;               /* home domain name in ASCII */
    NQ_WCHAR * homeDomain = NULL;           /* pointer to the client's home domain */
    NQ_STATUS result = NQ_ERR_BADPARAM;     /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "token:%p file:%s", token, cmWDump(fileName));

    /* find user token. try 1) remote host 2) DC */
    pMount = ccMountFind(fileName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot find mount point ");
        goto Exit;
    }

    userName = pMount->share->user->credentials->user;
    domainName = pMount->share->user->credentials->domain.name;

    /* 1) try local user */
    lsa = ccDcerpcConnect(pMount->server->item.name, pMount->share->user->credentials, ccLsaGetPipe(), TRUE);
    if (NULL != lsa)
    {
        status = ccLsaGetUserToken(lsa, userName, domainName, token);
        if (status == NQ_SUCCESS)
        {
            ccDcerpcDisconnect(lsa);
            result = status;
            goto Exit;
        }
        else
        {
            status = ccLsaGetUserToken(lsa, userName, NULL, token);
            ccDcerpcDisconnect(lsa);
            if (status == NQ_SUCCESS)
            {
                result = status;
                goto Exit;
            }
        }
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Unable to resolve user on host");

    /* 2) try domain user */
    if (NULL == pDCName)
    {
        dcNameA = (NQ_CHAR *)cmMemoryAllocate(CM_BUFFERLENGTH(NQ_CHAR, CM_NQ_HOSTNAMESIZE));
        if (NULL == dcNameA)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            result = NQ_ERR_OUTOFMEMORY;
            goto Exit;
        }
        if (NQ_SUCCESS != cmGetDCName(dcNameA, NULL))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Cannot acquire DC name");
            result = NQ_ERR_BADPARAM;
            goto Exit;

        }
        pDCName = cmMemoryCloneAString(dcNameA);
        if (NULL == pDCName)
        {
            result = NQ_ERR_OUTOFMEMORY;
            goto Exit;
        }
    }
    lsa = ccDcerpcConnect(pDCName, NULL, ccLsaGetPipe(), TRUE);
    if (NULL == lsa)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to open LSA on PDC");
        result = NQ_ERR_BADPARAM;
        goto Exit;
    }
    homeDomain = cmMemoryCloneAString(cmNetBiosGetDomain()->name);
    if (NULL == homeDomain)
    {
        result = NQ_ERR_OUTOFMEMORY;
        goto Exit;
    }
    status = ccLsaGetUserToken(lsa, userName, homeDomain, token);
    ccDcerpcDisconnect(lsa);
    if (NQ_SUCCESS != status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to resolve user on domain");
        result = NQ_ERR_BADPARAM;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    cmMemoryFree(dcNameA);
    cmMemoryFree(homeDomain);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/* withdraw file SD */
static NQ_STATUS queryFileSecurityDescriptor(NQ_HANDLE handle, CMSdSecurityDescriptor * sd)
{
    NQ_STATUS status = NQ_FAIL;               /* generic status */
    CCFile * pFile = (CCFile *)handle;        /* casted pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle: %p sd:%p", handle, sd);

    status = pFile->share->user->server->smb->doQuerySecurityDescriptor(pFile, sd);
    if (NQ_SUCCESS != status)
    {
        sySetLastError((NQ_UINT32)status);
        goto Exit;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

/* change file SD */
static NQ_STATUS setFileSecurityDescriptor(NQ_HANDLE handle, const CMSdSecurityDescriptor * sd)
{
    NQ_STATUS status;                       /* generic status */
    CCFile * pFile = (CCFile *)handle;        /* casted pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle: %p sd:%p", handle, sd);

    status = pFile->share->user->server->smb->doSetSecurityDescriptor(pFile, sd);
    if (NQ_SUCCESS != status)
    {
        sySetLastError((NQ_UINT32)status);
        goto Exit;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}


/* -- API functions */

NQ_BOOL ccSdescrStart(void)
{
    pDCName = NULL;
    return TRUE;
}

void ccSdescrShutdown(void)
{
    if (NULL != pDCName)
        cmMemoryFree(pDCName);
}

NQ_BOOL ccSetExclusiveAccessToFileA(NQ_CHAR * fileName, NQ_BOOL makeExclusive)
{
    NQ_BOOL result = FALSE;  /* Unicode result */
    NQ_WCHAR * fileNameW;    /* the same in Unicode */

    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL != fileNameW)
    {
        result = ccSetExclusiveAccessToFileW(fileNameW, makeExclusive);
        cmMemoryFree(fileNameW);
    }

    return result;
}

NQ_BOOL ccSetExclusiveAccessToFileW(NQ_WCHAR * fileName, NQ_BOOL makeExclusive)
{
    NQ_STATUS status;                      /* generic status */
    CMSdSecurityDescriptor * pSd = NULL;   /* pointer to security descriptor in packet */
    NQ_HANDLE fileHandle = NULL;           /* for open file */
    NQ_BOOL result;                        /* call result */
    CMSdAccessToken * pToken = NULL;       /* pointer to user token */
    NQ_BOOL res = FALSE;                   /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%s make:%s", cmWDump(fileName), makeExclusive ? "TRUE" : "FALSE");

    /* lookup access token for the current user */
    pToken = (CMSdAccessToken *)cmMemoryAllocate(sizeof(CMSdAccessToken));
    if (NULL == pToken)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    status = lookupUserToken(pToken, fileName);
    if (NQ_SUCCESS != status)
    {
        sySetLastError((NQ_UINT32)status);
        goto Exit;
    }

    /* create security descriptor */
    pSd = (CMSdSecurityDescriptor *)cmMemoryAllocate(sizeof(CMSdSecurityDescriptor));
    if (NULL == pSd)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    if (makeExclusive)
    {
        result = cmSdCreateExclusiveSecurityDescriptor(pToken, pSd);
    }
    else
    {
        NQ_WCHAR * pSeparator;                   /* pointer to the last separator in the file path */
        NQ_WCHAR saved;                          /* changed char */

        /* read parent folder's SD */
        pSeparator = cmWStrrchr(fileName, cmWChar('\\'));
        if (NULL == pSeparator)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Illegal file name");
            sySetLastError(NQ_ERR_BADPARAM);
            goto Exit;
        }
        saved = *pSeparator;
        *pSeparator = cmWChar('\0');
        fileHandle = ccCreateFileW(
                        fileName,
                        READ_ACCESSMASK,
                        FILE_SM_DENY_NONE,
                        0,
                        FALSE,
                        SMB_ATTR_DIRECTORY,
                        FILE_CA_FAIL,
                        FILE_OA_OPEN
                        );
        *pSeparator = saved;
        if (NULL == fileHandle)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open file");
            sySetLastError(NQ_ERR_BADPARAM);
            goto Exit;
        }
        status = queryFileSecurityDescriptor(fileHandle, pSd);
        ccCloseHandle(fileHandle);
        if (status != NQ_SUCCESS)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
            sySetLastError((NQ_UINT32)status);
            goto Exit;
        }
        result = TRUE;
        res = result;
    }

    if (!result)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create security descriptor");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    /* open file */
    fileHandle = ccCreateFileW(
                    fileName,
                    WRITE_ACCESSMASK,
                    FILE_SM_DENY_NONE,
                    0,
                    FALSE,
                    0,
                    FILE_CA_FAIL,
                    FILE_OA_OPEN
                    );
    if (NULL == fileHandle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    status = setFileSecurityDescriptor(fileHandle, pSd);
    ccCloseHandle(fileHandle);
    if (status != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
        sySetLastError((NQ_UINT32)status);
        goto Exit;
    }

    res = TRUE;

Exit:
    cmMemoryFree(pToken);
    cmMemoryFree(pSd);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccIsExclusiveAccessToFileA(NQ_CHAR *fileName)
{
    NQ_BOOL result = FALSE;    /* Unicode result */
    NQ_WCHAR * fileNameW;      /* the same in Unicode */

    fileNameW = cmMemoryCloneAString(fileName);
    if (NULL != fileNameW)
    {
        result = ccIsExclusiveAccessToFileW(fileNameW);
        cmMemoryFree(fileNameW);
    }

    return result;
}

NQ_BOOL ccIsExclusiveAccessToFileW(NQ_WCHAR * fileName)
{
    NQ_STATUS status;                      /* generic status */
    NQ_HANDLE fileHandle;                  /* for open file */
    NQ_BOOL result = FALSE;                /* call result */
    CMSdAccessToken * pToken = NULL;       /* pointer to user token */
    CMSdSecurityDescriptor * pSd = NULL;   /* pointer to security descriptor in packet */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "dile:%s", cmWDump(fileName));

    /* lookup access token for the current user */
    pToken = (CMSdAccessToken *)cmMemoryAllocate(sizeof(CMSdAccessToken));
    if (NULL == pToken)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    status = lookupUserToken(pToken, fileName);
    if (NQ_SUCCESS != status)
    {
        sySetLastError((NQ_UINT32)status);
        goto Exit;
    }

    /* query security descriptor */
    fileHandle = ccCreateFileW(
                    fileName,
                    READ_ACCESSMASK,
                    FILE_SM_DENY_NONE,
                    0,
                    FALSE,
                    0,
                    FILE_CA_FAIL,
                    FILE_OA_OPEN
                    );
    if (NULL == fileHandle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pSd = (CMSdSecurityDescriptor *)cmMemoryAllocate(sizeof(CMSdSecurityDescriptor));
    if (NULL == pSd)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    status = queryFileSecurityDescriptor(fileHandle, pSd);
    ccCloseHandle(fileHandle);
    if (NQ_SUCCESS != status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
        sySetLastError((NQ_UINT32)status);
        goto Exit;
    }

    result = cmSdIsExclusiveSecurityDescriptor(pToken, pSd);

Exit:
    cmMemoryFree(pToken);
    cmMemoryFree(pSd);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#else /* UD_CC_INCLUDESECURITYDESCRIPTORS */

NQ_BOOL ccSdescrStart(void)
{
    return TRUE;
}

void ccSdescrShutdown(void)
{
}

#endif /* defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDESECURITYDESCRIPTORS) */
