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

static NQ_WCHAR * pDCName;	/* pointer to domain name */

/* fill user token for the user authenticated to a given file */ 
static NQ_STATUS lookupUserToken(CMSdAccessToken * token,  const NQ_WCHAR * fileName)
{
    NQ_STATUS status;                       /* generic status */
    NQ_HANDLE lsa;                          /* pipe handle for LSA */
    CCMount * pMount;						/* mount point */
    const NQ_WCHAR * userName;				/* user name */
    const NQ_WCHAR * domainName;			/* domain name */
    NQ_WCHAR * homeDomain;					/* pointer to the client's home domain */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    	
    /* find user token. try 1) remote host 2) DC */
    pMount = ccMountFind(fileName);
    if (NULL == pMount)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_BADPATH;
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
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return status;
        }
        else
        {
            status = ccLsaGetUserToken(lsa, userName, NULL, token);
            ccDcerpcDisconnect(lsa);
            if (status == NQ_SUCCESS)
            {
        		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return status;
            }
        }
    }
    
    LOGERR(CM_TRC_LEVEL_ERROR, "Unable to resolve user on host");
    
    /* 2) try domain user */
    if (NULL == pDCName)
    {
    	NQ_CHAR * dcNameA;	/* home domain name in ASCII */
    	
    	dcNameA = cmMemoryAllocate(CM_BUFFERLENGTH(NQ_CHAR, CM_NQ_HOSTNAMESIZE + 1));
        if (NULL == dcNameA)
    	{
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    		return NQ_ERR_OUTOFMEMORY;
    	}
        if (NQ_SUCCESS != cmGetDCName(dcNameA, NULL))
        {
            cmMemoryFree(dcNameA);
            LOGERR(CM_TRC_LEVEL_ERROR, "Cannot acquire DC name");
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_ERR_BADPARAM;
        }
        pDCName = cmMemoryCloneAString(dcNameA);
        cmMemoryFree(dcNameA);
        if (NULL == pDCName)
    	{
    		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    		return NQ_ERR_OUTOFMEMORY;
    	}
    }
    lsa = ccDcerpcConnect(pDCName, NULL, ccLsaGetPipe(), TRUE);
    if (NULL == lsa)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to open LSA on PDC");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_BADPARAM;
    }
	homeDomain = cmMemoryCloneAString(cmNetBiosGetDomain()->name);
	if (NULL == homeDomain)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_OUTOFMEMORY;
	}
    status = ccLsaGetUserToken(lsa, userName, homeDomain, token);
    cmMemoryFree(homeDomain);
    ccDcerpcDisconnect(lsa);
    if (NQ_SUCCESS != status)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to resolve user on domain");
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_ERR_BADPARAM;
    }

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

/* withdraw file SD */
static NQ_STATUS queryFileSecurityDescriptor(NQ_HANDLE handle, CMSdSecurityDescriptor * sd)
{
    NQ_STATUS status;                       /* generic status */
    CCFile * pFile = (CCFile *)handle;		/* casted pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	status = pFile->share->user->server->smb->doQuerySecurityDescriptor(pFile, sd);
	if (NQ_SUCCESS != status)
	{
		sySetLastError((NQ_UINT32)status);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return status;
	}
	
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return 0;
}

/* change file SD */
static NQ_STATUS setFileSecurityDescriptor(NQ_HANDLE handle, const CMSdSecurityDescriptor * sd)
{
    NQ_STATUS status;                       /* generic status */
    CCFile * pFile = (CCFile *)handle;		/* casted pointer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	status = pFile->share->user->server->smb->doSetSecurityDescriptor(pFile, sd);
	if (NQ_SUCCESS != status)
	{
		sySetLastError((NQ_UINT32)status);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return status;
	}
	
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return 0;
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
    NQ_BOOL result = FALSE;	/* Unicode result */
    NQ_WCHAR * fileNameW;	/* the same in Unicode */

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
    NQ_STATUS status;            	/* generic status */
    CMSdSecurityDescriptor * pSd;   /* pointer to security descriptor in packet */
    NQ_HANDLE fileHandle = NULL;    /* for open file */
    NQ_BOOL result;                 /* call result */
    CMSdAccessToken * pToken;       /* pointer to user token */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* lookup access token for the current user */
	pToken = cmMemoryAllocate(sizeof(CMSdAccessToken));
	if (NULL == pToken)
    {
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }
    status = lookupUserToken(pToken, fileName);
    if (0 != status)
    {
		cmMemoryFree(pToken);
		sySetLastError((NQ_UINT32)status);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }

    /* create security descriptor */
    pSd = cmMemoryAllocate(sizeof(CMSdSecurityDescriptor));
	if (NULL == pSd)
    {
		cmMemoryFree(pToken);
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
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
       		cmMemoryFree(pToken);
     		cmMemoryFree(pSd);
            TRCERR("Illegal file name");
            TRCE();
            sySetLastError(NQ_ERR_BADPARAM);
            return FALSE;
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
        	cmMemoryFree(pSd);
    		cmMemoryFree(pToken);
            LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open file");
            sySetLastError(NQ_ERR_BADPARAM);
        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return FALSE;
        }
        status = queryFileSecurityDescriptor(fileHandle, pSd);
        ccCloseHandle(fileHandle);
        if (status != 0)
        {
    		cmMemoryFree(pToken);
    		cmMemoryFree(pSd);
        	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
            sySetLastError((NQ_UINT32)status);
        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return FALSE;
        }
        result = TRUE;
    }

    cmMemoryFree(pToken);
    
    if (!result)
    {
   		cmMemoryFree(pSd);
    	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create security descriptor");
        sySetLastError(NQ_ERR_BADPARAM);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
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
		cmMemoryFree(pSd);
    	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
        sySetLastError(NQ_ERR_BADPARAM);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    status = setFileSecurityDescriptor(fileHandle, pSd);
    ccCloseHandle(fileHandle);
	cmMemoryFree(pSd);
    if (status != 0)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
        sySetLastError((NQ_UINT32)status);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    TRCE();
    return TRUE;
}

NQ_BOOL ccIsExclusiveAccessToFileA(NQ_CHAR *fileName)
{
    NQ_BOOL result = FALSE;	/* Unicode result */
    NQ_WCHAR * fileNameW;	/* the same in Unicode */

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
    NQ_STATUS status;                       /* generic status */
    NQ_HANDLE fileHandle;                   /* for open file */
    NQ_BOOL result;                         /* call result */
    CMSdAccessToken * pToken;           	/* pointer to user token */
    CMSdSecurityDescriptor * pSd;       	/* pointer to security descriptor in packet */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* lookup access token for the current user */
	pToken = cmMemoryAllocate(sizeof(CMSdAccessToken));
	if (NULL == pToken)
    {
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }
    status = lookupUserToken(pToken, fileName);
    if (NQ_SUCCESS != status)
    {
		cmMemoryFree(pToken);
		sySetLastError((NQ_UINT32)status);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
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
		cmMemoryFree(pToken);
        LOGERR(CM_TRC_LEVEL_ERROR, "Cannot open file");
        sySetLastError(NQ_ERR_BADPARAM);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    pSd = cmMemoryAllocate(sizeof(CMSdSecurityDescriptor));
	if (NULL == pSd)
    {
		cmMemoryFree(pToken);
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    status = queryFileSecurityDescriptor(fileHandle, pSd);
    ccCloseHandle(fileHandle);
    if (status != 0)
    {
		cmMemoryFree(pToken);
		cmMemoryFree(pSd);
    	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to acquire security descriptor");
        sySetLastError((NQ_UINT32)status);
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }

    result = cmSdIsExclusiveSecurityDescriptor(pToken, pSd);

	cmMemoryFree(pToken);
	cmMemoryFree(pSd);

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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

