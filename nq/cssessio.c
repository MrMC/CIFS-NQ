/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Session setup
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csparams.h"
#include "csauth.h"
#include "csdispat.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/*====================================================================
 * PURPOSE: Perform LOGOFF_ANDX command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComLogoffAndX(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsLogoffAndXRequest* logoffRequest;   /* casted pointer to the request */
    CMCifsLogoffAndXResponse* logoffResponse; /* casted pointer to the response */
    NQ_UINT32 returnValue;      /* error code returns by other routines - NT */
    CSUser* pUser;              /* user descriptor */

    TRCB();

    /* cast pointers */

    logoffRequest = (CMCifsLogoffAndXRequest*)pRequest;
    logoffResponse = (CMCifsLogoffAndXResponse*)(*pResponse);

    if (logoffRequest->wordCount != SMB_LOGOFFANDX_REQUEST_WORDCOUNT)     /* expected word count */
    {
        TRCERR("Unexpected word count");
        TRC2P("  is: %d expected: %d", *pRequest, SMB_LOGOFFANDX_REQUEST_WORDCOUNT);
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_IMPLEMENTED, SRV_ERRsmbcmd);
    }

    /* check space in the output buffer */

    if ((returnValue =
         csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*logoffResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    if (pUser == NULL)
    {
        TRCERR("Unknown UID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_PARAMETER, SRV_ERRinvuid);
    }

    /* check that the next AndX command is a valid one */

    switch (logoffRequest->andXCommand)
    {
    case SMB_COM_SESSION_SETUP_ANDX:
    case 0xFF:
        break;
    default:
        TRCERR("Illegal command follows Session Setup AndX");
        TRC1P("  command: %d", (NQ_INT)logoffRequest->andXCommand);
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*logoffResponse);

    /* compose response */

    logoffResponse->wordCount = SMB_SESSIONSETUPANDX_RESPONSE_WORDCOUNT;
    logoffResponse->andXCommand = logoffRequest->andXCommand; /* the same command */
    logoffResponse->andXReserved = 0;    /* must be */
    if (logoffResponse->andXCommand == 0xFF)
    {
        cmPutSUint16(logoffResponse->andXOffset, 0);
    }
    else
    {
        NQ_UINT16 offset;   /* for calculating offsets */

        offset = (NQ_UINT16)(*pResponse - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(logoffResponse->andXOffset, cmHtol16(offset));
    }
    cmPutSUint16(logoffResponse->byteCount, 0);

    /* do the work */

    csReleaseUser(pUser->uid,TRUE);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform SESSION_SETUP_ANDX command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComSessionSetupAndX(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CSSession* pSession;        /* pointer to the session slot */
    CMCifsSessionSetupAndXRequest* setupRequest;   /* casted pointer to the request */
    CMCifsSessionSetupAndXResponse* setupResponse; /* casted pointer to the response */
    NQ_UINT32 returnValue;      /* error code returns by other routines - NT */
    NQ_BOOL unicodeRequired;    /* client requires UNICODE */
    const NQ_BYTE* pOsName;     /* pointer to the OS name */
    CSUser* pUser = NULL;       /* pointer to the user descriptor */
    CSUid uid;					/* UID value in request */
    NQ_BYTE* pData;             /* abstract pointer */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    NQ_COUNT blobLength;        /* length of the security blob generated */
    NQ_BYTE* pBlob;             /* pointer to the blob buffer for SPNEGO */
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */
    NQ_UINT32 response;         /* status to return */
    NQ_UINT32 clientCapabilities; /* client capabilities */
    CMCifsHeader *pHeaderIn;    /* pointer to incoming header */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    NQ_BOOL	andXCommand = FALSE;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDUserAccessEvent	eventInfo;
#endif /*UD_NQ_INCLUDEEVENTLOG*/

    TRCB();

    /* read unicode flag */

    unicodeRequired = (cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE) != 0;

    /* cast pointers */

    pHeaderIn = (CMCifsHeader *)(pRequest - sizeof(CMCifsHeader));
    setupRequest = (CMCifsSessionSetupAndXRequest*)pRequest;
    setupResponse = (CMCifsSessionSetupAndXResponse*)(*pResponse);

    if (   setupRequest->wordCount != SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        && setupRequest->wordCount != SMB_SESSIONSETUPANDXSSP_REQUEST_WORDCOUNT
#endif
       )     /* expected word count */
    {
        TRCERR("Unexpected word count");
        TRC2P("  is: %d expected: %d", *pRequest, SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT);
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_IMPLEMENTED, SRV_ERRsmbcmd);
    }

    /* check space in the output buffer */

    if ((returnValue =
         csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*setupResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    pSession = csGetSessionBySocket();
    if (pSession == NULL)       /* mulformed command or there was no Negotiate yet */
    {
        TRCERR("Unknown session by socket");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* check that the next AndX command is a valid one */

    switch (setupRequest->andXCommand)
    {
    case SMB_COM_TREE_CONNECT_ANDX:
    case SMB_COM_OPEN_ANDX:
    case SMB_COM_CREATE_NEW:
    case SMB_COM_DELETE:
    case SMB_COM_FIND:
    case SMB_COM_RENAME:
    case SMB_COM_TRANSACTION:
    case SMB_COM_QUERY_INFORMATION:
    case SMB_COM_GET_PRINT_QUEUE:
    case SMB_COM_OPEN:
    case SMB_COM_CREATE:
    case SMB_COM_CREATE_DIRECTORY:
    case SMB_COM_DELETE_DIRECTORY:
    case SMB_COM_FIND_UNIQUE:
    case SMB_COM_CHECK_DIRECTORY:
    case SMB_COM_SET_INFORMATION:
    case SMB_COM_OPEN_PRINT_FILE:
    case SMB_COM_COPY:
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    	andXCommand = TRUE;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
    case 0xFF:
        break;
    default:
        TRCERR("Illegal command follows Session Setup AndX");
        TRC1P("  command: %d", (NQ_INT)setupRequest->andXCommand);
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

#ifdef UD_CS_MESSAGESIGNINGPOLICY    
    /* decide on security signatures */
    pSession->signingOn = (csIsMessageSigningEnabled() ? (csIsMessageSigningRequired() ?
    					TRUE : (cmLtoh16(cmGetSUint16(pHeaderIn->flags2)) & SMB_FLAGS2_SMB_SECURITY_SIGNATURES)) : FALSE);
    TRC("session will %s signed", pSession->signingOn ? "be" : "not be");
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

    /* read UID */

    uid = cmLtoh16(cmGetSUint16(pHeaderIn->uid));
    if (uid != 0)
    {
    	pUser = csGetUserByUid(uid);
    	if (pUser != NULL && pUser->authenticated)
    		pUser = NULL;
    }

    /* check client authentication  */

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    pBlob = (NQ_BYTE*)(((CMCifsSessionSetupAndXSSPResponse*)(*pResponse)) + 1);
    blobLength = 0;
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */  
    response = csAuthenticateUser(
                    (const NQ_BYTE*)setupRequest, 
                    pSession, 
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
                    pBlob, 
                    &blobLength, 
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */  
                    unicodeRequired, 
                    &pUser,
                    &pOsName
                    );
    if (NQ_SUCCESS != response)
    {
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        if (csErrorReturn(SMB_STATUS_MORE_PROCESSING_REQUIRED, NQ_ERR_MOREDATA) != response)
        {
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */
#ifdef UD_NQ_INCLUDEEVENTLOG
        	if (response != csErrorReturn(SMB_STATUS_LOGON_FAILURE, DOS_ERRnoaccess))
        	{
        		NQ_WCHAR nullName = '\0';

				eventInfo.rid = (pUser != NULL) ? csGetUserRid(pUser) : CS_ILLEGALID;
				udEventLog(UD_LOG_MODULE_CS,
					UD_LOG_CLASS_USER,
					UD_LOG_USER_LOGON,
					(pUser != NULL) ? (NQ_WCHAR *)&pUser->name : (NQ_WCHAR *)&nullName,
					&pSession->ip,
					response,
					(NQ_BYTE *)&eventInfo);
        	}
#endif /* UD_NQ_INCLUDEEVENTLOG */
            TRCERR("Authentication failed");
            TRCE();
            return response;
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
        }
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */   
    }

    if (NQ_SUCCESS == response)
    {
    	pUser->authenticated = TRUE;
#ifdef UD_NQ_INCLUDEEVENTLOG
		{
			eventInfo.rid = csGetUserRid(pUser);
			udEventLog(UD_LOG_MODULE_CS,
				UD_LOG_CLASS_USER,
				UD_LOG_USER_LOGON,
				(NQ_WCHAR *)&pUser->name,
				&pSession->ip,
				0,
				(NQ_BYTE *)&eventInfo);
		}
#endif /* UD_NQ_INCLUDEEVENTLOG */
    }

    /* prepare the response */

    cmPutSUint16(setupResponse->action, cmHtol16(CS_SESSIONACTION));
    setupResponse->andXCommand = setupRequest->andXCommand; /* the same command */
    setupResponse->andXReserved = 0;    /* must be */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    if (setupRequest->wordCount == SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT)  /* NTLM logon */
    {
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */   
        setupResponse->wordCount = SMB_SESSIONSETUPANDX_RESPONSE_WORDCOUNT;
        pData = (NQ_BYTE*)(setupResponse + 1);
        clientCapabilities = cmLtoh32(cmGetSUint32(setupRequest->capabilities));
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    }
    else
    {
        CMCifsSessionSetupAndXSSPResponse* pResponseSsp;
        
        pResponseSsp = (CMCifsSessionSetupAndXSSPResponse*)setupResponse;
        pResponseSsp->wordCount = SMB_SESSIONSETUPANDXSSP_RESPONSE_WORDCOUNT;
        cmPutSUint16(pResponseSsp->blobLength, cmHtol16((NQ_UINT16)blobLength));
        pData = (NQ_BYTE*)(pResponseSsp + 1) + blobLength;
        clientCapabilities = cmLtoh32(cmGetSUint32(((CMCifsSessionSetupAndXSSPRequest*)setupRequest)->capabilities));     
    }
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */  

    /* place string values at the end of the response */

    {
        NQ_STATIC NQ_CHAR lanStr[100];

        sySprintf(lanStr, "NQE %d.%d", CM_SOFTWAREVERSIONMAJOR, CM_SOFTWAREVERSIONMINOR);
        if (unicodeRequired)
        {
            NQ_WCHAR* pStr;

            pStr = (NQ_WCHAR*)pData;
            pStr = (NQ_WCHAR*)cmAllignTwo((NQ_BYTE*)pStr);

            syAnsiToUnicode(pStr, SY_OSNAME);
            pStr += syWStrlen(pStr) + 1;
            syAnsiToUnicode(pStr, lanStr);
            pStr += syWStrlen(pStr) + 1;
            syAnsiToUnicode(pStr, cmNetBiosGetDomain()->name);
            pStr += syWStrlen(pStr) + 1;
            pData = (NQ_BYTE*)pStr;
        }
        else
        {
            NQ_CHAR* pStr;

            pStr = (NQ_CHAR*)pData;

            syStrcpy(pStr, SY_OSNAME);
            pStr += syStrlen(SY_OSNAME) + 1;
            syStrcpy(pStr, lanStr);
            pStr += syStrlen(lanStr) + 1;
            syStrcpy(pStr, cmNetBiosGetDomain()->name);
            pStr += syStrlen(cmNetBiosGetDomain()->name) + 1;
            pData = (NQ_BYTE*)pStr;
        }

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    if (setupRequest->wordCount == SMB_SESSIONSETUPANDX_REQUEST_WORDCOUNT)  /* NTLM logon */
    {
#endif  /* UD_CS_INCLUDEEXTENDEDSECURITY */   
        cmPutSUint16(setupResponse->byteCount, cmHtol16((NQ_UINT16)(pData - (NQ_BYTE*)(setupResponse + 1))));
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    }
    else
    { 
        CMCifsSessionSetupAndXSSPResponse* pResponseSsp;
        
        pResponseSsp = (CMCifsSessionSetupAndXSSPResponse*)setupResponse;
        cmPutSUint16(pResponseSsp->byteCount, cmHtol16((NQ_UINT16)(pData - (NQ_BYTE*)(pResponseSsp + 1))));
    }
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */  
        *pResponse += pData - (NQ_BYTE*)setupResponse;
    }

    /* calculate offset to the next AndX command if any */
    {
        NQ_UINT16 offset;   /* offset to the next response */

        offset = (NQ_UINT16)(*pResponse - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(setupResponse->andXOffset, cmHtol16(offset));
    }

    /* set UID in the header for response and request (for further AndX commands) */
    cmPutSUint16(pHeaderOut->uid, cmLtoh16(pUser->uid));

    if (pUser->authenticated)
    {
    	cmPutSUint16(setupResponse->action, pUser->isGuest ? cmLtoh16(CS_SESSIONACTION_GUEST) : 0);

    	/* consider client's operating system */

        pUser->preservesCase = (UD_FS_FILESYSTEMATTRIBUTES & CM_FS_CASESENSITIVESEARCH) == 0;
        pUser->supportsReadAhead = TRUE;
        pUser->supportsNtErrors = 0 != (clientCapabilities & SMB_CAP_NT_STATUS);
        /* consider Windows NT/95/98 */
        {
            NQ_CHAR osName[12];
#define WINNTSIGNATURE "Windows NT "
#define WIN9XSIGNATURE "Windows 4.0"

            if (unicodeRequired)
                cmUnicodeToAnsiN(osName, (NQ_WCHAR*)pOsName, (NQ_UINT)(syStrlen(WINNTSIGNATURE) * sizeof(NQ_WCHAR)));
            else
                syStrncpy(osName, (NQ_CHAR*)pOsName, syStrlen(WINNTSIGNATURE));
    
            if (0 == cmAStrincmp((const NQ_CHAR *)osName, WIN9XSIGNATURE, (NQ_UINT)syStrlen(WIN9XSIGNATURE)))          /* WinNT */
            {
                pUser->preservesCase = FALSE;
                pUser->supportsReadAhead = FALSE;
            }
            pUser->supportsNotify = TRUE;
            /*pUser->supportsNotify = 0!=syStrcmp(osName, WINNTSIGNATURE);*/
            /*pUser->supportsNotify =    syStrlen(osName) > 0
                                    && 0!=syStrcmp(osName, WINNTSIGNATURE);*/
        }
    }

#ifdef UD_CS_MESSAGESIGNINGPOLICY
    if (pSession->sequenceNum == 0 && response == NQ_SUCCESS)
    {
        pSession->sequenceNumRes = 1;
        pSession->sequenceNum = pSession->sequenceNumRes + 1;
    }
    if (andXCommand)
    	pSession->sequenceNum -= 2;
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

    TRCE();
    return response;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

