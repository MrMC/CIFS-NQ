/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Negotiate parser
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 25-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdispat.h"
#include "csparams.h"
#include "csdataba.h"
#include "csauth.h"
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
#include "amspnego.h"
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
#ifdef UD_NQ_INCLUDESMB2
#include "cmsmb2.h"
#include "cs2disp.h"
#endif /* UD_NQ_INCLUDESMB2 */
#include "cmcrypt.h"
#ifdef UD_NQ_INCLUDECIFSSERVER

/* static functions */

static
void
generatePositiveResponse(
    CSSession* pSession,
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    NQ_BOOL extendedSecurity,
#endif
    NQ_UINT16  agreedDialectIndex,
    NQ_BYTE**  pResponse
    );

/* This code implements the NEGOTIATE command
 */

/*
 *====================================================================
 * PURPOSE: Perform Negotiate command
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT double pointer to the command in the message
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
csComNegotiate(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    NQ_UINT byteCount;                      /* down-counter for the array of dialects */
    NQ_UINT16 dialectIndex;                 /* next dialect */
    NQ_UINT16 agreedDialectIndex;           /* negotiated dialect */

#ifdef UD_NQ_INCLUDESMB2
    NQ_BOOL	smb2Availble = FALSE;
#endif
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    const CMCifsHeader* pHeaderIn;          /* pointer to incoming header */
    NQ_BOOL extendedSecurity = FALSE;       /* SPNEGO logon */
#endif

    TRCB();

#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    pHeaderIn = (CMCifsHeader*)(pRequest-sizeof(CMCifsHeader));
    extendedSecurity = cmLtoh16(cmGetSUint16(pHeaderIn->flags2)) & SMB_FLAGS2_EXTENDED_SECURITY;
    cmPutSUint16(
        pHeaderOut->flags2, 
        cmGetSUint16(pHeaderOut->flags2) | cmHtol16(SMB_FLAGS2_EXTENDED_SECURITY)
        );
#endif /*  UD_CS_INCLUDEEXTENDEDSECURITY */

    if (*pRequest != 0)     /* word count should be zero */
    {
        TRCERR("Unexpected word count");
        TRC2P("  is: %d expected: %d", *pRequest, 0);
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_IMPLEMENTED, SRV_ERRsmbcmd);
    }

    pRequest++;                     /* skip word count - pointing to byte count */

    byteCount = cmLtoh16(cmGetUint16(pRequest));
    pRequest += 2;  /* now pointing to the 1st dialect structure */

    /* parse dialect records, comparing each dialect with the one, we support */

    agreedDialectIndex = 0xFFFF;    /* (-1) not dialect agreed upon yet */
    dialectIndex = 0;

    while (byteCount > 0)
    {
        NQ_UINT strLen;        /* dialect name length */

        if (*pRequest != 0x02)
        {
            TRCERR("Dialect buffer format is not 2");
            TRC1P("  dialect index: , format %04x", *pRequest);
            TRCE();
            return csErrorReturn(SMB_STATUS_NOT_IMPLEMENTED, SRV_ERRsmbcmd);
        }

        pRequest++;         /* skip format and point to the dialect name */

        TRC3P("byte count: %d, compare %s with %s", byteCount, pRequest, CS_SUPPORTEDDIALECT);

        if (syStrcmp((NQ_CHAR*)pRequest, CS_SUPPORTEDDIALECT) == 0)
        {
            agreedDialectIndex = dialectIndex;
        }

#ifdef UD_NQ_INCLUDESMB2
        /* check for SMB2.002 dialect */
        if (syStrcmp((NQ_CHAR*)pRequest, SMB2_DIALECTSTRING) == 0)
        	smb2Availble = TRUE;

#ifdef UD_NQ_INCLUDESMB3
        /* check for SMB2.??? dialect */
        if (syStrcmp((NQ_CHAR*)pRequest, SMB2ANY_DIALECTSTRING) == 0)
        {
            /* SMB2 is supported, answer with SMB2 negotiate response */
            NQ_UINT32 status;

            status = csSmb2OnSmb1Negotiate(pResponse , TRUE);

            if (smb2Availble)
            {
            	CSSession	*	pSession = csGetSessionBySocket();

            	pSession->dialect = CS_DIALECT_SMB2;
            }

            TRCE();
            return status;
        }
#endif /* UD_NQ_INCLUDESMB3 */

#endif /* UD_NQ_INCLUDESMB2 */

        dialectIndex++;
        strLen = (NQ_UINT)syStrlen((NQ_CHAR*)pRequest);
        byteCount -= strLen + 2;    /* one for format and one for the terminating zero */
        pRequest += strLen + 1;     /* shift to the next dialect */
    }
#ifdef UD_NQ_INCLUDESMB2
    if (smb2Availble)
	{
		/* SMB2 is supported, answer with SMB2 negotiate response */
		NQ_UINT32 status;
		status = csSmb2OnSmb1Negotiate(pResponse , FALSE);

		TRCE();
		return status;
	}
#endif /* UD_NQ_INCLUDESMB2 */

    /* compose a response */

    if (agreedDialectIndex == (NQ_BYTE)-1)
    {
        CMCifsNegotiateNegative* negotiateResponse; /* outgoing message pointer */

        TRCERR("No dialect is supported");

        /* we are about to send a negative response */

        negotiateResponse = (CMCifsNegotiateNegative*)*pResponse;

        negotiateResponse->wordCount = 1;
        cmPutSUint16(negotiateResponse->dialectIndex, 0xFFFF);   /* (-1) HBO = NBO */

        /* advance to the next response */

        *pResponse = (NQ_BYTE*)(negotiateResponse + 1);
    }
    else
    {
        CSSession* pSession;   /* session slot */

        /* check if this is the second Negotiate command */

        if (csSessionExists())
        {
            TRCERR("Second Negotiate for the same connection");
            TRCE();
            return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
        }

        /* create a new session and fill its session key in the response
           socket pointer will be set in csDispatchRequest() */

        if ((pSession = csGetNewSession()) == NULL)
        {
            TRCERR("Out of session slots");
            TRCE();
            return csErrorReturn(SMB_STATUS_REQUEST_NOT_ACCEPTED, SRV_ERRnoresource);
        }

        cmGenerateRandomEncryptionKey(pSession->encryptionKey);
        pSession->dialect = CS_DIALECT_SMB1;

        generatePositiveResponse(
            pSession, 
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
            extendedSecurity,
#endif 
            agreedDialectIndex, 
            pResponse
            );

#ifdef UD_CS_MESSAGESIGNINGPOLICY
        pSession->sequenceNum = pSession->sequenceNumRes = 0;
#endif        
    }

    TRCE();
    return 0;
}

/*
 *====================================================================
 * PURPOSE: Perform SMB_COM_ECHO command
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT double pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   
 *====================================================================
 */
NQ_UINT32
csComEcho(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsEcho* echoRequest;    /* casted request */
    CMCifsEcho* echoResponse;   /* casted response */
    NQ_UINT16 echoDataSize;     /* size of echoed data */
    NQ_UINT32 result;

    TRCB();
    
    /* verify there was negotiate (find session with the same socket) */
    if (csGetSessionBySocket() == NULL)      
    {
        TRCERR("No negotiate yet");
        TRCE();
        return SMB_STATUS_NORESPONSE;
    }

    echoRequest = (CMCifsEcho*)pRequest;

    /* check word count */
    if (echoRequest->wordCount != SMB_ECHO_WORDCOUNT)
    {
        TRCERR("Unexpected word count");
        TRCE();
        return csErrorReturn(0, SRV_ERRerror);
    }

    /* check echo count */
    if (cmLtoh16(cmGetSUint16(echoRequest->echoCount)) == 0)
    {
        TRC("echoCount = 0");
        TRCE();
        return SMB_STATUS_NORESPONSE;
    }
    
    /* check space in output buffer */
    echoDataSize = cmLtoh16(cmGetSUint16(echoRequest->byteCount));
    if ((result = csDispatchCheckSpace(pHeaderOut, *pResponse, (NQ_UINT)(sizeof(*echoResponse) + echoDataSize))) 
        != NQ_SUCCESS)
    {
        TRCERR("Insufficient space in output buffer");
        TRCE();
        return result;
    }
    
    /* prepare the response */
    echoResponse = (CMCifsEcho*)*pResponse;
    echoResponse->wordCount = SMB_ECHO_WORDCOUNT;
    cmPutSUint16(echoResponse->echoCount, cmHtol16(1));
    cmPutSUint16(echoResponse->byteCount, cmHtol16(echoDataSize));
    /* copy echoed data from the request */
    syMemcpy(echoResponse + 1, echoRequest + 1, echoDataSize);              
    *pResponse += sizeof(*echoResponse) + echoDataSize;

    TRCE();
    return NQ_SUCCESS;
}


static
void
generatePositiveResponse(
    CSSession* pSession,
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    NQ_BOOL extendedSecurity,
#endif
    NQ_UINT16 agreedDialectIndex,
    NQ_BYTE** pResponse
    )
{
    CMCifsNegotiateResponse* negotiateResponse;    /* outgoing message pointer */
    NQ_UINT32 lowUtc;                              /* time in the UTC format - low portion */
    NQ_UINT32 highUtc;                             /* time in the UTC format - high portion */
    NQ_TIME systemTime;                          /* system (Unix-format) time */
    NQ_UINT32 capabilities;                        /* server capabilities */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    NQ_UINT16 byteCount;
#endif
    
    TRCB();

    /* we are about to send a positive response */

    negotiateResponse = (CMCifsNegotiateResponse*)*pResponse;

    /* fill parameters */

    negotiateResponse->wordCount = SMB_NEGOTIATE_RESPONSE_WORDCOUNT;
    cmPutSUint16(negotiateResponse->dialectIndex, cmHtol16(agreedDialectIndex));
    negotiateResponse->securityMode = (NQ_BYTE)(SMB_SECURITY_USER | SMB_SECURITY_ENCRYPT_PASSWORD 
#ifdef UD_CS_MESSAGESIGNINGPOLICY        
                                    | (csIsMessageSigningEnabled() ? SMB_SECURITY_SM_SIGNATURES_ENABLED : 0) 
                                    | (csIsMessageSigningRequired() ? SMB_SECURITY_SM_SIGNATURES_REQUIRED : 0)
#endif                                    
                                    );
    cmPutSUint16(negotiateResponse->maxMpxCount, cmHtol16(CM_CS_MAXMPXCOUNT));
    cmPutSUint16(negotiateResponse->maxNumberVcs, cmHtol16(CS_MAXNUMBERVC));
    cmPutSUint32(
        negotiateResponse->maxBufferSize, 
        cmHtol32(
            CS_MAXBUFFERSIZE > 0x10000? 0x10000 : CS_MAXBUFFERSIZE
            )
        );
    cmPutSUint32(negotiateResponse->maxRawSize, cmHtol32(CS_MAXRAWSIZE));

    /* the following value prompts the client to use one of possible scenarios:
        1) extended CIFS (NT commands) with UNICODE strings
        2) pure CIFS commands with ACSII strings
       use only one of the following two lines, another one should be commented out */

    capabilities = ( SMB_CAP_UNICODE
                   | SMB_CAP_NT_SMBS
                   | SMB_CAP_LARGE_FILES
                   | SMB_CAP_NT_STATUS
#if    defined(UD_CS_INCLUDERPC_WINREG) \
    || defined(UD_CS_INCLUDERPC_SPOOLSS)\
    || defined(UD_CS_INCLUDERPC_LSARPC) \
    || defined(UD_CS_INCLUDERPC_SAMRPC) \
    || defined(UD_CS_INCLUDERPC_SRVSVC_EXTENSION)
                   | SMB_CAP_RPC_REMOTE_APIS
#endif
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
                   | (extendedSecurity? SMB_CAP_EXTENDED_SECURITY:0)
#endif
                   | SMB_CAP_INFOLEVEL_PASSTHRU 
#if defined(UD_CS_INCLUDEDIRECTTRANSFER) || (UD_NS_BUFFERSIZE > (65536 + 40))
                   | SMB_CAP_LARGE_READX
                   | SMB_CAP_LARGE_WRITEX
#endif
                   )
#if   !defined(UD_CS_INCLUDERPC_WINREG) \
    ||!defined(UD_CS_INCLUDERPC_SRVSVC) \
    ||!defined(UD_CS_INCLUDERPC_WKSSVC)
                   & ~SMB_CAP_RPC_REMOTE_APIS
#endif
        ;
    cmPutSUint32(negotiateResponse->capabilities, cmHtol32(capabilities));
    pSession->capabilities = capabilities;

    /* fill in the server time by obtaining the system time and converting it to
       the UTC format */

    systemTime = syGetTimeInMsec();
    cmCifsTimeToUTC(systemTime, &lowUtc, &highUtc);

    cmPutSUint32(negotiateResponse->systemTime.low, cmHtol32(lowUtc));
    cmPutSUint32(negotiateResponse->systemTime.high, cmHtol32(highUtc));
    cmPutSUint16(negotiateResponse->serverTimeZone, cmHtol16((NQ_UINT16)syGetTimeZone()));
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    if (extendedSecurity)
    {
    	/* Notice - here we use extended negotiate response format */
        CMBlob blob;

        negotiateResponse->encryptKeyLength = 0;

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS    
        syMemcpy(negotiateResponse->_un._st.serverGUID, cmSdGetComputerSid()->subs, 16);
#else /* UD_CS_INCLUDESECURITYDESCRIPTORS */
        syMemset(negotiateResponse->_un._st.serverGUID, 0, 16);
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

        blob = amSpnegoServerGenerateMechList();

        /* upon finish should set pointer on end of structure */
        *pResponse = negotiateResponse->_un._st.securityBlob;
        if (NULL != blob.data)
        {
            syMemcpy(negotiateResponse->_un._st.securityBlob, blob.data, blob.len);
            *pResponse += blob.len;
            byteCount = (NQ_UINT16)blob.len; 
            cmMemoryFreeBlob(&blob);
        }
        else
        {
            byteCount = 0;
        }
        cmPutSUint16(negotiateResponse->byteCount, cmHtol16((NQ_UINT16)(byteCount + 16))); 
    }
    else
    {
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
        negotiateResponse->encryptKeyLength = SMB_ENCRYPTION_LENGTH;
    
        /* fill in the session key - always zero as in Win - is not used by client and since
         * it is not properly returned back in SessionSetup by some clients - we cannot count
         * on it. In SessionSetup we rather use socket to identify the session. */
        cmPutSUint32(negotiateResponse->sessionKey, 0);
    
        /* generate random numbers for the encryption key of this session, write it
           both into the response and into the session */
        syMemcpy(negotiateResponse->_un.encryptKey, pSession->encryptionKey, SMB_ENCRYPTION_LENGTH);
    
        /* calculate data length as the length of the encryption key + the length of the
           domain name */
        /* domainName = cmNetBiosGetDomain()->name; */
        cmPutSUint16(negotiateResponse->byteCount, cmHtol16(SMB_ENCRYPTION_LENGTH/* + syStrlen(domainName) + 1*/));
		/* An intentinal access above the array range - shift to the next field */    
        *pResponse = (NQ_BYTE*)(negotiateResponse->_un.encryptKey + 9);
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    }
#endif
    TRCE();
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

