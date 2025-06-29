/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 session setup/logoff command handler
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Jan-2009
 ********************************************************************/

#include "csauth.h"
#include "cs2disp.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

#define SMB2_SESSION_SETUP_RESPONSE_DATASIZE 9
#define SMB2_LOGOFF_RESPONSE_DATASIZE        4
#define SMB2_ECHO_RESPONSE_DATASIZE          4

#ifdef UD_CS_MESSAGESIGNINGPOLICY

static
NQ_BOOL
isConnectionSigningRequired(
    NQ_BYTE securityFlags,
    NQ_UINT32 headerFlags
    )
{
    return csIsMessageSigningEnabled() ? 
            (csIsMessageSigningRequired() ? TRUE : (securityFlags & SMB2_NEGOTIATE_SIGNINGREQUIRED)) : FALSE;
}
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

/*====================================================================
 * PURPOSE: Perform Session Setup processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Session Setup command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnSessionSetup(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    NQ_UINT16 inBlobLen;
    NQ_UINT16 inBlobOffset;
    NQ_COUNT outBlobLen; 
    const NQ_BYTE* pOsName;     
    CMBufferWriter outSecurityBlob;
    NQ_UINT32 result;
    NQ_BYTE securityMode;
    NQ_UINT64 previousSid;
    CSUser* previousSession;
    NQ_UINT16	sessionFlags;
#ifdef UD_NQ_INCLUDESMB311
    NQ_BOOL firstSessionSetup = FALSE;
    NQ_BYTE preauthTemp[SMB3_PREAUTH_INTEG_HASH_LENGTH];
#endif
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDUserAccessEvent   eventInfo;
#endif
    
    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* check whether reauthentication is needed */
    if (in->sid.low != 0)
    {
        CSUser* expiredSession = csGetUserByUid((CSUid)sessionIdToUid(in->sid.low));

        if (expiredSession == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "User session deleted");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_USER_SESSION_DELETED;
        }
        else
        {
            /* check whether session has expired */
            if (!csUserHasExpired(expiredSession->uid))
            {
                if (expiredSession->authenticated)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Another session setup for unexpired session");
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return SMB_STATUS_REQUEST_NOT_ACCEPTED;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Authentication for sid = 0x%x is in progress", in->sid.low);
            }
            else
            {
                /* session has expired, reauthenticate it */
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Reauthenticating sid = 0x%x", in->sid.low);
                csRenewUserTimeStamp(expiredSession);
                expiredSession->authenticated = FALSE;
            }
            session = expiredSession;
        }
    }

#ifdef UD_NQ_INCLUDESMB311
    if (connection->dialect == CS_DIALECT_SMB311)
    {
		if (session == NULL)
		{
			firstSessionSetup = TRUE;
			syMemcpy(preauthTemp , connection->preauthIntegHashVal , SMB3_PREAUTH_INTEG_HASH_LENGTH);
		}
		else
		{
			NQ_BYTE ctxBuff[SHA512_CTXSIZE];
			/* in this point full packet is in buffer and not tampered yet. can calculate message hash */
			cmSmb311CalcMessagesHash(reader->origin, reader->length + 4, session->preauthIntegHashVal, ctxBuff);
		}
    }
#endif

    /* read request */
    cmBufferReaderSkip(reader, 1);           /* skip vc number */
    cmBufferReadByte(reader, &securityMode); /* security mode */
    cmBufferReaderSkip(reader, 8);           /* skip capabilities and channel */

    /* security blob offset */    
    cmBufferReadUint16(reader, &inBlobOffset);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Received security blob offset = 0x%x", inBlobOffset);
    if (inBlobOffset >= in->size + cmBufferReaderGetRemaining(reader)) 
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid security blob offset");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER;        
    }

    /* security blob length */    
    cmBufferReadUint16(reader, &inBlobLen);
    if (inBlobLen == 0)
    {
        LOGERR(CM_TRC_LEVEL_WARNING, "Received empty security blob");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER;        
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Received security blob with length = %d", inBlobLen);

    /* previous session id */
    cmBufferReadUint64(reader, &previousSid);  

    /* authenticate user and prepare response security blob */
    cmBufferWriterBranch(writer, &outSecurityBlob, 8);  
    result = csAuthenticateUser((const NQ_BYTE *)(reader->current),
                                connection,
                                outSecurityBlob.current, 
                                &outBlobLen,                                 
                                TRUE, 
                                &session, 
                                &pOsName);                           

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Generated security blob with length = %d", outBlobLen); 

#ifdef UD_NQ_INCLUDESMB311
    if (session != NULL)
    {
    	if (firstSessionSetup && session->preauthIntegOn)
    	{
    		NQ_BYTE ctxBuff[SHA512_CTXSIZE];

    		syMemcpy(session->preauthIntegHashVal , preauthTemp, SMB3_PREAUTH_INTEG_HASH_LENGTH);
			/* in this point full packet is in buffer and not tampered yet. can calculate message hash */
			cmSmb311CalcMessagesHash(reader->origin, reader->length + 4, session->preauthIntegHashVal, ctxBuff);
    	}

    }
#endif
    if (result == NQ_SUCCESS && NULL != session)
    {

        session->authenticated = TRUE;
        session->preservesCase = (UD_FS_FILESYSTEMATTRIBUTES & CM_FS_CASESENSITIVESEARCH) == 0;
        session->supportsNotify = TRUE;
#ifdef UD_NQ_INCLUDESMB3
        session->preauthIntegOn = FALSE;
#endif /* UD_NQ_INCLUDESMB3 */
        
        /* release previous session, if authenticated for the same user */
        if (previousSid.low != 0)
        {
            previousSid.low = sessionIdToUid(previousSid.low);
            if ((NULL != session)&& 
                (session->uid != previousSid.low) && 
                ((previousSession = csGetUserByUid((CSUid)previousSid.low)) != NULL)
               )
            {
                if (syWStrncmp(session->name, previousSession->name, syWStrlen(session->name)) == 0)
                {
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Releasing previous sid = 0x%x", previousSid.low);
                    csReleaseUser(previousSession->uid , TRUE);
                }
            }  
        }
#ifdef UD_NQ_INCLUDESMB3
        if (connection->dialect == CS_DIALECT_SMB30)
        {
        	TRCDUMP("Session Key" , session->sessionKey , sizeof(session->sessionKey));
        	cmKeyDerivation( session->sessionKey, sizeof(session->sessionKey)    , (NQ_BYTE*)"SMB2AESCMAC\0", 12 , (NQ_BYTE*)"SmbSign\0"   , 8  , (NQ_BYTE *)session->signingKey );
        	cmKeyDerivation( session->sessionKey, sizeof(session->encryptionKey) , (NQ_BYTE*)"SMB2AESCCM\0" , 11 , (NQ_BYTE*)"ServerOut\0" , 10 , (NQ_BYTE *)session->encryptionKey );
        	cmKeyDerivation( session->sessionKey, sizeof(session->decryptionKey) , (NQ_BYTE*)"SMB2AESCCM\0" , 11 , (NQ_BYTE*)"ServerIn \0" , 10 , (NQ_BYTE *)session->decryptionKey );
        	cmKeyDerivation( session->sessionKey, sizeof(session->applicationKey), (NQ_BYTE*)"SMB2APP\0"    , 8 , (NQ_BYTE*)"SmbRpc\0"    , 7  , (NQ_BYTE *)session->applicationKey);
        	TRCDUMP("Signing Key" , session->signingKey , sizeof(session->signingKey));
        }
        else /* connection->dialect == CS_DIALECT_SMB311 */
        {
			TRCDUMP("Session Key" , session->sessionKey , sizeof(session->sessionKey));
			cmKeyDerivation(session->sessionKey, sizeof(session->sessionKey), (NQ_BYTE*)"SMBSigningKey\0",   14 , session->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)session->signingKey );
			cmKeyDerivation(session->sessionKey, sizeof(session->sessionKey), (NQ_BYTE*)"SMBS2CCipherKey\0", 16 , session->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)session->encryptionKey );
			cmKeyDerivation(session->sessionKey, sizeof(session->sessionKey), (NQ_BYTE*)"SMBC2SCipherKey\0", 16 , session->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)session->decryptionKey );
			cmKeyDerivation(session->sessionKey, sizeof(session->sessionKey), (NQ_BYTE*)"SMBAppKey\0",       10 , session->preauthIntegHashVal, SMB3_PREAUTH_INTEG_HASH_LENGTH , (NQ_BYTE *)session->applicationKey);
			TRCDUMP("Signing Key" , session->signingKey , sizeof(session->signingKey));
        }
#endif /* UD_NQ_INCLUDESMB3 */
#ifdef UD_NQ_INCLUDEEVENTLOG
    	eventInfo.rid = csGetUserRid(session);
		udEventLog(UD_LOG_MODULE_CS,
				   UD_LOG_CLASS_USER,
				   UD_LOG_USER_LOGON,
				   (NQ_WCHAR*)session->name,
				   &connection->ip,
				   0,
				   (const NQ_BYTE *)&eventInfo);
#endif /* UD_NQ_INCLUDEEVENTLOG */
    }
    else if (result != SMB_STATUS_MORE_PROCESSING_REQUIRED)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
    	if (result != csErrorReturn(SMB_STATUS_LOGON_FAILURE, DOS_ERRnoaccess))
    	{
    		NQ_WCHAR noName[] = CM_WCHAR_NULL_STRING;

			eventInfo.rid = (session != NULL) ? csGetUserRid(session) : CS_ILLEGALID;
			udEventLog(UD_LOG_MODULE_CS,
					   UD_LOG_CLASS_USER,
					   UD_LOG_USER_LOGON,
					   (session != NULL) ? (NQ_WCHAR *)&session->name : (NQ_WCHAR *)&noName,
					   &connection->ip,
					   result,
					   (const NQ_BYTE *)&eventInfo);
    	}
#endif /* UD_NQ_INCLUDEEVENTLOG */
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);

        return result;
    }

    /* write the response */
    cmBufferWriterSkip(&outSecurityBlob, outBlobLen);



    out->sid.high = 0;            
    out->sid.low = (NQ_UINT32)(session != NULL ? uidToSessionId(session->uid) : 0);
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    /* decide on security signatures */
    if (session)
    {
#ifdef UD_CS_INCLUDEPASSTHROUGH
        if (connection->usePassthrough && session->isDomainUser && !session->authBySamlogon)
        {
            /* disable signing */
            connection->signingOn = FALSE;
        }
        else
#endif /* UD_CS_INCLUDEPASSTHROUGH */
        {
             connection->signingOn = isConnectionSigningRequired(securityMode, in->flags);
             out->flags |= (connection->signingOn && !session->isAnonymous && !session->isGuest && session->authenticated) ? SMB2_FLAG_SIGNED : 0;
        }
        TRC("Connection signing%s mandatory.", connection->signingOn ? "" : " not");
    }
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "sid=0x%x", (session != NULL ? uidToSessionId(session->uid) : 0));

    cmBufferWriteUint16(writer, SMB2_SESSION_SETUP_RESPONSE_DATASIZE);                             /* constant data length */
    sessionFlags = 0;
    if (NULL != session)
    {
#ifdef UD_NQ_INCLUDESMB3
        if (connection->dialect >= CS_DIALECT_SMB30 && session->isEncrypted)
            sessionFlags = SMB2_SESSIONSETUP_ENCRYPT;
        else
#endif /* UD_NQ_INCLUDESMB3 */
            sessionFlags = (NQ_UINT16)(session->isAnonymous ? SMB2_SESSIONSETUP_ANONYM : (session->isGuest ? SMB2_SESSIONSETUP_GUEST : 0));
    }
    cmBufferWriteUint16(writer, sessionFlags);                                                     /* session flags */
    cmBufferWriteUint16(writer, (NQ_UINT16)(cmSmb2HeaderGetWriterOffset(out, writer) + 4));        /* security blob offset */   
    cmBufferWriteUint16(writer, (NQ_UINT16)cmBufferWriterGetDataCount(&outSecurityBlob));          /* security blob size */    
    cmBufferWriterSync(writer, &outSecurityBlob);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return result;
}


/*====================================================================
 * PURPOSE: Perform Logoff processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Logoff command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnLogoff(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
	 LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* read remaining request data (reserved 2 bytes) */
    cmBufferReaderSkip(reader, 2);

    /* logoff session */

    csReleaseUser(session->uid , TRUE);

    /* write the response */
    cmBufferWriteUint16(writer, SMB2_LOGOFF_RESPONSE_DATASIZE);  /* constant data length */
    cmBufferWriteUint16(writer, 0);                              /* reserved */

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}


/*====================================================================
 * PURPOSE: Perform Echo processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN session - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Echo command.
 *====================================================================
 */
NQ_UINT32 csSmb2OnEcho(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* read remaining request data (reserved 2 bytes) */
    cmBufferReaderSkip(reader, 2);

    /* write the response */
    cmBufferWriteUint16(writer, SMB2_ECHO_RESPONSE_DATASIZE);    /* constant data length */
    cmBufferWriteUint16(writer, 0);                              /* reserved */

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

