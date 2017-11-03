/*********************************************************************
 *
 *           Copyright (c) 2010 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Message signing
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 27-July-2010
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cssignin.h"
#include "cmcrypt.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_MESSAGESIGNINGPOLICY)

#define BSRSPYL "BSRSPYL "

static
NQ_BOOL
isZeroSignature(
    NQ_BYTE* pData,
    NQ_COUNT length
    )
{
    for (   ; length > 0; length--, pData++)
    {
        if (*pData != 0)
            return FALSE;
    }
    return TRUE;
}


/*
 *====================================================================
 * PURPOSE: Create message signature  SMB
 *--------------------------------------------------------------------
 * PARAMS:  
 *          IN     pointer to session structure
 *          IN     pointer to user structure
 *          IN     pointer to packet header 
 *          IN     packet length
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */

void
csCreateMessageSignatureSMB(
    CSSession *pSession,
    CSUser *pUser,
    NQ_BYTE *pHeaderOut,
    NQ_COUNT dataLength
    )
{   
    CMCifsHeader* pHeader = (CMCifsHeader*)pHeaderOut;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pSession:%p pUser:%p pHeaderIn:%p dataLength:%d", pSession, pUser, pHeaderOut, dataLength);

    if (pSession && pSession->signingOn)
    {
        cmPutSUint16(pHeader->flags2, cmGetSUint16(pHeader->flags2) | cmHtol16(SMB_FLAGS2_SMB_SECURITY_SIGNATURES));

        if (pSession->isBsrspyl)
		{
			syMemcpy(pHeader->status1.extra.securitySignature, BSRSPYL, SMB_SECURITY_SIGNATURE_LENGTH);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return;
		}

        if (pUser && pUser->isGuest)
		{
			cmPutSUint16(pHeader->flags2, (NQ_UINT16)(cmGetSUint16(pHeader->flags2) & ~(cmHtol16(SMB_FLAGS2_SMB_SECURITY_SIGNATURES))));
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return;
		}

		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "seq: %ld", pSession->sequenceNumRes);
		cmSmbCalculateMessageSignature(pSession->sessionKey,
								sizeof(pSession->sessionKey),
								pSession->sequenceNumRes,
								pHeaderOut,
								dataLength,
								NULL,
								0,
								(pUser && !pUser->isAnonymous) ? pUser->password.data : NULL,
								(pUser && !pUser->isAnonymous) ? pUser->password.len : 0,
								pHeader->status1.extra.securitySignature);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: Check message signature  SMB
 *--------------------------------------------------------------------
 * PARAMS:  
 *          IN     pointer to session structure
 *          IN     pointer to user structure
 *          IN     pointer to packet header 
 *          IN     packet length
 *
 * RETURNS: TRUE for valid signature, FALSE otherwise
 *
 * NOTES:   none
 *====================================================================
 */

NQ_BOOL
csCheckMessageSignatureSMB(
    CSSession *pSession,
    CSUser *pUser,
    NQ_BYTE *pHeaderIn,
    NQ_COUNT dataLength
    )
{
    NQ_BOOL result = TRUE;
    NQ_BYTE recievedSig[SMB_SECURITY_SIGNATURE_LENGTH];
    NQ_BYTE *pSignature = ((CMCifsHeader*)pHeaderIn)->status1.extra.securitySignature;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pSession:%p pUser:%p pHeaderIn:%p dataLength:%d", pSession, pUser, pHeaderIn, dataLength);

    if (pSession && pSession->signingOn && !pSession->isBsrspyl)
    {
        if (pUser && (pUser->isGuest || (pUser->isAnonymous && isZeroSignature(pSignature, SMB_SECURITY_SIGNATURE_LENGTH))))
        {
        	result = TRUE;
        }
        else
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "seq: %ld", pSession->sequenceNum);

			syMemcpy(recievedSig, pSignature, SMB_SECURITY_SIGNATURE_LENGTH);
			cmSmbCalculateMessageSignature(pSession->sessionKey,
									sizeof(pSession->sessionKey),
									pSession->sequenceNum,
									pHeaderIn,
									dataLength,
									NULL,
									0,
									(pUser && !pUser->isAnonymous) ? pUser->password.data : NULL,
									(pUser && !pUser->isAnonymous) ? pUser->password.len : 0,
								    pSignature);
			result = syMemcmp(recievedSig, pSignature, SMB_SECURITY_SIGNATURE_LENGTH) == 0;
			pSession->sequenceNumRes = pSession->sequenceNum + 1;
			pSession->sequenceNum += 2;
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "signatures %s", result ? "match" : "not match");
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result;
}

#ifdef UD_NQ_INCLUDESMB2

/*
 *====================================================================
 * PURPOSE: Create message signature  SMB2
 *--------------------------------------------------------------------
 * PARAMS:  
 *          IN     user's sid
 *          IN     pointer to packet header 
 *          IN     packet length
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void
csCreateMessageSignatureSMB2(
    NQ_UINT32 sid,                          
    NQ_BYTE *pHeaderOut,                  
    NQ_COUNT dataLength                     
    )
{
    CSUser *pUser;
    CSSession *pSession;
    NQ_BOOL isPacketSigned = (cmLtoh32(*(pHeaderOut + 16)) & cmLtoh32(SMB2_FLAG_SIGNED)) != 0;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sid:%d pHeaderOut:%p dataLength:%d", sid, pHeaderOut, dataLength);

    if (sid != 0)
    {
        if ((pUser = csGetUserByUid((CSUid)sessionIdToUid(sid))) && (pSession = csGetSessionById(pUser->session)))
        {
            if (!pUser->isGuest && ((pSession->signingOn && !pUser->isAnonymous) || (!pSession->signingOn && isPacketSigned)) && pUser->authenticated)
			{
                cmSmb2CalculateMessageSignature(pUser->sessionKey, sizeof(pUser->sessionKey), pHeaderOut, dataLength, NULL, 0, pHeaderOut + SMB2_SECURITY_SIGNATURE_OFFSET);
			}
            else
            {
            	NQ_BYTE * sign = pHeaderOut + SMB2_SECURITY_SIGNATURE_OFFSET;

            	if (*sign != 0 || *(sign + 1) != 0)
            		syMemset(sign, 0, 16);

            	/* if the flags contain the signing flag disable it */
            	if (isPacketSigned)
            		*(pHeaderOut + 16) &= (NQ_BYTE)(~SMB2_FLAG_SIGNED);

			}
        }
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: Check message signature  SMB2
 *--------------------------------------------------------------------
 * PARAMS:  
 *          IN     pointer to user structure
 *          IN     pointer to packet header 
 *          IN     packet length
 *          IN     packet flag
 *
 * RETURNS: TRUE for valid signature, FALSE otherwise
 *
 * NOTES:   none
 *====================================================================
 */
NQ_BOOL                                     
csCheckMessageSignatureSMB2(
    CSUser *pUser,                          
    NQ_BYTE *pHeaderIn,                   
    NQ_COUNT dataLength,
    NQ_UINT32 flags              
    )
{
    NQ_BYTE sigReceived[SMB2_SECURITY_SIGNATURE_SIZE];
    NQ_BYTE *sig = pHeaderIn + SMB2_SECURITY_SIGNATURE_OFFSET;
    CSSession *pSession;
    NQ_BOOL result = TRUE;
    NQ_BOOL isPacketSigned = (flags & SMB2_FLAG_SIGNED) != 0;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pUser:%p pHeaderIn:%p dataLength:%d flags:0x%x", pUser, pHeaderIn, dataLength, flags);

    if (pUser && !pUser->isAnonymous && !pUser->isGuest && (pSession = csGetSessionById(pUser->session)) && pUser->authenticated)
    {
        if (pSession->signingOn || (!pSession->signingOn && isPacketSigned))
        {
            syMemcpy(sigReceived, sig, sizeof(sigReceived));
            syMemset(sig, 0, SMB2_SECURITY_SIGNATURE_SIZE);
            cmSmb2CalculateMessageSignature(pUser->sessionKey, sizeof(pUser->sessionKey), pHeaderIn, dataLength, NULL, 0, sig);
            result = syMemcmp(sigReceived, sig, 16) == 0;
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "signatures %s", result ? "match" : "not match");
            return result;
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "signatures not checked");
    return result;
}

#ifdef UD_NQ_INCLUDESMB3
/*
 *====================================================================
 * PURPOSE: Create message signature  SMB2
 *--------------------------------------------------------------------
 * PARAMS:
 *          IN     user's sid
 *          IN     pointer to packet header
 *          IN     packet length
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void
csCreateMessageSignatureSMB3(
    NQ_UINT32 sid,
    NQ_BYTE *pHeaderOut,
    NQ_COUNT dataLength
    )
{
    CSUser *pUser;
    CSSession *pSession;
    NQ_BOOL isPacketSigned = (cmLtoh32(*(pHeaderOut + 16)) & cmLtoh32(SMB2_FLAG_SIGNED)) != 0;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sid:%d pHeaderOut:%p dataLength:%d", sid, pHeaderOut, dataLength);

    if (sid != 0)
    {
        if ((pUser = csGetUserByUid((CSUid)sessionIdToUid(sid))) && (pSession = csGetSessionById(pUser->session)))
        {
        	if (!pUser->isGuest && ((pSession->signingOn && !pUser->isAnonymous) || (isPacketSigned)) && pUser->authenticated)
			{
        		cmSmb3CalculateMessageSignature(pUser->signingKey, sizeof(pUser->signingKey), pHeaderOut, dataLength, NULL, 0, pHeaderOut + SMB2_SECURITY_SIGNATURE_OFFSET);
			}
			else
			{
				NQ_BYTE * sign = pHeaderOut + SMB2_SECURITY_SIGNATURE_OFFSET;

				if (*sign != 0 || *(sign + 1) != 0)
					syMemset(sign, 0, 16);

				/* if the flags contain the signing flag disable it */
				if (isPacketSigned)
					*(pHeaderOut + 16) &= (NQ_BYTE)(~SMB2_FLAG_SIGNED);

			}
        }
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL
csCheckMessageSignatureSMB3(
    CSUser *pUser,
    NQ_BYTE *pHeaderIn,
    NQ_COUNT dataLength,
    NQ_UINT32 flags
    )
{
	NQ_BYTE sigReceived[SMB2_SECURITY_SIGNATURE_SIZE];
	NQ_BYTE *sig = pHeaderIn + SMB2_SECURITY_SIGNATURE_OFFSET;
	CSSession *pSession;
	NQ_BOOL result = TRUE;
	NQ_BOOL isPacketSigned = (flags & SMB2_FLAG_SIGNED) != 0;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pUser:%p pHeaderIn:%p dataLength:%d flags:0x%x", pUser, pHeaderIn, dataLength, flags);

	if (pUser && !pUser->isAnonymous && !pUser->isGuest && (pSession = csGetSessionById(pUser->session)) && pUser->authenticated)
	{
		if (pSession->signingOn || isPacketSigned)
		{
			syMemcpy(sigReceived, sig, sizeof(sigReceived));
			syMemset(sig, 0, SMB2_SECURITY_SIGNATURE_SIZE);

			cmSmb3CalculateMessageSignature(pUser->signingKey, sizeof(pUser->signingKey), pHeaderIn, dataLength, NULL, 0, sig);
			result = syMemcmp(sigReceived, sig, 16) == 0;
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "signatures %s", result ? "match" : "not match");
            return result;
		}
	}
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "signatures not checked");
	return result;
}
#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_NQ_INCLUDESMB2 */

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_MESSAGESIGNINGPOLICY) */

