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
    
static
NQ_BOOL   
isBsrspylSignature(
    NQ_BYTE* pData,
    NQ_COUNT length
    )
{   
    if (length > syStrlen(BSRSPYL))
        return FALSE;
    return syStrcmp((NQ_CHAR *)pData, BSRSPYL) == 0 ? TRUE : FALSE;
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
 *          IN     pointer to sequence number if noncontinuous should be used
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
    MD5Context tmpCtx;

    TRCB();

    if (pSession && pSession->signingOn)
    {
        cmPutSUint16(pHeader->flags2, cmGetSUint16(pHeader->flags2) | cmHtol16(SMB_FLAGS2_SMB_SECURITY_SIGNATURES));

        if (pUser)
        {
            if (pUser->isGuest)
            {
                cmPutSUint16(pHeader->flags2, cmGetSUint16(pHeader->flags2) & ~(cmHtol16(SMB_FLAGS2_SMB_SECURITY_SIGNATURES)));
                return;
            }

            if (pUser->isAnonymous)
            {
                /* anonymous user */  
                if (pSession->isBsrspyl)
                {
                    /* if no "real" user logged in yet in this session - just use BSRSPYL signature */
                    syMemcpy(pHeader->status1.extra.securitySignature, BSRSPYL, 8);
                }
                else
                {
                    /* choose sequence number: regular response, delayed response or notify cancel response */
                    cmCreateSigningContext(&tmpCtx, pSession->sessionKey, sizeof(pSession->sessionKey), NULL, 0);
                    cmCreateMACByContext(&tmpCtx, pSession->sequenceNumRes, pHeaderOut, dataLength, pHeader->status1.extra.securitySignature);
                }
            }
            else
            {
                /* choose sequence number: regular response, delayed response or notify cancel response */
                syMemcpy(&tmpCtx, &pUser->signingCtx, sizeof(MD5Context));
                cmCreateMACByContext(&tmpCtx, pSession->sequenceNumRes, pHeaderOut, dataLength, pHeader->status1.extra.securitySignature);          
            }
        }
        else
        {
            if (pSession->isBsrspyl)
            {
                /* if no "real" user logged in yet in this session - just use BSRSPYL signature */
                syMemcpy(pHeader->status1.extra.securitySignature, BSRSPYL, 8);
            }
            else
            {            
                /* choose sequence number: regular response, delayed response or notify cancel response */
                cmCreateSigningContext(&tmpCtx, pSession->sessionKey, sizeof(pSession->sessionKey), NULL, 0);
                cmCreateMACByContext(&tmpCtx, pSession->sequenceNumRes, pHeaderOut, dataLength, pHeader->status1.extra.securitySignature);
            }
        }
    }

    TRCE();
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
    CMCifsHeader* pHeader = (CMCifsHeader*)pHeaderIn;      
    MD5Context tmpCtx;

    TRCB();

    if (pSession && pSession->signingOn)
    {
        if (pUser)
        {
            if (pUser->isGuest)
            {
                result = TRUE;
            }
            else if (pUser->isAnonymous)
            {
                if (pSession->isBsrspyl || isZeroSignature(pHeader->status1.extra.securitySignature, SMB_SECURITY_SIGNATURE_LENGTH))
                {
                    result = TRUE;
                }
                else
                {
                    cmCreateSigningContext(&tmpCtx, pSession->sessionKey, sizeof(pSession->sessionKey), NULL, 0);
                    result = cmCheckMACByContext(&tmpCtx, pSession->sequenceNum, pHeaderIn, dataLength, pHeader->status1.extra.securitySignature); 
                    pSession->sequenceNumRes = pSession->sequenceNum + 1;
                    pSession->sequenceNum += 2;
                }
            }
            else
            {
                syMemcpy(&tmpCtx, &pUser->signingCtx, sizeof(MD5Context));
                result = cmCheckMACByContext(&tmpCtx, pSession->sequenceNum, pHeaderIn, dataLength, pHeader->status1.extra.securitySignature); 
                pSession->sequenceNumRes = pSession->sequenceNum + 1;
                pSession->sequenceNum += 2;
            }
        }
        else
        {
            /* no user yet - sign, increase seq num*/
            result = TRUE;
            if (!pSession->isBsrspyl)
            {
                if ( !isBsrspylSignature(pHeader->status1.extra.securitySignature, SMB_SECURITY_SIGNATURE_LENGTH))
                {
                    cmCreateSigningContext(&tmpCtx, pSession->sessionKey, sizeof(pSession->sessionKey), NULL, 0);
                    result = cmCheckMACByContext(&tmpCtx, pSession->sequenceNum, pHeaderIn, dataLength, pHeader->status1.extra.securitySignature); 
                }
                pSession->sequenceNumRes = pSession->sequenceNum + 1;
                pSession->sequenceNum += 2;
            }
        }
        TRC("signatures %s", result ? "match" : "not match");
    }

    TRCE();
    return result;
}

#ifdef UD_NQ_INCLUDESMB2

/*
 *====================================================================
 * PURPOSE: Create message signature  SMB2
 *--------------------------------------------------------------------
 * PARAMS:  
 *          IN     user'd sid
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

    TRCB();

    if (sid != 0)
    {
        if ((pUser = csGetUserByUid((CSUid)sessionIdToUid(sid))) && (pSession = csGetSessionById(pUser->session)))
        {
            if ((pSession->signingOn && !pUser->isGuest && !pUser->isAnonymous) || (!pSession->signingOn && isPacketSigned))
			{
                cmSmb2CalculateMessageSignature(pUser->sessionKey, sizeof(pUser->sessionKey), pHeaderOut, dataLength, NULL, 0, pHeaderOut + SMB2_SECURITY_SIGNATURE_OFFSET);
			}
        }
    }
    TRCE();
}

/*
 *====================================================================
 * PURPOSE: Check message signature  SMB2
 *--------------------------------------------------------------------
 * PARAMS:  
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


    TRCB();

    if (pUser && !pUser->isAnonymous && !pUser->isGuest && (pSession = csGetSessionById(pUser->session)))
    {
        if (pSession->signingOn || (!pSession->signingOn && isPacketSigned))
        {
            syMemcpy(sigReceived, sig, sizeof(sigReceived));
            syMemset(sig, 0, SMB2_SECURITY_SIGNATURE_SIZE);
            cmSmb2CalculateMessageSignature(pUser->sessionKey, sizeof(pUser->sessionKey), pHeaderIn, dataLength, NULL, 0, sig);
            result = syMemcmp(sigReceived, sig, 16) == 0;
            TRC("signatures %s", result ? "match" : "not match");
            TRCE();
            return result; 
        }
    }
    TRCE();
    return result;  
}


#endif /* UD_NQ_INCLUDESMB2 */

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_MESSAGESIGNINGPOLICY) */

