/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Negotiate command handler
 *--------------------------------------------------------------------
 * MODULE        : CS
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 02-Dec-2008
 ********************************************************************/

#include "csparams.h"
#include "cmgssapi.h"
#include "cmcrypt.h"
#include "cs2disp.h"
#include "csauth.h"
#include "amspnego.h"
#include "cmcrypt.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

#define RESPONSE_DATASIZE 65

/*

Structure to hold values for negotiation response that are specific per dialect.

*/

typedef struct NegotRespPerDialect
{    
    NQ_UINT32 capability;                   /* Capabilities flags */
    NQ_UINT32 maxReadSize;                  /* Max read size */    
} NegotRespPerDialect;

static const NegotRespPerDialect respPerDialect[] = {{0, CS_SMB2_MAX_READ_SIZE},                                                      /* dialect 2.0.2 */
                                                     {0, CS_SMB2_MAX_READ_SIZE},                                                      /* dialect 2.1 */
                                                     {SMB2_CAPABILITY_ENCRYPTION, CS_SMB2_MAX_READ_SIZE - SMB2_TRANSFORMHEADER_SIZE}, /* dialect 3.0 */
                                                     {0, CS_SMB2_MAX_READ_SIZE - SMB2_TRANSFORMHEADER_SIZE }};                        /* dialect 3.1.1 */
/* SMB 3.1.1 will notify encryption capability with negotiation context. */


static void writeSecurityData(CMBufferWriter *writer)
{
    CMBlob blob; 

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    blob = amSpnegoServerGenerateMechList();
    if (NULL != blob.data)
    {
        cmBufferWriteBytes(writer, blob.data, blob.len);
        cmMemoryFreeBlob(&blob);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
}

static void writeResponseData(CMSmb2Header *header, CMBufferWriter *writer , NQ_INT dialect, NQ_INT numContext, NQ_INT cipher, NQ_INT chosenHashAlgo)
{
    CMTime time;
    CMBufferWriter sbw;
    NQ_UINT16 securityMode = 0;
    NQ_INT dialectRespEntry = 0;
    NQ_UINT32 securtityBufferLength, contextBufferOffset = 0;  

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

	/* some negotiation responses are listed in a table above. */
	switch (dialect)
	{
		case SMB3_DIALECTREVISION:
			dialectRespEntry = 2;
			break;
#ifdef UD_NQ_INCLUDESMB311
		case SMB3_1_1_DIALECTREVISION:
			dialectRespEntry = 3;
			break;
#endif /* UD_NQ_INCLUDESMB311 */
        case SMB2_1_DIALECTREVISION:
            dialectRespEntry = 1;
            break;
		case SMB2_DIALECTREVISION:
		case SMB2ANY_DIALECTREVISION:
		default:
			dialectRespEntry = 0;
	}
	
    cmBufferWriteUint16(writer, RESPONSE_DATASIZE);    /* data length */
#ifdef UD_CS_MESSAGESIGNINGPOLICY    
    securityMode |= (NQ_UINT16)((csIsMessageSigningEnabled() ? SMB2_NEGOTIATE_SIGNINGENABLED : 0) | (csIsMessageSigningRequired() ? SMB2_NEGOTIATE_SIGNINGREQUIRED : 0));
#endif    
    cmBufferWriteUint16(writer, securityMode);            /* security mode */
    cmBufferWriteUint16(writer, (NQ_UINT16)dialect);      /* dialect revision */
    cmBufferWriteUint16(writer, (NQ_UINT16) numContext); /* 3.1.1 and higher context count otherwise 0 */
    cmUuidWrite(writer, cs2GetServerUuid());              /* server GUID */
    cmBufferWriteUint32(writer, respPerDialect[dialectRespEntry].capability);         /* capabilities (0) */
    cmBufferWriteUint32(writer, CS_MAXBUFFERSIZE);        /* max transact size */
    cmBufferWriteUint32(writer, respPerDialect[dialectRespEntry].maxReadSize);/* max read size */
    cmBufferWriteUint32(writer, CS_SMB2_MAX_WRITE_SIZE);  /* max write size */

    cmGetCurrentTime(&time);
    cmTimeWrite(writer, &time);                        /* current time */
    cmTimeWrite(writer, cs2GetServerStartTime());      /* server start time */

    /* write security buffer data with a dedicated writer (offsetting 8 bytes from the current position) */
    cmBufferWriterBranch(writer, &sbw, 8);
    cmBufferWriteUint16(writer, (NQ_UINT16)(contextBufferOffset = cmSmb2HeaderGetWriterOffset(header, &sbw))); /* security buffer offset */    
    writeSecurityData(&sbw);
    securtityBufferLength = cmBufferWriterGetDataCount(&sbw);
    cmBufferWriteUint16(writer, (NQ_UINT16)securtityBufferLength); /* security data size */
    
#ifdef UD_NQ_INCLUDESMB311
    if (dialect == SMB3_1_1_DIALECTREVISION) /* at least one context is mandatory */
    {
        contextBufferOffset += securtityBufferLength;
        contextBufferOffset += contextBufferOffset % 8? 8 - contextBufferOffset % 8 : 0;        /* 8 byte alignment */
        cmBufferWriteUint32(writer, contextBufferOffset);          /* dialect 3.1.1 and higher context buffer offset otherwise 0 */
    }
    else
#endif /* UD_NQ_INCLUDESMB311 */
    {
        cmBufferWriteUint32(writer, 0);                            /* dialect 3.1.1 context buffer offset */
    }    

    /* synchronize the main writer (set it after last written byte in the security buffer */
    cmBufferWriterSync(writer, &sbw);

#ifdef UD_NQ_INCLUDESMB311
    /* dialect 3.1.1 and higher. context count can be larger than 1 */
    if (dialect == SMB3_1_1_DIALECTREVISION) /* at least one context is mandatory */
    {
         cmBufferWriterAlign(writer, writer->origin, 8); /* 8 byte allignment */

         /* pre authentication integrity context - mandatory for 3.1.1*/
         cmBufferWriteUint16(writer, SMB2_PREAUTH_INTEGRITY_CAPABILITIES);  /* context type */ 
         cmBufferWriteUint16(writer, SMB2_PREAUTH_INTEGRITY_CONTEXT_LEN_BYTES); /* data length */
         cmBufferWriteUint32(writer, 0);                                    /* reserved(4) */
         cmBufferWriteUint16(writer, 1);                                    /* hash algorithm count */
         cmBufferWriteUint16(writer, SMB2_PREAUTH_INTEGRITY_SALT_SIZE);     /* salt length */
         cmBufferWriteUint16(writer, (NQ_UINT16)chosenHashAlgo);            /* hash algorithm/s */
         cmBufferWriteRandomBytes(writer, SMB2_PREAUTH_INTEGRITY_SALT_SIZE);/* salt bytes */
         cmBufferWriterAlign(writer, writer->origin, 8);                    /* 8 byte alignment */
        
         /* cipher context - not mandatory for 3.1.1 */
         if (numContext > 1)
         {
             cmBufferWriteUint16(writer, SMB2_ENCRYPTION_CAPABILITIES);     /* 3.1.1 context type */ 
             cmBufferWriteUint16(writer, 4);                                /* data length - 4 bytes to reply with one cipher. */ 
             cmBufferWriteUint32(writer, 0);                                /* reserved(4) */
             cmBufferWriteUint16(writer, 1);                                /* cipher count */
             cmBufferWriteUint16(writer, (NQ_UINT16)cipher);                /* chosen cipher */
         }
    }
#endif /* UD_NQ_INCLUDESMB311 */

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
}

static NQ_UINT32 negotiate(CSSession **connection , NQ_INT dialect, NQ_BOOL isCipherAesGcm)
{
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

   /* if (connection != NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Second negotiate for same connection");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return SMB_STATUS_INVALID_PARAMETER;
    }*/

    /* allocate new connection entry */
    if (*connection == NULL)
    	*connection = csGetNewSession();

    if (*connection == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Couldn't get new connection");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return SMB_STATUS_REQUEST_NOT_ACCEPTED;
    }
#ifdef UD_NQ_INCLUDESMB3
    cmGenerateRandomEncryptionKey((*connection)->encryptionKey);
#endif

    switch (dialect)
    {
    	case SMB2_DIALECTREVISION:
    	{
    		(*connection)->dialect = CS_DIALECT_SMB2;
			break;
    	}
        case SMB2_1_DIALECTREVISION:
		{
			(*connection)->dialect = CS_DIALECT_SMB210;
			break;
		}
    	case SMB2ANY_DIALECTREVISION:
    	{
    		(*connection)->dialect = 0;
    		break;
    	}
#ifdef UD_NQ_INCLUDESMB3
    	case SMB3_DIALECTREVISION:
		{
    		(*connection)->dialect = CS_DIALECT_SMB30;
    		break;
    	}
#ifdef UD_NQ_INCLUDESMB311
		case SMB3_1_1_DIALECTREVISION:
    	{
    		(*connection)->dialect = CS_DIALECT_SMB311;
			memset(&((*connection)->preauthIntegHashVal), 0, SMB3_PREAUTH_INTEG_HASH_LENGTH); /* zero the hash val = initial value */ 
    		break;
    	}
#endif /* UD_NQ_INCLUDESMB311 */
#endif
    }
    (*connection)->credits = UD_CS_SMB2_NUMCREDITS;
#ifdef UD_NQ_INCLUDESMB3
    (*connection)->isAesGcm = isCipherAesGcm;
#endif

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return 0;
}

#ifdef UD_NQ_INCLUDESMB311
static NQ_INT choosePreAuthIntegrityHashAlgo(CMBufferReader *reader, NQ_UINT16 dataLength)
{
	NQ_UINT16 	hashAuthAlgorithm, algorithmCount, saltLength;
	NQ_INT		chosenHashAlgo = NQ_FAIL;
	
	cmBufferReadUint16(reader, &algorithmCount);
	cmBufferReadUint16(reader, &saltLength);	

	for (; algorithmCount > 0; --algorithmCount)
	{
		cmBufferReadUint16(reader, &hashAuthAlgorithm);
		
		if(hashAuthAlgorithm == SHA_512)
			 chosenHashAlgo = SHA_512;
	}
	
	cmBufferReaderSkip(reader, saltLength);

	return chosenHashAlgo;
}

static NQ_INT chooseCipher(CMBufferReader *reader, NQ_UINT16 dataLength)
{
	NQ_UINT16 cipher, cipherCount;
	NQ_INT chosenCipher = NQ_FAIL;

	cmBufferReadUint16(reader, &cipherCount);

	for (; cipherCount > 0; --cipherCount)
	{
		cmBufferReadUint16(reader, &cipher);
		if (cipher == CIPHER_AES128GCM)
			return CIPHER_AES128GCM;
		if(cipher == CIPHER_AES128CCM)
			chosenCipher = CIPHER_AES128CCM;
   }
			
    return chosenCipher;
}
#endif /* UD_NQ_INCLUDESMB311 */

static NQ_INT chooseDialect(CMBufferReader *reader, NQ_UINT16 count)
{
    NQ_UINT16 dialect;
    NQ_INT returnDialect = NQ_FAIL;

    for (   ; count > 0; --count)
    {
        cmBufferReadUint16(reader, &dialect);

        if (dialect == SMB2_DIALECTREVISION)
            returnDialect = SMB2_DIALECTREVISION;
        if (dialect == SMB2_1_DIALECTREVISION)
            returnDialect = SMB2_1_DIALECTREVISION;
#ifdef UD_NQ_INCLUDESMB3
        else if (dialect == SMB3_DIALECTREVISION)
        	returnDialect = SMB3_DIALECTREVISION;
#ifdef UD_NQ_INCLUDESMB311
        else if (dialect == SMB3_1_1_DIALECTREVISION)
        	returnDialect = SMB3_1_1_DIALECTREVISION;
#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDESMB3 */
    }
    return returnDialect;
}
/*====================================================================
 * PURPOSE: Perform SMB2 Negotiate processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN user - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Create command.
 *====================================================================
 */

NQ_UINT32 csSmb2OnNegotiate(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    /* todo: check for packet size against read buffer size */
    NQ_UINT16 dialects, security;
    NQ_UINT32 capabilities, status = 0;
    NQ_INT chosenDialect;
#ifdef UD_NQ_INCLUDESMB3
    NQ_UINT16 contextCount;
    NQ_UINT32 contextOffset;
#ifdef UD_NQ_INCLUDESMB311
    NQ_INT numPreauthIntegContext = 0;
#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDESMB3 */
    NQ_INT chosenCipher = 0, chosenHashAlgo = 0, numContextOnResponse = 0;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    cmBufferReadUint16(reader, &dialects);
    cmBufferReadUint16(reader, &security);
    cmBufferReaderSkip(reader, 2);              /* reserved (2) */
    cmBufferReadUint32(reader, &capabilities);
#ifdef UD_NQ_INCLUDESMB3
    cmBufferReaderSkip(reader, 16);      	      /* client GUID (16) */
    cmBufferReadUint32(reader, &contextOffset); /* 3.1 and higher */   
    cmBufferReadUint16(reader, &contextCount);  /* 3.1 and higher */   
    cmBufferReaderSkip(reader, 2);              /* reserved (2) */
#else /* UD_NQ_INCLUDESMB3  */
	cmBufferReaderSkip(reader, 16 + 8); 	 /* client GUID (16) + client start time (8) */
#endif /* UD_NQ_INCLUDESMB3 */ 

    chosenDialect = chooseDialect(reader, dialects);

#ifdef UD_NQ_INCLUDESMB311
    /* read attached negotiation contexts for version 3.1.1 and above */
    if (chosenDialect >= SMB3_1_1_DIALECTREVISION) /* at least one context is mandatory */ 
    {
	    /* move reader to context offset */ 	
	    cmBufferReaderSetOffset(reader, contextOffset);

	    for (; contextCount > 0; --contextCount)
	    {
			NQ_UINT16 contextType, dataLength;
			cmBufferReadUint16(reader, &contextType);
			cmBufferReadUint16(reader, &dataLength);
			cmBufferReaderSkip(reader, 4);			/* reserved (4) */

			switch (contextType)
			{
	        	case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
	        		++numPreauthIntegContext;
	        		++numContextOnResponse;
	        		chosenHashAlgo = choosePreAuthIntegrityHashAlgo(reader, dataLength);
	        		break;
	        	case SMB2_ENCRYPTION_CAPABILITIES:
	        		chosenCipher = chooseCipher(reader, dataLength);
	        		if (chosenCipher != NQ_FAIL)
	        			++numContextOnResponse;
	        		break;
	        	default:
	        		LOGERR(CM_TRC_LEVEL_ERROR, "Received unsupported negotiation context: %d\n", contextType);
			}
			
			if (contextCount > 1)
				cmBufferReaderAlign(reader, reader->origin, 8); /* next context is 8 byte aligned */
	    }
		
		/* each SMB 3.1.1 request must have exactly one SMB2_PREAUTH_INTEGRITY_CAPABILITIES context */
		if (numPreauthIntegContext != 1)
			return SMB_STATUS_INVALID_PARAMETER;
		
		connection->preauthIntegOn = TRUE;
    }

#endif /* UD_NQ_INCLUDESMB311 */

    /* process negotiate request */
    if (chosenDialect != NQ_FAIL)
    {
        status = negotiate(&connection , chosenDialect, (chosenCipher == CIPHER_AES128GCM));
    }
    else if (chosenDialect == NQ_FAIL && connection->dialect == CS_DIALECT_SMB2)
    {
        chosenDialect = SMB2_DIALECTREVISION;    	
    	status = NQ_SUCCESS;
    }

#ifdef UD_NQ_INCLUDESMB311
	if (connection->preauthIntegOn == TRUE)
	{		
		static NQ_BYTE ctxBuff[SHA512_CTXSIZE];
		cmSmb311CalcMessagesHash(reader->origin, (reader->length + 4), connection->preauthIntegHashVal, ctxBuff);
	}
#endif /* UD_NQ_INCLUDESMB311 */

    writeResponseData(out, writer, chosenDialect, numContextOnResponse, chosenCipher, chosenHashAlgo);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return status;
}

/*====================================================================
 * PURPOSE: Perform SMB1 Negotiate processing
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT - pointer to the response 
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB1 Negotiate, when SMB2 supported
 *====================================================================
 */

NQ_UINT32 csSmb2OnSmb1Negotiate(NQ_BYTE **response , NQ_BOOL anySmb2)
{
    CMBufferWriter writer;
    CMSmb2Header header;
    NQ_UINT32 status;
    CSSession *connection = csGetNewSession();

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);
    
    if ((status = negotiate(&connection , anySmb2 ? SMB2ANY_DIALECTREVISION : SMB2_DIALECTREVISION, FALSE)) == 0)
    {
        /* compose SMB2 response (overwrite SMB1 header) */
        cmBufferWriterInit(&writer, *response - 32, 0);
        cmSmb2HeaderInitForResponse(&header, &writer, 1);
        cmSmb2HeaderWrite(&header, &writer);
        writeResponseData(&header, &writer , anySmb2 ? SMB2ANY_DIALECTREVISION : SMB2_DIALECTREVISION, 0, 0, 0);

        *response = cmBufferWriterGetPosition(&writer);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return status;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

