/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Transform Header command handler
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 05-Jan-2009
 ********************************************************************/
#include "cmsmb2.h"
#include "csdataba.h"
#include "cmcrypt.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB3)

NQ_BOOL cs2TransformHeaderEncrypt( /*CSSession * pSession,*/
									CSUser	*	user,
									NQ_BYTE * response,
									NQ_COUNT length)
{
	CSUser	*	pUser = NULL;
	CMBufferReader	reader;
	CMBufferWriter	writer;
	CMSmb2Header	smb2Header;
	CMSmb2TransformHeader	tranHeader;
	CSSession *pSession = NULL;

	syMemset(&tranHeader , 0 , sizeof(CMSmb2TransformHeader));

	if (user != NULL)
	{
		pUser = user;
		tranHeader.sid.low = (NQ_UINT32)uidToSessionId(pUser->uid);
	}
	else
	{
		cmBufferReaderInit(&reader , response + SMB2_TRANSFORMHEADER_SIZE, length);
		cmSmb2HeaderRead(&smb2Header , &reader);
		pUser = csGetUserByUid((CSUid)sessionIdToUid(smb2Header.sid.low));
		if (pUser == NULL)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "No User found");
			LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
			return FALSE;
		}
		tranHeader.sid = smb2Header.sid;
	}

	pSession = csGetSessionById(pUser->session);
	if (NULL == pSession)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "No session found");
		LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
		return FALSE;
	}


	tranHeader.originalMsgSize = length;
	tranHeader.encryptionArgorithm = pSession->dialect >= CS_DIALECT_SMB311? SMB2_USE_NEGOTIATED_CIPHER : SMB2_ENCRYPTION_AES128_CCM; /* starting 3.1.1 this field is called flags */
	/* use received nonce - copy using GCM size. maybe one extra byte copy */
	syMemcpy(tranHeader.nonce, pUser->encryptNonce, SMB2_AES128_GCM_NONCE_SIZE);
	cmBufferWriterInit(&writer, response, SMB2_TRANSFORMHEADER_SIZE);
	cmSmb2TransformHeaderWrite(&tranHeader , &writer);

	/* encrypted part: payload and not SMB header. authenticated part: all (SMBheader + payload) - protocolID (4 bytes) - signature (16 bytes). so first 20 bytes aren't authenticated */

	if (pSession->dialect >= CS_DIALECT_SMB311 && pSession->isAesGcm)
	{
		static NQ_BYTE keyBuffer[AES_PRIV_SIZE];
		static NQ_BYTE msgBuffer[UD_NS_BUFFERSIZE];
		aes128GcmEncrypt(pUser->encryptionKey, pUser->encryptNonce, response + SMB2_TRANSFORMHEADER_SIZE, length, response + 20,
			SMB2_TRANSFORMHEADER_SIZE - 20, response + 4, keyBuffer, msgBuffer);
	}
	else
	{
		AES_128_CCM_Encrypt(pUser->encryptionKey , pUser->encryptNonce, response + SMB2_TRANSFORMHEADER_SIZE , length, response + 20,
			SMB2_TRANSFORMHEADER_SIZE - 20, response + 4);
	}
	return TRUE;
}

NQ_BOOL cs2TransformHeaderDecrypt(	NSRecvDescr * recvDescr,
									NQ_BYTE * request,
									NQ_COUNT length)
{
	CMSmb2TransformHeader	header;
	NQ_BYTE	nonce[SMB2_ENCRYPTION_HDR_NONCE_SIZE];
	CMBufferReader	reader;
	NQ_BYTE * pBuf = request + 4;
	CSUser	* pUser;
	CSSession *pSession;
	NQ_UINT msgLen;
	NQ_BOOL res;
	NQ_UINT nonceSize;

	syMemset(&nonce , 0 , SMB2_ENCRYPTION_HDR_NONCE_SIZE);

	if (NQ_FAIL == nsRecvIntoBuffer(recvDescr, pBuf, SMB2_TRANSFORMHEADER_SIZE - 4)) /* read the rest of the header + StructureSize */
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Error reading from socket");
		LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
		return NQ_FAIL;
	}

	cmBufferReaderInit(&reader , request , length);
	cmSmb2TransformHeaderRead(&header , &reader);
	
	pUser = csGetUserByUid((CSUid)sessionIdToUid(header.sid.low));
	if (pUser == NULL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "No User found");
		LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
		return FALSE;
	}

	if (NULL == (pSession = csGetSessionById(pUser->session)))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "No session found");
		LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
		return FALSE;
	}
	
	if (pSession->dialect >= CS_DIALECT_SMB311 && header.encryptionArgorithm /* = flags */ == SMB2_USE_NEGOTIATED_CIPHER && pSession->isAesGcm)
	{
		nonceSize = SMB2_AES128_GCM_NONCE_SIZE;
		LOGERR(CM_TRC_LEVEL_MESS_SOME, "decrypt with GCM. nonce size: %d", nonceSize);
	}
	else
	{
		nonceSize = SMB2_AES128_CCM_NONCE_SIZE;
	}

	syMemcpy(&nonce , header.nonce ,nonceSize);
	
	syMemset(&pUser->encryptNonce , 0 , SMB2_ENCRYPTION_HDR_NONCE_SIZE);
	syMemcpy(&pUser->encryptNonce , nonce , nonceSize);
	pBuf += SMB2_TRANSFORMHEADER_SIZE - 4;
	msgLen = (NQ_UINT)nsRecvIntoBuffer(recvDescr, pBuf, (NQ_COUNT)header.originalMsgSize); /* read the encrypted packet */
	if (msgLen == (NQ_UINT)NQ_FAIL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "error receiving command");
		LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
		return FALSE;
	}

	if (nonceSize == SMB2_AES128_GCM_NONCE_SIZE)
	{
		static NQ_BYTE keyBuffer[AES_PRIV_SIZE];
		static NQ_BYTE msgBuffer[UD_NS_BUFFERSIZE];
		res = aes128GcmDecrypt(pUser->decryptionKey , nonce, pBuf , (NQ_UINT)header.originalMsgSize, request + 20 , SMB2_TRANSFORMHEADER_SIZE - 20,
				header.signature, keyBuffer, msgBuffer);
	}
	else
	{
		res = AES_128_CCM_Decrypt(pUser->decryptionKey , nonce, pBuf , (NQ_UINT)header.originalMsgSize, request + 20 , SMB2_TRANSFORMHEADER_SIZE - 20, header.signature);
	}

	return res;
}
#endif  /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */
