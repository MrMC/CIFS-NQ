/*********************************************************************
 *
 *           Copyright (c) 2012 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Oplock breaks functionality
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 02-Apr-2012
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmsmb1.h"
#include "cmsmb2.h"
#include "cmbuf.h"
#include "csdataba.h"
#include "cscreate.h"
#include "cssignin.h"
#include "csutils.h"
#include "cs2disp.h"
#include "csbreak.h"

#ifdef UD_NQ_INCLUDECIFSSERVER


static NQ_BYTE buffer[200]; /* used for sending LockingAndX, NtCreateAndX, Close, Create responses */


/*
It uses functions from cmsmb1 to compose and send a LockingAndX request. The request is composed in a static buffer. 
*/
static NQ_BOOL breakSmb(CSFile *pFile);

#ifdef UD_NQ_INCLUDESMB2
/*
It uses functions from cmsmb2 to compose and send a break request. The request is composed in a static buffer.
 */
static NQ_BOOL breakSmb2(CSFile *pFile);
#endif /* #ifdef UD_NQ_INCLUDESMB2 */


/*API function NQ_BOOL csBreakCheck(CSFile * pFile). This function enumerates CSFile structures of the same CSName and looks for  oplockGranted. 
For the first TRUE value it calls either breakSmb() of breakSmb2() - see below. This function sets breakContext for the file whose oplock is being broken. 
This context contains the FID and generic context of the file that breaks oplock (pFile). It returns TRUE when oplockbreak was sent or FALSE when there were no oplocks. */

NQ_BOOL 
csBreakCheck(
    CSCreateParams * pParams
    )
{
    CSFile *pFile;
    CSName *pName;
    CSFile *pFilePrevGranted;
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);
    
    pFile = pParams->file;
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "fid: 0x%x", pFile->fid);

#ifdef UD_CS_INCLUDERPC
    if (pFile->isPipe)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return FALSE;
    }
#endif

    pName = csGetNameByNid(pFile->nid);
    if (pName == NULL)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Internal error: file name descriptor not found. Nid: %d", pFile->nid);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return FALSE;
    }    

    /* break previously granted oplock */
    for (pFilePrevGranted = pName->first; pFilePrevGranted != NULL; pFilePrevGranted = pFilePrevGranted->next)
    {
        if (pFilePrevGranted->oplockGranted)
        {
        	 /* mark breaking file as create pending and save header for late response */
        	pFile->isCreatePending = TRUE;
        	csDispatchSaveResponseContext(&pFile->breakContext);

#ifdef UD_NQ_INCLUDESMB2
			if (pFile->breakContext.isSmb2)
			{
				/* save command data */
				pFile->breakContext.prot.smb2.commandData.oplockBreak.fid = pParams->file->fid;
				pFile->breakContext.prot.smb2.commandData.oplockBreak.createAction = pParams->takenAction;
				pFile->breakContext.prot.smb2.commandData.oplockBreak.fileInfo = pParams->fileInfo;
				pFile->breakContext.prot.smb2.commandData.oplockBreak.context = pParams->context;
			}
			else
#endif /* UD_NQ_INCLUDESMB2 */
			{
				/* save command data */
				pFile->breakContext.prot.smb1.commandData.lockingAndX.fid = pParams->file->fid;
				pFile->breakContext.prot.smb1.commandData.lockingAndX.createAction = pParams->takenAction;
				pFile->breakContext.prot.smb1.commandData.lockingAndX.fileInfo = pParams->fileInfo;
			}

			if (pFilePrevGranted->isBreakingOpLock != TRUE)
			{
				/* mark this file as breaking its oplock */
				pFilePrevGranted->isBreakingOpLock = TRUE;

				result =
#ifdef UD_NQ_INCLUDESMB2
						pFilePrevGranted->breakContext.isSmb2?  breakSmb2(pFilePrevGranted) :
#endif /* UD_NQ_INCLUDESMB2 */
																breakSmb(pFilePrevGranted);
				/* mark this file name as oplock broken once */
				pName->wasOplockBroken = TRUE;
        	}
        	else
        	{
        		/* file is already breaking its oplock */
        		result = TRUE;
        	}
        }
    }
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return result;
}


/*
Compose and send an NTCreateAndX/Create response according to the protocol. This is done in a static buffer using the pContext's pFile.
*/
static NQ_BOOL csSignalPendingCreate(CSLateResponseContext * pContext, void * pHeaderOut, NQ_UINT32 headerInFlags)
{
    CMBufferWriter writer;                  /* used to compose either of two responses */
    NQ_COUNT dataLength;                    /* response length */
    NQ_BOOL result = FALSE;                 /* operation result */
    CSSession *pBrokenSession = NULL;       /* session whose response was postponed */
    CSSession *pBreakingSession = NULL;     /* session that is causing postponed response */ 
    CSFile *pFile = NULL;                   /* context file */
#ifdef UD_NQ_INCLUDESMB3
    NQ_BYTE	encryptBuf[200 + SMB2_TRANSFORMHEADER_SIZE];
    NQ_BOOL doEncrypt = pContext->doEncrypt;
#endif
#ifdef UD_CS_MESSAGESIGNINGPOLICY
	CSUser * pUser;                     	/* context user */
#ifdef UD_NQ_INCLUDESMB2
    CMSmb2Header * pHeaderOut2 = (CMSmb2Header *)pHeaderOut; /* pointer to SMB2 header */
#endif /* UD_NQ_INCLUDESMB2 */
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor * sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    csDispatchPrepareLateResponse(pContext);

    pBrokenSession = csGetSessionBySpecificSocket(pContext->socket);

    if (pHeaderOut)                             /* send close response */
    {
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "send Close response");
        pBreakingSession = csGetSessionBySocket();
        cmBufferWriterInit(&writer, buffer + sizeof(CMNetBiosSessionMessage), sizeof(buffer));
        cmBufferWriteBytes(&writer, (NQ_BYTE *)pHeaderOut, pBreakingSession->dialect == CS_DIALECT_SMB1 ? 35 :124); /* copy response to local buffer */
        if (pBreakingSession->dialect == CS_DIALECT_SMB1)
        {
        	if (csDispatchIsNtError())
        	{
        		CMSmbHeader hdr;
				CMBufferReader	reader;
				CMBufferWriter	writer;

				cmBufferReaderInit(&reader , (NQ_BYTE *)&buffer[4] , 32);
				cmSmbHeaderRead(&hdr, &reader);
        		hdr.flags2 = hdr.flags2 | cmHtol16(SMB_FLAGS2_32_BIT_ERROR_CODES);
        		cmBufferWriterInit(&writer , (NQ_BYTE *)&buffer[4] , 32);
        		cmSmbHeaderWrite(&hdr , &writer);
        	}
        }

        dataLength = cmBufferWriterGetDataCount(&writer);
#ifdef UD_CS_MESSAGESIGNINGPOLICY
        /* sign outgoing message */ 

		pUser = csGetUserBySession(pBreakingSession);
#ifdef UD_NQ_INCLUDESMB2
		if (pBreakingSession->dialect != CS_DIALECT_SMB1)
		{
			CMBufferReader	reader;
			CMBufferWriter	writer;
			CMSmb2Header hdr;
			cmBufferReaderInit(&reader , (NQ_BYTE *)&buffer[4] , 64);
			cmSmb2HeaderRead(&hdr, &reader);
			if (headerInFlags & SMB2_FLAG_SIGNED)
				hdr.flags |= SMB2_FLAG_SIGNED;
			cmBufferWriterInit(&writer , (NQ_BYTE *)&buffer[4] , 65);
			cmSmb2HeaderWrite(&hdr , &writer);
		}
#ifdef UD_NQ_INCLUDESMB3
		if (pBreakingSession->dialect >= CS_DIALECT_SMB30)
		{
			if (!doEncrypt)
				csCreateMessageSignatureSMB3(pHeaderOut2->sid.low, cmBufferWriterGetStart(&writer), (NQ_COUNT)dataLength);
		}
#endif /* UD_NQ_INCLUDESMB3 */
		else if((pBreakingSession->dialect == CS_DIALECT_SMB2) || (pBreakingSession->dialect == CS_DIALECT_SMB210))
		{
			csCreateMessageSignatureSMB2(pHeaderOut2->sid.low, cmBufferWriterGetStart(&writer), (NQ_COUNT)dataLength);
		}
		else
#endif /* UD_NQ_INCLUDESMB2 */
		{
			csCreateMessageSignatureSMB(pBreakingSession, pUser, cmBufferWriterGetStart(&writer), (NQ_COUNT)dataLength);
		}
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
#ifdef UD_NQ_INCLUDESMBCAPTURE
        {
        	NSSocketHandle	sock = csDispatchGetSocket();
			sockDescr = csGetClientSocketDescriptorBySocket(sock);
			if (sockDescr != NULL)
			{
				sockDescr->captureHdr.receiving = FALSE;
				cmCapturePacketWriteStart(&sockDescr->captureHdr , dataLength);
				cmCapturePacketWritePacket(buffer + 4, dataLength);
				cmCapturePacketWriteEnd();
			}
        }
#endif /* UD_NQ_INCLUDESMBCAPTURE */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
#ifdef UD_NQ_INCLUDESMB3
       if ((pBreakingSession->dialect >= CS_DIALECT_SMB30) && doEncrypt)
		{
        	syMemset(&encryptBuf , 0 , sizeof(encryptBuf));
			syMemcpy(&encryptBuf[sizeof(CMNetBiosSessionMessage)] , &buffer[sizeof(CMNetBiosSessionMessage)] , dataLength);
			cs2TransformHeaderEncrypt( pUser, &encryptBuf[sizeof(CMNetBiosSessionMessage)] , dataLength);

			dataLength = dataLength + SMB2_TRANSFORMHEADER_SIZE;
		}
#endif /* UD_NQ_INCLUDESMB3 */
#endif /* UD_CS_MESSAGESIGNINGPOLICY */
       dataLength = nsPrepareNBBuffer(
#ifdef UD_NQ_INCLUDESMB3
    		   	   	   doEncrypt ? encryptBuf :
#endif
    				   buffer, dataLength, dataLength);

	    if(0 == dataLength)
	    {
	    	LOGERR(CM_TRC_LEVEL_ERROR, "Error prepare buffer for Close response");
	    }
	    else if ((NQ_INT)dataLength != nsSendFromBuffer(csDispatchGetSocket(),
#ifdef UD_NQ_INCLUDESMB3
											doEncrypt ? encryptBuf :
#endif
											buffer,
											dataLength,
											dataLength,
											NULL))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error sending Close response");
        }
    }
    if (NULL != pBrokenSession)
    {
        csDispatchSetSocket(pContext->socket);
    }
#ifdef UD_NQ_INCLUDESMB2
    if (pContext->isSmb2)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "compose and send Create response");
        cmBufferWriterInit(&writer, pContext->commandData, sizeof(buffer));
        pFile = csGetFileByFid(pContext->prot.smb2.commandData.oplockBreak.fid, (CSTid)pContext->prot.smb2.tid, (CSUid)sessionIdToUid(pContext->prot.smb2.sid.low));
        if (pFile == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Internal error: invalid fid");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return FALSE;
        }
        if (NQ_SUCCESS == pContext->status)
        {
            cmBufferWriteUint16(&writer, 89);    /* structure size */
            cmBufferWriteByte(&writer, SMB2_OPLOCK_LEVEL_NONE);
            cmBufferWriteByte(&writer, 0);       /* reserved */
            cmBufferWriteUint32(&writer, pContext->prot.smb2.commandData.oplockBreak.createAction);
            csWriteFileTimes(&pContext->prot.smb2.commandData.oplockBreak.fileInfo, csGetNameByNid(pFile->nid), cmBufferWriterGetPosition(&writer));
            cmBufferWriterSetPosition(&writer, cmBufferWriterGetPosition(&writer) + 32);

            cmBufferWriteUint32(&writer, pContext->prot.smb2.commandData.oplockBreak.fileInfo.allocSizeLow);
            cmBufferWriteUint32(&writer, pContext->prot.smb2.commandData.oplockBreak.fileInfo.allocSizeHigh);
            cmBufferWriteUint32(&writer, pContext->prot.smb2.commandData.oplockBreak.fileInfo.sizeLow);
            cmBufferWriteUint32(&writer, pContext->prot.smb2.commandData.oplockBreak.fileInfo.sizeHigh);
            cmBufferWriteUint32(&writer, pContext->prot.smb2.commandData.oplockBreak.fileInfo.attributes);
            cmBufferWriteUint32(&writer, 0);          /* reserved2 */
            cmBufferWriteUint16(&writer, pContext->prot.smb2.commandData.oplockBreak.fid); /* fid */
            cmBufferWriteZeroes(&writer, 14);         /* fid */

            /* write contexts data */
            {
                CMBufferWriter cwriter;  /* contexts writer */

                cmBufferWriterBranch(&writer, &cwriter, 8);
                cmBufferWriteUint32(&writer, SMB2_HEADERSIZE + (NQ_UINT32)cmBufferWriterGetDataCount(&writer) + 8); /* offset to contexts */ 
                cmBufferWriteUint32(&writer, cs2PackCreateContexts(&cwriter, &pContext->prot.smb2.commandData.oplockBreak.context));  /* contexts length */
                cmBufferWriterSync(&writer, &cwriter);
            }
        }
        else
        {
            cmBufferWriteUint16(&writer, 9);    /* structure size */
            cmBufferWriteUint16(&writer, 0);    /* reserved */
            cmBufferWriteUint32(&writer, 0);    /* byte count */
            cmBufferWriteByte(&writer, 0);      /* error data */
        }
        dataLength = cmBufferWriterGetDataCount(&writer);
        result = csDispatchSendLateResponse(pContext, (NQ_UINT32)pContext->status, dataLength);
    }
    else
#endif /* UD_NQ_INCLUDESMB2 */
    {
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "compose and send NtCreateAndX response");
        cmBufferWriterInit(&writer, pContext->commandData, sizeof(CMCifsNtCreateAndXResponse));
        pFile = csGetFileByFid(pContext->prot.smb1.commandData.lockingAndX.fid, pContext->prot.smb1.tid, pContext->prot.smb1.uid);
        if (pFile == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Internal error: invalid fid");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return FALSE;
        }
        if (NQ_SUCCESS == pContext->status)
        {
            cmBufferWriteByte(&writer, SMB_NTCREATEANDX_RESPONSE_WORDCOUNT);
            cmBufferWriteByte(&writer, 0xFF);
            cmBufferWriteZeroes(&writer, 3);
            cmBufferWriteByte(&writer, SMB_NTCREATEANDX_RESPONSENOOPLOCK);                                  /* oplock */
            cmBufferWriteUint16(&writer, pContext->prot.smb1.commandData.lockingAndX.fid);                  /* fid */
            cmBufferWriteUint32(&writer, pContext->prot.smb1.commandData.lockingAndX.createAction);         /* taken action */
            csWriteFileTimes(&pContext->prot.smb1.commandData.lockingAndX.fileInfo, csGetNameByNid(pFile->nid), cmBufferWriterGetPosition(&writer));
            cmBufferWriterSetPosition(&writer, cmBufferWriterGetPosition(&writer) + 32);

            cmBufferWriteUint32(&writer, pContext->prot.smb1.commandData.lockingAndX.fileInfo.attributes);  /* file attribs */
            cmBufferWriteUint32(&writer, pContext->prot.smb1.commandData.lockingAndX.fileInfo.allocSizeLow);
            cmBufferWriteUint32(&writer, pContext->prot.smb1.commandData.lockingAndX.fileInfo.allocSizeHigh);
            cmBufferWriteUint32(&writer, pContext->prot.smb1.commandData.lockingAndX.fileInfo.sizeLow);
            cmBufferWriteUint32(&writer, pContext->prot.smb1.commandData.lockingAndX.fileInfo.sizeHigh);
            cmBufferWriteUint16(&writer, 0); /* fileType */
            cmBufferWriteUint16(&writer, 7); /* deviceState */
            cmBufferWriteByte(&writer, 0);   /* isDirectory */
            cmBufferWriteUint16(&writer, 0); /* byteCount */
        }
        else
        {
            cmBufferWriteByte(&writer, 0);      /* word count */
            cmBufferWriteUint16(&writer, 0);    /* byte count */
        }
        dataLength = cmBufferWriterGetDataCount(&writer);
        if ((result = csDispatchSendLateResponse(pContext, (NQ_UINT32)pContext->status, dataLength)) == FALSE)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error sending late NtCreateAndX response");
        }
    }
    /* release fake file */
    if (NQ_SUCCESS != pContext->status && NULL != pFile)
    {
        csReleaseFile(pFile->fid);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return result;
} 

/*
Traverse file list. see files with pending create and write final create response
*/
NQ_BOOL csBreakComplete(CSFile *pFile, void * pHeaderOut, NQ_UINT32 headerInFlags)
{
	NQ_BOOL result = TRUE;
	CSName *pName;

	/* start with first file in this list */
	pName = csGetNameByNid(pFile->nid);
	pFile = pName->first;

	for(;pFile != NULL; pFile = pFile->next)
	{
		if (pFile->isCreatePending)
		{
			csSignalPendingCreate(&pFile->breakContext, pHeaderOut, headerInFlags);
			pFile->isCreatePending = FALSE;
		}
	}

	return result;
}


#ifdef UD_NQ_INCLUDESMB2

#define OPLOCK_BREAK_RESPONSE_LENGTH 24  /* length of the oplock break response not including header */

/*====================================================================
 * PURPOSE: Perform Oplock Break Acknowledgment processing
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
 * NOTES:   This function is called on SMB2 Oplock Break command.
 *====================================================================
 */

/*
It should parse the request, call csBreakComplete() and compose the response.  */
NQ_UINT32 csSmb2OnOplockBreak(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    NQ_BYTE oplockLevel;
    CSFid   fid;
    CSFile *pFile;
    CMBufferWriter stWriter;
#ifdef UD_NQ_INCLUDESMB3
    NQ_BOOL			doEncrypt;
    NQ_BYTE			encryptBuf[200 + SMB2_TRANSFORMHEADER_SIZE];
#endif
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor * sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    
    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);
   
    /* read Oplock Break Acknowledgment request */
    cmBufferReadByte(reader, &oplockLevel);
    cmBufferReaderSkip(reader, 5);          /* reserved */
    cmBufferReadUint16(reader, &fid);       /* fid */

    if ((pFile = csGetFileByFid(fid, tree->tid, session->uid)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_FILE_CLOSED;
    }
#ifdef UD_NQ_INCLUDESMB3
    doEncrypt = pFile->breakContext.doEncrypt;
#endif

    /* compose Oplock Break Response packet in a static buffer */
    if (pFile->oplockGranted)
    {
        NQ_COUNT packetLen;

        cmBufferWriterInit(&stWriter, buffer + sizeof(CMNetBiosSessionMessage), sizeof(buffer));
        cmSmb2HeaderWrite(out, &stWriter);
       
        cmBufferWriteUint16(&stWriter, OPLOCK_BREAK_RESPONSE_LENGTH);
        cmBufferWriteByte(&stWriter, oplockLevel); /* same as client sent */
        cmBufferWriteZeroes(&stWriter, 5);         /* reserved */
        cmBufferWriteUint16(&stWriter, pFile->fid); /* fid */
        cmBufferWriteZeroes(&stWriter, 14);         /* fid */

        /* send */  
        packetLen = cmBufferWriterGetDataCount(&stWriter);

#ifdef UD_NQ_INCLUDESMBCAPTURE
		sockDescr = csGetClientSocketDescriptorBySocket(pFile->breakContext.socket);
		if (sockDescr != NULL)
		{
			sockDescr->captureHdr.receiving = FALSE;
			cmCapturePacketWriteStart(&sockDescr->captureHdr , packetLen);
			cmCapturePacketWritePacket(buffer + 4, packetLen);
			cmCapturePacketWriteEnd();
		}
#endif /* UD_NQ_INCLUDESMBCAPTURE */
#ifdef UD_NQ_INCLUDESMB3
		if (doEncrypt)
		{
			syMemset(&encryptBuf , 0 , sizeof(encryptBuf));
			syMemcpy(&encryptBuf[sizeof(CMNetBiosSessionMessage) + SMB2_TRANSFORMHEADER_SIZE] , &buffer[sizeof(CMNetBiosSessionMessage)] , packetLen);
			cs2TransformHeaderEncrypt( session, &encryptBuf[sizeof(CMNetBiosSessionMessage)] , packetLen);

			packetLen = packetLen + SMB2_TRANSFORMHEADER_SIZE;
		}
#endif  /* UD_NQ_INCLUDESMB3 */
	    packetLen = nsPrepareNBBuffer(
#ifdef UD_NQ_INCLUDESMB3
	    								doEncrypt ? encryptBuf :
#endif
	    								buffer,
										packetLen,
										packetLen);
		if(0 == packetLen)
		{
            LOGERR(CM_TRC_LEVEL_ERROR, "Error prepare buffer for OPLOCK_BREAK response");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
            return FALSE;
		}

        if ((NQ_INT)packetLen != nsSendFromBuffer(pFile->breakContext.socket,
#ifdef UD_NQ_INCLUDESMB3
        									doEncrypt ? encryptBuf :
#endif
      										buffer,
        									packetLen,
											packetLen,
											NULL))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error sending OPLOCK_BREAK response");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
            return FALSE;
        }

        /* send Create response */
        csBreakComplete(pFile, NULL, in->flags);
        pFile->oplockGranted = FALSE;
        pFile->isBreakingOpLock = FALSE;
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Oplock break completed");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_NORESPONSE;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return SMB_STATUS_INVALID_DEVICE_STATE;
}


static NQ_BOOL breakSmb2(CSFile *pFile)
{
    CMSmb2Header header;
    CMBufferWriter writer;
    NQ_COUNT packetLen;
#ifdef UD_NQ_INCLUDESMB3
    NQ_BYTE			encryptBuf[200 + SMB2_TRANSFORMHEADER_SIZE];
    NQ_BOOL			doEncrypt = pFile->breakContext.doEncrypt;
#endif
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor * sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "Fid: %d", pFile->fid);

    /* compose Oplock Break response */
    cmBufferWriterInit(&writer, buffer + sizeof(CMNetBiosSessionMessage), sizeof(buffer));

    /* header - unsolicited response */
    cmSmb2HeaderInitForResponse(&header, &writer, 0);
    header.command = SMB2_CMD_OPLOCKBREAK;
    header.credits = 0;
    header.mid.low = 0xFFFFFFFF;
    header.mid.high = 0xFFFFFFFF;
    header.sid.low = (NQ_UINT32)uidToSessionId(pFile->uid);
    header.tid = pFile->tid;
    cmSmb2HeaderWrite(&header, &writer);

    /* data */
    cmBufferWriteUint16(&writer, OPLOCK_BREAK_RESPONSE_LENGTH); 
    cmBufferWriteByte(&writer, SMB2_OPLOCK_LEVEL_NONE); /* new oplock level for client: no oplock (can be level II)*/
    cmBufferWriteZeroes(&writer, 5);          /* reserved */
    cmBufferWriteUint16(&writer, pFile->fid); /* fid */
    cmBufferWriteZeroes(&writer, 14);         /* fid */

    /* send */
	packetLen = cmBufferWriterGetDataCount(&writer);

#ifdef UD_NQ_INCLUDESMBCAPTURE
    sockDescr = csGetClientSocketDescriptorBySocket(pFile->breakContext.socket);
    if (sockDescr != NULL)
    {
		sockDescr->captureHdr.receiving = FALSE;
		cmCapturePacketWriteStart(&sockDescr->captureHdr , packetLen);
		cmCapturePacketWritePacket(buffer + 4, packetLen);
		cmCapturePacketWriteEnd();
    }
#endif /* UD_NQ_INCLUDESMBCAPTURE */
#ifdef UD_NQ_INCLUDESMB3
    if (doEncrypt)
    {
    	CSUser 		* 	pUser;

    	pUser = (pFile->user != NULL) ? pFile->user : csGetUserByUid(pFile->uid);

    	if (NULL == pUser)
    	{
    		LOGERR(CM_TRC_LEVEL_ERROR, "No user, can't encrypt packet. Not sending break.");
    		LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    		return FALSE;
    	}
    	/* encryptNonce shouldn't repeat in a session. usually we copy nonce from request to user data and use in in response.
    	 * For break there is no request so nonce will be same as previous packet.
    	 * Solution: create new nonce in user data. */
    	cmCreateRandomByteSequence(pUser->encryptNonce, SMB2_AES128_GCM_NONCE_SIZE);
    	syMemset(&encryptBuf , 0 , sizeof(encryptBuf));
    	syMemcpy(&encryptBuf[sizeof(CMNetBiosSessionMessage) + SMB2_TRANSFORMHEADER_SIZE], &buffer[sizeof(CMNetBiosSessionMessage)], packetLen);
    	cs2TransformHeaderEncrypt( pUser, &encryptBuf[sizeof(CMNetBiosSessionMessage)] , packetLen);
    	packetLen = packetLen + SMB2_TRANSFORMHEADER_SIZE;

    }
#endif /* UD_NQ_INCLUDESMB3 */
    packetLen = nsPrepareNBBuffer(
#ifdef UD_NQ_INCLUDESMB3
    		doEncrypt ? encryptBuf :
#endif
    				buffer, packetLen, packetLen);
    if(0 == packetLen)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Error prepare buffer for OPLOCK_BREAK response");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
    }

    if ((NQ_INT)packetLen != nsSendFromBuffer(pFile->breakContext.socket,
#ifdef UD_NQ_INCLUDESMB3
									doEncrypt ? encryptBuf :
#endif
											buffer,
									packetLen,
									packetLen,
									NULL))
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Error sending OPLOCK_BREAK response");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
    }
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return TRUE;
}
#endif /* UD_NQ_INCLUDESMB2 */


static NQ_BOOL breakSmb(CSFile *pFile)
{
    CMSmbHeader header;  
    CMBufferWriter writer;
    NQ_COUNT packetLen;
#ifdef UD_NQ_INCLUDESMBCAPTURE
    CSSocketDescriptor * sockDescr;
#endif /* UD_NQ_INCLUDESMBCAPTURE */

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* compose SMB_COM_LOCKING_ANDX request */  
    cmBufferWriterInit(&writer, buffer + sizeof(CMNetBiosSessionMessage), sizeof(buffer));

    /* header */
    cmSmbHeaderInitForRequest(&header, &writer, 0x24);
    header.tid = pFile->tid;
    header.uid = pFile->uid;
    header.mid = 0xFFFF;
    header.pid = 0xFFFF;
    cmSmbHeaderWrite(&header, &writer);

    /* data */
    cmBufferWriteByte(&writer, 8);              /* word count */
    cmBufferWriteByte(&writer, 0xFF);           /* andX command */
    cmBufferWriteZeroes(&writer, 3);            /* reserved and offset to next command */
    cmBufferWriteUint16(&writer, pFile->fid);   /* fid */  
    cmBufferWriteByte(&writer, 0x2);            /* lock type: oplock break notification */
    cmBufferWriteByte(&writer, 0);              /* new oplock level for client: no oplock (can be level II)*/
    cmBufferWriteUint32(&writer, 0);            /* timeout: return immediately */
    cmBufferWriteUint16(&writer, 0);            /* number of unlocks: 0 */ 
    cmBufferWriteUint16(&writer, 0);            /* number of locks: 0  */ 
    cmBufferWriteUint16(&writer, 0);            /* byte count */ 
    
    /* send */
    packetLen = cmBufferWriterGetDataCount(&writer);

#ifdef UD_NQ_INCLUDESMBCAPTURE
    sockDescr = csGetClientSocketDescriptorBySocket(pFile->breakContext.socket);
    if (sockDescr != NULL)
    {
		sockDescr->captureHdr.receiving = FALSE;
		cmCapturePacketWriteStart(&sockDescr->captureHdr , packetLen);
		cmCapturePacketWritePacket(buffer + 4, packetLen);
		cmCapturePacketWriteEnd();
    }
#endif /* UD_NQ_INCLUDESMBCAPTURE */

    packetLen = nsPrepareNBBuffer(buffer, packetLen, packetLen);
    if(0 == packetLen)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error prepare buffer for SMB_COM_LOCKING_ANDX request");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
    }

    if ((NQ_INT)packetLen != nsSendFromBuffer(pFile->breakContext.socket, buffer, packetLen, packetLen, NULL))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending SMB_COM_LOCKING_ANDX request");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return FALSE;
    }
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return TRUE;
}


#endif /* UD_NQ_INCLUDECIFSSERVER */
