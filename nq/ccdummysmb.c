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
/*
 * ccWaitNegoClient.c
 *
 *  Created on: Oct 27, 2016
 *      Author: iland
 */

#include "ccapi.h"
#include "ccsmb20.h"
#include "cmsmb2.h"
#include "ccserver.h"
#include "ccshare.h"
#include "ccuser.h"
#include "ccfile.h"
#include "ccsearch.h"
#include "ccinfo.h"
#include "ccsmb2common.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT


/* CCCifsSmb methods */
static void * allocateContext(CCServer * server);
static void freeContext(void * context, void * server);
static void setSolo(NQ_BOOL set){};
static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * blob);
static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2);
static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob);
static NQ_STATUS doLogOff(CCUser * pUser);
static NQ_STATUS doTreeConnect(CCShare * pShare);
static NQ_STATUS doTreeDisconnect(CCShare * pShare);
static NQ_STATUS doCreate(CCFile * pFile);
static NQ_STATUS doRestoreHandle(CCFile * pFile);
static NQ_STATUS doClose(CCFile * pFile);
static NQ_STATUS doQueryDfsReferrals(CCShare * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list);
static NQ_STATUS doFindOpen(CCSearch * pSearch);
static NQ_STATUS doFindMore(CCSearch * pSearch);
static NQ_STATUS doFindClose(CCSearch * pSearch);
static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context, void *hook);
static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context, void *hook);
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS
static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd);
static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd);
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */
static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo);
static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCFileInfo * pInfo);
static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCFileInfo * pInfo);
static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes);
static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size);
static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime);
static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile);
static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName);
static NQ_STATUS doFlush(CCFile * pFile);
static NQ_STATUS doRapTransaction(void * pShare, const CMBlob * inData, CMBlob * outParams, CMBlob * outData);
static NQ_STATUS doEcho(CCShare * pShare);
static NQ_BOOL	 validateNegotiate(void *pServ, void *pUser, void *pShare);

static void handleWaitingNotifyResponse(void *pServer, void *pFile);
static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch, NQ_BOOL (*callback)(CMItem * pItem));
static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse);
static void anyResponseCallback(void * transport);

static void keyDerivation(void * user);
static void signalAllMatches(void * pTransport);
/* -- Static data */

static const NQ_WCHAR rpcPrefix[] = { 0 };  /* value to prefix RPC pipe names */

static const CCCifsSmb dialect =
{
        SMB2_DIALECTSTRING,
        SMB2_DIALECTREVISION,
        16,
		TRUE,
        rpcPrefix,
		(void * (*)(void *))allocateContext,
		freeContext,
        setSolo,
		(NQ_STATUS (*)(void *, CMBlob *))doNegotiate,
		(NQ_STATUS (*)(void *, const CMBlob *, const CMBlob *))doSessionSetup,
		(NQ_STATUS (*)(void *, const CMBlob *, CMBlob *))doSessionSetupExtended,
		(NQ_STATUS (*)(void *))doLogOff,
		(NQ_STATUS (*)(void *))doTreeConnect,
		(NQ_STATUS (*)(void *))doTreeDisconnect,
		(NQ_STATUS (*)(void *))doCreate,
		(NQ_STATUS (*)(void *))doRestoreHandle,
		(NQ_STATUS (*)(void *))doClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, CCCifsParseReferral, CMList *))doQueryDfsReferrals,
		(NQ_STATUS (*)(void *))doFindOpen,
		(NQ_STATUS (*)(void *))doFindMore,
		(NQ_STATUS (*)(void *))doFindClose,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsWriteCallback, void *, void *))doWrite,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsReadCallback, void *, void *))doRead,
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS
		(NQ_STATUS (*)(void *, CMSdSecurityDescriptor *))doQuerySecurityDescriptor,
		(NQ_STATUS (*)(void *, const CMSdSecurityDescriptor *))doSetSecurityDescriptor,
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */
		(NQ_STATUS (*)(void *, void *))doQueryFsInfo,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, void *))doQueryFileInfoByName,
		(NQ_STATUS (*)(void *, void *))doQueryFileInfoByHandle,
		(NQ_STATUS (*)(void *, NQ_UINT32))doSetFileAttributes,
		(NQ_STATUS (*)(void *, NQ_UINT64))doSetFileSize,
		(NQ_STATUS (*)(void *, NQ_UINT64, NQ_UINT64, NQ_UINT64))doSetFileTime,

		(NQ_STATUS (*)(void *))doSetFileDeleteOnClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *))doRename,
		(NQ_STATUS (*)(void * pFile))doFlush,
		(NQ_STATUS(*)(void *, const CMBlob *, CMBlob *, CMBlob *))doRapTransaction,
        (NQ_STATUS (*)(void *))doEcho,
        (NQ_STATUS (*)(void * pServer, void * pUser, void * pRequest, void * pMatch, NQ_BOOL (*callback)(CMItem * pItem)))sendRequest,
		(NQ_STATUS (*)(void * pServer, void * pUser, void * pRequest, void * pResponse))sendReceive,
		anyResponseCallback,
		keyDerivation,
		signalAllMatches,
		handleWaitingNotifyResponse,
		validateNegotiate,
        FALSE,
        TRUE
};

/* -- API Functions */

NQ_BOOL ccSmbStart(void);
NQ_BOOL ccSmbStart(void)
{
	return TRUE;
}

NQ_BOOL ccSmbShutdown(void);
NQ_BOOL ccSmbShutdown(void)
{
	return TRUE;
}

const CCCifsSmb *ccSmbDummyGetCifs(void);
const CCCifsSmb *ccSmbDummyGetCifs(void)
{
	return &dialect;
}

/* -- Static functions -- */

static void * allocateContext(CCServer * pServer)
{
	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return (pServer->smb->allocateContext(pServer));
}

static void freeContext(void * context, void * server)
{
	CCServer * pServer = (CCServer *)server;	/* casted pointer */

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	pServer->smb->freeContext(context, server);
}


static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch, NQ_BOOL (*callback)(CMItem * pItem))
{
	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->sendRequest(pServer, pUser, pRequest, pMatch, callback);
}

static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse)
{
	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->sendReceive(pServer, pUser, pRequest, pResponse);
}

/*
	 * Server sends notify responses == response without request. Ex: break notification
	 * If file ID for sent response isn't found. we save the response and try again on newly created files.
	 * To avoid missing a break notification that is handled while file creation on our side still in process.
	 */
static void handleWaitingNotifyResponse(void *pserver, void *pfile)
{
	CCServer * pServer = (CCServer *)pserver;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	pServer->smb->handleWaitingNotifyResponses(pserver, pfile);
}

static void anyResponseCallback(void * transport)
{
	CCTransport * pTransport = (CCTransport *)transport; 	/* casted to transport entry */
	CCServer * pServer = (CCServer *)pTransport->context;							/* casted pointer */

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	pServer->smb->anyResponseCallback(transport);
}

static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * inBlob)
{
	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doNegotiate(pServer, inBlob);
}


static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2)
{
	CCServer *pServer = pUser->server;
	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doSessionSetup(pUser, pass1, pass2);
}

static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob)
{
	CCServer * pServer;		/* server object pointer */
	pServer = pUser->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doSessionSetup(pUser, outBlob, inBlob);
}

static NQ_STATUS doLogOff(CCUser * pUser)
{
	CCServer * pServer = pUser->server;		/* server object pointer */

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doLogOff(pUser);
}

static NQ_STATUS doTreeConnect(CCShare * pShare)
{
	CCServer * pServer = pShare->user->server;		/* server object pointer */

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doTreeConnect(pShare);
}

static NQ_STATUS doTreeDisconnect(CCShare * pShare)
{
	CCServer * pServer = pShare->user->server;		/* server object pointer */

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doTreeDisconnect(pShare);
}

static NQ_STATUS doCreate(CCFile * pFile)
{
	CCServer * pServer = pFile->share->user->server;		/* server object pointer */

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doCreate(pFile);
}

static NQ_STATUS doRestoreHandle(CCFile * pFile)
{
	CCServer * pServer = pFile->share->user->server;		/* server object pointer */

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pFile->share->user->server->smb->doRestoreHandle(pFile);
}

static NQ_STATUS doClose(CCFile * pFile)
{
	CCServer * pServer = pFile->share->user->server;
	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pFile->share->user->server->smb->doClose(pFile);
}

static NQ_STATUS doQueryDfsReferrals(CCShare * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list)
{
	CCServer * pServer = share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doQueryDfsReferrals(share, path, parser, list);
}

static NQ_STATUS doFindOpen(CCSearch * pSearch)
{
	CCServer * pServer = pSearch->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doFindOpen(pSearch);
}

static NQ_STATUS doFindMore(CCSearch * pSearch)
{
	CCServer * pServer = pSearch->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doFindOpen(pSearch);
}

static NQ_STATUS doFindClose(CCSearch * pSearch)
{
	CCServer * pServer = pSearch->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doFindClose(pSearch);
}


static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context, void *hook)
{
    CCServer    *   pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doWrite(pFile, data, bytesToWrite, callback, context, hook);
}


static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * buffer, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context, void *hook)
{
    CCServer    *   pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doRead(pFile, buffer, bytesToRead, callback, context, hook);
}

#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS

static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd)
{
	CCServer    *   pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doQuerySecurityDescriptor(pFile, sd);
}

static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doSetSecurityDescriptor(pFile, sd);
}

#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */


static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCFileInfo * pInfo)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doQueryFileInfoByHandle(pFile, pInfo);
}

static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCFileInfo * pInfo)
{
	CCServer *pServer = pShare->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doQueryFileInfoByName(pShare, fileName, pInfo);
}

static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo)
{
	CCServer *pServer = pShare->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doQueryFsInfo(pShare, pInfo);
}

static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doSetFileAttributes(pFile, attributes);
}

static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doSetFileSize(pFile, size);
}

static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doSetFileTime(pFile, creationTime, lastAccessTime, lastWriteTime);
}

static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doSetFileDeleteOnClose(pFile);
}

static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doRename(pFile, newName);
}

static NQ_STATUS doFlush(CCFile * pFile)
{
	CCServer *pServer = pFile->share->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doFlush(pFile);
}

static 	NQ_STATUS doRapTransaction(void * pshare, const CMBlob * inData, CMBlob * outParams, CMBlob * outData)
{
	CCShare *pShare = (CCShare *) pshare;

	CCServer *pServer = pShare->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doRapTransaction(pshare, inData, outParams, outData);
}


static NQ_STATUS doEcho(CCShare * pShare)
{
	CCServer *pServer = pShare->user->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->doEcho(pShare);
}

static void keyDerivation(void * user)
{
	CCUser *pUser = (CCUser *)user;

	CCServer *pServer = pUser->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	pServer->smb->keyDerivation(user);
}

static void signalAllMatches(void * trans)
{
	CCTransport * 	pTransport = (CCTransport *)trans;
	CCServer * 		pServer = (CCServer *)pTransport->server;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	pServer->smb->signalAllMatch(trans);
}

static NQ_BOOL validateNegotiate(void *pServ, void *_pUser, void *pShare)
{
	CCServer * 		pServer = (CCServer *)pServ;

	cmListItemTake(&pServer->item);
	cmListItemGive(&pServer->item);

	return pServer->smb->validateNegotiate(pServer, _pUser, pShare);
}


#endif /* UD_NQ_INCLUDECIFSCLIENT */

