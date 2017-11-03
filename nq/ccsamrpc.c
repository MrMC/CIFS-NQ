/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SAMR RPC client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 14-Oct-2005
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccsamrpc.h"
#include "ccfile.h"
#include "cmrpcdef.h"
#include "cmsdescr.h"
#include "cmbuf.h"
#include "cmcrypt.h"
#include "nqapi.h"

#if defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH)

/*
 * Static data, functions and defintions
 * -------------------------------------
 */

#define CONNECT_OPNUM       64  /* currently - Connect5 */
#define OPENDOMAIN_OPNUM    7   /* currently - OpenDomain */
#define LOOKUPDOMAIN_OPNUM  5   /* currently - LookupDomain */
#define OPENUSER_OPNUM      34  /* currently - OpenUser */
#define GETGROUPS_OPNUM     39  /* currently - GetGroupsForUser */
#define CLOSE_OPNUM         1   /* */
#define LOOKUPNAMES_OPNUM   17
#define GETUSERINFO2_OPNUM  47
#define SETUSERINFO2_OPNUM  58
#define CREATEUSER2_OPNUM   50
#define DELETEUSER_OPNUM    35


#define CONNECT_ACCESSMASK  0x20031

/* parameters for callbacks */
typedef struct
{
    const NQ_WCHAR * host;      /* host name */
    const NQ_WCHAR * user;      /* user name */
    const NQ_WCHAR * domain;    /* domain name */
    CMRpcPolicyHandle *connect; /* connect policy handle */
    CMRpcUuid pipeUuid;         /* uuid for the pipe policy handle */
    NQ_UINT32 pipeId;           /* ID for the pipe policy handle */
    CMRpcUuid domainUuid;       /* uuid for the domain policy handle */
    NQ_UINT32 domainId;         /* ID for the domain policy handle */
    CMRpcUuid userUuid;         /* uuid for the user policy handle */
    NQ_UINT32 userId;           /* ID for the domain policy handle */
    const CMRpcUuid* uuid;      /* uuid for Close */
    NQ_UINT32 id;               /* ID for Close */
    CMSdAccessToken* token;     /* token buffer */
    CMSdDomainSid* sid;         /* domain SID buffer */
    CMSdDomainSid* domainSid;   /* domain SID */
    NQ_UINT32 access;           /* access mask */
    NQ_UINT32 flags;
    NQ_UINT32 status;
}
CallbackParams;

/* pipe descriptor */
static const NQ_WCHAR pipeName[] = { cmWChar('s'), cmWChar('a'), cmWChar('m'), cmWChar('r'), cmWChar('\0') };
static const CCDcerpcPipeDescriptor pipeDescriptor =
{ pipeName,
  {cmPack32(0x12345778),cmPack16(0x1234),cmPack16(0xabcd),{0xef,0x00},{0x01,0x23,0x45,0x67,0x89,0xac}},
  cmRpcVersion(1, 0)
};

/* Connect request callback */

static NQ_COUNT                /* count of outgoing data */
connectRequestCallback (
    NQ_BYTE* buffer,    /* outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* Connect response callback */

static NQ_STATUS                   /* NQ_SUCCESS or error code */
connectResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* OpenDomain request callback */

static NQ_COUNT                /* count of outgoing data */
openDomainRequestCallback (
    NQ_BYTE* buffer,    /* Outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* OpenDomain response callback */

static NQ_STATUS                   /* NQ_SUCCESS or error code */
openDomainResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

static NQ_COUNT                /* count of outgoing data */
lookupDomainRequestCallback (
    NQ_BYTE* buffer,    /* Outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* OpenDomain response callback */

static NQ_STATUS                   /* NQ_SUCCESS or error code */
lookupDomainResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* OpenUser request callback */

static NQ_COUNT                /* count of outgoing data */
openUserRequestCallback (
    NQ_BYTE* buffer,    /* Outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* OpenUser response callback */

static NQ_STATUS                   /* NQ_SUCCESS or error code */
openUserResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* GetGroupsForUser request callback */

static NQ_COUNT                /* count of outgoing data */
getGroupsForUserRequestCallback (
    NQ_BYTE* buffer,    /* Outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* GetGroupsForUser response callback */

static NQ_STATUS                   /* NQ_SUCCESS or error code */
getGroupsForUserResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/* Close request callback */

static NQ_COUNT                /* count of outgoing data */
closeRequestCallback (
    NQ_BYTE* buffer,    /* Outgoing data buffer */
    NQ_COUNT size,      /* room in the buffer */
    void* params,       /* abstract parameters */
    NQ_BOOL* moreData   /* put here TRUE when more outgoing data available */
    );

/* Close response callback */

static NQ_STATUS                   /* NQ_SUCCESS or error code */
closeResponseCallback (
    const NQ_BYTE* data,    /* data portion pointer */
    NQ_COUNT size,          /* data portion size */
    void* params,           /* abstract parameters */
    NQ_BOOL moreData        /* TRUE when more data available */
    );

/*====================================================================
 * PURPOSE: Return this pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Pipe descriptor
 *
 * NOTES:
 *====================================================================
 */

const CCDcerpcPipeDescriptor * ccSamGetPipe(void)
{
    return &pipeDescriptor;
}

/* SAMR::Connect5 */

NQ_UINT32
ccSamrConnect5(
    NQ_HANDLE samr,
    NQ_UINT32 access,
    CMRpcPolicyHandle *connect
    )
{
    CallbackParams p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p access:%u connect:%p", samr, access, connect);

    /* pass parameters */
    p.host = ((CCFile *)samr)->share->user->server->item.name;
    p.access = access;

    /* call SAMR::Connect5 */
    if (ccDcerpcCall(samr, connectRequestCallback, connectResponseCallback, &p))
    {
        connect->id = p.pipeId;
        connect->uuid = p.pipeUuid;
    }
    else
    {
        p.status = (NQ_UINT32)NQ_ERR_NOACCESS;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::Connect5");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

/* SAMR::OpenDomain */

NQ_UINT32
ccSamrOpenDomain(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *connect,
    const CMSdDomainSid *domain,
    NQ_UINT32 access,
    CMRpcPolicyHandle *open
    )
{
    CallbackParams p;
    CMSdAccessToken token;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p connect:%p domain:%p access:%u open:%p", samr, connect, domain, access, open) ;

    /* token must be initialized with the supplied domain SID */
    token.domain = *domain;

    /* pass parameters */
    p.pipeId = connect->id;
    p.pipeUuid = connect->uuid;
    p.token = &token;
    p.access = access;

    /* call SAMR::OpenDomain */
    if (ccDcerpcCall(samr, openDomainRequestCallback, openDomainResponseCallback, &p))
    {
        open->id = p.domainId;
        open->uuid = p.domainUuid;
    }
    else
    {
        p.status = (NQ_UINT32)NQ_ERR_BADPARAM;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::OpenDomain");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

/* SAMR::CreateUser2 */

typedef struct {
    const CMRpcPolicyHandle *domain;
    const NQ_WCHAR *name;
    NQ_UINT32 flags;
    NQ_UINT32 access;
    CMRpcPolicyHandle *user;
    NQ_UINT32 *granted;
    NQ_UINT32 *rid;
    NQ_UINT32 status;
}
ParamsSamrUserCreate2;

static NQ_COUNT
composeCreateUser2 (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;
    ParamsSamrUserCreate2 *p = (ParamsSamrUserCreate2 *)params;
    NQ_UINT32 refId = 1;
    NQ_UINT16 length = (NQ_UINT16)cmWStrlen(p->name);
    NQ_UINT16 sz = (NQ_UINT16)(length * sizeof(NQ_WCHAR));

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    cmBufferWriterInit(&w, buffer, size);

    cmBufferWriteUint16(&w, CREATEUSER2_OPNUM);  /* CreateUser2 opnum */
    /* domain policy handle */
    cmBufferWriteUint32(&w, p->domain->id);      /* id */
    cmRpcUuidWrite(&w, &p->domain->uuid);        /* uuid */
    /* account name */
    cmBufferWriteUint16(&w, sz);                 /* length in bytes */
    cmBufferWriteUint16(&w, sz);                 /* size in bytes */
    cmBufferWriteUint32(&w, refId);              /* ref ID */
    cmBufferWriteUint32(&w, length);             /* max count in symbols */
    cmBufferWriteUint32(&w, 0);                  /* offset */
    cmBufferWriteUint32(&w, length);             /* actual count in symbols */
    cmBufferWriteUnicodeNoNull(&w, p->name);
    cmBufferWriterAlign(&w, buffer + 2, 4);      /* 4 byte alignment */
    /* rest of the data */
    cmBufferWriteUint32(&w, p->flags);           /* flags */
    cmBufferWriteUint32(&w, p->access);          /* access */

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS
processCreateUser2 (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsSamrUserCreate2 *p = (ParamsSamrUserCreate2 *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    cmBufferReaderInit(&r, data, size);

    /* check if the data and status fit into the buffer */
    if (size >= 4 + sizeof(CMRpcUuid) + 4 + 4 + 4)
    {
        cmBufferReadUint32(&r, &p->user->id);
        cmRpcUuidRead(&r, &p->user->uuid);
        cmBufferReadUint32(&r, p->granted);
        cmBufferReadUint32(&r, p->rid);
    }

    cmBufferReadUint32(&r, &p->status);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", p->status);
    return (NQ_STATUS)p->status;
}

NQ_UINT32
ccSamrCreateUser2(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *domain,
    const NQ_WCHAR *name,
    NQ_UINT32 flags,
    NQ_UINT32 access,
    CMRpcPolicyHandle *user,
    NQ_UINT32 *rid,
    NQ_UINT32 *granted
    )
{
    ParamsSamrUserCreate2 p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p domain:%p name:%s flags:0x%x access:0x%x user:%p rid:%p granted:%p", samr, domain, cmWDump(name), flags, access, user, rid, granted);

    /* pass parameters */
    p.domain = domain;
    p.name = name;
    p.flags = flags;
    p.access = access;
    p.user = user;
    p.rid = rid;
    p.granted = granted;

    /* call SAMR::CreateUser2 */
    if (!ccDcerpcCall(samr, composeCreateUser2, processCreateUser2, &p))
    {
        p.status = (NQ_UINT32)NQ_ERR_BADPARAM;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::CreateUser2");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

/* SAMR::SetUserInfo2 */

typedef struct {
    const CMRpcPolicyHandle *user;
    NQ_UINT16 level;
/*    const NQ_BYTE *password; */
/*    NQ_UINT16 size;    */
/*    NQ_BYTE expired;    */
    NQ_BYTE *params;
    NQ_UINT32 status;
}
ParamsSamrUserSetInfo2;

static void
composeLevel(
    CMBufferWriter *w,
    ParamsSamrUserSetInfo2 *p
    )
{
    cmBufferWriteUint16(w, p->level);                              /* info level */

    switch (p->level)
    {
        case 16:
        {
            ParamsSamrUserSetInfo2Level16 *params = (ParamsSamrUserSetInfo2Level16 *)p->params;

            cmBufferWriteUint32(w, params->flags);                  /* flags */
            break;
        }
        case 24:
        {
            ParamsSamrUserSetInfo2Level24 *params = (ParamsSamrUserSetInfo2Level24 *)p->params;

            cmBufferWriteBytes(w, params->password, params->size);  /* encrypted password */
            cmBufferWriteByte(w, 24/*params->expired*/);            /* expired flag */
            /* todo: docs say it has to be expiration flag, samba says it's just 24 (as in level)... */
            break;
        }
        default:
            break;
    }
}

static NQ_COUNT composeSetUserInfo2 (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;
    ParamsSamrUserSetInfo2 *p = (ParamsSamrUserSetInfo2 *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    cmBufferWriterInit(&w, buffer, size);
    cmBufferWriteUint16(&w, SETUSERINFO2_OPNUM);   /* SetUserInfo2 opnum */
    /* user policy handle */
    cmBufferWriteUint32(&w, p->user->id);          /* id */
    cmRpcUuidWrite(&w, &p->user->uuid);            /* uuid */
    cmBufferWriteUint16(&w, p->level);             /* info level */

    /* write data according to info level */
    composeLevel(&w, p);

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return cmBufferWriterGetDataCount(&w);
}


static NQ_COUNT composeGetUserInfo2 (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;
    ParamsSamrUserSetInfo2 *p = (ParamsSamrUserSetInfo2 *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    cmBufferWriterInit(&w, buffer, size);
    cmBufferWriteUint16(&w, GETUSERINFO2_OPNUM);   /* GetUserInfo2 opnum */
    /* user policy handle */
    cmBufferWriteUint32(&w, p->user->id);          /* id */
    cmRpcUuidWrite(&w, &p->user->uuid);            /* uuid */
    cmBufferWriteUint16(&w, p->level);             /* info level */

    /* write data according to info level */
    /*composeLevel(&w, p);*/

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS processGetUserInfo2 (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsSamrUserSetInfo2 *p = (ParamsSamrUserSetInfo2 *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    cmBufferReaderInit(&r, data, size);
    cmBufferReadUint32(&r, &p->status);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", p->status);
    return (NQ_STATUS)p->status;
}

static NQ_STATUS processSetUserInfo2 (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsSamrUserSetInfo2 *p = (ParamsSamrUserSetInfo2 *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    cmBufferReaderInit(&r, data, size);
    cmBufferReadUint32(&r, &p->status);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", p->status);
    return (NQ_STATUS)p->status;
}

NQ_UINT32
ccSamrGetUserInfo2(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user,
    NQ_UINT16 level,
    NQ_BYTE *params
    )
{
    ParamsSamrUserSetInfo2 p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p user:%p level:%u parame:%p", samr, user, level, params);

    p.user = user;
    p.level = level;
    p.params = params;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "level = %d", p.level);

    /* call SAMR::GetUserInfo2 */
    if (!ccDcerpcCall(samr, composeGetUserInfo2, processGetUserInfo2, &p))
    {
        p.status = (NQ_UINT32)NQ_ERR_BADPARAM;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::GetUserInfo2");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

NQ_UINT32
ccSamrSetUserInfo2(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user,
    NQ_UINT16 level,
    NQ_BYTE *params
    )
{
    ParamsSamrUserSetInfo2 p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p user:%p level:%u params:%p", samr, user, level, params);

    p.user = user;
    p.level = level;
    p.params = params;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "level = %d", p.level);

    /* call SAMR::SetUserInfo2 */
    if (!ccDcerpcCall(samr, composeSetUserInfo2, processSetUserInfo2, &p))
    {
        p.status = (NQ_UINT32)NQ_ERR_BADPARAM;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::SetUserInfo2");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

NQ_UINT32
ccSamrSetUserPassword(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user,
    const NQ_BYTE *password,
    NQ_UINT16 length
    )
{
    NQ_UINT32 status;
    NQ_BYTE buffer[516]; /* 512 bytes of RC4 encrypted password + 4 bytes length */
    NQ_UINT16 size = (NQ_UINT16)(length * 2),
              offset = (NQ_UINT16)(sizeof(buffer) - size - 4);
    CCUser * pUser = ((CCFile *)samr)->share->user;
    ParamsSamrUserSetInfo2Level24 params;
    CMBufferWriter w;
#ifdef UD_NQ_INCLUDESMB3
    CCServer    * pServer = ((CCFile *)samr)->share->user->server;
#endif /* UD_NQ_INCLUDESMB3 */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p user:%p pass:xxx len:%u", samr, user, length);

    cmBufferWriterInit(&w, buffer, sizeof(buffer));

    /* fill unused buffer space with random values */
    cmBufferWriteRandomBytes(&w, offset);
    /* plain text unicode password is aligned to the right followed by its size */
    cmBufferWriteAsciiAsUnicodeN(&w, (const NQ_CHAR *)password, length, CM_BSF_NOFLAGS);
    cmBufferWriteUint32(&w, size);
    /* encrypt the entire password buffer */
#ifdef UD_NQ_INCLUDESMB3
    if (pServer->smb->revision != CCCIFS_ILLEGALSMBREVISION && pServer->smb->revision >= 0x0300 /* SMB3 Dialect Revision */)
    {
        cmArcfourCrypt(buffer, sizeof(buffer), pUser->applicationKey.data, pUser->applicationKey.len);
    }
    else
#endif /* UD_NQ_INCLUDESMB3 */
    {
        cmArcfourCrypt(buffer, sizeof(buffer), pUser->macSessionKey.data, pUser->macSessionKey.len);
    }
    /* call SAMR::SetUserInfo2 with level 24 */
    params.password = buffer;
    params.size = sizeof(buffer);
    status = ccSamrSetUserInfo2(samr, user, 24, (NQ_BYTE *)&params);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", status);
    return status;
}

typedef struct {
    const NQ_UINT32 *rid;
    CMRpcPolicyHandle *user;
    NQ_UINT32 status;
}
ParamsSamrOpenUser;

/* SAMR::OpenUser */

NQ_UINT32
ccSamrOpenUser(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *domain,
    const NQ_UINT32 *rid,
    NQ_UINT32 access,
    CMRpcPolicyHandle *user
    )
{
    CallbackParams p;
    CMSdAccessToken token;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p domain:%p rid:%p access:0x%x user:%p", samr, domain, rid, access, user);

    p.domainId = domain->id;
    p.domainUuid = domain->uuid;
    p.access = access;
    p.token = &token;
    p.token->rids[0] = *rid;

    /* call SAMR::OpenUser */
    if (ccDcerpcCall(samr, openUserRequestCallback, openUserResponseCallback, &p))
    {
        user->id = p.userId;
        user->uuid = p.userUuid;
    }
    else
    {
        p.status = (NQ_UINT32)NQ_ERR_BADPARAM;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::OpenUser");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

typedef struct {
    const CMRpcPolicyHandle *domain;
    const NQ_WCHAR *name;
    NQ_UINT32 rid;
    NQ_UINT32 type;
    NQ_UINT32 status;
}
ParamsSamrLookupNames;

static NQ_COUNT composeLookupNames (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;
    ParamsSamrLookupNames *p = (ParamsSamrLookupNames *)params;
    NQ_UINT32 refId = 1;
    NQ_UINT16 length = (NQ_UINT16)cmWStrlen(p->name);
    NQ_UINT16 sz = (NQ_UINT16)(length * sizeof(NQ_WCHAR));

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    cmBufferWriterInit(&w, buffer, size);
    cmBufferWriteUint16(&w, LOOKUPNAMES_OPNUM);  /* LookupNames opnum */
    /* domain policy handle */
    cmBufferWriteUint32(&w, p->domain->id);      /* id */
    cmRpcUuidWrite(&w, &p->domain->uuid);        /* uuid */
    cmBufferWriteUint32(&w, 1);                  /* number of names */
    cmBufferWriteUint32(&w, 1000);               /* max count */
    cmBufferWriteUint32(&w, 0);                  /* offset */
    cmBufferWriteUint32(&w, 1);                  /* actual count */
    /* account name */
    cmBufferWriteUint16(&w, sz);                 /* length in bytes */
    cmBufferWriteUint16(&w, sz);                 /* size in bytes */
    cmBufferWriteUint32(&w, refId);              /* ref ID */
    cmBufferWriteUint32(&w, length);             /* max count in symbols */
    cmBufferWriteUint32(&w, 0);                  /* offset */
    cmBufferWriteUint32(&w, length);             /* actual count in symbols */
    cmBufferWriteUnicodeNoNull(&w, p->name);

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS processLookupNames (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsSamrLookupNames *p = (ParamsSamrLookupNames *)params;
    NQ_UINT32 count;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    cmBufferReaderInit(&r, data, size);
    cmBufferReadUint32(&r, &count);
    if (count == 0)
    {
        cmBufferReaderSkip(&r, 4);
    }
    else
    {
        cmBufferReaderSkip(&r, 2 * 4);
        cmBufferReadUint32(&r, &p->rid);    /* user rid */
    }
    cmBufferReadUint32(&r, &count);
    if (count == 0)
    {
        cmBufferReaderSkip(&r, 4);
    }
    else
    {
        cmBufferReaderSkip(&r, 2 * 4);
        cmBufferReadUint32(&r, &p->type);   /* user type */
    }
    cmBufferReadUint32(&r, &p->status);     /* status */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", p->status);
    return (NQ_STATUS)p->status;
}

/* SAMR::LookupNames */

NQ_UINT32
ccSamrLookupNames(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *domain,
    const NQ_WCHAR *name,
    NQ_UINT32 *rid,
    NQ_UINT32 *type
    )
{
    ParamsSamrLookupNames p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p domain:%p name:%s rid:%p type:%p", samr, domain, name ? "TRUE" : "FALSE", rid, type);

    /* pass parameters */
    p.domain = domain;
    p.name = name;

    /* call SAMR::LookupNames */
    if (ccDcerpcCall(samr, composeLookupNames, processLookupNames, &p))
    {
        *rid = p.rid;
        *type = p.type;
    }
    else
    {
        p.status = (NQ_UINT32)NQ_ERR_BADPARAM;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::LookupNames");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

/* SAMR::Close */

NQ_UINT32
ccSamrClose(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *policy
    )
{
    CallbackParams p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p policy:%p", samr, policy);

    p.id = policy->id;
    p.uuid = &policy->uuid;

    if (!ccDcerpcCall(samr, closeRequestCallback, closeResponseCallback, &p))
    {
        p.status = (NQ_UINT32)NQ_ERR_ERROR;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::Close");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;
}

typedef struct {
    const CMRpcPolicyHandle *user;
    NQ_UINT32 status;
}
ParamsSamrDeleteUser;

static NQ_COUNT composeDeleteUser(
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;
    ParamsSamrDeleteUser *p = (ParamsSamrDeleteUser *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    cmBufferWriterInit(&w, buffer, size);
    cmBufferWriteUint16(&w, DELETEUSER_OPNUM);   /* DeleteUser opnum */
    /* user policy handle */
    cmBufferWriteUint32(&w, p->user->id);        /* id */
    cmRpcUuidWrite(&w, &p->user->uuid);          /* uuid */

    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS processDeleteUser(
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsSamrDeleteUser *p = (ParamsSamrDeleteUser *)params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" :"FALSE");

    cmBufferReaderInit(&r, data, size);
    cmBufferReaderSkip(&r, sizeof(CMRpcUuid));    /* skip uuid */
    cmBufferReadUint32(&r, &p->status);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", p->status);
    return (NQ_STATUS)p->status;
}

/* SAMR::DeleteUser */

NQ_UINT32 ccSamrDeleteUser(
    NQ_HANDLE samr,
    const CMRpcPolicyHandle *user
    )
{
    ParamsSamrDeleteUser p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "samr:%p user:%p", samr, user);

    /* pass parameters */
    p.user = user;

    /* call SAMR::DeleteUser */
    if (!ccDcerpcCall(samr, composeDeleteUser, processDeleteUser, &p))
    {
        p.status = (NQ_UINT32)NQ_ERR_ERROR;
        LOGERR(CM_TRC_LEVEL_ERROR, "SAMR::DeleteUser");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%u", p.status);
    return p.status;

}

/*
 *====================================================================
 * PURPOSE: get user's groups by account name
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe handle
 *          IN user name
 *          IN domain name
 *          OUT buffer for token
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES: synchronized version
 *====================================================================
 */

NQ_STATUS
ccSamGetUserGroups(
    NQ_HANDLE pipeHandle,
    const NQ_WCHAR* name,
    const NQ_WCHAR* domain,
    CMSdAccessToken* token
    )
{
    CallbackParams params;      /* parameters for OpenPolciy2/Close */
    NQ_BOOL res;                /* operation result */
    NQ_STATUS result = NQ_FAIL; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "pipe:%p name:%s domain:%s token:%p", pipeHandle, cmWDump(name), cmWDump(domain), token);

    /* pass parameters */
    params.user = name;
    params.domain = domain;
    params.token = token;
    params.host = ((CCFile *)pipeHandle)->share->user->server->item.name;
    params.access = CONNECT_ACCESSMASK;

    /* open SAMR policy handle */
    res = ccDcerpcCall(pipeHandle, connectRequestCallback, connectResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Connect2");
        goto Exit;
    }

    params.access = 0x20285;
    /* open domain's policy handle */
    res = ccDcerpcCall(pipeHandle, openDomainRequestCallback, openDomainResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing OpenDomain");
        goto Exit;
    }

    params.access = 0x00000100;  /* get groups */

    /* open user's policy handle */
    res = ccDcerpcCall(pipeHandle, openUserRequestCallback, openUserResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing OpenUser");
        goto Exit;
    }

    /* get groups */
    res = ccDcerpcCall(pipeHandle, getGroupsForUserRequestCallback, getGroupsForUserResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing GetGroupsForUser");
        goto Exit; 
    }

    /* close user policy handle */
    params.id = params.userId;
    params.uuid = &params.userUuid;
    res = ccDcerpcCall(pipeHandle, closeRequestCallback, closeResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Close for user");
        goto Exit;
    }

    /* close domain policy handle */
    params.id = params.domainId;
    params.uuid = &params.domainUuid;
    res = ccDcerpcCall(pipeHandle, closeRequestCallback, closeResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Close for SAMR");
        goto Exit;
    }

    /* close pipe policy handle */
    params.id = params.pipeId;
    params.uuid = &params.pipeUuid;
    res = ccDcerpcCall(pipeHandle, closeRequestCallback, closeResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Close for SAMR");
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: get domain SID
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe handle
 *          IN domain name
 *          OUT buffer for SID
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES: synchronized version
 *====================================================================
 */

NQ_STATUS
ccSamGetDomainSid(
    NQ_HANDLE pipeHandle,
    const NQ_WCHAR * domain,
    CMSdDomainSid* sid
    )
{
    CallbackParams params;      /* parameters for OpenPolciy2/Close */
    NQ_BOOL res;                /* operation result */
    NQ_STATUS result = NQ_FAIL; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "pipe:%p domain:%s sid:%p", pipeHandle, cmWDump(domain), sid);

    /* pass parameters */
    params.domain = domain;
    params.sid = sid;
    params.host = ((CCFile *)pipeHandle)->share->user->server->item.name;
    params.access = CONNECT_ACCESSMASK;

    /* open SAMR policy handle */
    res = ccDcerpcCall(pipeHandle, connectRequestCallback, connectResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Connect2");
        goto Exit;
    }

    /* resolve domain */
    res = ccDcerpcCall(pipeHandle, lookupDomainRequestCallback, lookupDomainResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing LookupDomain");
        goto Exit;
    }

    /* close pipe policy handle */
    params.id = params.pipeId;
    params.uuid = &params.pipeUuid;
    res = ccDcerpcCall(pipeHandle, closeRequestCallback, closeResponseCallback, &params);
    if (!res)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in processing Close for SAMR");
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", result);
    return result;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT
connectRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    NQ_UINT32 refId;                    /* running referent ID */
    CallbackParams* callParams;         /* casted parameters for callback */
    static NQ_WCHAR unicodeHostName[CM_NQ_HOSTNAMESIZE + 3] =
    {
         cmWChar('\\'),  cmWChar('\\')
    };                  /* host name in Unicode, including two backslashes */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    refId = 1;
    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, CONNECT_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, refId);  /* object attributes */
    refId++;
    cmWStrcpy(unicodeHostName + 2, callParams->host);
    cmRpcPackUnicode(&desc, unicodeHostName, (CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
    cmRpcAllign(&desc, 4);
    cmRpcPackUint32(&desc, 0x20031);     /* access mask */
    cmRpcPackUint32(&desc, 1);      /* undocumented */
    cmRpcPackUint32(&desc, 1);      /* undocumented */
    cmRpcPackUint32(&desc, 3);      /* undocumented */
    cmRpcPackUint32(&desc, 0);      /* undocumented */
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (desc.current - desc.origin) + 2);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

static NQ_STATUS
connectResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;
    CallbackParams* callParams = (CallbackParams*)params;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    if (size < (sizeof(CMRpcUuid) + 4 + 4 * 4))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "response too short");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  size: %d", size);
        goto Exit;
    }

    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);
    cmRpcParseSkip(&desc, 4 * 4);   /* undocumented */
    cmRpcParseUint32(&desc, &callParams->pipeId);   /* policy ID */
    cmRpcParseUuid(&desc, &callParams->pipeUuid);   /* policy uuid */
    cmRpcParseUint32(&desc, &callParams->status);   /* status */
    result = (NQ_STATUS)callParams->status;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT
openDomainRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, OPENDOMAIN_OPNUM);
    desc.origin = desc.current;                 /* for alignment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->pipeId); /* id of policy handle */
    cmRpcPackUuid(&desc, &callParams->pipeUuid);/* uuid of policy handle */
    cmRpcPackUint32(&desc, callParams->access); /* access mask */
    cmRpcPackUint32(&desc, callParams->token->domain.numAuths); /* id of policy handle */
    cmSdPackSid(&desc, &callParams->token->domain);
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (desc.current - desc.origin) + 2);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

static NQ_STATUS
openDomainResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams = (CallbackParams*)params;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    if (size < (sizeof(CMRpcUuid) + 4 + 4))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "response too short");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  size: %d", size);
        goto Exit;
    }

    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);
    cmRpcParseUint32(&desc, &callParams->domainId);   /* policy ID */
    cmRpcParseUuid(&desc, &callParams->domainUuid);   /* policy uuid */
    cmRpcParseUint32(&desc, &callParams->status);     /* status */
    result = (NQ_STATUS)callParams->status;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}


/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT
lookupDomainRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_UINT32 refId;                    /* running referent ID */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    refId = 1;
    cmRpcPackUint16(&desc, LOOKUPDOMAIN_OPNUM);
    desc.origin = desc.current;                 /* for alignment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->pipeId); /* id of policy handle */
    cmRpcPackUuid(&desc, &callParams->pipeUuid);/* uuid of policy handle */
    cmRpcPackUint16(&desc, (NQ_UINT16)(cmWStrlen(callParams->domain) * sizeof(NQ_WCHAR)));  /* length */
    cmRpcPackUint16(&desc, (NQ_UINT16)(cmWStrlen(callParams->domain) * sizeof(NQ_WCHAR)));  /* maxlen */
    cmRpcPackUint32(&desc, refId);              /* ref id */
    refId++;
    cmRpcPackUnicode(&desc, callParams->domain, (CM_RP_SIZE32 | CM_RP_FRAGMENT32));
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (desc.current - desc.origin) + 2);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

static NQ_STATUS
lookupDomainResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_UINT32 value;                    /* parsed long value */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    if (size < (sizeof(CMRpcUuid) + 4 + 4))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "response too short");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  size: %d", size);
        goto Exit;
    }
    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);
    cmRpcParseSkip(&desc, 4);           /* sid - refId */
    cmRpcParseSkip(&desc, 4);           /* sid - count */
    cmSdParseSid(&desc, callParams->sid);               /* sid - value */
    cmRpcParseUint32(&desc, &value);                    /* status */
    if (0 != value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected status in response");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  status: %ld", value);
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}


/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT
openUserRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, OPENUSER_OPNUM);
    desc.origin = desc.current;                     /* for alignment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->domainId);   /* id of policy handle */
    cmRpcPackUuid(&desc, &callParams->domainUuid);  /* uuid of policy handle */
    cmRpcPackUint32(&desc, callParams->access);     /* access mask */
    cmRpcPackUint32(&desc, callParams->token->rids[0]); /* rid */
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (desc.current - desc.origin) + 2);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   Parses share names
 *====================================================================
 */

static NQ_STATUS
openUserResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_STATUS result = NQ_FAIL;         /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    if (size < (sizeof(CMRpcUuid) + 4 + 4))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "response too short");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  size: %d", size);
        goto Exit;
    }
    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);
    cmRpcParseUint32(&desc, &callParams->userId);   /* policy ID */
    cmRpcParseUuid(&desc, &callParams->userUuid);   /* policy uuid */
    cmRpcParseUint32(&desc, &callParams->status);   /* status */
    if (0 != callParams->status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected status in response");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  status: %ld", callParams->status);
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT
closeRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, CLOSE_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->id);     /* policy ID */
    cmRpcPackUuid(&desc, callParams->uuid);     /* policy UUID */
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (desc.current - desc.origin) + 2);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
closeResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CallbackParams* p;         /* casted parameters for callback */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    p = (CallbackParams*)params;
    p->status = NQ_SUCCESS;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", p->status);
    return (NQ_STATUS)p->status;
}

/*====================================================================
 * PURPOSE: DCERPC request callback function
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for outgoing data
 *          IN buffer size
 *          IN/OUT params
 *          OUT set here TRUE when more data remains
 *
 * RETURNS: number of bytes placed into the buffer or
 *          zero on buffer overflow
 *
 * NOTES:   Composes request
 *====================================================================
 */

static NQ_COUNT
getGroupsForUserRequestCallback (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buff:%p size:%d params:%p more:%p", buffer, size, params, moreData);

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, buffer, FALSE);
    cmRpcPackUint16(&desc, GETGROUPS_OPNUM);
    desc.origin = desc.current;     /* for alligment to 4 bytes */
    cmRpcPackUint32(&desc, callParams->userId);     /* policy ID */
    cmRpcPackUuid(&desc, &callParams->userUuid);    /* policy UUID */
    *moreData = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (desc.current - desc.origin) + 2);
    return (NQ_COUNT)((desc.current - desc.origin) + 2);
}


/*====================================================================
 * PURPOSE: DCERPC response callback function
 *--------------------------------------------------------------------
 * PARAMS:  IN data portion
 *          IN data length in the portion
 *          IN/OUT params
 *          IN TRUE when more data to come
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   This function sets group RIDs from index 1, assuming
 *          that index 0 is reserved for user RID
 *====================================================================
 */

static NQ_STATUS
getGroupsForUserResponseCallback (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMRpcPacketDescriptor desc;         /* descriptor for SRVSVC request */
    CallbackParams* callParams;         /* casted parameters for callback */
    NQ_UINT32 cnt;                      /* parsed long value */
    NQ_COUNT idx;                       /* group index */
    NQ_STATUS result = NQ_FAIL;         /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "data:%p size:%d params:%p more:%s", data, size, params, moreData ? "TRUE" : "FALSE");

    callParams = (CallbackParams*)params;
    cmRpcSetDescriptor(&desc, (NQ_BYTE*)data, FALSE);

    cmRpcParseSkip(&desc, 4);   /* array - ref id */
    cmRpcParseUint32(&desc, &cnt);              /* array - count */
    cmRpcParseSkip(&desc, 4);   /* array - ref id */
    cmRpcParseUint32(&desc, &cnt);              /* array - count */
    if (cnt > UD_CM_MAXUSERGROUPS)
    {
        cnt = UD_CM_MAXUSERGROUPS;
    }
    callParams->token->numRids = (NQ_UINT16)(cnt + 1);
    for (idx = 1; idx <= cnt; idx++)
    {
        cmRpcParseUint32(&desc, &callParams->token->rids[idx]);   /* RID */
        cmRpcParseSkip(&desc, 4);       /* RID ATTRIB */
    }

    cmRpcParseUint32(&desc, &cnt);   /* status */
    if (0 != cnt)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "unexpected status in response");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  status: %ld", cnt);
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

#endif /* defined(UD_CC_INCLUDESECURITYDESCRIPTORS) || defined(UD_CC_INCLUDEDOMAINMEMBERSHIP) || defined(UD_CS_INCLUDEPASSTHROUGH) */
