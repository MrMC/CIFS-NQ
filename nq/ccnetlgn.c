/*********************************************************************
 *
 *           Copyright (c) 2010 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : NETLOGON RPC client
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 22-Dec-2010
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ccnetlgn.h"
#include "ccconfig.h"
#include "cmbuf.h"
#include "ccerrors.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT


#define NETRSERVERREQUESTCHALLENGE_NETLOGON_OPNUM    4
#define NETRSERVERAUTHENTICATE2_NETLOGON_OPNUM      15
#define DSRENUMERATEDOMAINTRUSTS_NETLOGON_OPNUM     40


#define NETLOGON_AUTH2_FLAGS                0x600fffff  
#define NETLOGON_TRUST_FLAGS                0x0000003f                                          


typedef struct
{
    const NQ_WCHAR * server;
    const NQ_WCHAR * computer;
    CCNetlogonCredential *credential;
    NQ_UINT32 status;
}
ParamsNetrServerReqChallenge;

typedef struct
{
    const NQ_WCHAR * server;
    const NQ_WCHAR * computer;
    CCNetlogonCredential *credential;
    NQ_UINT32 flags;
    NQ_UINT32 status;
}
ParamsNetrServerAuthenticate2;

typedef struct
{
    const NQ_WCHAR * server;            /* server name */ 
    CCNetrEnumerateNamesCallback callback;  /* add name callback */
    void * list;                        /* list to add name to */
    NQ_UINT32 status;                   /* operation status */
}
ParamsDsrEnumerateDomainTrusts;

/* NETLOGON pipe descriptor */
static const NQ_WCHAR pipeName[] = { cmWChar('n'), cmWChar('e'), cmWChar('t'), cmWChar('l'), cmWChar('o'), cmWChar('g'), cmWChar('o'), cmWChar('n'), cmWChar(0) };
static const CCDcerpcPipeDescriptor _nlpd = {
    pipeName,
    {cmPack32(0x12345678),cmPack16(0x1234),cmPack16(0xabcd),{0xef,0x00},{0x01,0x23,0x45,0x67,0xcf,0xfb}},
    cmRpcVersion(1, 0)
};

const CCDcerpcPipeDescriptor * ccNetlogonGetPipe(void)
{
    return &_nlpd; 
}


static NQ_COUNT composeNetrServerReqChallenge (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;               /* for composing request */
    ParamsNetrServerReqChallenge *p = (ParamsNetrServerReqChallenge *)params;
    NQ_UINT32 ref = 0;              /* ref id */
    NQ_UINT32 sz;                   /* string size */

    TRCB();

    cmBufferWriterInit(&w, buffer, size);

    cmBufferWriteUint16(&w, NETRSERVERREQUESTCHALLENGE_NETLOGON_OPNUM);

    /* server name prefixed by double back slash */
    sz = 3 + (NQ_UINT32)cmWStrlen(p->server);

    cmBufferWriteUint32(&w, ++ref);                /* ref ID */
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteAsciiAsUnicodeN(&w, "\\\\", 2, CM_BSF_NOFLAGS);
    cmBufferWriteUnicode(&w, p->server);
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */
 
    /* computer name (no trailing '$') */
    sz = 1 + (NQ_UINT32)cmWStrlen(p->computer);

    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteUnicode(&w, p->computer);

    /* client credential */
    cmBufferWriteBytes(&w, p->credential->client, sizeof(p->credential->client));

    *moreData = FALSE;

    TRCE();
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS processNetrServerReqChallenge (
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsNetrServerReqChallenge *p = (ParamsNetrServerReqChallenge *)params;

    TRCB();

    cmBufferReaderInit(&r, data, size);
    cmBufferReadBytes(&r, p->credential->server, sizeof(p->credential->server));
    cmBufferReadUint32(&r, &p->status);

    TRCE();
    return (NQ_STATUS)p->status;
}

NQ_UINT32
ccNetrServerReqChallenge(NQ_HANDLE netlogon, const NQ_WCHAR *server, const NQ_WCHAR *computer, CCNetlogonCredential *credential)
{
    ParamsNetrServerReqChallenge p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    p.server = server;
    p.computer = computer;
    p.credential = credential;
    p.status = 0;

    /* call NETLOGON::NetrServerReqChallenge */
    if (!ccDcerpcCall(netlogon, composeNetrServerReqChallenge, processNetrServerReqChallenge, &p))
    {
        p.status = (p.status == 0) ? (NQ_UINT32)syGetLastError() : (NQ_UINT32)ccErrorsStatusToNq(p.status, TRUE);
        TRCERR("NETLOGON::NetrServerReqChallenge");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return p.status;
}

static NQ_COUNT
composeNetrServerAuthenticate2 (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;       /* for composing request */
    ParamsNetrServerAuthenticate2 *p = (ParamsNetrServerAuthenticate2 *)params;
    NQ_UINT32 ref = 0;      /* ref if */
    NQ_UINT32 sz;           /* string size */

    TRCB();

    cmBufferWriterInit(&w, buffer, size);

    cmBufferWriteUint16(&w, NETRSERVERAUTHENTICATE2_NETLOGON_OPNUM);

    /* server name prefixed by double back slash */
    sz = 3 + (NQ_UINT32)cmWStrlen(p->server);

    cmBufferWriteUint32(&w, ++ref);                /* ref ID */
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteAsciiAsUnicodeN(&w, "\\\\", 2, CM_BSF_NOFLAGS);
    cmBufferWriteUnicode(&w, p->server);
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */

    /* user name = computer name (with trailing '$')*/
    sz = 2 + (NQ_UINT32)cmWStrlen(p->computer);

    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteUnicodeNoNull(&w, p->computer);
    cmBufferWriteAsciiAsUnicodeN(&w, "$", 1, CM_BSF_WRITENULLTERM);
    cmBufferWriteUint16(&w, 2);                    /* type: workstation */
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */

    /* computer name (no trailing '$') */
    sz = 1 + (NQ_UINT32)cmWStrlen(p->computer);
 
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteUnicode(&w, p->computer);

    /* client credential */
    cmBufferWriteBytes(&w, p->credential->client, sizeof(p->credential->client));
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */

    /* negotiation flags */
    cmBufferWriteUint32(&w, NETLOGON_AUTH2_FLAGS); 

    *moreData = FALSE;

    TRCE();
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS
processNetrServerAuthenticate2(
    const NQ_BYTE* data,
    NQ_COUNT size,
    void* params,
    NQ_BOOL moreData
    )
{
    CMBufferReader r;
    ParamsNetrServerAuthenticate2 *p = (ParamsNetrServerAuthenticate2 *)params;

    TRCB();

    cmBufferReaderInit(&r, data, size);
    cmBufferReadBytes(&r, p->credential->server, sizeof(p->credential->server));
    cmBufferReadUint32(&r, &p->flags);
    cmBufferReadUint32(&r, &p->status);

    TRCE();
    return (NQ_STATUS)p->status;
}

NQ_UINT32
ccNetrServerAuthenticate2(
    NQ_HANDLE netlogon,
    const NQ_WCHAR *server,
    const NQ_WCHAR *computer,
    CCNetlogonCredential *credential,
    NQ_UINT32 * flags
   )
{
    ParamsNetrServerAuthenticate2 p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    p.server = server;
    p.computer = computer;
    p.credential = credential;
    p.status = 0;
    
    /* call NETLOGON::NetrServerAuthenticate2 */
    if (ccDcerpcCall(netlogon, composeNetrServerAuthenticate2, processNetrServerAuthenticate2, &p))
    {
        /* cred. and flags? */
        if (NULL != flags)
            *flags = p.flags;
    }
    else
    {
        p.status = (p.status == 0) ? (NQ_UINT32)syGetLastError() : (NQ_UINT32)ccErrorsStatusToNq(p.status, TRUE);
        TRCERR("NETLOGON::NetrServerAuthenticate2");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return p.status;
}

static NQ_COUNT
composeDsrEnumerateDomainTrusts (
    NQ_BYTE* buffer,
    NQ_COUNT size,
    void* params,
    NQ_BOOL* moreData
    )
{
    CMBufferWriter w;   /* for coposing request */ 
    ParamsDsrEnumerateDomainTrusts  *p = (ParamsDsrEnumerateDomainTrusts  *)params;
    NQ_UINT32 ref = 0;  /* ref id */
    NQ_UINT32 sz;       /* string size */

    TRCB();

    cmBufferWriterInit(&w, buffer, size);

    cmBufferWriteUint16(&w, DSRENUMERATEDOMAINTRUSTS_NETLOGON_OPNUM);

    /* server name */
    sz = 1 + (NQ_UINT32)cmWStrlen(p->server);
    cmBufferWriteUint32(&w, ++ref);                /* ref ID */
    cmBufferWriteUint32(&w, sz);                   /* max count */
    cmBufferWriteUint32(&w, 0);                    /* offset */
    cmBufferWriteUint32(&w, sz);                   /* actual count */
    cmBufferWriteUnicode(&w, p->server);
    cmBufferWriterAlign(&w, buffer + 2, 4);        /* 4 byte alignment */

    /* trust flags */
    cmBufferWriteUint32(&w, NETLOGON_TRUST_FLAGS); 

    *moreData = FALSE;

    TRCE();
    return cmBufferWriterGetDataCount(&w);
}

static NQ_STATUS
processDsrEnumerateDomainTrusts(
    const NQ_BYTE * data,
    NQ_COUNT size,
    void * params,
    NQ_BOOL moreData
    )
{
    CMBufferReader structs;             /* parser for structures */
    CMBufferReader strings;             /* parser for strings */
    ParamsDsrEnumerateDomainTrusts * p = (ParamsDsrEnumerateDomainTrusts *)params;
    NQ_UINT32 count = 0;                /* number of answers */                
    NQ_INT i;                           /* just a counter */

    TRCB();

    cmBufferReaderInit(&strings, data, size);
    cmBufferReaderInit(&structs, data, size);
    cmBufferReadUint32(&structs, &count);
    cmBufferReaderSkip(&structs, 2 * 4);

    TRC("Count: %d", count);

    if (count == 0)
    {
        cmBufferReadUint32(&structs, &p->status);

        TRCE();
        return (NQ_STATUS)p->status;
    }

    for (i = 0; i < (NQ_INT)count; i++)
    {
        NQ_UINT32 maxCount;                 /* name length */
        NQ_UINT32 refIdNetBIOS;             /* refId */
        NQ_UINT32 refIdDNS;                 /* refId */
        NQ_UINT32 refIdSID;                 /* refId */

    	cmBufferReadUint32(&structs, &refIdNetBIOS);
    	cmBufferReadUint32(&structs, &refIdDNS);
    	cmBufferReaderSkip(&structs,(NQ_UINT)(4 * 4)); 	/* 4 fields in structure */
    	cmBufferReadUint32(&structs, &refIdSID);
    	cmBufferReaderSkip(&structs, 16); 				/* GUID */

    	cmBufferReaderSetPosition(&strings, cmBufferReaderGetPosition(&structs));
    	cmBufferReaderSkip(&strings, ((count - (NQ_UINT32)i - 1) * (NQ_UINT)(7 * 4 + 16))); /* skip other structures */

    	/* write NetBIOS domain names to output buffer */
    	if (0 != refIdNetBIOS)
    	{
            cmBufferReadUint32(&strings, &maxCount);                                  /* read NetBIOS domain name length */
            cmBufferReaderSkip(&strings, 4 * 2);                                      /* skip offset and actual count */
            (*p->callback)((NQ_WCHAR *)cmBufferReaderGetPosition(&strings), p->list);
            cmBufferReaderSkip(&strings,(NQ_UINT)( maxCount * sizeof(NQ_WCHAR)));     /* skip name */
            cmBufferReaderAlign(&strings, (NQ_BYTE *)data , 4);                       /* 4 byte alignment */
    	}
    	if (0 != refIdDNS)
    	{
			cmBufferReadUint32(&strings, &maxCount);                                  /* read DNS domain name length */
			cmBufferReaderSkip(&strings,(NQ_UINT)( 4 * 2 + maxCount * sizeof(NQ_WCHAR)));        /* skip DNS domain name */
			cmBufferReaderAlign(&strings, (NQ_BYTE *)data , 4);                       /* 4 byte alignment */
    	}
    	if (0 != refIdSID)
    	{
    		cmBufferReaderSkip(&strings, 4 + 24);                                     /* skip SID */
    	}
    }

    cmBufferReadUint32(&strings, &p->status);

    TRCE();
    return (NQ_STATUS)p->status;
}


/* returns list of domain names, up to buffer space supplied */
NQ_UINT32
ccDsrEnumerateDomainTrusts(
    NQ_HANDLE netlogon,
    const NQ_WCHAR * server, 
    CCNetrEnumerateNamesCallback callback,
    CMList * list
    )
{
    ParamsDsrEnumerateDomainTrusts p;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    p.server = server;
    p.callback = callback;
    p.list = list;
    p.status = 0;
    
    /* call NETLOGON::DsrEnumerateDomainTrusts */
    if (ccDcerpcCall(netlogon, composeDsrEnumerateDomainTrusts, processDsrEnumerateDomainTrusts, &p))
    {
        
    }
    else
    {
        p.status = (p.status == 0) ? (NQ_UINT32)syGetLastError() : (NQ_UINT32)ccErrorsStatusToNq(p.status, TRUE);
        TRCERR("NETLOGON::DsrEnumerateDomainTrusts");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return p.status;
}


#endif /* UD_NQ_INCLUDECIFSCLIENT */


