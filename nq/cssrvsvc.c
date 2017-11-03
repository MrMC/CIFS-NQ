/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SRVSVC pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cssrvsvc.h"

#include "nqapi.h"
#include "csdataba.h"
#include "csutils.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

#ifdef UD_CS_INCLUDERPC_SRVSVC

#ifndef UD_CS_INCLUDERPC
#error illegal combination of parametsrs UD_CS_INCLUDERPC_SRVSVC (defined) and UD_CS_INCLUDERPC (not defined)
#endif

/*
    Static data and definitions
    ---------------------------
 */

/* packet sizes */

#define NETSRVGETINFO_SIZE          200
#define NETSHAREENUMALL_HDRSIZE     24
#define NETSHAREINFO_HDRSIZE        8
#define NETSHAREENUMALL_ENTRYSIZE   40
#define NETUSERENUMALL_HDRSIZE      24
#define NETUSERENUMALL_ENTRYSIZE    40
#define NETFILEENUMALL_HDRSIZE      24
#define NETFILEENUMALL_ENTRYSIZE    50
#define NETCONNENUMALL_HDRSIZE      24
#define NETCONNENUMALL_ENTRYSIZE    50

#define TEMPSHARENAME "__temp__"

typedef struct
{
    NQ_WCHAR shareNameW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXSHARELEN)];   /* share name*/
    NQ_WCHAR shareMapW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXPATHLEN)];     /* share path */
    NQ_WCHAR shareDescriptionW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXDESCRIPTIONLEN)];   /* share description */
    NQ_WCHAR tempW[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_MAXPATHLEN)];         /* temporary */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

static NQ_STATUS    /* initialialization of the open entry table */
initData(
    void
    );

static void            /* release open entry table */
stopData(
    void
    );

/* pipe function prototypes */

/* static NQ_UINT32 srvsvcNetCharDevEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetCharDevGetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetCharDevControl(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetCharDevQEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetCharDevQGetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetCharDevQSetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetCharDevQPurge(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetCharDevQPurgeSelf(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetConnEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetFileEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
/* static NQ_UINT32 srvsvcNetFileGetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetFileClose(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetSessEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetSessDel(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetShareAdd(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
static NQ_UINT32 srvsvcNetShareEnumAll(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 srvsvcNetShareGetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 srvsvcNetShareSetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetShareDel(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
/* static NQ_UINT32 srvsvcNetShareDelSticky(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetShareCheck(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 srvsvcNetSrvGetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 srvsvcNetSrvSetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetDiskEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSERVERSTATISTICSGET(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSERVERTRANSPORTADD(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetTransportEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSERVERTRANSPORTDEL(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNetRemoteTOD(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSERVERSETSERVICEBITS(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRPRPATHTYPE(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRPRPATHCANONICALIZE(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRPRPATHCOMPARE(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
static NQ_UINT32 srvsvcNetNameValidate(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
/* static NQ_UINT32 srvsvcNETRPRNAMECANONICALIZE(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRPRNAMECOMPARE(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 srvsvcNetShareEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 srvsvcNETRSHAREDELSTART(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSHAREDELCOMMIT(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNET_FILE_QUERY_SECDESC(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNET_FILE_SET_SECDESC(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSERVERTRANSPORTADDEX(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSERVERSETSERVICEBITSEX(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSGETVERSION(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSCREATELOCALPARTITION(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSDELETELOCALPARTITION(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSSETLOCALVOLUMESTATE(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSSETSERVERINFO(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSCREATEEXITPOINT(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSDELETEEXITPOINT(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSMODIFYPREFIX(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSFIXLOCALVOLUME(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRDFSMANAGERREPORTSITEINFO(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 srvsvcNETRSERVERTRANSPORTDELEX(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */

static const CSRpcFunctionDescriptor functions[] =
{
    { NULL /* srvsvcNetCharDevEnum */                 /* 0x00 */ },
    { NULL /* srvsvcNetCharDevGetInfo */              /* 0x01 */ },
    { NULL /* srvsvcNetCharDevControl */              /* 0x02 */ },
    { NULL /* srvsvcNetCharDevQEnum */                /* 0x03 */ },
    { NULL /* srvsvcNetCharDevQGetInfo */             /* 0x04 */ },
    { NULL /* srvsvcNetCharDevQSetInfo */             /* 0x05 */ },
    { NULL /* srvsvcNetCharDevQPurge */               /* 0x06 */ },
    { NULL /* srvsvcNetCharDevQPurgeSelf */           /* 0x07 */ },
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetConnEnum                               /* 0x08 */ },
#else
    { NULL /* srvsvcNetConnEnum */                    /* 0x08 */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetFileEnum                               /* 0x09 */ },
#else
    { NULL /* srvsvcNetFileEnum */                    /* 0x09 */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
    { NULL /* srvsvcNetFileGetInfo */                 /* 0x0a */ },
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetFileClose                              /* 0x0b */ },
#else
    { NULL /* srvsvcNetFileClose */                   /* 0x0b */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetSessEnum                               /* 0x0c */ },
#else
    { NULL /* srvsvcNetSessEnum */                    /* 0x0c */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetSessDel                                /* 0x0d */ },
#else
    { NULL /* srvsvcNetSessDel */                     /* 0x0d */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetShareAdd                               /* 0x0e */ },
#else
    { NULL /* srvsvcNetShareAdd */                    /* 0x0e */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
    { srvsvcNetShareEnumAll                           /* 0x0f */ },
    { srvsvcNetShareGetInfo                           /* 0x10 */ },
    { srvsvcNetShareSetInfo                           /* 0x11 */ },
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetShareDel                               /* 0x12 */ },
#else
    { NULL /* srvsvcNetShareDel */                    /* 0x12 */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
    { NULL /* srvsvcNetShareDelSticky */              /* 0x13 */ },
    { NULL /* srvsvcNetShareCheck */                  /* 0x14 */ },
    { srvsvcNetSrvGetInfo                             /* 0x15 */ },
    { NULL /* srvsvcNetSrvSetInfo */                  /* 0x16 */ },
    { NULL /* srvsvcNetDiskEnum */                    /* 0x17 */ },
    { NULL /* srvsvcNETRSERVERSTATISTICSGET */        /* 0x18 */ },
    { NULL /* srvsvcNETRSERVERTRANSPORTADD */         /* 0x19 */ },
    { NULL /* srvsvcNetTransportEnum */               /* 0x1a */ },
    { NULL /* srvsvcNETRSERVERTRANSPORTDEL */         /* 0x1b */ },
    { NULL /* srvsvcNetRemoteTOD */                   /* 0x1c */ },
    { NULL /* srvsvcNETRSERVERSETSERVICEBITS */       /* 0x1d */ },
    { NULL /* srvsvcNETRPRPATHTYPE */                 /* 0x1e */ },
    { NULL /* srvsvcNETRPRPATHCANONICALIZE */         /* 0x1f */ },
    { NULL /* srvsvcNETRPRPATHCOMPARE */              /* 0x20 */ },
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    { srvsvcNetNameValidate                           /* 0x21 */ },
#else
    { NULL /* srvsvcNetNameValidate */                /* 0x21 */ },
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
    { NULL /* srvsvcNETRPRNAMECANONICALIZE */         /* 0x22 */ },
    { NULL /* srvsvcNETRPRNAMECOMPARE */              /* 0x23 */ },
    { srvsvcNetShareEnum                              /* 0x24 */ },
    { NULL /* srvsvcNETRSHAREDELSTART */              /* 0x25 */ },
    { NULL /* srvsvcNETRSHAREDELCOMMIT */             /* 0x26 */ },
    { NULL /* srvsvcNET_FILE_QUERY_SECDESC */         /* 0x27 */ },
    { NULL /* srvsvcNET_FILE_SET_SECDESC */           /* 0x28 */ },
    { NULL /* srvsvcNETRSERVERTRANSPORTADDEX */       /* 0x29 */ },
    { NULL /* srvsvcNETRSERVERSETSERVICEBITSEX */     /* 0x2a */ },
    { NULL /* srvsvcNETRDFSGETVERSION */              /* 0x2b */ },
    { NULL /* srvsvcNETRDFSCREATELOCALPARTITION */    /* 0x2c */ },
    { NULL /* srvsvcNETRDFSDELETELOCALPARTITION */    /* 0x2d */ },
    { NULL /* srvsvcNETRDFSSETLOCALVOLUMESTATE */     /* 0x2e */ },
    { NULL /* srvsvcNETRDFSSETSERVERINFO */           /* 0x32 */ },
    { NULL /* srvsvcNETRDFSCREATEEXITPOINT */         /* 0x30 */ },
    { NULL /* srvsvcNETRDFSDELETEEXITPOINT */         /* 0x31 */ },
    { NULL /* srvsvcNETRDFSMODIFYPREFIX */            /* 0x32 */ },
    { NULL /* srvsvcNETRDFSFIXLOCALVOLUME */          /* 0x33 */ },
    { NULL /* srvsvcNETRDFSMANAGERREPORTSITEINFO */   /* 0x34 */ },
    { NULL /* srvsvcNETRSERVERTRANSPORTDELEX */       /* 0x35 */ }
};

static NQ_UINT32 /* required size or zero if default will be used */
checkSize(
  NQ_UINT16 code    /* function code */
  );

static const CSRpcPipeDescriptor pipeDescriptor =
{
  initData,
  stopData,
  NULL,
  "srvsvc",
  {cmPack32(0x4b324fc8),cmPack16(0x1670),cmPack16(0x01d3),{0x12,0x78},{0x5a,0x47,0xbf,0x6e,0xe1,0x88}},
  cmRpcVersion(3, 0),
  (sizeof(functions) / sizeof(functions[0])),
  functions,
  checkSize
};

static NQ_UINT32                        /* status */
setShareInfo(
   CMRpcPacketDescriptor* in,           /* request packet */
   CSShare* pShare                      /* share descriptor */
   );

/* pack information about one share */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packShareEntry(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    CSShare* pShare,                    /* pointer to share */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* pack text information for a share */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packShareStrings(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    CSShare* pShare,                    /* pointer to share */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* require access to a share */
static NQ_BOOL                          /* TRUE when granted */
checkAccessToShare(
    const CMRpcPacketDescriptor* out,   /* output descriptor */
    CSShare* pShare,                    /* pointer to share */
    NQ_UINT32 desiredAccess             /* access bits */
    );

/* check administrative access */
static NQ_BOOL
hasAdministrativeAccess(
    const CMRpcPacketDescriptor* in     /* packet descriptor */
    );

/* convert share path from network to local form */
static NQ_WCHAR*        /* local path */
pathNetworkToLocal(
    NQ_WCHAR* path      /* network path */
    );

/* convert share path from local to network form */
static NQ_WCHAR*        /* network path */
pathLocalToNetwork(
    CSShare *share      /* share */
    );

#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION

/* pack information about one user */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packUserEntry(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    CSUser* pUser,                      /* pointer to user */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* pack text information for a user */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packUserStrings(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    CSUser* pUser,                      /* pointer to user */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* pack information about one file */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packFileEntry(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    CSFid fid,                          /* FID */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* pack text information for a file */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packFileStrings(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    CSFid fid,                          /* FID */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* pack information about one connection */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packConnEntry(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    const CSTree* pTree,                /* tree desriptor */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* pack text information for a connection */
static NQ_UINT32                        /* NQ_SUCCESS or error code */
packConnStrings(
    CMRpcPacketDescriptor* out,         /* output descriptor */
    const CSTree* pTree,                /* tree desriptor */
    NQ_UINT32 infoLevel                 /* information level */
    );

/* require access to a user */
static NQ_BOOL                          /* TRUE when granted */
checkAccessToUsers(
    const CMRpcPacketDescriptor* out    /* output descriptor */
    );

/* covert file access to file permissions */
static NQ_UINT32                        /* file permissions */
convertAccessToPermissions(
    NQ_UINT16 access                    /* access bits */
    );

#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */

/*====================================================================
 * PURPOSE: Get pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pipe descriptor for this pipe
 *
 * NOTES:
 *====================================================================
 */

const CSRpcPipeDescriptor*
csRpcSrvsvc(
    )
{
    return &pipeDescriptor;
}

/*
    Pipe functions
    --------------

    All pipe functions have the same signature:

 *====================================================================
 * PURPOSE: A pipe function
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          OUT outgoing packet descriptor
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   a pipe function parses incoming packet and packs outgoing
 *          packet
 *====================================================================
 */

/* Get server information */

static NQ_UINT32
srvsvcNetSrvGetInfo (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_UINT32 referentId;            /* running number */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);

    TRC1P("info level: %ld", infoLevel);

    /* check space according to the largest variant */

    CS_RP_CHECK(out, NETSRVGETINFO_SIZE);

    /* prepare results */

    referentId = 2;                         /* an arbitrary value ??? */

    /* pack the result header */

    cmRpcPackUint32(out, infoLevel);
    savedPtr = out->current;
    cmRpcPackUint32(out, 0);                /* null pointer meanwhile */
    cmRpcCloneDescriptor(out, &outTemp);

    /* switch by info level */

    switch (infoLevel)
    {
    case 100:
        cmRpcPackUint32(&outTemp, 500);    /* unknown platform */
        cmRpcPackUint32(&outTemp, referentId++);     /* server name */
        break;
    case 101:
        cmRpcPackUint32(&outTemp, 500);                /* NT platform */
        cmRpcPackUint32(&outTemp, referentId++);    /* server name */
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMINOR);
        cmRpcPackUint32(&outTemp, csGetHostType()); /* server type */
        cmRpcPackUint32(&outTemp, referentId++);    /* server comment */
        break;
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    case 102:
        cmRpcPackUint32(&outTemp, 500);               /* unknown platform */
        cmRpcPackUint32(&outTemp, referentId++);    /* server name */
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMINOR);
        cmRpcPackUint32(&outTemp, csGetHostType()); /* server type */
        cmRpcPackUint32(&outTemp, referentId++);    /* server comment */
        cmRpcPackUint32(&outTemp, csGetUsersCount());   /* user */
        cmRpcPackUint32(&outTemp, 0);                   /* disk */
        cmRpcPackUint32(&outTemp, 0);                   /* hidden */
        cmRpcPackUint32(&outTemp, 0);               /* announce */
        cmRpcPackUint32(&outTemp, 0);               /* announce delta */
        cmRpcPackUint32(&outTemp, 0);               /* licenses */
        cmRpcPackUint32(&outTemp, referentId++);    /* user path */
        break;
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
    /*case 402:
    case 403:
    case 502:
    case 503:
    case 599:
    case 1005:
    case 1010:
    case 1016:
    case 1017:
    case 1018:
    case 1107:
    case 1501:
    case 1502:
    case 1503:
    case 1506:
    case 1509:
    case 1510:
    case 1511:
    case 1512:
    case 1513:
    case 1514:
    case 1515:
    case 1516:
    case 1518:
    case 1520:
    case 1521:
    case 1522:
    case 1523:
    case 1524:
    case 1525:
    case 1528:
    case 1529:
    case 1530:
    case 1533:
    case 1534:
    case 1535:
    case 1536:
    case 1537:
    case 1538:
    case 1539:
    case 1540:
    case 1541:
    case 1542:
    case 1543:
    case 1544:
    case 1545:
    case 1546:
    case 1547:
    case 1548:
    case 1549:
    case 1550:
    case 1552:
    case 1553:
    case 1554:
    case 1555:
    case 1556:*/
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_FAULTUSERDEFINED;
    }

    /* add referred data */
    switch (infoLevel)
    {
    case 100:
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, cmNetBiosGetHostNameZeroed(), CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        break;
    case 101:
        {
            CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, cmNetBiosGetHostNameZeroed(), CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            udGetServerComment(staticData->shareNameW);
            CS_RP_CALL(cmRpcPackWcharAsUnicode(&outTemp, staticData->shareNameW, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        }
        break;
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION
    case 102:
        {
            CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, cmNetBiosGetHostNameZeroed(), CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            udGetServerComment(staticData->shareNameW);
            CS_RP_CALL(cmRpcPackWcharAsUnicode(&outTemp, staticData->shareNameW, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        }
        break;
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
    /*case 402:
    case 403:
    case 502:
    case 503:
    case 599:
    case 1005:
    case 1010:
    case 1016:
    case 1017:
    case 1018:
    case 1107:
    case 1501:
    case 1502:
    case 1503:
    case 1506:
    case 1509:
    case 1510:
    case 1511:
    case 1512:
    case 1513:
    case 1514:
    case 1515:
    case 1516:
    case 1518:
    case 1520:
    case 1521:
    case 1522:
    case 1523:
    case 1524:
    case 1525:
    case 1528:
    case 1529:
    case 1530:
    case 1533:
    case 1534:
    case 1535:
    case 1536:
    case 1537:
    case 1538:
    case 1539:
    case 1540:
    case 1541:
    case 1542:
    case 1543:
    case 1544:
    case 1545:
    case 1546:
    case 1547:
    case 1548:
    case 1549:
    case 1550:
    case 1552:
    case 1553:
    case 1554:
    case 1555:
    case 1556:*/
    }

    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    out->current = outTemp.current;    /* advance the original descriptor */
    TRCE();
    return 0;
}

/* Get all shares information */

static NQ_UINT32
srvsvcNetShareEnum (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* requested information level */
    NQ_UINT32 numberOfEntries;      /* num of shares */
    NQ_UINT32 i;                    /* just a counter */
    NQ_UINT32 status;               /* temporary status code */
    NQ_UINT32 ret = 0;              /* returned status code */
    NQ_BYTE* savedPtr1;             /* saved pointer to the entry referral */
    NQ_BYTE* savedPtr2;             /* saved pointer to the entry referral */
    NQ_UINT32 actualEntries = 0;    /* actual number of entries */
    NQ_UINT32 referentId;            /* running number */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);

    /* check space according to the largest variant */

    CS_RP_CHECK(out, NETSHAREENUMALL_HDRSIZE);

    /* prepare results */
    numberOfEntries = csGetSharesCount();
    referentId = 1;                         /* an arbitrary value ??? */

    /* pack the result */
    cmRpcPackUint32(out, infoLevel);
    savedPtr1 = out->current;
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);

    /* pack values and referrals */
    for(i = 0; i < numberOfEntries; i++)
    {
        CSShare* pShare = csGetShareByIndex((NQ_UINT)i); /* pointer to share descriptor */

        status = packShareEntry(out, pShare, infoLevel);
    }

    /* place referred strings */
    for(i = 0; i < numberOfEntries; i++)
    {
        CSShare* pShare = csGetShareByIndex((NQ_UINT)i); /* pointer to share descriptor */

        status = packShareStrings(out,pShare, infoLevel);
        if (status == 0)
        {
            actualEntries++;
        }
        else
        {
            ret = status;
        }
    }
    cmRpcPackUint32(out, actualEntries);
    if (actualEntries > 0)
    {
        ret = 0;
    }
    cmRpcPackUint32(out, 0);                /* resume handle - no support */

    savedPtr2 = out->current;
    out->current = savedPtr1;
    cmRpcPackUint32(out, referentId++);
    cmRpcPackUint32(out, actualEntries);
    cmRpcPackUint32(out, referentId++);
    cmRpcPackUint32(out, actualEntries);
    out->current = savedPtr2;    /* advance the original descriptor */
    TRCE();
    return ret;
}

/* Get all shares information (alternative code) */

static NQ_UINT32
srvsvcNetShareEnumAll (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* requested information level */
    NQ_BYTE* savedPtr;              /* saved pointer to input packet */

    /* parse input parameters */
    savedPtr = in->current;
    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);
    cmRpcPackUint32(out, infoLevel);    /* this is the only difference between this and NetShareEnum */
    in->current = savedPtr;
    return srvsvcNetShareEnum(in ,out);
}

/* Get information on a specific share */

static NQ_UINT32
srvsvcNetShareGetInfo (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    CMRpcUnicodeString shareName;   /* requested share name */
    NQ_UINT32 infoLevel;            /* requested information level */
    NQ_UINT32 status;               /* returned status code */
    CSShare* pShare;                /* pointer to the share structure */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);

    /* find the share */

    syWStrncpy(staticData->shareNameW, shareName.text, shareName.length);
    staticData->shareNameW[shareName.length] = cmWChar(0);
    pShare = csGetShareByName(staticData->shareNameW);
    if (NULL == pShare)
    {
        cmRpcPackUint32(out, infoLevel);
        cmRpcPackUint32(out, 0);    /* null ref id */
        TRCERR("Share not found");
        TRC1P(" required: %s", cmWDump(staticData->shareNameW));
        TRCE();
        return CM_RP_FAULTNAMENOTFOUND;
    }

    /* check space according to the largest variant */

    CS_RP_CHECK(out, NETSHAREINFO_HDRSIZE);

    /* pack the result */
    cmRpcPackUint32(out, infoLevel);
    savedPtr = out->current;
    cmRpcPackUint32(out, 0);
    cmRpcCloneDescriptor(out, &outTemp);

    status = packShareEntry(&outTemp, pShare, infoLevel);
    if (status != 0)
    {
        TRCE();
        return status;
    }

    /* place referred strings */
    status = packShareStrings(&outTemp, pShare, infoLevel);
    if (status != 0)
    {
        TRCE();
        return status;
    }

    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    out->current = outTemp.current;    /* advance the original descriptor */
    TRCE();
    return 0;
}

/* Modify information on a specific share */

static NQ_UINT32
srvsvcNetShareSetInfo (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString shareName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* requested information level */
    CSShare* pShare;                /* pointer to the share structure */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);

    /* find the share */

    syWStrncpy(staticData->shareNameW, shareName.text, shareName.length);
    staticData->shareNameW[shareName.length] = cmWChar(0);
    pShare = csGetShareByName(staticData->shareNameW);
    if (NULL == pShare)
    {
        cmRpcPackUint32(out, 0);    /* Parameter Error */
        TRCERR("Share not found");
        TRC1P(" required: %s", cmWDump(staticData->shareNameW));
        TRCE();
        return CM_RP_FAULTNAMENOTFOUND;
    }
    if (!checkAccessToShare(out, pShare, SMB_DESIREDACCESS_WRITEDAC))
    {
        cmRpcPackUint32(out, 0);    /* Parameter Error */
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    /* set info */

    setShareInfo(in, pShare);

    /* pack the result */
    cmRpcPackUint32(out, 0);    /* Parameter Error */

    TRCE();
    return 0;
}

#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION

/* Get information about sessions */

static NQ_UINT32
srvsvcNetSessEnum (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* requested information level */
    NQ_UINT32 prefLength;           /* preferred data length */
    NQ_UINT32 numberOfEntries;      /* number of sessions */
    NQ_UINT32 refId = 3;            /* referent ID */
    NQ_UINT32 actualEntries = 0;    /* actual number of entries */
    NQ_BYTE* savedPtr1;             /* pointer in the descriptor */
    NQ_BYTE* savedPtr2;             /* pointer in the descriptor */
    NQ_UINT32 ret = 0;              /* return value */
    NQ_INDEX i;                     /* session index */
    NQ_UINT32 status = 0;           /* call result */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseSkip(in, 4);  /* computer */
    cmRpcParseSkip(in, 4);  /* user */
    cmRpcParseUint32(in, &infoLevel);       /* info level */
    cmRpcParseUint32(in, &infoLevel);       /* again */
    cmRpcParseSkip(in, 4);  /* container ref id */
    cmRpcParseSkip(in, 4);  /* number of entries */
    cmRpcParseSkip(in, 4);  /* array */
    cmRpcParseUint32(in, &prefLength);      /* preferred length */

    /* pack results */
    refId = 1;
    numberOfEntries = csGetUsersCount();
    savedPtr1 = out->current;
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, 0);                /* null container */
    cmRpcPackUint32(out, 0);                /* number of entries */

    if (!checkAccessToUsers(out))
    {
        cmRpcPackUint32(out, 0);            /* resume handle */
        TRCERR("Access denied");
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    cmRpcPackUint32(out, 0);                /* null session info array */
    cmRpcPackUint32(out, 0);                /* max count */

    /* pack values and referrals */
    for(i = 0; i < numberOfEntries; i++)
    {
        CSUser* pUser = csGetUserByIndex(i); /* pointer to user descriptor */

        status = packUserEntry(out, pUser, infoLevel);
    }

    CS_RP_CHECK(out, NETUSERENUMALL_HDRSIZE);

    /* place referred strings */
    for(i = 0; i < numberOfEntries; i++)
    {
        CSUser* pUser = csGetUserByIndex(i); /* pointer to user descriptor */

        status = packUserStrings(out, pUser, infoLevel);
        if (status == 0)
        {
            actualEntries++;
        }
        else
        {
            ret = status;
        }
    }
    cmRpcPackUint32(out, actualEntries);
    if (actualEntries > 0)
    {
        ret = 0;
    }
    cmRpcPackUint32(out, refId++);  /* resume handle - ref id */
    cmRpcPackUint32(out, 0);  /* resume handle - no support */

    savedPtr2 = out->current;
    out->current = savedPtr1;
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, refId++);          /* container ref id */
    cmRpcPackUint32(out, actualEntries);    /* number of entries */
    cmRpcPackUint32(out, refId++);          /* array ref id */
    cmRpcPackUint32(out, actualEntries);    /* number of entries */
    out->current = savedPtr2;    /* advance the original descriptor */
    TRCE();
    return ret;
}

/* Delete a sessions */

static NQ_UINT32
srvsvcNetSessDel (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString userName;    /* requested user name */
    CMRpcUnicodeString compName;    /* requested client computer name */
    CSSession * pSess = NULL;       /* session to kill user for */
    const CSUser * pUser;           /* user slot to kill */
    NQ_STATIC NQ_CHAR buffer[CM_IPADDR_MAXLEN + 3]; /* text conversion storage */
    NQ_IPADDRESS ip;                /* client IP */
    NQ_BOOL allClients;             /* TRUE when all sessions should be closed for the given user */
    NQ_BOOL allUsers;               /* TRUE when all sessions should be closed for the given client machine */
    NQ_UINT32 refId;                /* ref id buffer */
    NQ_UINT userIdx;                /* index in users */
    NQ_BOOL wasDeleted = FALSE;     /* flag for at least one delete */
    NQ_BOOL selfdestruction = FALSE;

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &userName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &refId);           /* computer ref id */
    allClients = (0 == refId);

    if (!allClients)
    {
        NQ_CHAR * pClient;   /* pointer to client name */

        cmRpcParseUnicode(in, &compName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        cmUnicodeToAnsiN(buffer, compName.text, (NQ_UINT)(compName.length * sizeof(NQ_WCHAR)));
        buffer[compName.length] = '\0';
        pClient = buffer;
        if ('\\' == *pClient)
            pClient += 2;
        cmAsciiToIp(pClient, &ip);
        pSess = csGetSessionByIp(&ip);
        if (NULL == pSess)
        {
            CSSessionKey id = 0;            /* session id */
            NQ_INT numIps = 0;              /* number of IPs */
            const NQ_IPADDRESS * clientIps; /* array of client IPs */
            NQ_WCHAR * pClientW;            /* client name in Unicode */

            pClientW = cmMemoryCloneAString(pClient);
            if (NULL == pClientW)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                return CM_RP_OUTOFMEMORY;
            }
            clientIps = cmResolverGetHostIps(pClientW, &numIps);
            cmMemoryFree(pClientW);
            if (NULL == clientIps)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Client '%s' not resoled", pClient);
                return CM_RP_FILENOTFOUND;
            }
            while (NULL != (pSess = csGetSessionById(id)))
            {
                NQ_INT i;
                for (i = 0; i < numIps; i++)
                {
                    if (CM_IPADDR_EQUAL(pSess->ip, clientIps[i]))
                        break;
                }
                id++;
            }
            cmMemoryFree(clientIps);
            if (NULL == pSess)
            {
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Client name not found");
                LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
                return CM_RP_FAULTSESSIONNOTFOUND;
            }
        }
    }

    cmRpcParseUint32(in, &refId);           /* user ref id */
    allUsers = (0 == refId);

    if (!allUsers)
    {
        cmRpcParseUnicode(in, &userName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        syWStrncpy(staticData->shareNameW, userName.text, userName.length);
        staticData->shareNameW[userName.length] = cmWChar(0);
    }

    if (!checkAccessToUsers(out))
    {
        TRCERR("Access denied");
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    for (userIdx = 0; NULL != (pUser = csGetUserByIndex(userIdx)); userIdx++)
    {
        NQ_BOOL doDel = FALSE;

        if (!allClients)
        {
            if (allUsers)
            {
                doDel = pSess->key == pUser->session;
            }
            else
            {
                doDel =    (0 == syWStrcmp(pUser->name, staticData->shareNameW))
                        && pSess->key == pUser->session;
            }
        }
        else
            doDel = (0 == syWStrcmp(pUser->name, staticData->shareNameW));

        if (doDel)
        {
            /* check if the current session is being destroyed */
            selfdestruction = selfdestruction || (in->user == (NQ_BYTE *)pUser);

            csReleaseUserAndDisconnect(pUser->uid , FALSE);
            wasDeleted = TRUE;
        }
    }

    TRCE();

    /* in case the current session is being destroyed return no response as the
       communication socket becomes closed */
    return wasDeleted ? (selfdestruction ? SMB_STATUS_NORESPONSE : 0) : CM_RP_FAULTSESSIONNOTFOUND;
}

/* Close a file */

static NQ_UINT32
srvsvcNetFileClose (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString compName;    /* requested client computer name */
    NQ_UINT32 fid;                  /* file to close */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &compName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &fid);             /* fid */

    if (!checkAccessToUsers(out))
    {
        TRCERR("Access denied");
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    csReleaseFile((CSFid)fid);

    TRCE();
    return 0;
}

/* Validate a name before creation */

static NQ_UINT32
srvsvcNetNameValidate (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString nameDesc;    /* abstract name descriptor */
    NQ_UINT32 type;                 /* validation type */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &nameDesc, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUnicode(in, &nameDesc, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &type);            /* type */

    switch (type)
    {
    case 9:
        break;
    default:
        TRCERR("Unknown validation type");
        TRC1P(" value: %ld", type);

        TRCE();
        return CM_RP_FAULTUSERDEFINED;
    }

    TRCE();
    return 0;
}

/* Get information about files */

static NQ_UINT32
srvsvcNetFileEnum (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* requested information level */
    NQ_UINT32 prefLength;           /* preferred data length */
    NQ_UINT32 refId;                /* referent ID */
    NQ_UINT32 actualEntries = 0;    /* actual number of entries */
    NQ_BYTE* savedPtr1;             /* pointer in the descriptor */
    NQ_BYTE* savedPtr2;             /* pointer in the descriptor */
    NQ_UINT32 ret = 0;              /* return value */
    NQ_UINT32 resume = 0;           /* resume handle */
    NQ_UINT32 status = 0;           /* call result */
    CSFid fid;                      /* running fid */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseSkip(in, 4);  /* path */
    cmRpcParseSkip(in, 4);  /* user */
    cmRpcParseUint32(in, &infoLevel);       /* info level */
    cmRpcParseUint32(in, &infoLevel);       /* again */
    cmRpcParseSkip(in, 4);  /* container ref id */
    cmRpcParseSkip(in, 4);  /* number of entries */
    cmRpcParseSkip(in, 4);  /* array */
    cmRpcParseUint32(in, &prefLength);      /* preferred length */
    cmRpcParseUint32(in, &refId);           /* resume handle ref id */
    if (refId != 0)
        cmRpcParseUint32(in, &resume);      /* resume handle */

    resume = (NQ_UINT32)(resume == 0? CS_ILLEGALID : (CSFid)status);

    /* pack results */
    refId = 1;
    savedPtr1 = out->current;
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, 0);        /* container */
    cmRpcPackUint32(out, 0);        /* number of entries */

    if (!checkAccessToUsers(out))
    {
        cmRpcPackUint32(out, 0);        /* resume handle */
        TRCERR("Access denied");
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    cmRpcPackUint32(out, 0);        /* session info array */
    cmRpcPackUint32(out, 0);        /* max count */

   /* pack values and referrals */
    fid = (CSFid)resume;
    for(;;)
    {
        fid = csGetNextFileOpen(fid); /* enumerate files */
        if (CS_ILLEGALID == fid)
            break;
        status = packFileEntry(out, fid, infoLevel);
        if (0 != status)
            break;
    }

    CS_RP_CHECK(out, NETFILEENUMALL_HDRSIZE);

    /* place referred strings */
    fid = (CSFid)resume;
    for(;;)
    {
        fid = csGetNextFileOpen(fid); /* enumerate files */
        if (CS_ILLEGALID == fid)
            break;
        status = packFileStrings(out, fid, infoLevel);
        if (status == 0)
        {
            actualEntries++;
        }
        else
        {
            ret = status;
            break;
        }
    }
    cmRpcPackUint32(out, actualEntries);
    if (actualEntries > 0)
    {
        ret = 0;
    }
    cmRpcPackUint32(out, refId++);                      /* resume handle - ref id */
    cmRpcPackUint32(out, fid == CS_ILLEGALID? 0 : (NQ_UINT32)fid); /* resume handle - no support */

    savedPtr2 = out->current;
    out->current = savedPtr1;
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, infoLevel);        /* info level */
    cmRpcPackUint32(out, refId++);          /* container ref ID */
    cmRpcPackUint32(out, actualEntries);    /* number of entries */
    cmRpcPackUint32(out, refId++);          /* array ref ID */
    cmRpcPackUint32(out, actualEntries);    /* number of entries */
    out->current = savedPtr2;    /* advance the original descriptor */
    TRCE();
    return ret;
}

/* Add a share */

static NQ_UINT32
srvsvcNetShareAdd (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString serverName;  /* requested server name */
    NQ_UINT32 infoLevel;            /* info level */
    NQ_UINT32 status;               /* return status */
    CSShare* pShare;                /* share descriptor */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &serverName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);       /* info level */

    if (!checkAccessToUsers(out))
    {
        cmRpcPackUint32(out, 0);        /* error handle */
        TRCERR("Access denied");
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    /* create temporary share */
    status = (NQ_UINT32)nqAddShareA(TEMPSHARENAME, "/", FALSE, "", "");
    if (0 != status)
    {
        cmRpcPackUint32(out, 0);        /* error handle */
        TRCERR("Unable to create share");
        TRC1P("reason: %ld", status);
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    syAnsiToUnicode(staticData->shareNameW, TEMPSHARENAME);
    pShare = csGetShareByName(staticData->shareNameW);
    if (NULL == pShare)
    {
        cmRpcPackUint32(out, 0);        /* error handle */
        TRCERR("Unable to use temporary share");
        TRCE();
        return CM_RP_OUTOFMEMORY;
    }

    status = setShareInfo(in, pShare);

    if (0 != status)
        nqRemoveShareW(pShare->name);

    cmRpcPackUint32(out, 0);        /* error handle */

    TRCE();
    return status;
}

/* Delete a share */

static NQ_UINT32
srvsvcNetShareDel (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString shareName;   /* requested share name */
    NQ_UINT32 status;               /* share removal status */

    TRCB();

    if (!checkAccessToUsers(out))
    {
        TRCERR("Access denied");
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    /* parse input parameters */
    cmRpcParseSkip(in, 4);  /* server ref id */
    cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    syWStrncpy(staticData->shareNameW, shareName.text, shareName.length);
    staticData->shareNameW[shareName.length] = cmWChar(0);

    /* delete share from user persistent store */
    if (!udRemoveShare(staticData->shareNameW))
    {
        TRCERR("Unable to remove share from the persistent store");
        TRCE();
        return CM_RP_FAULTOBJECTNOTFOUND;
    }

    /* delete share */
    status = (NQ_UINT32)nqRemoveShareW(staticData->shareNameW);
    if (0 != status)
    {
        TRCERR("Unable to remove share");
        TRC1P("reason: %ld", status);
        TRCE();
        return CM_RP_FAULTOBJECTNOTFOUND;
    }

    TRCE();
    return 0;
}

/* Get all connections information */

static NQ_UINT32
srvsvcNetConnEnum (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString shareName;   /* requested share name */
    NQ_UINT32 infoLevel;            /* requested information level */
    NQ_UINT32 status;               /* temporary status code */
    NQ_UINT32 ret = 0;              /* returned status code */
    NQ_BYTE* savedPtr1;             /* saved pointer to the entry referral */
    NQ_BYTE* savedPtr2;             /* saved pointer to the entry referral */
    NQ_UINT32 actualEntries = 0;    /* actual number of entries */
    NQ_UINT32 referentId;           /* running number */
    const CSShare* pShare;          /* share descriptor */
    CSTid tid;                      /* index to enumerate trees */

    TRCB();

    /* parse input parameters */
    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);       /* info level */

    /* check space according to the largest variant */

    CS_RP_CHECK(out, NETCONNENUMALL_HDRSIZE);

    referentId = 1;                         /* an arbitrary value ??? */

    /* pack the result */
    cmRpcPackUint32(out, infoLevel);    /* info level */
    cmRpcPackUint32(out, infoLevel);    /* info level again */
    savedPtr1 = out->current;
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);

    /* find the share */

    syWStrncpy(staticData->shareNameW, shareName.text, shareName.length);
    staticData->shareNameW[shareName.length] = cmWChar(0);
    pShare = csGetShareByName(staticData->shareNameW);
    if (NULL == pShare)
    {
        TRCERR("Share not found");
        TRC1P(" required: %s", cmWDump(staticData->shareNameW));
        TRCE();
        return CM_RP_FAULTNAMENOTFOUND;
    }

    /* pack values and referrals */
    tid = CS_ILLEGALID;
    for (;;)
    {
        const CSTree* pTree = csGetNextTreeByShare(pShare, tid);

        if (NULL == pTree)
            break;
        tid = pTree->tid;
        status = packConnEntry(out, pTree, infoLevel);
    }

    /* place referred strings */
    tid = CS_ILLEGALID;
    for (;;)
    {
        const CSTree* pTree = csGetNextTreeByShare(pShare, tid);

        if (NULL == pTree)
            break;
        tid = pTree->tid;
        status = packConnStrings(out, pTree, infoLevel);
        if (status == 0)
        {
            actualEntries++;
        }
        else
        {
            ret = status;
        }
    }
    cmRpcPackUint32(out, actualEntries);
    if (actualEntries > 0)
    {
        ret = 0;
    }
    cmRpcPackUint32(out, 0);                /* resume handle - no support */

    savedPtr2 = out->current;
    out->current = savedPtr1;
    cmRpcPackUint32(out, referentId++);
    cmRpcPackUint32(out, actualEntries);
    cmRpcPackUint32(out, referentId++);
    cmRpcPackUint32(out, actualEntries);
    out->current = savedPtr2;    /* advance the original descriptor */
    TRCE();
    return ret;
}

#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */

/*====================================================================
 * PURPOSE: place information on one share - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN share descriptor
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This information contains refereals but does not contain referred strings
 *====================================================================
 */

static NQ_UINT32
packShareEntry(
    CMRpcPacketDescriptor* out,
    CSShare* pShare,
    NQ_UINT32 infoLevel
    )
{
    NQ_UINT32 shareType;              /* share type (see above) */
    NQ_UINT tempUint;                 /* temporary storage */
    NQ_UINT32 referentId;             /* running number */
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    CMSdAccessToken* token = (CMSdAccessToken *)out->token;
    NQ_BYTE* sdStart;                 /* saved position in descriptor just before SD */
    CMRpcPacketDescriptor savedOut1;  /* saved descriptor for late placing of SD length */
    CMRpcPacketDescriptor savedOut2;  /* saved descriptor for late placing of SD length */
    NQ_UINT32 tempUint32;             /* temporary storage */
#endif
    
    TRCB();

    referentId = 1;
    
#ifdef UD_CS_HIDE_NOACCESS_SHARE
    /* hide share from user that has no right to use it */
    if (!cmSdHasAccess((CMSdAccessToken*)out->token, pShare->sd.data, SMB_DESIREDACCESS_READDATA))
    {
        TRCERR("No access - hidding share: %s", cmWDump(pShare->name));
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }
#endif

    if (infoLevel > 1 && !hasAdministrativeAccess(out))
    {
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }

    CS_RP_CHECK(out, NETSHAREENUMALL_ENTRYSIZE);

    /* compose share type */
    shareType = SMB_SHARETYPE_DISKTREE;
    if (pShare->ipcFlag)
    {
        shareType = SMB_SHARETYPE_IPC | SMB_SHARETYPE_HIDDEN;
    }
    else if (pShare->isPrintQueue)
    {
        shareType = SMB_SHARETYPE_PRINTQ;
    }
    else if (pShare->isDevice)
    {
        shareType = SMB_SHARETYPE_DEVICE;
    }
    else if (pShare->isHidden)
    {
        shareType = SMB_SHARETYPE_HIDDEN;
    }

    switch (infoLevel)
    {
    case 0:
        cmRpcPackUint32(out, referentId++);    /* share name referral */
        break;
    case 1:
        cmRpcPackUint32(out, referentId++);    /* share name referral */
        cmRpcPackUint32(out, shareType);
        cmRpcPackUint32(out, referentId++);    /* share comment referral */
        break;
    case 2:
        cmRpcPackUint32(out, referentId++);    /* share name referral */
        cmRpcPackUint32(out, shareType);
        cmRpcPackUint32(out, referentId++);     /* share comment referral */
        cmRpcPackUint32(out, 0);                /* permissions - hardcoded */
        cmRpcPackUint32(out, UD_FS_NUMSERVERUSERS); /* max users for share */
        tempUint = csGetNumberOfShareUsers(pShare);
        cmRpcPackUint32(out, tempUint);             /* current users for share */
        cmRpcPackUint32(out, referentId++);     /* share path referral */
        cmRpcPackUint32(out, 0);                /* we do not report password(s) */
        break;
    case 501:
        cmRpcPackUint32(out, referentId++);    /* share name referral */
        cmRpcPackUint32(out, shareType);
        cmRpcPackUint32(out, referentId++);    /* share comment referral */
        cmRpcPackUint32(out, 0);               /* we do not report policy */
        break;
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    case 502:
        /* NOTE: undocumented feature - the security descriptor (SD) should be
         * followed by two additional ACEs, not counted into the DACLs
         * "num ACEs" field but with their size counted into the total
         * SD length */
        cmRpcPackUint32(out, referentId++);         /* share name referral */
        cmRpcPackUint32(out, shareType);            /* share type */
        cmRpcPackUint32(out, referentId++);         /* share comment referral */
        cmRpcPackUint32(out, 0);                    /* permissions */
        cmRpcPackUint32(out, UD_FS_NUMSERVERTREES); /* max uses */
        tempUint32 = csGetNumberOfShareUsers(pShare);
        cmRpcPackUint32(out, tempUint32);           /* current uses */
        cmRpcPackUint32(out, referentId++);         /* path referral */
        cmRpcPackUint32(out, 0);                    /* password */
        cmRpcCloneDescriptor(out, &savedOut1);      /* save SD length position */
        cmRpcPackUint32(out, 0);                    /* security descriptor container length inluding extra ACEs TODO */
        cmRpcPackUint32(out, referentId++);         /* security descriptor referral */
        cmRpcAllignZero(out, 4);
        CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pShare->name , (CM_RP_NULLTERM | CM_RP_SIZE32 | CM_RP_FRAGMENT32)));
        CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pShare->description, (CM_RP_NULLTERM | CM_RP_SIZE32 | CM_RP_FRAGMENT32)));
        CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pathLocalToNetwork(pShare), (CM_RP_NULLTERM | CM_RP_SIZE32 | CM_RP_FRAGMENT32)));
        cmRpcCloneDescriptor(out, &savedOut2);      /* save SD length position */
        cmRpcPackUint32(out, 0);      /* security descriptor container length inluding extra ACEs TODO */
        sdStart = out->current;
        cmSdPackSecurityDescriptor(out, &pShare->sd, 0x0f);     /* security descriptor */
        cmSdPackSidRid(out, &token->domain, token->rids[0]);       /* owner SID and RID */
        cmSdPackSidRid(out, &token->domain, CM_SD_RIDALIASUSER);   /* group SID and RID */
        cmRpcPackUint32(&savedOut1, (NQ_UINT32)(out->current - sdStart));
        cmRpcPackUint32(&savedOut2, (NQ_UINT32)(out->current - sdStart));
        break;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: place referred strings on one share - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  IN incoming packet descriptor
 *          OUT outgoing packet descriptor
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This function assumes that referrals were already placed
 *====================================================================
 */

static NQ_UINT32
packShareStrings(
    CMRpcPacketDescriptor* out,
    CSShare* pShare,
    NQ_UINT32 infoLevel
    )
{  
    TRCB();
#ifdef UD_CS_HIDE_NOACCESS_SHARE
  /* hide share from user that has no right to use it */
    if (!cmSdHasAccess((CMSdAccessToken*)out->token, pShare->sd.data, SMB_DESIREDACCESS_READDATA))
    {
        TRCERR("No access - hidding share: %s", cmWDump(pShare->name));
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }
#endif
    if (infoLevel > 1 && !hasAdministrativeAccess(out))
    {
        TRCE();
        return CM_RP_FAULTACCESSDENIED;
    }
    switch (infoLevel)
    {
    case 0:
        {
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pShare->name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        }
        break;
    case 1:
    case 501:
        {
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pShare->name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pShare->description, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        }
        break;
    case 502:
    	break;
    case 2:
        {
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pShare->name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pShare->description, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, pathLocalToNetwork(pShare), (CM_RP_NULLTERM | CM_RP_SIZE32 | CM_RP_FRAGMENT32)));
        }
        break;
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION

/*====================================================================
 * PURPOSE: place information on one user - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN user descriptor
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This information contains refereals but does not contain referred strings
 *====================================================================
 */

static NQ_UINT32
packUserEntry(
    CMRpcPacketDescriptor* out,
    CSUser* pUser,
    NQ_UINT32 infoLevel
    )
{
    NQ_UINT32 refId = 101;               /* running number */

    TRCB();

    CS_RP_CHECK(out, NETUSERENUMALL_ENTRYSIZE);

    switch (infoLevel)
    {
    case 0:
        cmRpcPackUint32(out, refId++);    /* client */
        break;
    case 1:
        cmRpcPackUint32(out, refId++);    /* client */
        cmRpcPackUint32(out, refId++);    /* user */
        cmRpcPackUint32(out, csGetNumberOfUserFiles(pUser)); /* num open */
        cmRpcPackUint32(out, 0);    /* time */
        cmRpcPackUint32(out, 0);    /* idle time */
        cmRpcPackUint32(out, 0);    /* user flags */
        break;
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: place referred strings on one user - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN user descriptor
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This function assumes that referrals were already placed
 *====================================================================
 */

static NQ_UINT32
packUserStrings(
    CMRpcPacketDescriptor* out,
    CSUser* pUser,
    NQ_UINT32 infoLevel
    )
{
    TRCB();

    switch (infoLevel)
    {
    case 0:
        {
            CS_RP_CALL(cmRpcPackAsciiAsUnicode(out, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        }
        break;
    case 1:
        {
            NQ_CHAR buffer[CM_IPADDR_MAXLEN + 1];   /* text conversion storage */
            const CSSession* pSess;                 /* session to use */

            pSess = csGetSessionById(pUser->session);
            if (NULL == pSess)
            {
                TRCERR("User session was not found");
                TRCE();
                return CM_RP_FAULTOBJECTNOTFOUND;
            }
            cmIpToAscii(buffer, &pSess->ip);
            cmRpcPackAsciiAsUnicode(out, buffer, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
            cmRpcPackWcharAsUnicode(out, pUser->name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM);
        }
        break;
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: place information on one file - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN file ID
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This information contains refereals but does not contain referred strings
 *====================================================================
 */

static NQ_UINT32
packFileEntry(
    CMRpcPacketDescriptor* out,
    CSFid fid,
    NQ_UINT32 infoLevel
    )
{
    NQ_UINT32 refId = 101;                      /* running number */
    const CSFile* pFile = csGetFileByJustFid(fid);    /* file pointer */

    TRCB();

    if (NULL == pFile)
    {
        TRCERR("Unexpected FID");
        TRCE();
        return CM_RP_FAULTOBJECTNOTFOUND;
    }

    CS_RP_CHECK(out, NETFILEENUMALL_ENTRYSIZE);

    switch (infoLevel)
    {
    case 3:
        cmRpcPackUint32(out, (NQ_UINT32)fid);           /* fid */
        cmRpcPackUint32(out, convertAccessToPermissions(pFile->access)); /* permissions */
        cmRpcPackUint32(out, 0);                        /* num locks */
        cmRpcPackUint32(out, refId++);                  /* path */
        cmRpcPackUint32(out, refId++);                  /* user */
        break;
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: place referred strings on one file - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN file ID
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This function assumes that referrals were already placed
 *====================================================================
 */

static NQ_UINT32
packFileStrings(
    CMRpcPacketDescriptor* out,
    CSFid fid,
    NQ_UINT32 infoLevel
    )
{
    const CSFile* pFile = csGetFileByJustFid(fid);    /* file pointer */


    TRCB();

    if (NULL == pFile)
    {
        TRCERR("Unexpected FID");
        TRCE();
        return CM_RP_FAULTOBJECTNOTFOUND;
    }

    switch (infoLevel)
    {
    case 3:
        {
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, csGetNameByNid(pFile->nid) != NULL ? csGetNameByNid(pFile->nid)->name : NULL, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            CS_RP_CALL(cmRpcPackWcharAsUnicode(out, csGetUserByUid(pFile->uid) != NULL ? csGetUserByUid(pFile->uid)->name : NULL, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        }
        break;
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: place information on one connection - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN tree descriptor
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This information contains refereals but does not contain referred strings
 *====================================================================
 */

static NQ_UINT32
packConnEntry(
    CMRpcPacketDescriptor* out,
    const CSTree* pTree,
    NQ_UINT32 infoLevel
    )
{
    NQ_UINT32 refId = 101;                      /* running number */

    TRCB();

    CS_RP_CHECK(out, NETCONNENUMALL_ENTRYSIZE);

    switch (infoLevel)
    {
    case 1:
        cmRpcPackUint32(out, pTree->tid);       /* connection id */
        cmRpcPackUint32(out, 0);                /* connection type */
        cmRpcPackUint32(out, 1);                /* num opens */
        cmRpcPackUint32(out, 1);                /* users */
        cmRpcPackUint32(out, 0);                /* connection time */
        cmRpcPackUint32(out, refId++);          /* user */
        cmRpcPackUint32(out, refId++);          /* server */
        break;
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: place referred strings on one connection - this function is used internally
 *--------------------------------------------------------------------
 * PARAMS:  OUT outgoing packet descriptor
 *          IN tree descriptor
 *          IN information level
 *
 * RETURNS: zero on success or error code
 *
 * NOTES:   This function assumes that referrals were already placed
 *====================================================================
 */

static NQ_UINT32
packConnStrings(
    CMRpcPacketDescriptor* out,
    const CSTree* pTree,
    NQ_UINT32 infoLevel
    )
{
    TRCB();

    switch (infoLevel)
    {
    case 1:
        {
        	CS_RP_CALL(cmRpcPackWcharAsUnicode(out, csGetUserByUid(pTree->uid) != NULL ? csGetUserByUid(pTree->uid)->name : NULL, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
            CS_RP_CALL(cmRpcPackAsciiAsUnicode(out, cmNetBiosGetHostNameZeroed(), CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        }
        break;
    default:
        TRCERR("Unknown info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: check access to user
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor
 *
 * RETURNS: TRUE when access is allowed
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
checkAccessToUsers(
    const CMRpcPacketDescriptor* in
    )
{
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    return cmSdIsAdmin(((CMSdAccessToken*)in->token)->rids[0]);
#else /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    return TRUE;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
}

/*====================================================================
 * PURPOSE: covert file access to file permissions
 *--------------------------------------------------------------------
 * PARAMS:  IN access bits
 *
 * RETURNS: permissions
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
convertAccessToPermissions(
    NQ_UINT16 access
    )
{
    return (NQ_UINT32)((access & 3) + 1);
}

#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */

/*====================================================================
 * PURPOSE: check access to share
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor
 *          IN pointer to share struct
 *          IN desired access bits
 *
 * RETURNS: TRUE when access is allowed
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
checkAccessToShare(
    const CMRpcPacketDescriptor* in,
    CSShare* pShare,
    NQ_UINT32 desiredAccess
    )
{
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    return cmSdHasAccess((CMSdAccessToken*)in->token, pShare->sd.data, desiredAccess);
#else /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    return cmSdHasAccess((CMSdAccessToken*)in->token, NULL, desiredAccess);
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
}

/*====================================================================
 * PURPOSE: check administrative rights
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor
 *
 * RETURNS: TRUE when access is allowed
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
hasAdministrativeAccess(
    const CMRpcPacketDescriptor* in
    )
{
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
    return cmSdIsAdministrator((CMSdAccessToken*)in->token);
#else /* UD_CS_INCLUDESECURITYDESCRIPTORS */
    return TRUE;
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
}

/*====================================================================
 * PURPOSE: initialize data
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
initData(
    void
    )
{
    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate SRVSVC data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */
    staticData->shareMapW[0] = 0;
    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: release data
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
stopData(
    void
    )
{
    TRCB();

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    TRCE();
}

/*====================================================================
 * PURPOSE: set share information
 *--------------------------------------------------------------------
 * PARAMS:  IN request packet descriptor
 *          IN/OUT share pointer
 *
 * RETURNS: error code or zero on success
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
setShareInfo(
   CMRpcPacketDescriptor* in,
   CSShare* pShare
   )
{
    CMRpcUnicodeString shareName;           /* new share name */
    CMRpcUnicodeString shareMap;            /* new share path */
    CMRpcUnicodeString shareDescription;    /* new description */
    NQ_UINT32 infoLevel;                    /* info level */
    NQ_UINT32 sdRefId;                      /* ID of security descriptor */

    /* parse info container */
    cmRpcParseUint32(in, &infoLevel);       /* another info level */
    switch (infoLevel)
    {
    case 2:
    case 502:
        cmRpcParseSkip(in, 4);  /* share container ref id */
        cmRpcParseSkip(in, 4);  /* share name ref id */
        cmRpcParseSkip(in, 4);  /* share type - not modified */
        cmRpcParseSkip(in, 4);  /* share comment ref id */
        cmRpcParseSkip(in, 4);  /* permision - not modified */
        cmRpcParseSkip(in, 4);  /* max users - not modified */
        cmRpcParseSkip(in, 4);  /* current users - not modified */
        cmRpcParseSkip(in, 4);  /* share path ref id */
        cmRpcParseSkip(in, 4);  /* password - not modified */
        if (infoLevel > 2)
        {
            cmRpcParseSkip(in, 4);  /* SD length */
            cmRpcParseUint32(in, &sdRefId);  /* SD ref id */
        }
        /* parse referenced data in the order of their ref ids */
        cmRpcParseUnicode(in, &shareName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        syWStrncpy(staticData->shareNameW, shareName.text, shareName.length);
        staticData->shareNameW[shareName.length] = cmWChar(0);
        cmRpcParseUnicode(in, &shareDescription, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        syWStrncpy(staticData->shareDescriptionW, shareDescription.text, shareDescription.length);
        staticData->shareDescriptionW[shareDescription.length] = cmWChar(0);
        cmRpcParseUnicode(in, &shareMap, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        syWStrncpy(staticData->tempW, shareMap.text, shareMap.length);
        staticData->tempW[shareMap.length] = cmWChar(0);

        pathNetworkToLocal(staticData->tempW);
#ifdef UD_CS_INCLUDERPC_SRVSVC_EXTENSION     
        {
			if (!udSaveShareInformation(
					pShare->name,
					staticData->shareNameW,
					 staticData->shareMapW,
					staticData->shareDescriptionW
				))
			{
				TRCERR("User level persistence failed");
				TRCE();
				return CM_RP_FAULTACCESSDENIED;
			}
        }
#endif /* UD_CS_INCLUDERPC_SRVSVC_EXTENSION */
        syWStrncpy(pShare->name, shareName.text, sizeof(pShare->name));
        syWStrncpy(pShare->description, shareDescription.text, sizeof(pShare->description));
        if (0 != syWStrcmp(staticData->shareMapW, pShare->map))
        {
            if (csGetNumberOfShareFiles(pShare))
            {
                TRCERR("Access violation - an attempt to remap a share with files opened");
                TRCE();
                return CM_RP_FAULTACCESSDENIED;
            }
            syWStrncpy(pShare->map, staticData->shareMapW, sizeof(pShare->map));
        }


#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
        if (infoLevel > 2 && 0 != sdRefId)
        {
            cmRpcParseSkip(in, 4);  /* SD length once again */
            cmSdParseSecurityDescriptor(in, &pShare->sd);  /* share SD */
            if (!csSetShareSecurityDescriptor(pShare))
            {
                TRCERR("Security descriptor too big");
                TRCE();
                return CM_RP_FAULTACCESSDENIED;
            }
        }
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
        break;
    case 1005:
        /* do nothing */
        break;
    default:
        TRCERR("Unsupported info level");
        TRC1P(" info level: %ld", infoLevel);
        TRCE();
        return CM_RP_UNKNOWNLEVEL;
    }

    return 0;
}

/*====================================================================
 * PURPOSE: convert share path from network to local form
 *--------------------------------------------------------------------
 * PARAMS:  IN network path
 *
 * RETURNS: local path
 *
 * NOTES:
 *====================================================================
 */

static NQ_WCHAR*
pathNetworkToLocal(
    NQ_WCHAR* path
    )
{
	NQ_WCHAR* pc;           									/* pointer in path */
	const NQ_WCHAR wrongSeparator = cmWChar(SY_PATHSEPARATOR == '/'? '\\':'/');
	NQ_WCHAR name[3] = {cmWChar(0), cmWChar('$'), cmWChar(0)};  /* buffer for hidden admin share name */
        
    syWStrcpy(staticData->shareMapW, path);
        
#ifndef SY_DRIVELETTERINPATH
    if (cmWStrlen(path) > 1 && path[1] == cmWChar(':'))
    {
        if (csHasAdminShare())
        {
            /* convert path of form 'C:\folder' into local path */
            /* for example 'C:\folder' -> '/ata0a/folder'  */
            name[0] = path[0];
            syWStrcpy(staticData->shareMapW, csGetShareByName(name)->map);
            if (staticData->shareMapW[cmWStrlen(staticData->shareMapW) - 1] == cmWChar(SY_PATHSEPARATOR))
                staticData->shareMapW[cmWStrlen(staticData->shareMapW) - 1] = 0;
            path += 2;
            cmWStrcat(staticData->shareMapW, path);
        }
        else
        {
            path += 2;
            syWStrcpy(staticData->shareMapW, path);
        }
    }
   
#endif /* SY_DRIVELETTERINPATH */

    /* convert path separators into local */
    
    pc = staticData->shareMapW;
    for (;;)
	{
		pc = cmWStrchr(pc, wrongSeparator);
		if (NULL == pc)
			break;
		*pc++ = cmWChar(SY_PATHSEPARATOR);
	}
    return staticData->shareMapW;
}

/*====================================================================
 * PURPOSE: convert share path from local to network form
 *--------------------------------------------------------------------
 * PARAMS:  IN share
 *
 * RETURNS: network path
 *
 * NOTES:
 *====================================================================
 */

static NQ_WCHAR*
pathLocalToNetwork(
    CSShare *share
    )
{    
#ifdef SY_DRIVELETTERINPATH
    return share->map;
#else
	NQ_WCHAR path[] = {cmWChar(0), cmWChar(':'), cmWChar('\\'), cmWChar(0)};
    CSShare *hidden;  /* pointer to hidden administrative share */
    NQ_WCHAR *p, *t;  /* pointers in path */

    if (csHasAdminShare())
    {
        /* construct share path of form C:\folder, omitting local file system root */
        /* for example '/ata0a/folder' -> 'C:\folder'   */
        if (share->isHidden)
        {
            path[0] = share->name[0];
            syWStrcpy(staticData->shareMapW, path);
        }
        else if (share->ipcFlag)
        {
        	syAnsiToUnicode(staticData->shareMapW, "");
        }
        else if ((hidden = csGetHiddenShareByMap(share->map)) != NULL)
        {
            path[0] = hidden->name[0];
            syWStrcpy(staticData->shareMapW, path);
            p = share->map;
            t = hidden->map;
            while (*p != 0 && *p == *t)
            {   p++;
                t++;
            }
            if (*p != 0)
                cmWStrcat(staticData->shareMapW, p);
        }
        else    
            syWStrcpy(staticData->shareMapW, share->map);
        
        /* convert local path separators to '\\' */
        p = staticData->shareMapW;
        for (;;)
        {
            p = syWStrchr(p, '/');
            if (NULL == p)
                break;
            *p++ = cmWChar('\\');
        } 
    }
    else
    {
        /* just add 'C:' prefix to local path */
        syAnsiToUnicode(staticData->shareMapW, "C:");
        cmWStrcat(staticData->shareMapW, share->map);
    } 
   
    return staticData->shareMapW;
#endif /* SY_DRIVELETTERINPATH */   
}

/*====================================================================
 * PURPOSE: calculate response size by function code
 *--------------------------------------------------------------------
 * PARAMS:  IN function code
 *
 * RETURNS: required response size or zero to use default
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32 
checkSize(
  NQ_UINT16 code 
  )
{
    switch (code)
    {
    case 0xf:       /* ShareEnumAll */
    case 0x24:      /* ShareEnum */
        return (UD_FS_MAXSHARELEN + UD_FS_MAXPATHLEN + UD_FS_MAXDESCRIPTIONLEN + 40) * csGetSharesCount() + 20;
    default:
        return 0;
    }
}

#endif /* UD_CS_INCLUDERPC_SRVSVC */

#endif /* UD_NQ_INCLUDECIFSSERVER */

