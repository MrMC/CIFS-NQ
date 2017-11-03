/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : WKSSVS pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cswkssvc.h"

#include "csdataba.h"

#ifdef UD_CS_INCLUDERPC_WKSSVC

#ifndef UD_CS_INCLUDERPC
#error illegal combination of parametsrs UD_CS_INCLUDERPC_WKSSVC (defined) and UD_CS_INCLUDERPC (not defined)
#endif

/*
    Static data and definitions
    ---------------------------
 */

/* packet sizes - maximum packet sizes not including strings */

#define NETWKSTAGETINFO_ENTRYSIZE   56

/* pipe function prototypes */

/* static NQ_UINT32 srvsvcNetCharDevEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 wkssvcNetWkstaGetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 wkssvcNetWkstaSetInfo(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRWKSTAUSERENUM(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRWKSTAUSERGETINFO(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRWKSTAUSERSETINFO(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
static NQ_UINT32 wkssvcNetWkstaTransportEnum(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/* static NQ_UINT32 WKSSVCNETRWKSTATRANSPORTADD(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRWKSTATRANSPORTDEL(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRUSEADD(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRUSEGETINFO(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRUSEDEL(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRUSEENUM(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRMESSAGEBUFFERSEND(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRWORKSTATIONSTATISTICSGET(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRLOGONDOMAINNAMEADD(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRLOGONDOMAINNAMEDEL(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRJOINDOMAIN(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRUNJOINDOMAIN(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRRENAMEMACHINEINDOMAIN(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRVALIDATENAME(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRGETJOININFORMATION(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRGETJOINABLEOUS(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRJOINDOMAIN2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRUNJOINDOMAIN2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRRENAMEMACHINEINDOMAIN2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRVALIDATENAME2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRGETJOINABLEOUS2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRADDALTERNATECOMPUTERNAME(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRREMOVEALTERNATECOMPUTERNAME(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRSETPRIMARYCOMPUTERNAME(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */
/* static NQ_UINT32 WKSSVCNETRENUMERATECOMPUTERNAMES(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out); */

static const CSRpcFunctionDescriptor functions[] =
{
    { wkssvcNetWkstaGetInfo                             /* 0x00 */ },
    { NULL /* wkssvcNetWkstaSetInfo */                  /* 0x01 */ },
    { NULL /* WKSSVCNETRWKSTAUSERENUM */                /* 0x02 */ },
    { NULL /* WKSSVCNETRWKSTAUSERGETINFO */             /* 0x03 */ },
    { NULL /* WKSSVCNETRWKSTAUSERSETINFO */             /* 0x04 */ },
    { wkssvcNetWkstaTransportEnum                       /* 0x05 */ },
    { NULL /* WKSSVCNETRWKSTATRANSPORTADD */            /* 0x06 */ },
    { NULL /* WKSSVCNETRWKSTATRANSPORTDEL */            /* 0x07 */ },
    { NULL /* WKSSVCNETRUSEADD */                       /* 0x08 */ },
    { NULL /* WKSSVCNETRUSEGETINFO */                   /* 0x08 */ },
    { NULL /* WKSSVCNETRUSEDEL */                       /* 0x0a */ },
    { NULL /* WKSSVCNETRUSEENUM */                      /* 0x0b */ },
    { NULL /* WKSSVCNETRMESSAGEBUFFERSEND */            /* 0x0c */ },
    { NULL /* WKSSVCNETRWORKSTATIONSTATISTICSGET */     /* 0x0d */ },
    { NULL /* WKSSVCNETRLOGONDOMAINNAMEADD */           /* 0x0e */ },
    { NULL /* WKSSVCNETRLOGONDOMAINNAMEDEL */           /* 0x0f */ },
    { NULL /* WKSSVCNETRJOINDOMAIN */                   /* 0x10 */ },
    { NULL /* WKSSVCNETRUNJOINDOMAIN */                 /* 0x11 */ },
    { NULL /* WKSSVCNETRRENAMEMACHINEINDOMAIN */        /* 0x12 */ },
    { NULL /* WKSSVCNETRVALIDATENAME */                 /* 0x13 */ },
    { NULL /* WKSSVCNETRGETJOININFORMATION */           /* 0x14 */ },
    { NULL /* WKSSVCNETRGETJOINABLEOUS */               /* 0x15 */ },
    { NULL /* WKSSVCNETRJOINDOMAIN2 */                  /* 0x16 */ },
    { NULL /* WKSSVCNETRUNJOINDOMAIN2 */                /* 0x17 */ },
    { NULL /* WKSSVCNETRRENAMEMACHINEINDOMAIN2 */       /* 0x18 */ },
    { NULL /* WKSSVCNETRVALIDATENAME2 */                /* 0x19 */ },
    { NULL /* WKSSVCNETRGETJOINABLEOUS2 */              /* 0x1a */ },
    { NULL /* WKSSVCNETRADDALTERNATECOMPUTERNAME */     /* 0x1b */ },
    { NULL /* WKSSVCNETRREMOVEALTERNATECOMPUTERNAME */  /* 0x1c */ },
    { NULL /* WKSSVCNETRSETPRIMARYCOMPUTERNAME */       /* 0x1d */ },
    { NULL /* WKSSVCNETRENUMERATECOMPUTERNAMES */       /* 0x1e */ }
};

static const CSRpcPipeDescriptor pipeDescriptor =
{
  NULL,
  NULL,
  NULL,
  "wkssvc",
  {cmPack32(0x6bffd098),cmPack16(0xa112),cmPack16(0x3610),{0x98,0x33},{0x46,0xc3,0xf8,0x7e,0x34,0x5a}},
  cmRpcVersion(1, 0),
  (sizeof(functions) / sizeof(functions[0])),
  functions
};

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
csRpcWkssvc(
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

/* Get workstation information */

static NQ_UINT32
wkssvcNetWkstaGetInfo (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString hostName;    /* requested workstation name */
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_UINT32 referentId;           /* running number */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &hostName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);

    TRC1P("info level: %ld", infoLevel);

    /* check space according to the largest variant */

    CS_RP_CHECK(out, NETWKSTAGETINFO_ENTRYSIZE);

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
        cmRpcPackUint32(&outTemp, 500);     /* unknown platform */
        cmRpcPackUint32(&outTemp, referentId++);     /* workstation name */
        cmRpcPackUint32(&outTemp, referentId++);     /* domain name */
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMINOR);
        break;
    case 101:
        cmRpcPackUint32(&outTemp, 500);     /* unknown platform */
        cmRpcPackUint32(&outTemp, referentId++);     /* workstation name */
        cmRpcPackUint32(&outTemp, referentId++);     /* domain name */
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMINOR);
        cmRpcPackUint32(&outTemp, referentId++);     /* lan root */
        break;
    case 102:
        cmRpcPackUint32(&outTemp, 500);     /* unknown platform */
        cmRpcPackUint32(&outTemp, referentId++);     /* workstation name */
        cmRpcPackUint32(&outTemp, referentId++);     /* domain name */
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMAJOR);
        cmRpcPackUint32(&outTemp, CM_SOFTWAREVERSIONMINOR);
        cmRpcPackUint32(&outTemp, referentId++);     /* lan root */
        cmRpcPackUint32(&outTemp, 0);     /* logged on users */
        break;
    default:
        TRCERR("Unknown info level");
        TRC1P(" value: %ld", infoLevel);

        TRCE();
        return CM_RP_FAULTUSERDEFINED;
    }

    /* add referred data */
    switch (infoLevel)
    {
    case 100:
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, cmNetBiosGetHostNameZeroed(), CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, cmNetBiosGetDomain()->name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        break;
    case 101:
    case 102:
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, cmNetBiosGetHostNameZeroed(), CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, cmNetBiosGetDomain()->name, CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, "", CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        break;
    }

    out->current = savedPtr;    /* advance the original descriptor */
    cmRpcPackUint32(out, 1);    /* a referral instead of null */
    out->current = outTemp.current;    /* advance the original descriptor */
    TRCE();
    return 0;
}

/* Enumerate transports */

static NQ_UINT32
wkssvcNetWkstaTransportEnum (
    CMRpcPacketDescriptor* in,
    CMRpcPacketDescriptor* out
    )
{
    CMRpcUnicodeString hostName;    /* requested workstation name */
    NQ_UINT32 infoLevel;            /* requested information level */
    CMRpcPacketDescriptor outTemp;  /* this descriptor creates actual output,
                                       on error it will be discarded, on success
                                       its pointer will be copied into "out" */
    NQ_BYTE* savedPtr;              /* saved pointer to the entry referral */
    NQ_UINT32 referentId;           /* running number */

    TRCB();

    /* parse input parameters */

    cmRpcParseSkip(in, 4);
    cmRpcParseUnicode(in, &hostName, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    cmRpcParseUint32(in, &infoLevel);

    TRC1P("info level: %ld", infoLevel);

    /* check space according to the largest variant */

    CS_RP_CHECK(out, NETWKSTAGETINFO_ENTRYSIZE);

    /* prepare results */

    referentId = 2;                         /* an arbitrary value ??? */

    /* pack the result header */

    cmRpcPackUint32(out, infoLevel);
    cmRpcPackUint32(out, infoLevel);
    savedPtr = out->current;
    cmRpcPackUint32(out, 0);                /* null pointer meanwhile */
    cmRpcCloneDescriptor(out, &outTemp);
    cmRpcPackUint32(&outTemp, 1);                /* num entries */

    /* switch by info level */

    switch (infoLevel)
    {
    case 0:
        cmRpcPackUint32(&outTemp, referentId++);    /* entry */
        cmRpcPackUint32(&outTemp, 1);               /* max count */
        cmRpcPackUint32(&outTemp, 0x0000ffff);      /* quality of service */
        cmRpcPackUint32(&outTemp, 0);               /* num of VCs */
        cmRpcPackUint32(&outTemp, referentId++);    /* transport name */
        cmRpcPackUint32(&outTemp, referentId++);    /* transport address */
        cmRpcPackUint32(&outTemp, 0x00000400);      /* WAN ish */
        break;
    default:
        TRCERR("Unknown info level");
        TRC1P(" value: %ld", infoLevel);

        TRCE();
        return CM_RP_FAULTUSERDEFINED;
    }

    /* add referred data */
    switch (infoLevel)
    {
    case 0:
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, "\\Device\\NetbiosSmb", CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        CS_RP_CALL(cmRpcPackAsciiAsUnicode(&outTemp, "000000000000", CM_RP_SIZE32 | CM_RP_FRAGMENT32 | CM_RP_NULLTERM));
        break;
    }

    cmRpcPackUint32(&outTemp, 1);   /* total entries */
    cmRpcPackUint32(&outTemp, 0);   /* resume handle */
    out->current = savedPtr;        /* advance the original descriptor */
    cmRpcPackUint32(out, 1);        /* a referral instead of null */
    out->current = outTemp.current; /* advance the original descriptor */
    TRCE();
    return 0;
}

#endif /* UD_CS_INCLUDERPC_WKSSVC */
