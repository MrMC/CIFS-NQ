/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RPC definition
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Libraries
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 18-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMRPCDEF_H_
#define _CMRPCDEF_H_

#include "cmapi.h"

/*
    Structures for pipe definition
    ------------------------------

    A pipe is described by a pipe descriptor. A descriptor points to a list of
    pipe functions.
 */

/*
    DCE RPC Packets
    ---------------

    Since we parse incoming packet and pack outgoing packet, most of structures below
    are for reference only.

    All structures are packed
 */

/* Beginning of packed structures definition */

#include "sypackon.h"

/* GUID */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 timeLow;
    NQ_SUINT16 timeMid;
    NQ_SUINT16 timeHiVersion;
    NQ_SBYTE clockSeq[2];
    NQ_SBYTE node[6];
}
SY_PACK_ATTR CMRpcUuid;

/* RPC version structure */

#define cmRpcVersion(_major, _minor)    (_major + 0x10000 * _minor)

/* NULL relative reference */

#define CS_RP_NULLOFFSET 0

/* Syntax description */
typedef SY_PACK_PREFIX struct
{
	NQ_Uuid uuid;                 	/* syntax UUID */
    NQ_UINT32 interfaceVersion;     /* version */
}
SY_PACK_ATTR CMRpcDcerpcSyntaxId;

#define CM_RPC_TRANSFERSYNTAXSIGNATURE { cmPack32(0x8a885d04), cmPack16(0x1ceb), cmPack16(0x11c9),{0x9f,0xe8},{0x08,0x00,0x2b,0x10,0x48,0x60}}
#define CM_RPC_NDRVERSION 0x00000002

/* Context description. Transport syntaxes array follows the last field */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 contextId;                /* ID of this context */
    NQ_SBYTE numTransferSyntaxes;        /* number of trasfer syntaxes following this record */
    CMRpcDcerpcSyntaxId abstractSyntax;  /* transfer-independent syntax */
}
SY_PACK_ATTR CMRpcDcerpcCtxList;

#define CM_RPC_MAXNUMBEROFCONTEXTS  2

/* Bind PDU */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 maxXmitFrag;   /* maximum length of a transmit fragment */
    NQ_SUINT16 maxRecvFrag;   /* maximum length of a receive fragment */
    NQ_SUINT32 assocGroupId;  /* required association group or zero for a new one */
    NQ_SBYTE  numContexts;    /* number of contexts following this record */
}
SY_PACK_ATTR CMRpcDcerpcBind;

/* Request PDU */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 allocHint;     /* recommended space for response */
    NQ_SUINT16 contextId;     /* used context */
    NQ_SUINT16 opnum;         /* function code */
}
SY_PACK_ATTR CMRpcDcerpcRequest;

/* Purpose is unknown meanwhile */
#define CM_RP_REQUESTLENGTH  24
#define CM_RP_MAXSIGNSIZE    32

/* Accepted syntax for bin_ack */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 result;            /* result code */
    NQ_SUINT16 reason;            /* result reason for error */
    CMRpcDcerpcSyntaxId syntax;  /* syntax id */
}
SY_PACK_ATTR CMRpcDcerpcAckCtx;

/* result values, any non zero will be error */
#define CM_RP_ACCEPTANCE        0
#define CM_RP_USERREJECTION     1
#define CM_RP_PROVIDERREJECTION 2

/* Bind_ack PDU, this record is followed by secondary address, and response record  */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 maxXmitFrag;       /* maximum length of a transmit fragment */
    NQ_SUINT16 maxRecvFrag;       /* maximum length of a receive fragment */
    NQ_SUINT32 assocGroupId;      /* generated or existing association group id */
}
SY_PACK_ATTR CMRpcDcerpcBindAck;

/* Bind_nak PDU */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 rejectReason;      /* error code */
    NQ_SUINT32 numVersions;       /* supported versions follow this field */
}
SY_PACK_ATTR CMRpcDcerpcBindNak;

/* reason values */
#define CM_RP_REASONREASONNOTSPECIFIED          0
#define CM_RP_REASONABSTRACTSYNTAXNOTSUPPORTED  1
#define CM_RP_REASONTRANSFERSYNTAXNOTSUPPORTED  2
#define CM_RP_REASONLOCALLIMITEXCEEDED          3
#define CM_RP_REASONPROTOCOLVERSIONNOTSUPPORTED 4


/* Response PDU */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 allocHint;     /* recommended space for next request */
    NQ_SUINT16 contextId;     /* context used */
    NQ_SBYTE cancelCount;     /* should be zero for response */
}
SY_PACK_ATTR RPDcerpcResponse;

/* Fault PDU */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 allocHint;     /* recommended space for next request */
    NQ_SUINT16 contextId;     /* context used */
    NQ_SBYTE cancelCount;     /* should be non-zero */
    NQ_SUINT32 status;        /* error code, may be zero for function exception */
}
SY_PACK_ATTR CMRpcDcerpcFault;

/* Status values */
/* generic: */
#define CM_RP_FAULTVERSIONMISMATCH  0x1c000008
#define CM_RP_FAULTREJECT           0x1c000009
#define CM_RP_FAULTBADACTID         0x1c00000a
#define CM_RP_FAULTWHOAREYOU        0x1c00000b
#define CM_RP_FAULTMANAGER          0x1c00000c
#define CM_RP_FAULTOPRNGERROR       0x1c010002
#define CM_RP_FAULTUNKIF            0x1c010003
#define CM_RP_FAULTINVALIDTAG       0x1c000006
#define CM_RP_FAULTCONTEXTMISMATCH  0x1c00001a
#define CM_RP_FAULTOTHER            0x00000001
#define CM_RP_FAULTLOGONFAILURE     0xc0000005
#define CM_RP_FAULTACCESSDENIED     0x00000005
#define CM_RP_FAULTNOLEVEL          0xc0000003
#define CM_RP_FAULTNDR              0x000006f7
#define CM_RP_FAULTUNSUPPORTED      0xc0000032
#define CM_RP_FILENOTFOUND          0x00000002
#define CM_RP_OUTOFMEMORY           0x00000008
#define CM_RP_INVALIDFID            0x00000006
#define CM_RP_INSUFFICIENTRESOURCE  0xc000009a

/* function internal: */
#define CM_RP_FAULTOBJECTNOTFOUND      0x1c000024
#define CM_RP_FAULTCALLCANCELLED       0x1c00000d
#define CM_RP_FAULTADDRERROR           0x1c000002
#define CM_RP_FAULTCONTEXTMISMATCH     0x1c00001a
#define CM_RP_FAULTFPDIVBYZERO         0x1c000003
#define CM_RP_FAULTFPERROR             0x1c00000f
#define CM_RP_FAULTFPOVERFLOW          0x1c000005
#define CM_RP_FAULTFPUNDERFLOW         0x1c000004
#define CM_RP_FAULTILLINST             0x1c00000e
#define CM_RP_FAULTINTDIVBYZERO        0x1c000001
#define CM_RP_FAULTINTOVERFLOW         0x1c000010
#define CM_RP_FAULTINVALIDBOUND        0x1c000007
#define CM_RP_FAULTINVALIDTAG          0x1c000006
#define CM_RP_FAULTPIPECLOSED          0x1c000015
#define CM_RP_FAULTPIPECOMMERROR       0x1c000018
#define CM_RP_FAULTPIPEDISCIPLINE      0x1c000017
#define CM_RP_FAULTPIPEEMPTY           0x1c000014
#define CM_RP_FAULTPIPEMEMORY          0x1c000019
#define CM_RP_FAULTPIPEORDER           0x1c000016
#define CM_RP_FAULTREMOTENOMEMORY      0x1c00001b
#define CM_RP_FAULTUSERDEFINED         0x1c000021
#define CM_RP_FAULTTXOPENFAILED        0x1c000022
#define CM_RP_FAULTCODESETCONVERROR    0x1c000023
#define CM_RP_FAULTNOCLIENTSTUB        0x1c000025
#define CM_RP_FAULTNONEMAPPED          0xc0000073
#define CM_RP_FAULTSOMENOTMAPPED       0x00000107
#define CM_RP_FAULTINVALIDPRINTERNAME  0x00000709
#define CM_RP_INSUFFICIENTBUFFER       0x0000007a
#define CM_RP_UNKNOWNLEVEL             0x0000007C
#define CM_RP_FAULTNAMENOTFOUND        0x00000906
#define CM_RP_FAULTSESSIONNOTFOUND     0x00000908
#define CM_RP_FAULTINVALIDPARAMETER    0x00000057
#define CM_RP_SERVER_UNAVAILABLE       0x000006ba


/* Auth PDU */
typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE  authType;              /* authentication type */
    NQ_SBYTE  authLevel;             /* authentication level */
    NQ_SBYTE  authPadLength;         /* padding length */
    NQ_SBYTE  authReserved;          /* not used */
    NQ_SBYTE  authContextId;         /* context used */
}
SY_PACK_ATTR CMRpcDcerpcAuth;

/* authType values */
#define CM_RP_AUTHTYPENONE     0
#define CM_RP_AUTHTYPEKRB5     1
#define CM_RP_AUTHTYPESPNEGO   9
#define CM_RP_AUTHTYPENTLMSSP  10
#define CM_RP_AUTHTYPEKRB5_16  16
#define CM_RP_AUTHTYPESCHANNEL 68

/* authLevel values */
#define CM_RP_AUTHLEVELNONE      1
#define CM_RP_AUTHLEVELCONNECT   2
#define CM_RP_AUTHLEVELCALL      3
#define CM_RP_AUTHLEVELPACKET    4
#define CM_RP_AUTHLEVELINTEGRITY 5
#define CM_RP_AUTHLEVELPRIVACY   6

/* Auth3 PDU */
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 pad;      /* not used */
}
SY_PACK_ATTR CMRpcDcerpcAuth3;

/* RPC versions */

#define CM_RP_MAJORVERSION 5
#define CM_RP_MINORVERSION 0

/* packet type values */

#define CM_RP_PKT_REQUEST     0
#define CM_RP_PKT_PING        1
#define CM_RP_PKT_RESPONSE    2
#define CM_RP_PKT_FAULT       3
#define CM_RP_PKT_WORKING     4
#define CM_RP_PKT_NOCALL      5
#define CM_RP_PKT_REJECT      6
#define CM_RP_PKT_ACK         7
#define CM_RP_PKT_CLCANCEL    8
#define CM_RP_PKT_FACK        9
#define CM_RP_PKT_CANCELACK   10
#define CM_RP_PKT_BIND        11
#define CM_RP_PKT_BINDACK     12
#define CM_RP_PKT_BINDNAK     13
#define CM_RP_PKT_ALTER       14
#define CM_RP_PKT_ALTERACK    15
#define CM_RP_PKT_AUTH3       16
#define CM_RP_PKT_SHUTDOWN    17
#define CM_RP_PKT_COCANCEL    18
#define CM_RP_PKT_ORPHANED    19

/* pfcFlags values */

#define CM_RP_PFCFLAG_FIRST  0x01
#define CM_RP_PFCFLAG_LAST   0x02
#define CM_RP_PFCFLAG_NOCALL 0x20

/* these offsets are needed by the signing code */

#define CM_RP_DREPOFFSET     4
#define CM_RP_FRAGLENOFFSET  8
#define CM_RP_AUTHLENOFFSET  10

/* little-endian flag */

#define CM_RP_DREPLE         0x10

#include "sypackof.h"

/* End of packed structures definition */

/* Policy handle */
typedef struct {
    NQ_UINT32 id;
    CMRpcUuid uuid;
}
CMRpcPolicyHandle;

/* Data representation field */
typedef struct
{
    NQ_BYTE flags;          /* LE and ASCII flags */
    NQ_BYTE fp;             /* float point representation */
    NQ_UINT16 pad;          /* padding */
}
CMRpcDcerpcDataRepresentation;

typedef struct
{
    NQ_BYTE rpcVers;                   /* RPC version */
    NQ_BYTE rpcVersMinor;              /* minor version */
    NQ_BYTE packetType;                /* packet type */
    NQ_BYTE pfcFlags;                  /* fragmentation flags */
    CMRpcDcerpcDataRepresentation drep;/* NDR data representation */
    NQ_UINT16 fragLength;              /* Total length of fragment */
    NQ_UINT16 authLength;              /* authenticator length */
    NQ_UINT32 callId;                  /* Call identifier */
}
CMRpcDcerpcPacket;

/*
    Definitions and macros for parsing incoming packets and
    packing outgoing packets
    -------------------------------------------------------
 */

typedef struct      /* packet descriptor used for parsing/packing */
{
    NQ_BYTE* token;         /* token of a user responsible for this packet results */
    NQ_BYTE* current;       /* pointer to the current position in the packet */
    NQ_BOOL nbo;            /* TRUE when packet is in NBO, FALSE when in LBO */
    NQ_BYTE* origin;        /* pointer to the original start of the packet, points to */
                            /* the beginning of the portion to be parsed/packed */
    NQ_UINT length;         /* number of bytes in the packet */
    NQ_BYTE* user;          /* user structure pointer  */
    NQ_UINT32 callId;       /* unique call number */
}
CMRpcPacketDescriptor;

typedef struct      /* Unicode string descriptor. Any unicode string is converted to this
                       form */
{
    NQ_UINT32 size;     /* total string size */
    NQ_UINT32 offset;   /* fragment offset */
    NQ_UINT32 length;   /* fragment length */
    NQ_WCHAR* text;     /* string text */
}
CMRpcUnicodeString;

typedef struct      /* Ascii string descriptor. Any ascii string is converted to this
                       form */
{
    NQ_UINT32 size;     /* total string size */
    NQ_UINT32 offset;   /* fragment offset */
    NQ_UINT32 length;   /* fragment length */
    NQ_CHAR*  text;     /* string text */
}
CMRpcAsciiString;

/*
   --- Types of (packed) unicode and ascii strings ---
 */

#define CM_RP_NULLTERM     1       /* string is null-terminated */
#define CM_RP_SIZE32       2       /* string is prefixed by 32-bit size */
#define CM_RP_SIZE16       4       /* string is prefixed by 16-bit size */
#define CM_RP_FRAGMENT32   8       /* string is prefixed by offset and length, all 32 bits */
#define CM_RP_INCMAXCOUNT  16      /* make string's max count = actual count + 1 */
#define CM_RP_DECACTCOUNT  32      /* make string's actual count = max count - 1 */

/* security_descriptor flags */

#define CM_RP_SD_OWNERDEFAULTED     0x0001
#define CM_RP_SD_GROUPDEFAULTED     0x0002
#define CM_RP_SD_DACLPRESENT        0x0004
#define CM_RP_SD_DACLDEFAULTED      0x0008
#define CM_RP_SD_SACLPRESENT        0x0010
#define CM_RP_SD_SACLDEFAULTED      0x0020
#define CM_RP_SD_DACLTRUSTED        0x0040
#define CM_RP_SD_SERVERSECURITY     0x0080
#define CM_RP_SD_DACLAUTOINHERITREQ 0x0100
#define CM_RP_SD_SACLAUTOINHERITREQ 0x0200
#define CM_RP_SD_DACLAUTOINHERITED  0x0400
#define CM_RP_SD_SACLAUTOINHERITED  0x0800
#define CM_RP_SD_DACLPROTECTED      0x1000
#define CM_RP_SD_SACLPROTECTED      0x2000
#define CM_RP_SD_RM_CONTROL_VALID   0x4000
#define CM_RP_SD_SELF_RELATIVE      0x8000

/*
    Parsing primitives
 */

/* a UCS2 string prefixed with [size] [offset] [length], all 32 bits not null terminated */
#define CM_RP_UNISIZEFRAG      (CM_RP_SIZE32 | CM_RP _FRAGMENT32)
/* a UCS2 string prefixed with [size] [offset] [length], all 32 bits */
#define CM_RP_UNISIZEFRAG0     (CM_RP _SIZE32 | CM_RP _FRAGMENT32 | CM_RP _NULLTERM)
/* a UCS2 string prefixed with [size], 32 bits */
#define CM_RP_UNISIZE          (CM_RP _SIZE32 | CM_RP _FRAGMENT32)
/* a null terminated UCS2 string */
#define CM_RP_UNI0             (CM_RP_NULLTERM)
/* an ascii string prefixed with [offset] [length], both 32 bits null terminated */
#define CM_RP_ASCFRAG0         (CM_RP _FRAGMENT32 | CM_RP _NULLTERM)
/* an ascii string prefixed with [size], 16 bits null terminated */
#define CM_RP_ASCSIZE160       (CM_RP _SIZE16 | CM_RP _NULLTERM)
/* an ascii string prefixed with [size] [offset] [length], all 32 bits not null terminated */
#define CM_RP_ASCSIZEFRAG      (CM_RP _SIZE32 | CM_RP _FRAGMENT32)
/* a null terminated ascii string */
#define CM_RP_ASC0             (CM_RP _NULLTERM)

void
cmRpcSetDescriptor(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pData,
    NQ_BOOL nbo
    );

void
cmRpcSetTokenDescriptor(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pData,
    NQ_BOOL nbo,
    NQ_BYTE *token
    );

void
cmRpcCloneDescriptor(
    CMRpcPacketDescriptor *pSrc,
    CMRpcPacketDescriptor *pDst
    );

void
cmRpcResetDescriptor(
    CMRpcPacketDescriptor *pDesc
    );

void
cmRpcParseByte(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pRes
    );

void
cmRpcParseUint16(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT16 *pRes
    );

void
cmRpcParseUint32(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 *pRes
    );

void
cmRpcParseUnicode(
    CMRpcPacketDescriptor *pDesc,
    CMRpcUnicodeString *pRes,
    NQ_UINT16 flags
    );

void
cmRpcParseAscii(
    CMRpcPacketDescriptor *pDesc,
    CMRpcAsciiString *pRes,
    NQ_UINT16 flags
    );

void
cmRpcParseBytes(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE *pRes,
    NQ_UINT32 num
    );

void
cmRpcParseSkip(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 num
    );

void
cmRpcAllign(
    CMRpcPacketDescriptor *pDesc,
    NQ_INT align
    );

void
cmRpcParseUuid(
    CMRpcPacketDescriptor *pDesc,
    CMRpcUuid *pUuid
    );

void
cmRpcPackByte(
    CMRpcPacketDescriptor *pDesc,
    NQ_BYTE src
    );

void
cmRpcPackUint16(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT16 src
    );

void
cmRpcPackUint32(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 src
    );

void
cmRpcPackUint64(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 low,
    NQ_UINT32 high
    );

void cmRpcPackTimeAsUTC(
    CMRpcPacketDescriptor *pDesc,
    NQ_TIME time
    );

void
cmRpcPackUnicode(
    CMRpcPacketDescriptor *pDesc,
    const NQ_WCHAR *str,
    NQ_UINT16 flags
    );

void
cmRpcPackAscii(
    CMRpcPacketDescriptor *pDesc,
    const NQ_CHAR *str,
    NQ_UINT16 flags
    );

void
cmRpcPackBytes(
    CMRpcPacketDescriptor *pDesc,
    const NQ_BYTE *pRes,
    NQ_UINT32 num
    );

void
cmRpcPackSkip(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT32 num
    );

void
cmRpcAllignZero(
    CMRpcPacketDescriptor *pDesc,
    NQ_UINT16 align
    );

void
cmRpcPackUuid(
    CMRpcPacketDescriptor *pDesc,
    const CMRpcUuid *pUuid
    );

#define cmRpcUuidRead(_reader, _uuid) cmRpcParseUuid(_reader, _uuid)
#define cmRpcUuidWrite(_writer, _uuid) cmRpcPackUuid(_writer, _uuid)

NQ_UINT32 cmRpcSpace(CMRpcPacketDescriptor *pDesc);

NQ_UINT32 cmRpcPackAsciiAsUnicode(
    CMRpcPacketDescriptor * desc,
    const NQ_CHAR * source,
    NQ_INT flags
    );

NQ_UINT32 cmRpcPackTcharAsUnicode(
    CMRpcPacketDescriptor * desc,
    const NQ_TCHAR * source,
    NQ_INT flags
    );

NQ_UINT32 cmRpcTcharAsUnicodeLength(
    const NQ_TCHAR* source
    );

#endif  /* _CMRPCDEF_H_ */

