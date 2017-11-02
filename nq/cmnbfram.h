/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Definition of NetBIOS frames as in RFC 1002
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMNBFRAM_H_
#define _CMNBFRAM_H_

#include "cmapi.h"
#include "cmnbvisu.h"

/* Beginning of packed structures definition */

#include "sypackon.h"

/*
    *************************
    *                       *
    *   NAMING SERVICE      *
    *                       *
    *************************

    A NetBIOS Naming Service package looks as follows:

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   + ------                                                ------- +
   |                            HEADER                             |
   + ------                                                ------- +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                       QUESTION ENTRIES                        /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                    ANSWER RESOURCE RECORDS                    /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                  AUTHORITY RESOURCE RECORDS                   /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                  ADDITIONAL RESOURCE RECORDS                  /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Packet Header
    -------------
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 tranID;      /* name transaction ID */
    NQ_SUINT16 packCodes;   /* OPCODE, NM_FLAGS and RCODE */
    NQ_SUINT16 qdCount;     /* number of Question Entries */
    NQ_SUINT16 anCount;     /* number of resource records in the Answer section */
    NQ_SUINT16 nsCount;     /* number of resource records in the Authority section */
    NQ_SUINT16 arCount;     /* number of resource records in the Additional Resource section */
} SY_PACK_ATTR
CMNetBiosHeader;

/*
    OPCODE
 */

#define CM_NB_RESPONSE      (1<<15)                 /* packet is response */
#define _OPCODE_SHIFT       11                      /* for defining opcodes */
#define CM_NB_OPCODE        (0xF<<_OPCODE_SHIFT)    /* opcode bits */

#define CM_NB_OPCODE_QUERY          0<<_OPCODE_SHIFT    /* standard query */
#define CM_NB_OPCODE_REGISTRATION   5<<_OPCODE_SHIFT    /* registration */
#define CM_NB_OPCODE_RELEASE        6<<_OPCODE_SHIFT    /* release name */
#define CM_NB_OPCODE_WACK           7<<_OPCODE_SHIFT    /* wait for acknowledgement */
#define CM_NB_OPCODE_REFRESH        8<<_OPCODE_SHIFT    /* refresh registration */
#define CM_NB_OPCODE_REFRESHALT     9<<_OPCODE_SHIFT    /* refresh registration (alternate opcode) */
#define CM_NB_OPCODE_MHREGISTRATION 15<<_OPCODE_SHIFT   /* multi-homed registration */

/*
    NM_FLASG (NB_FLAGS):
 NM_FLAGS of the header and NB_FLASG of an Addr Entry have the same bitset.
 Some bits are relevant for a response only
 */

#define CM_NB_NAMEFLAGS_G       (1<<15) /* group name flag */
#define CM_NB_NAMEFLAGS_ONT     (3<<13) /* bits for node type */
#define CM_NB_NAMEFLAGS_ONT_B   (0<<13) /* B-mode node */
#define CM_NB_NAMEFLAGS_ONT_P   (1<<13) /* P-mode node */
#define CM_NB_NAMEFLAGS_ONT_M   (2<<13) /* M-mode node */
#define CM_NB_NAMEFLAGS_DRG     (1<<12) /* name is being deregistered */
#define CM_NB_NAMEFLAGS_CNF     (1<<11) /* name is in conflict */
#define CM_NB_NAMEFLAGS_ACT     (1<<10) /* name is active */
#define CM_NB_NAMEFLAGS_PRM     (1<<9)  /* name is permanent node name */
#define CM_NB_NAMEFLAGS_AA     (1<<10)  /* response is authoritative */
#define CM_NB_NAMEFLAGS_TC     (1<<9)   /* response is truncated */
#define CM_NB_NAMEFLAGS_RD     (1<<8)   /* recursion desired */
#define CM_NB_NAMEFLAGS_RA     (1<<7)   /* recursion available */
#define CM_NB_NAMEFLAGS_B      (1<<4)   /* broadcast/multicast packet */

/*
    RDCODE:
 */

#define CM_NB_RCODE         (0xF<<0)        /* reply code */
#define CM_NB_RCODE_NOERR    0x0000         /* positive response */
#define CM_NB_RCODE_FMTERR   0x0001         /* format error */
#define CM_NB_RCODE_SRVFAIL  0x0002         /* server fail to complete */
#define CM_NB_RCODE_NAMERR   0x0003         /* name error */
#define CM_NB_RCODE_NOTIMPL  0x0004         /* service not implemented */
#define CM_NB_RCODE_REFUSED  0x0005         /* server refused */
#define CM_NB_RCODE_ACTIVE   0x0006         /* active */
#define CM_NB_RCODE_CONFLICT 0x0007         /* name in conflict */

#define CM_NB_RCODE_MASK    0xf             /* mask for RCODE */

/*
    Common values
    -------------
 These values are used in different fields, yet have the same values

    Classes
*/

#define CM_NB_RCLASS_IN 0x0001     /* Internet class */

#define CM_NB_RTYPE_A       0x0001  /* IP address Resource Record (See REDIRECT NAME QUERY RESPONSE) */
#define CM_NB_RTYPE_NS      0x0002  /* Name Server Resource Record (See REDIRECT NAME QUERY RESPONSE) */
#define CM_NB_RTYPE_NULL    0x000A  /* NULL Resource Record (See WAIT FOR ACKNOWLEDGEMENT RESPONSE) */
#define CM_NB_RTYPE_NB      0x0020  /* NetBIOS general Name Service Resource Record (See NB_FLAGS and NB_ADDRESS, below) */
#define CM_NB_RTYPE_NBSTAT  0x0021  /* NetBIOS NODE NQ_STATUS Resource Record (See NODE NQ_STATUS RESPONSE) */

/*
    Question Entry
    --------------
 Since name is variable-length we define only fields following it

 */

typedef SY_PACK_PREFIX struct  /* fields following the name */
{
    NQ_SUINT16 questionType;    /* question tupe */
    NQ_SUINT16 questionClass;   /* question class */
} SY_PACK_ATTR
CMNetBiosQuestion;

/*
    Resource Record
    ---------------
 Since name is variable-length we define only fields following it

 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 rrType;          /* record type */
    NQ_SUINT16 rrClass;         /* record class */
    NQ_SUINT32 ttl;             /* time-to-live */
    NQ_SUINT16 rdLength;        /* length of the resource data */
                            /* From here the rr data starts.
                               This 16-bit field is all we need for the NB record
                               type (RR_TYPE) */
} SY_PACK_ATTR
CMNetBiosResourceRecord;

/*
    Name offset pointer
    -------------------
 This format applies to an NB name that is a pointer to a prevously specified name

 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16  offset;     /* Offset to name bits 6,7 should be set */
} SY_PACK_ATTR
CMNetBiosNameOffset;
#define CM_NB_NAMEOFFSET    (3<<6)  /* Bits 6,7 in the 1st byte of a name indicate that next
                                       14 bits are offset to the original name */

/*
    ADDR ENTRY
    ----------

 This format applies to:
    NAME REGISTRATION REQUEST
    NAME OVERWRITE REQUEST & DEMAND
    NAME REFRESH REQUEST
    POSITIVE NAME REGISTRATION RESPONSE
    NEGATIVE NAME REGISTRATION RESPONSE
    END-NODE CHALLENGE REGISTRATION RESPONSE
    NAME CONFLICT DEMAND
    NAME RELEASE REQUEST & DEMAND
    POSITIVE NAME RELEASE RESPONSE
    NEGATIVE NAME RELEASE RESPONSE

 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16  flags;        /* flags - see above */
    NQ_SUINT32  ip;           /* IP address to bind to the name */
} SY_PACK_ATTR
CMNetBiosAddrEntry;

/*
    Packet codes
    ------------
 */

#define CM_NB_NAMEREGISTRATIONREQUEST   (CM_NB_OPCODE_REGISTRATION | CM_NB_NAMEFLAGS_RD)
#define CM_NB_NAMERELEASEREQUEST        (CM_NB_OPCODE_RELEASE)
#define CM_NB_NAMEQUERYREQUEST          (CM_NB_OPCODE_QUERY)

/*
    Name Flags for NODE NQ_STATUS RESPONSE
    -----------------------------------
 */

#define CM_NB_NAMESTATUS_PRM    0x200   /* Permanent Name Flag.  If one (1) then entry
                                           is for the permanent node name.  Flag is zero
                                           (0) for all other names. */
#define CM_NB_NAMESTATUS_ACT    0x400   /* Active Name Flag.  All entries have this flag
                                           set to one (1). */
#define CM_NB_NAMESTATUS_CNF    0x800   /* Conflict Flag.  If one (1) then name on this
                                           node is in conflict. */
#define CM_NB_NAMESTATUS_DRG    0x1000  /* Deregister Flag.  If one (1) then this name
                                           is in the process of being deleted. */
#define CM_NB_NAMESTATUS_ONT_B  0x0000  /* B Node */
#define CM_NB_NAMESTATUS_ONT_P  0x2000  /* P Node */
#define CM_NB_NAMESTATUS_ONT_M  0x4000  /* M Node */
#define CM_NB_NAMESTATUS_ONT_H  0x6000  /* H Node */
#define CM_NB_NAMESTATUS_G      0x8000  /* Group Name Flag. If one (1) then the name is a
                                           GROUP NetBIOS name.
                                           If zero (0) then it is a UNIQUE NetBIOS name. */

/*
    NODE NQ_STATUS structure
    ---------------------

    This structure is not specified. We do not use most of its fields and zero out them.
 */

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32  unitId;
    NQ_SUINT16  unitIdCont;
    NQ_SBYTE jumpers;
    NQ_SBYTE testResult;
    NQ_SUINT16 versionNumber;
    NQ_SUINT16 periodOfStatistics;
    NQ_SUINT16 numOfCrcs;
    NQ_SUINT16 numAlligmentErrors;
    NQ_SUINT16 numOfCollisions;
    NQ_SUINT16 numSendAborts;
    NQ_SUINT32 numGoodSends;
    NQ_SUINT32 numGoodReceives;
    NQ_SUINT16 numRetransmits;
    NQ_SUINT16 numNoResourceConditions;
    NQ_SUINT16 numFreeCommandBlocks;
    NQ_SUINT16 totalCommandBlocks;
    NQ_SUINT16 maxTotalNumberCommandBlocks;
    NQ_SUINT16 numPendingSessions;
    NQ_SUINT16 maxTotalSessionsPossible;
    NQ_SUINT16 sessionDataPacketSize;
} SY_PACK_ATTR
CMNetBiosNodeStatistics;

/*
    *************************
    *                       *
    *   SESSION SERVICE     *
    *                       *
    *************************
*/

/* general message structure */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE type;              /* packet type */
    NQ_SBYTE flags;             /* packet flags */
    NQ_SUINT16 length;          /* length of the rest of the paket */
} SY_PACK_ATTR
CMNetBiosSessionMessage;

/* possible types: */

#define CM_NB_SESSIONMESSAGE            0x00
#define CM_NB_SESSIONREQUEST            0x81
#define CM_NB_POSITIVESESSIONRESPONSE   0x82
#define CM_NB_NEGATIVESESSIONRESPONSE   0x83
#define CM_NB_SESSIONRETARGETRESPONSE      0x84
#define CM_NB_SESSIONKEEPALIVE          0x85

#define CM_NB_SESSIONLENGTHEXTENSION    0x1 /* extension (E) bit used to enlarge the length field */

/* Session Retarget Response */

typedef SY_PACK_PREFIX struct
{
    CMNetBiosSessionMessage header; /* generic part (see above) */
    NQ_SUINT32 ip;                      /* retarget IP */
    NQ_SUINT16 port;                    /* retarget port */
} SY_PACK_ATTR
CMNetBiosSessionRetarget;

/* error code for NEGATIVE SESSION RESPONSE */

#define CM_NB_SESSIONERROR_NOTLISTENINGON   0x80    /* not listening on called name */
#define CM_NB_SESSIONERROR_NOTLISTENINGFOR  0x81    /* not listening for calling name */
#define CM_NB_SESSIONERROR_NONAME           0x82    /* called name not present */
#define CM_NB_SESSIONERROR_NORESOURCES      0x83    /* called name present, but insufficient
                                                       resources */
#define CM_NB_SESSIONERROR_UNSPECIFIED      0x8F    /* unspecified error */

/*
    *************************
    *                       *
    *   DATAGRAM SERVICE    *
    *                       *
    *************************
*/

/* general message structure */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE type;              /* packet type */
    NQ_SBYTE flags;             /* packet flags */
    NQ_SUINT16 datagramID;      /* datagram subsequent number */
    NQ_SUINT32 sourceIP;        /* source IP address */
    NQ_SUINT16 sourcePort;      /* source port number */
    NQ_SUINT16 dataLen;         /* user data length */
    NQ_SUINT16 dataOffset;      /* offset from the next byte to the user data */
} SY_PACK_ATTR
CMNetBiosDatagramMessage;


/* error message structure */

typedef SY_PACK_PREFIX struct
{
    NQ_SBYTE type;               /* packet type */
    NQ_SBYTE flags;              /* packet flags */
    NQ_SUINT16 datagramID;       /* datagram subsequent number */
    NQ_SUINT32 sourceIP;         /* source IP address */
    NQ_SUINT16 sourcePort;       /* source port number */
    NQ_SBYTE errorCode;          /* error code */
} SY_PACK_ATTR
CMNetBiosDatagramError;

/* datagram types */

#define CM_NB_DATAGRAM_DIRECTUNIQUE      0x10
#define CM_NB_DATAGRAM_DIRECTGROUP       0x11
#define CM_NB_DATAGRAM_BROADCAST         0x12
#define CM_NB_DATAGRAM_ERROR             0x13
#define CM_NB_DATAGRAM_QUERYREQUEST      0x14
#define CM_NB_DATAGRAM_POSITIVERESPONSE  0x15
#define CM_NB_DATAGRAM_NEGATIVERESPONSE  0x16

/* error codes */

#define CM_NB_DATAGRAM_ERROR_NODESTIONATION     0x82    /* destination name not present */
#define CM_NB_DATAGRAM_ERROR_INVALIDSOURCE      0x83    /* invalid source name format */
#define CM_NB_DATAGRAM_ERROR_INVALIDDESTINATION 0x84    /* invalid destination name format */

/* flags */

#define CM_NB_DATAGRAM_MOREFLAG  0x1     /* this datagram is not the lsat fragment */
#define CM_NB_DATAGRAM_FIRSTFLAG 0x2     /* this datagram is the first fragment */
#define CM_NB_DATAGRAM_BNODE    0x0<<2   /* B node */
#define CM_NB_DATAGRAM_PNODE    0x1<<2   /* P node */
#define CM_NB_DATAGRAM_MNODE    0x2<<2   /* M node */

#include "sypackof.h"

/* End of packed structures definition */

/********************************************************************
 *  Frame generation functions
 ********************************************************************/

NQ_UINT16
cmNetBiosGetNextTranId(
    void
    );                      /* get next transaction ID */

NQ_BYTE
cmNetBiosSetDatagramFlags(
    NQ_BYTE flags              /* add necessary datagrm flags */
    );

#endif /* _CMNBFRAM_H_ */
