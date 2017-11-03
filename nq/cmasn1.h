/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Abstract GSASL interface
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Feb-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMASN1_H_
#define _CMASN1_H_

#include "cmbuf.h"

#if defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY)

/* OID prefixes */
#define CM_ASN1_1_2   0x2a
#define CM_ASN1_1_3   0x2b

/* tags */
#define CM_ASN1_APPLICATION     0x60
#define CM_ASN1_SIMPLE          0x40
#define CM_ASN1_CONTEXT         0xa0
#define CM_ASN1_SEQUENCE        0x30
#define CM_ASN1_ENUMERATED      0x0a
#define CM_ASN1_OID             0x06
#define CM_ASN1_BINARY          0x04
#define CM_ASN1_STRING          0x1b
#define CM_ASN1_NOTAG           0

typedef NQ_INT      CMAsn1Tag;      /* ASN1 tag */
typedef NQ_COUNT    CMAsn1Len;      /* ASN1 data length */

typedef struct
{
    NQ_BYTE *data;
    NQ_UINT size;
} CMAsn1Oid;

/* parse OID and compare it with another one */
NQ_BOOL                         /* TRUE on match */
cmAsn1ParseCompareOid(
    CMBufferReader * ds,  		/* packet descriptor pointed on OID */
    const CMAsn1Oid *oid,       /* OID to compare */
    NQ_BOOL toRevertOnMismatch  /* whether to revert descriptor on error or no match */
    );

/* parse tag and tag length and continue to tag data */
CMAsn1Tag                       /* parsed tag */
cmAsn1ParseTag(
    CMBufferReader * ds,  		/* packet descriptor pointed on OID */
    CMAsn1Len* dataLen          /* buffer for tag data length */
    );

/* calculate length of the tag data length field */
NQ_COUNT                        /* number of bytes in the tag length field */
cmAsn1PackLen(
    CMAsn1Len dataLen           /* tag data length */
    );

/* calculate length of ASN1 element */
NQ_COUNT                        /* actual number of bytes in the element */
cmAsn1GetElementLength(
    NQ_UINT length              /* data length */
    );

/* pack tag */
void
cmAsn1PackTag(
	CMBufferWriter * ds,  		/* packet descriptor pointed on OID */
    CMAsn1Tag tag,              /* tag to pack */
    CMAsn1Len dataLen           /* tag data length */
    );

/* pack OID */
void
cmAsn1PackOid(
	CMBufferWriter* ds,  		/* packet descriptor pointed on OID */
    const CMAsn1Oid *oid        /* OID */
    );

#endif /* defined(UD_CC_INCLUDEEXTENDEDSECURITY) || defined(UD_CS_INCLUDEEXTENDEDSECURITY) */

#endif /* _CMASN1_H_ */
