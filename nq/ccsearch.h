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

#ifndef _CCSEARCH_H_
#define _CCSEARCH_H_

#include "cmapi.h"
#include "ccserver.h"
#include "ccshare.h"
#include "cmbuf.h"

/* Description
   This structure describes a search handle. 
  
   Since this structure inherits from CMItem 
   the search path is designated as item name. */
typedef struct _ccsearch
{
	CMItem item;			/* List item. */
	CCServer * server;		/* Server pointer where to search. */
	CCShare * share;		/* Share pointer where to search */
	void * context;			/* Pointer to protocol-specific context - may be NULL. */
	CMBufferReader parser;	/* File entry parser. Use cmBufferReaderGetRemaining() to check its validity. */
	NQ_BYTE * buffer;		/* Receive buffer with current entries. The protocol creates and sets this buffer, 
							   while this module releases it after all entries are parsed. */
	NQ_BOOL isFirst;		/* TRUE for the first query, FALSE for others. */
    CMBlob lastFile;        /* Pointer to the last file name in the buffer. This may be used by FindNext. */
	NQ_BOOL localFile;		/* TRUE if the search has a local path , FALSE if remote path */ 
} CCSearch; /* Search descriptor. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccSearchStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccSearchShutdown(void);

#endif /* _CCSEARCH_H_ */
