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

#ifndef _CCDFSCACHE_H_
#define _CCDFSCACHE_H_

#include "cmapi.h"

/* -- Structures -- */


/* Description
   This structure describes a DFS cache entry.
   
   Since this structure inherits from <link CMItem> the DFS path 
   is designated as item name. 
   
   DFS entry is using unlock callback.
   
   An entry is created in <link ccDfsCacheAdd@NQ_WCHAR *@NQ_WCHAR *, ccDfsCacheAdd()>
   call and it is disposed in one of the following cases:
     * when it times out;
     * when NQ calls <link ccDfsCacheRemove@NQ_WCHAR *, ccDfsCacheRemove()>
     * when NQ shuts down and calls <link ccDfsCacheShutdown, ccDfsCacheShutdown()>   */
typedef struct _ccdfscacheentry
{
    CMItem item;                /* List item. (contains DFS path from request) */
    CMList * refList;           /* List of DFS referrals (i.e. the actual path) */
    NQ_UINT16 numPathConsumed;  /* number of referral path characters consumed */
    NQ_BOOL isRoot;             /* root target or link target otherwise (server type) */
    NQ_UINT32 ttl;              /* time to live */
    NQ_BOOL isExactMatch;       /* exact match */
} CCDfsCacheEntry; /* DFS cache entry. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccDfsCacheStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccDfsCacheShutdown(void);

/* Description
   Indicates whether cache is maintained.
   Returns 
   TRUE or FALSE
 */
NQ_BOOL ccDfsIsCacheOn(void);

/* Description
   Find cache entry by DFS path.
   Parameters
   path :  Remote path, containing host name and share path. This
           may be a DFS path.
   Returns
   Pointer to DFS cache entry or NULL if the DFS path is not in
   the cache.                                                     */
CCDfsCacheEntry * ccDfsCacheFindPath(const NQ_WCHAR * path);

/* Description
   Remove cache entry by DFS path.
   Parameters
   path : Remote path, containing host name and share path. This may be a DFS path.
   Returns
   None. */
void ccDfsCacheRemovePath(const NQ_WCHAR * path);

/* Description
   Add new entry to the cache.
   Parameters
   path :      Remote path, containing host name and share path.
               This may be a DFS path.
   referral :  A path to be used as a referral to the path above.
   ttl : Time to live in seconds
   isRoot   :   Referral type (root or link)
   numPathConsumed : number of path characters consumed 
   Returns
   Pointer to newly created DFS cache entry or NULL on error
   (although not expected).                                       */
CCDfsCacheEntry * ccDfsCacheAddPath(const NQ_WCHAR * path, const NQ_WCHAR * referral, NQ_UINT32 ttl, NQ_BOOL isRoot, NQ_UINT16 numPathConsumed);

/* Description
   Find cache entry by domain name.
   Parameters
   domain :  Domain name. May be either NetBIOS or FQDN.
   Returns
   Pointer to DFS cache entry or NULL if the DFS path is not in
   the cache.                                                   */
CCDfsCacheEntry * ccDfsCacheFindDomain(const NQ_WCHAR * domain);

/* Description
   Remove cache entry by domain name.
   Parameters
   domain : Domain name. May be either NetBIOS or FQDN.
   Returns
   None. */
void ccDfsCacheRemoveDomain(const NQ_WCHAR * domain);

/* Description
   Add new entry to the cache.
   Parameters
   domain :  Domain name. May be either NetBIOS or FQDN.
   host :    DC host name.
   ttl : time to luve in seconds
   Returns
   Pointer to newly created DFS cache entry or NULL on error
   (although not expected).                                  */
CCDfsCacheEntry * ccDfsCacheAddDomain(const NQ_WCHAR * domain, const NQ_WCHAR * host, NQ_UINT32 ttl);

#endif /* _CCDFSCACHE_H_ */
