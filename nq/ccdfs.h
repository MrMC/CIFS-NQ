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

#ifndef _CCDFS_H_
#define _CCDFS_H_

#include "cmapi.h"
#include "ccserver.h"
#include "ccshare.h"
#include "ccmount.h"

/* -- Structures -- */

/* Description
   This structure describes a result of DFS resolution. 
   
   As a result of DFS resolution there may be a new server, share and local (to the share)
   path.  
   
   An error result is designated by NULL server pointer */
typedef struct _ccdfsresult
{
    CCServer * server;  /* Pointer to server structure. NULL on error. */
    CCShare * share;    /* Pointer to share structure. May be NULL. */
    NQ_WCHAR * path;    /* Pointer to new path local to the share. May be NULL. This
                        string is <b>always</b> allocated and it is caller's
                        responsibility to dispose it.                              */
} CCDfsResult; /* DFS results. */

/* Description
   This structure describes a DFS referral. 
*/
typedef struct _ccdfsreferral
{
    CMItem item;                /* list item */
    NQ_UINT16 numPathConsumed;  /* number of request path characters consumed */
    NQ_UINT16 serverType;       /* server type */
    NQ_UINT16 flags;            /* referral flags */
    NQ_UINT32 ttl;              /* time to live */
    NQ_WCHAR * dfsPath;         /* original path */
    NQ_WCHAR * netPath;         /* resolved path */
    NQ_BOOL isConnected;        /* whether this host is connected and user has logged in */
    NQ_BOOL isIOPerformed;      /* whether IO operation was performed at least once */
    NQ_STATUS lastIOStatus;     /* last IO operation status */ 
} CCDfsReferral;

/* Description
   This structure describes a context of DFS operation. 
*/
typedef struct _ccdfscontext
{
    NQ_INT counter;
    NQ_STATUS lastError;
    CMItem *referral;
} CCDfsContext; /* DFS context. */


/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccDfsStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccDfsShutdown(void);

/* Description
   Resolve host name. Host name may be either real host or a
   domain name. In the last case it designates PDC.
   
   If the host name designates a server, this call will clone
   its name. If the host name designates a domain, this call
   will return a new string with PDC name in it.
   Parameters
   host :  Host name to resolve. This may be a real host or a
           domain name.
   Returns
   Newly allocated host name NULL on error.                   */
const NQ_WCHAR * ccDfsResolveHost(const NQ_WCHAR * host);

#define CC_DFS_NUMOFRETRIES (50 * CC_CONFIG_RETRYCOUNT) /* number of retries for DFS resolving, to decide on invalid DFS links */

/* Description
   Resolve DFS path local to a share.
   
   On success the result structure will contain valid server,
   share and path pointers. The resulted share pointer should
   not necessary be the same as the <i>pShare</i> parameter.
   Parameters
   pShare :  Pointer to the share. The share should be already
             resolved.
   path :    Remote path, containing host name and share path.
             This may be a DFS path.
   context : Pointer to a context structure (see <link CCDfsContext>), 
             describing current file operation.
   Returns
   DFS result structure. NULL in the path field designates an
   error.                                                       */
CCDfsResult ccDfsResolvePath(CCMount *pMount, CCShare *pShare, const NQ_WCHAR *file, CCDfsContext *context);

/* Description
   Dispose DFS results. Effectively it disposes file path
   string. This call does not dispose the structure itself.
   Parameters
   pRes :  Pointer to the DFS results structure (see <link CCDfsResult>).
   Returns
   None.                                                                  */
void ccDfsResolveDispose(CCDfsResult * pRes);

/* Description
   Switch DFS on/off in run-time.
   Parameters
   on :  <i>TRUE</i> to switch DFS on, <i>FALSE</i> to turn it off.
   Returns
   None.                                                                  */
void ccDfsResolveOn(NQ_BOOL on);

/* Description
   Determines whether supplied error code required additional DFS 
   resolution.
   Parameters
   errorCode : error code.
   Returns
   TRUE if error code requires DFS resolution, FALSE otherwise.            */
NQ_BOOL ccDfsIsError(NQ_STATUS errorCode);

#endif /* _CCDFS_H_ */
