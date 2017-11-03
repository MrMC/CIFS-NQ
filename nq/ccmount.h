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

#ifndef _CCMOUNT_H_
#define _CCMOUNT_H_

#include "ccapi.h"
#include "amapi.h"
#include "ccserver.h"
#include "ccshare.h"
#include "amapi.h"

/* -- Structures -- */

#ifdef UD_CC_INCLUDEDFS
/* when dfs active, each mount can reference additional shares that should be unlocked on mount disconnect */
typedef struct _CCShareLink
{
	CMItem item;
	CCShare *pShare;
}CCShareLink;
#endif

/* Description
   This structure describes a mount point.
   
   Mount point stands for an alias (shortcut/symbolic link) that hides a remote share. 
 
   Since this structure inherits from <link CMItem> the mount point name is designated
   as item name. 
   
   Mount points are only implicitely removed by calling <i>nqRemoveMount</i>. Therefore,
   objects of this structure do not specify unlock callbacks. */
typedef struct _ccmount
{
	CMItem item;		                /* List item. */
	NQ_WCHAR * path;	                /* Network path to remote share. */
    NQ_WCHAR * pathPrefix;              /* Home directory remote path, when mounting path of form <server><share><sub folder> */
	CCServer * server;	                /* Server pointer or NULL if not connected yet. */
	CCShare * share;	                /* Tree connect pointer or NULL if not connected yet. */
    const AMCredentialsW * credentials; /* Pointer to credentials used for share connect */
#ifdef UD_CC_INCLUDEDFS
    CMList shareLinks;					/* Per each mount, shares that are mounted as part of DFS
     	 	 	 	 	 	 	 	 	 * are kept in this list so they can be unlocked on remove mount. */
#endif
} CCMount; /* Mount point. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   <i>TRUE</i> on success and <i>FALSE</i> on failure.
 */
NQ_BOOL ccMountStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccMountShutdown(void);

/* Description
   Find mount point by local path. 
   
   Off the local path only the
   mount point clause is used.
   Parameters
   path :  Local path to a file or folder. This path starts from
           mount point and has a form of\: <i>\<mount
           point\>\<share path\></i> where <i>share path</i> is a
           path segment local to the remote share. The last
           clause, either including or not including the slash
           separator may be empty.
   Returns
   Pointer to mount point descriptor or NULL if it was not found or if the 
   mount point was not connected.                                       */
CCMount * ccMountFind(const NQ_WCHAR * path);

/* Description
   This function creates an iterator for enumerating mounts. 
   
   Parameters
   iterator : pointer to an iterator structure. Upon completion this function starts 
              this iterator
   Returns
   None.                                       */
void ccMountIterateMounts(CMIterator * iterator);

/*  Description
    This function adds share to a mount's list of shares.

    Per each mount, shares that are mounted as part of DFS
    are kept in a list so they can be unlocked on remove mount.

    Parameters
    pMount : mount pointer
    pShare : share pointer
    Returns
    None.                                       */
void ccMountAddShareLink(CCMount *pMount, CCShare *pShare);

#if SY_DEBUGMODE

/* Description
   Printout the list of mount points.
   Returns 
   None
 */
void ccMountDump(void);

#endif /* SY_DEBUGMODE */

#endif /* _CCMOUNT_H_ */
