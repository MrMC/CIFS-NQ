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

#ifndef _CCFILE_H_
#define _CCFILE_H_

#include "ccshare.h"

/* -- Constants -- */

/* Description
   When this bit is set in the <i>access</i> value in <i>ccCreateFile</i>
   has special meaning. After stripping off this bit, NQ uses it
   as <i>DesiredAccess</i> in the <i>NtCreateAndX </i>(SMB)
   command or in the <i>Create </i>(SMB2) command.                        */
#define CCFILE_ACCESSMASK_SPECIAL 0x8000000	

/* -- Structures -- */

/* Description
   This structure describes open file.
   
   Since this structure inherits from <link CMItem> the file name
   is designated as item name. 
   
   It is using unlock callback. It references the respective server. */
typedef struct _ccfile
{
	CMItem item;				/* List item. */
	CCShare * share;			/* Pointer to the remote share descriptor. */
	NQ_BYTE fid[16];			/* File ID. The usage of this field and its structure
								   depends on SMB dialect. */
	NQ_UINT32 accessMask;		/* NT Format access rights. */
	NQ_UINT32 sharedAccess;		/* Share access. */
	NQ_UINT32 disposition;		/* How to open file. */
	NQ_UINT32 options;			/* Create/open options. */
	NQ_UINT32 attributes;		/* File attributes. */
	NQ_BOOL open;				/* TRUE when file has been open. */
	NQ_UINT64 offset;			/* Current offset in the file */
	NQ_UINT16 maxRpcXmit;		/* Maximum length of RPC transmit fragment */
	NQ_UINT16 maxRpcRecv;		/* Maximum length of RPC receive fragment */
    NQ_BOOL isPipe;             /* TRUE when this is a pipe */
    NQ_BYTE oplockLevel;      /* Level of the oplock that has been granted*/
} 
CCFile; /* Open file descriptor. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccFileStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccFileShutdown(void);

/* Description
   Find open file by name.
   Parameters
   pShare :  Pointer to share to look files on.
   path : Local path to the file, starting from mount point.
   Returns
   Pointer to file descriptor or NULL if it was not found. */
CCFile * ccFileFind(CCShare * pShare, const NQ_WCHAR * path);

/* Description
   Find open file by file id.

   This function traverses the tree of users and shares on the given server.
   Parameters
   pServer :  Pointer to the server object.
   id : File ID to look for.
   Returns
   Pointer to file descriptor or NULL if it was not found. */
CCFile * ccFileFindById(CCServer * pServer, const NQ_BYTE * id);

/* Description
   Add new file descriptor to the list of open files for the given share.
   
   This call:
     * Locates share;
     * Creates and links a file object;
   Parameters
   pShare : Pointer to share to create share on. 
   path : Local path to the file, starting from mount point.
   Returns
   Pointer to file descriptor or NULL on failure. Creating a
   file may fail for the following reasons:
     * out of memory.*/
CCFile * ccFileCreate(CCShare * pShare, const NQ_WCHAR * path);

/* Description
   Create/Open file on server.
   
   This call creates and links a file object on a known share.
   Parameters
   pShare :        Pointer to share to create share on.
   path :          Local path to the file, starting from mount
                   point.
   pathIsLocal:   TRUE if path is local (e.g mounted share)
                      FALSE if path is remote (e.g srvsvc)
   access :        Access mode (see <i>ccCreateFileA/W</i>).
   shareMode :     Share mode (see <i>ccCreateFileA/W</i>).
   locality :      Locality (see <i>ccCreateFileA/W</i>)
   writeThrough :  Write through indicator (see <i>ccCreateFileA/W</i>).
   attributes :    File attributes (see <i>ccCreateFileA/W</i>).
   createAction :  Create action (see<i> ccCreateFileA/W</i>).
   openAction :    Open action (see <i>ccCreateFileA/W</i>).
   isPipe :        <i>TRUE</i> if the file is pipe, <i>FALSE</i>
                   for a regular file.
   Returns
   Pointer to an allocated file descriptor or NULL on failure.
   Creating a file may fail for the following reasons:
     * out of memory.                                                    */
CCFile * ccFileCreateOnServer(
		CCShare * pShare, 
		const NQ_WCHAR * path,
		NQ_BOOL pathIsLocal,
		NQ_INT access, 
		NQ_INT shareMode,
	    NQ_INT locality, 
	    NQ_BOOL writeThrough, 
	    NQ_UINT16 attributes, 
	    NQ_INT createAction, 
	    NQ_INT openAction,
	    NQ_BOOL isPipe
	    );

/* Description
   Starts operations caused by (temporary) disconnect.
   
   NQ call this function when it detects a condition that may
   indicate loss of connection to a the server. This call:
     * Locates server;
     * Calls server's reconnect method (this will cause
       reconnecting of all its underneath objects);
     * Reports reconnect results (either reconnected of failed);
   Parameters
   pFile : Pointer to the file object.
   Returns
   This call returns TRUE when the server was successfully
   reconnected. This call returns FALSE in one of the following
   cases:
     * Server connection still exists &#45; this was a false
       alarm;
     * NQ cannot reconnect to the server;
     * NQ cannot reconnect to the share;
     * NQ cannot reopen this file;                               */
NQ_BOOL ccFileReportDisconnect(CCFile * pFile);

/* Description
   This call re-opens previously open file by restoring its handle.
   
   This happens when NQ detects a connection loss (see <link ccFileReportDisconnect@CCFile *, ccFileReportDisconnect()>.
   When NQ calls this function it has also restored the enclosing context:
     * Connected to the server;
     * Conveyed negotiations;
     * Logged on;
     * Connected to file's share;
   This function attempts to restore file handle by using
   underlying protocol method. If the protocol does not support
   durable file handle, the protocol layer will fail the
   operation.
   Parameters
   pFile :  Pointer to the file object.
   Returns
   This call returns TRUE if file handle was restored
   successfully .It returns FALSE in one of the following cases:
     * The SMB dialect agreed upon during negotiations does not
       support durable handles;
     * Server does not support durable handles;
     * Server did not grant a durable handle before connection
       loss;
     * Re&#45;opening failed;                                                                                            */ 
NQ_BOOL ccFileRestore(CCFile * pFile);

#endif /* _CCFILE_H_ */
