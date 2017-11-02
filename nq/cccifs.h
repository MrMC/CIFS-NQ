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

#ifndef _CCCIFS_H_
#define _CCCIFS_H_

#include "cmapi.h"
#include "cmbuf.h"
#include "cmsdescr.h"
#include "nsapi.h"

/* -- Structures -- */

/* Description
   Prototype for a callback function to parse one DFS referral.
   
   This function is called from DFS query function of the procol
   object (see <link _cccifssmb::doQueryDfsReferrals, doQueryDfsReferrals>) 
   for each referral entry.
   Parameters
   reader :  The reader to use for parsing. This reader's pointer
             should be set at the beginning of the DFS response
             portion of the SMB response payload. After retrun from this
             function, the reader should point right after the end of the 
             DFS response portion.                         
   Returns 
   None. */
typedef void (* CCCifsParseReferral) (CMBufferReader * reader, CMList * list);

/* Description
   Prototype for a callback function on write response.
   
   This function is supplied as a parameter to <link _cccifssmb::doWrite, doWrite>
   function of the protocol. Protocol calls this callback after
   parsing write response.
   Parameters
   status :   NQ status of the response.
   len :      Number of bytes written.
   context :  Caller's context as passed in the <link _cccifssmb::doWrite, doWrite>
              function.
   Returns
   None.                                                                            */
typedef void (* CCCifsWriteCallback) (NQ_STATUS status, NQ_UINT len, void * context);

/* Description
   Prototype for a callback function on read response.
   
   This function is supplied as a parameter to <link _cccifssmb::doRead, doRead>
   function of the protocol. Protocol calls this callback after
   parsing write response.
   Parameters
   status :   NQ status of the response.
   len :      Number of bytes read.
   context :  Caller's context as passed in the <link _cccifssmb::doRead, doRead>
              function.
   final : 	  When this value is <i>TRUE</i> it means that the entire read operation completed
              with less data then required since the file does not have enough bytes. 
   Returns
   None.                                                                          */
typedef void (* CCCifsReadCallback) (NQ_STATUS status, NQ_UINT len, void * context, NQ_BOOL final);

/* Description
   Prototype for a callback function on file information
   response.
   
   This function is supplied as a parameter to <link _cccifssmb::doQueryFileInfoByName, doQueryFileInfoByName>
   or <link _cccifssmb::doQueryFileInfoByHandle, doQueryFileInfoByHandle>
   function of the protocol. Protocol calls this callback after
   parsing a query response.
   Parameters
   reader :   A reader set to the very first byte of a file
              information entry. This entry should conform to <i>FileAllInformation</i>.
   context :  Caller's context as passed to a <link _cccifssmb::doQueryFileInfoByName, doQueryFileInfoByName>
              or <link _cccifssmb::doQueryFileInfoByHandle, doQueryFileInfoByHandle>
              call.
   Returns
   None.                                                                                                       */
typedef void (* CCCifsParseFileInfoCallback) (CMBufferReader * reade, void * context);

/* Description
   This structure represents a CIFS dialect (SMB, SMB2, SMB2.1).
   
   It mostly comprises function pointers for abstract CIFS
   functionality.
   
   Most of fucntion pointers have a signature of type:
   <code>
     NQ_BOOL \<func\>(NQSocketHandle socket, ...);
   </code>                                                       */
typedef struct _cccifssmb
{
	/* Readable dialect name. */
	const NQ_CHAR * name;	
	/* Dialect revision ID. This value equals 1 for SMB. */
	NQ_UINT16 revision;	
    /* Maximum length of message signing keys. The keys, negotiated with server may exceed this value. Then, NQ will cut them for signing. */
	NQ_UINT maxSigningKeyLen;	
	/* If this value is TRUE and message signing is selected, NQ should attempt a 
	   restriction on the list of encrypters of the chosen security mechanism. 
	   The exact restrictions depend on the machanism. */
	NQ_BOOL restrictCrypters;	
	/* This is the prefix to add to a file name when this name is an RPC pipe. */
	const NQ_WCHAR * rpcNamePrefix;	
	/* Allocate dialect-specific context.
	   Parameters
	   server :  Pointer to master server. 
	   Returns
	   Pointer to context or NULL on error. */
	void * (* allocateContext)(void * server);	
	/* Free dialect-specific context.
	   Parameters
	   context :  Context pointer to dispose. 
	   server :  Server object pointer.  
	   Returns 
	   None. */
	void (* freeContext)(void * context, void * server);	
	/* Set this dialect as the only one.   

       This call affects the negotiation process and it works differently for different dialects. 
       Since normally a dialect may offer several diialects during negotioations, this call may restrict
       it to only self dialect. 

       Expected usage of this call is:
       * calling this function with a TRUE argument;
       * performing SMB connection;
       * performing some transactions;
       * disconnecting;
       * calling this function with a FALSE argument.

       Therefore, a dialect may implement critical section between those two calls. 
	   Parameters
	   set : When this argument is <i>TRUE</i>, NQ sets current dialect as the only one. 
             A <i>FALSE</i> value reverts the dialect to its default mode. 
	   Returns
	   None.  */
	void (* setSolo)(NQ_BOOL set);	
	/* Negotiate SMB dialect. After parsing successful response NQ installs this
	   dialect as the server's SMB dialect.  
	   Parameters
	   server :  Server object pointer. On a successful negotiation the dialect pointed by 
				 this structure, installs itself as the server's dialect. 
	   outBlob :  Pointer to security blob to be set on exit.
	   Returns
	   NQ_SUCCESS or error code.  */
	NQ_STATUS (* doNegotiate)(void * server, CMBlob * outBlob);	
	/* Negotiate SMB dialect. After parsing successful response NQ installs this
	   dialect as the server's SMB dialect.  
	   Parameters
	   server :  Server object pointer. On a successful negotiation the dialect pointed by 
				 this structure, installs itself as the server's dialect. 
	   pass1 :  LM paassword blob.
	   pass1 :  NTLM paassword blob.
	   Returns
	   NQ_SUCCESS or error code.  */
	NQ_STATUS (* doSessionSetup)(void * user, const CMBlob * pass1, const CMBlob * pass2);	
	/* Session setup with extended security.
	   Parameters
	   user :  User object pointer.
	   inBlob :  On call this pointer designates a blob to be sent to server. 
	   outBlob : On exit it is filled with an incoming blob or NULL.
	   Returns
	   NQ_SUCCESS or error code. SMB_STATUS_PENDING means iteration: the same method 
	   should be called again. */
	NQ_STATUS (* doSessionSetupExtended)(void * user, const CMBlob * inBlob, CMBlob * outBlob);	
	/* Log off.
	   Parameters
	   user :  User object pointer.
	   Returns
	   	   NQ_SUCCESS or error code.  */
	NQ_STATUS (* doLogOff)(void * user);	
	/* Tree connect.
	   Parameters
	   share :  Share object pointer.
	   Returns
	   NQ_SUCCESS or error code.  */
	NQ_STATUS (* doTreeConnect)(void * share);	
	/* Tree disconnect.
	   Parameters
	   share :  Share object pointer.
	   Returns
	   NQ_SUCCESS or error code.  */
	NQ_STATUS (* doTreeDisconnect)(void * share);	
	/* Open/Create file.
	   Parameters
	   file :  File object pointer. The protocol withdraws access and share 
			   rights as well as other create parameters. 
	   Returns
	   NQ_SUCCESS or error code.  */
	NQ_STATUS (* doCreate)(void * file);	
	/* Re-opene file.
	   Parameters
	   file :  File object pointer. This object should designate an open file with a valid handle (FID). 
	   Returns
	   NQ_SUCCESS or error code. If SMB dialect does not support durable handle it should return NQ_ERR_BADPARAM */
	NQ_STATUS (* doRestoreHandle)(void * file);	
	/* Close open file.
	   Parameters
	   file :  File object pointer. The protocol withdraws access and share 
			   rights as well as other create parameters. 
	   Returns
	   NQ_SUCCESS or error code.  */
	NQ_STATUS (* doClose)(void * file);	
	/* Query DFS referrals.
	   Parameters
	   share :   Pointer to the share object to query referrals over.
	   path :    Path to query for. This should be a local to share
	             path.
	   parser :  Callback function to parser referrals. This function
	             is protocol\-independent.
	   list :    Pointer to the list for the callback function to
	             fill with referrals.
	   Returns
	   NQ_SUCCESS or error code.                                      */
	NQ_STATUS (* doQueryDfsReferrals)(void * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list);	
	/* Start directory scanning.
	   
	   This call does not bring any entry but it rather prepares for
	   a <link _cccifssmb::doFindMore, doFindMore()> call.
	   Parameters
	   search :  Search structure.
	   Returns
	   NQ_SUCCESS or error code.                                     */
	NQ_STATUS (* doFindOpen)(void * search);	
	/* Continue directory scanning.
	   
	   NQ calls this protocol function each time to fill another buffer with 
	   file entries.
	   
	   On success, this call allocates a buffer and sets it into the
	   <i>search</i> structure. It also sets the parser reader in the
	   same structure.
	   
	   This call assumes that <link _cccifssmb::doFindOpen, doFindOpen()>
	   has been already called. The protocol level should use level
	   260 format.
	   Parameters
	   search :  Search structure.
	   Returns
	   NQ_SUCCESS or error code. This function return NQ_ERR_NOFILES
	   on end of search                                                   */
	NQ_STATUS (* doFindMore)(void * search);	
	/* Finish directory scanning.
	   Parameters
	   search :  Search structure.
	   Returns
	   NQ_SUCCESS or error code.                                      */
	NQ_STATUS (* doFindClose)(void * search);	
	/* Write bytes to file asynchronously.
	   
	   This function sends one write request and returns without waiting for response. 
	   On response, it calls the callback function.
	   Parameters
	   pFile :     \File object pointer. The file should be
	               previously open.
	   buffer :    Pointer to the bytes to writ.
	   num :       Number of bytes to write.
	   callback :  Function to call on response.
	   context :   Pointer to pass to the callback function.
	   Returns
	   NQ_SUCCESS or error code.                                   */
	NQ_STATUS (* doWrite)(void * pFile, const NQ_BYTE * buffer, NQ_UINT num, CCCifsWriteCallback callback, void * context);	
	/* Read bytes from file asynchronously.
	   
	   This function sends one read request and returns without waiting for response. 
	   On response, it calls the callback function.
	   Parameters
	   pFile :     \File object pointer. The file should be
	               previously open.
	   buffer :    Pointer to the bytes to writ.
	   num :       Number of bytes to read.
	   callback :  Function to call on response.
	   context :   Pointer to pass to the callback function.
	   Returns
	   NQ_SUCCESS or error code.                                   */
	NQ_STATUS (* doRead)(void * pFile, const NQ_BYTE * buffer, NQ_UINT num, CCCifsReadCallback callback, void * context);	
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	
	/* Withdraw file security descriptor.
	   
	   This function sends an appropriate (as used in the protocol) request to receive file security descriptor.
	   The file should be open. 
	   Parameters
	   pFile :     \File object pointer. The file should be
	               previously open.
	   sd :   Pointer to the security descriptor structure to be 
	          filled with a security descriptor returned by the server.
	   Returns
	   NQ_SUCCESS or error code.                                   */
	NQ_STATUS (* doQuerySecurityDescriptor)(void * pFile, CMSdSecurityDescriptor * sd);	
	/* Update file security descriptor.
	   
	   This function sends an appropriate (as used in the protocol) request to set file security descriptor.
	   The file should be open. 
	   Parameters
	   pFile :     \File object pointer. The file should be
	               previously open.
	   sd :   Pointer to the security descriptor structure.
	   Returns
	   NQ_SUCCESS or error code.                                   */
	NQ_STATUS (* doSetSecurityDescriptor)(void * pFile, const CMSdSecurityDescriptor * sd);	
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */	
	/* Withdraw volume information.
	   
	   This function sends an appropriate (as used in the protocol)
	   requests to receive volume information.
	   Parameters
	   pShare :  Pointer to the share object.
	   info :    Pointer to volume information structure (see <link CCVolumeInfo>).
	   Returns
	   NQ_SUCCESS or error code.                                                    */
	NQ_STATUS (* doQueryFsInfo)(void * pShare, void * info);	
	/* Withdraw file information providing file name.
	   
	   This function sends an appropriate (as used in the protocol)
	   request to receive file information. The file information
	   block in the response should conform to the <i>FileBothDirectoryInformation</i>
	   structure.
	   Parameters
	   pShare :    Pointer to the share object.
	   fileName :  Pointer to file name. This should be a
	               share\-local file name.
	   callback :  Function to call on response.
	   context :   Pointer to pass to the callback function.
	   Returns
	   NQ_SUCCESS or error code.                                                       */
	NQ_STATUS (* doQueryFileInfoByName)(void * pShare, const NQ_WCHAR * fileName, CCCifsParseFileInfoCallback callback, void * context);	
	/* Withdraw file information for an open file.
	   
	   This function sends an appropriate (as used in the protocol)
	   request to receive file information. The file information
	   block in the response should conform to the <i>FileBothDirectoryInformation</i>
	   structure.
	   Parameters
	   pFile :     \File object pointer. The file should be
	               previously open.
	   callback :  Function to call on response.
	   context :   Pointer to pass to the callback function.
	   Returns
	   NQ_SUCCESS or error code.                                                       */
	NQ_STATUS (* doQueryFileInfoByHandle)(void * pFile, CCCifsParseFileInfoCallback callback, void * context);	
	/* This function sets attributes for an open file.
	   
	   This function sends an appropriate (as used in the protocol)
	   request to set file information. 
	   Parameters
	   pFile : Open file handle. 
	   attributes :   File attributes to set.
	   Returns
	   NQ_SUCCESS or error code.                                                       */
	NQ_STATUS (* doSetFileAttributes)(void * pFile, NQ_UINT32 attributes);	
	/* This function changes file size for an open file.
	   
	   This function sends an appropriate (as used in the protocol)
	   request to set file information. 
	   Parameters
	   pFile : Open file handle. 
	   size :   File size to set.
	   Returns
	   NQ_SUCCESS or error code.                                                       */
	NQ_STATUS (* doSetFileSize)(void * pFile, NQ_UINT64 size);	
	/* This function changes file times for an open file.
	   
	   This function sends an appropriate (as used in the protocol)
	   request to set file information.
	   Parameters
	   pFile :           Open file handle.
	   creationTime :    \File creation time. A value of <i>\-1</i>
	                     means "apply no change".
	   lastAccessTime :  \File last access time. A value of <i>\-1</i>
	                     "apply no change".
	   lastWriteTime :   \File last write time. A value of <i>\-1</i>
	                     "apply no change".
	   Returns
	   NQ_SUCCESS or error code.                                       */
	NQ_STATUS (* doSetFileTime)(void * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime);	
	/* This function deletes file by setting <i>delete pending</i> flag. 
	   
	   Parameters
	   pFile :           Open file handle.
	   Returns
	   NQ_SUCCESS or error code.                                       */
	NQ_STATUS (* doSetFileDeleteOnClose)(void * pFile);	
	/* This function renames an open file. 
	   
	   Parameters
	   pFile :           Open file handle.
	   newName : 		The name to rename file to.
	   Returns
	   NQ_SUCCESS or error code.                                       */
	NQ_STATUS (* doRename)(void * pFile, const NQ_WCHAR * newName);	
	/* This function synchronizes file buffers. 
	   
	   Parameters
	   pFile :           Open file handle.
	   Returns
	   NQ_SUCCESS or error code.                                       */
	NQ_STATUS (* doFlush)(void * pFile);	
	/* This function performs an old-facioned RAP transaction. 
	   
	   Parameters
	   pShare :           Share handle.
       inData :           Pointer to RAP parameters.
       outData :          Pointer to blob to be set for RAP response. After a successfull return
                          this blob will designate an allocated buffer. It is caller's responsibility to 
                          release this buffer after usage. 
	   Returns
	   NQ_SUCCESS or error code.                                       */
	NQ_STATUS (* doRapTransaction)(void * pShare, const CMBlob * inData, CMBlob * outData);	
    /*
            This function sends an echo request.

        Parameters:
            pServer:    Server handle.
    */
    NQ_STATUS (* doEcho)(void * pShare);
    /* 
        SMB1 requires full path for a new name (Will be TRUE), while SMB2 requires relative path (Will be FALSE)
    */
    NQ_BOOL     useFullPath;
    /*
        SMB 2 (TRUE) requires to create the file before moving it SMB1 (FALSE) doesn't.
    */
    NQ_BOOL     createBeforeMove;
} CCCifsSmb; /* SMB dialect descriptor. */

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccCifsStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccCifsShutdown(void);

/* Description
   Get the default SMB dialect. This dialect is mostly used for
   negotiate.
   Returns
   Pointer to the default dialect structure.                    */
const CCCifsSmb * ccCifsGetDefaultSmb(void);

/* Description
   Obtain an array of SMB dialects.
   Parameters
   dialects :  Buffer for the pointer to an array of dialects.
               Array dimensions are specified by the return
               value.
   Returns
   Number of dialects in the array above.                      */
NQ_INT ccCifsGetDialects(const CCCifsSmb *** dialects);

/* Description
   Convert CIFS error into NQ error.
   Parameters
   code :  CIFS error in either DOS or NT format.
   isNt :  TRUE if the code above is in NT format, FALSE for DOS format.
   Returns
   NQ error.                      */
NQ_STATUS ccCifsGetError(NQ_UINT32 code, NQ_BOOL isNt);

/* Description
   This value, when placed in dialect reviison of a particular dialect, means that revision number 
   is not applicable to this dialect.
   
   For innstance, SMB dialect (NT LM 0.12) has illegal revision and it does not
   participate in SMB2.x negotiations.	*/
#define CCCIFS_ILLEGALSMBREVISION 0xFFFF

#endif /* _CCCIFS_H_	 */
