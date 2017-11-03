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

#ifndef _CCUTILS_H_
#define _CCUTILS_H_

#include "cmapi.h"

/* -- API Functions */

/* Description
   Initialize this module.
   Returns 
   None
 */
NQ_BOOL ccUtilsStart(void);

/* Description
   Release resources used by this module.
   Returns 
   None
 */
void ccUtilsShutdown(void);

/* Description
   This function checks a string for valid IP representation and converts it.
   Parameters
   name :  String to check.
   ip :  Buffer to put cinverted IP address.
   Returns
   TRUE if the input string conforms to an IP address
   representation and FALSE otherwise.
   Note
   If NQ is generated with IPv6 support, the string is checked
   for both IPv4 and IPV6 syntax.                              */
NQ_BOOL ccUtilsNameToIp(const NQ_WCHAR * name, NQ_IPADDRESS * ip);

/* Description
   This function withdraws the host name portion from a remote path.
   
   It creates host name string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   path :  Remote path of the format <i>\\\\\<host\>\\\<share\></i>. 
   Returns
   Pointer to  a newly created host name string or NULL on failure. */
NQ_WCHAR * ccUtilsHostFromRemotePath(const NQ_WCHAR * path);

/* Description
   This function withdraws the share name portion from a remote path.
   
   It creates share name string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   path :  Remote path of the format <i>\\\\\<host\>\\\<share\></i>. 
   Returns
   Pointer to a newly created share name string or NULL on failure. */
NQ_WCHAR * ccUtilsShareFromRemotePath(const NQ_WCHAR * path);

/* Description
   This function withdraws the host name and share name portion from a remote path.
   
   It creates share name string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   path :  Remote path of the format <i>\\\\\<host\>\\\<share\>\\\<file\></i>. 
   Returns
   Pointer to a newly created host name and share name string of format 
   <i>\\\\\<host\>\\\<share\></i> or NULL on failure. */
NQ_WCHAR * ccUtilsHostShareFromRemotePath(const NQ_WCHAR * path);

/* Description
   This function withdraws the file portion from a remote path.
   
   It creates file portion string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   path :  Remote path of the format <i>\\\\\<host\>\\\<share\>\\\<file\></i>. 
   stripBackslash : whether to strip leading backslash
   Returns
   Pointer to a newly created file portion string of format 
   <i>\\\<file portion\></i> or NULL on failure. */
NQ_WCHAR * ccUtilsFilePathFromRemotePath(const NQ_WCHAR * path, NQ_BOOL stripBackslash);

/* Description
   This function withdraws mount point portion from a local
   path.
   
   We assume that the path starts from mount point and has a
   form of: <i>\<mount point\>\<share path\></i> where <i>file
   path</i> is a path segment local to the remote share. The
   last clause, either including or not including the slash
   separator may be empty.
   
   This function creates a new string with mount point name in
   an allocated memory and it is caller's responsibility to free
   that memory.
   Parameters
   path :  Local path in the form of\: <i>\<mount point\>\<file
           path\></i>.
   Returns
   Pointer to a newly created string or NULL on failure.         */
NQ_WCHAR * ccUtilsMountPointFromLocalPath(const NQ_WCHAR * path);

/* Description
   This function withdraws file path from a local path.
   
   We assume that the path starts from mount point and has a
   form of: <i>\<mount point\>\<file path\></i> where <i>file
   path</i> is a path segment local to the remote share. The
   last clause, either including or not including the slash
   separator may be empty. In this case this function creates an
   empty name.
   
   This function creates a new string with mount point name in
   an allocated memory and it is caller's responsibility to free
   that memory.
   Parameters
   path :  Local path in the form of\: <i>\<mount point\>\<file
           path\></i>.
   pathPrefix : Remote home directory, sub folder of remote share
           if available.
   makeCanonic : Make canonicalized path (add leading backslash) - relevant for SMB only
   isLocalPath : Whether path is of local form
   Returns
   Pointer to a newly created string or NULL on failure.         */
NQ_WCHAR * ccUtilsFilePathFromLocalPath(const NQ_WCHAR * path, const NQ_WCHAR * pathPrefix, NQ_BOOL makeCanonic, NQ_BOOL isLocalPath);

/* Description
   This function creates network path from server name and share name. 
   
   Path syntax is <i>\\\\\<host\>\\\<share\></i>.
   
   It creates network path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   server :  Pointer to server name. 
   share :  Pointer to share name. 
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsComposeRemotePathToShare(const NQ_WCHAR * server, const NQ_WCHAR * share);

/* Description
   This function creates network path from server name, share name and a 
   share-local path to file. 
   
   Path syntax is <i>\\\\\<host\>\\\<share\></i>.
   
   It creates network path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   server :  Pointer to server name. 
   share :  Pointer to share name. 
   file :  Pointer to file path. This path should be local to the share. 
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsComposeRemotePathToFile(const NQ_WCHAR * server, const NQ_WCHAR * share, const NQ_WCHAR * file);

/* Description
   This function creates network path from server name, share name and a 
   share-local path to file. 
   
   Path syntax is <i>\\\\\<host\>\\\<share\></i>.
   
   It creates network path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   server :  Pointer to server name and share name (mount path). 
   file :  Pointer to file path. This path should be local to the share.
   isPathLocal : Whether path is of local form.
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsComposeRemotePathToFileByMountPath(const NQ_WCHAR * mountPath, const NQ_WCHAR * file, NQ_BOOL isPathLocal);

/* Description
   This function creates local path from mount point name and a 
   path to file. 
   
   Path syntax is <i>\<mount point\>\<file path\></i>.
   
   It creates network path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   mountPoint :  Pointer to mount point. 
   file :  Pointer to file path. This path should be local to the share. 
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsComposeLocalPathToFileByMountPoint(const NQ_WCHAR * mountPoint, const NQ_WCHAR * file);

/* Description
   This function checks widlcards in a path.
   
   Parameters
   origin :  Original path with or without widlcards. 
   Returns
   TRUE if the string has wildcards or FALSE oetherwise. */
NQ_BOOL ccUtilsFilePathHasWildcards(const NQ_WCHAR * origin);

/* Description
   This function strips possible widlcards from a path.
   
   The resulted string is either the same string or the diretcory path for of a 
   widlcard notation.  
   
   It creates new path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   origin :  Original path with or without widlcards. 
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsFilePathStripWildcards(const NQ_WCHAR * origin);

/* Description
   This function strips last component from a path.
   
   The resulted string is original string without last file path component.
   
   It creates new path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   origin :  Original path. 
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsFilePathStripLastComponent(const NQ_WCHAR * origin);

/* Description
   This function withdraws possible last path clause with widlcards.
   
   The resulted string is either the last path clause or an empty string.  
   
   It creates new string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   origin :  Original path with or without widlcards. 
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsFilePathGetWildcards(const NQ_WCHAR * origin);

/* Description
   This function creates full file path from directory path and file name. 
   
   It creates new path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   dir :  Directory path. 
   file :  File name. 
   Returns
   Pointer to a newly created path string or NULL on failure. */
NQ_WCHAR * ccUtilsComposePath(const NQ_WCHAR * dir, const NQ_WCHAR * file);

/* Description
   This function withdraws directory path from full path by taking the path component
   before the last delimiter. If there is no delimiter - it returns an empty string, 
   
   It creates new path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   path :  Full path. 
   Returns
   Pointer to a newly created directory path string or NULL on failure. */
NQ_WCHAR * ccUtilsDirectoryFromPath(const NQ_WCHAR * path);

/* Description
   This function withdraws file name from full path by taking the path component
   after the last delimiter. If there is no deleimiter - it returns an original string, 
   
   It creates new path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   path :  Full path. 
   Returns
   Pointer to a newly created file name string or NULL on failure. */
NQ_WCHAR * ccUtilsFileFromPath(const NQ_WCHAR * path);

/* Description
   This function checks whether supplied path is local. 
   
   Parameters
   path :  Full path. 
   Returns
   TRUE if the path is local or FALSE otherwise. */
NQ_BOOL ccUtilsPathIsLocal(const NQ_WCHAR * path);

/* Description
   This function makes a canonicalized path by adding a leading backslash, 
   relevant for SMB only.
   
   It creates new path string in an allocated memory and it is
   caller's responsibility to free that memory.
   Parameters
   path :  Path. 
   Returns
   Pointer to a newly created path or NULL on failure. */
NQ_WCHAR * ccUtilsCanonicalizePath(const NQ_WCHAR * path);

#endif /* _CCUTILS_H_ */
