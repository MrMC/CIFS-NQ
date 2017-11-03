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

#ifndef _AMCRYPT_H_ 
#define _AMCRYPT_H_

#include "cmapi.h"
#include "amcredentials.h"

/* This structure describes encrypted values. It consists of LM and NTLM 
   hashes respectively. These hashes may be either old-style or V2 hashes.
    
   Hashes are used for logon while session keys are used for message signing and 
   other encryptions during the application session. Rules for session keys may differ
   from those for hashes. */
typedef struct {
    CMBlob pass1;			/* first (LM) encrypted password */
    CMBlob pass2;			/* second (NTLM) encrypted password */
    CMBlob macKey;			/* mac key, i.e., - for message signing */
    CMBlob response;		/* signing response */
} AMCrypt;  /* hashes */

/* Description
   Create encrypted hashes.
   Parameters
   credentials :  Credentials to use for encryption.
   crypt1 : first crypter
   crypt2 : second crypter
   encryptionKey : key to use for encryption.
   names : Blob of names as returned from server. This value may be NULL.
   timeStamp : Time stamp to be used in blob.
   crypt :        Pointer to the result structure. The blob data
                  pointers will point to newly allocated data
                  blocks. Application should deallocate them
                  later using <link amCryptDispose@AMCrypt *, amCryptDispose()>.
   Returns
   TRUE on success, FALSE on failure. This function may fail because of lack of memory.                                                                                        */
NQ_BOOL amCryptEncrypt(const AMCredentialsW * credentials, NQ_UINT crypt1, NQ_UINT crypt2, const NQ_BYTE * encryptionKey, CMBlob * names, NQ_UINT64 timeStamp, AMCrypt * crypt);

/* Description
   Convert ASCII credential to Unicode
   Parameters
   crypt : Pointer to the crypt structure. This structure is
           expected to be created in <link amCryptCreateHash2@AMCredentialsW *@AMCryptHash2 *, amCryptCreateHash2()>.
   Returns
   None.                                                                                                              */
void amCryptDispose(AMCrypt * crypt);

#endif /* _AMCRYPT_H_ */
