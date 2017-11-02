/*********************************************************************
 *
 *           Copyright (c) 2004 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Cryptographic library and password handling
 *                 contains DES, MD4 and MD5 algorithm implementations
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 10-Jun-2004
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMCRYPT_H_
#define _CMCRYPT_H_

#include "cmapi.h"

typedef struct
{
    NQ_UINT32 buf[4];
    NQ_UINT32 bits[2];
    NQ_BYTE   in[64];
} MD5Context;

/* password handling */

#define CM_CRYPT_ENCLMPWDSIZE    24
#define CM_CRYPT_ENCNTLMPWDSIZE  24
#define CM_CRYPT_ENCLMv2BLIPSIZE 8
#define CM_CRYPT_ENCLMv2HMACSIZE 16
#define CM_CRYPT_ENCLMv2PWDSIZE  24

#define CM_CRYPT_NTLMV2RESPONSESIZE 52
#define CM_CRYPT_MAX_NTLMV2NTLMSSPRESPONSESIZE 1952 /* max possible blob length */

void
cmEncryptPlainTextPassword(
    const NQ_BYTE *passwd,
    const NQ_BYTE *key,
    NQ_BYTE *encrPasswd
    );

void
cmHashPassword(
    const NQ_BYTE *passwd,
    NQ_BYTE hshPasswd[16]
    );

void
cmEncryptHashedPassword(
    const NQ_BYTE hshPasswd[16],
    const NQ_BYTE key[8],
    NQ_BYTE encPasswd[24]
    );

void
cmEncryptLMPassword(
    const NQ_BYTE *key,
    const NQ_BYTE *password,
    NQ_BYTE *encrypted,
    NQ_UINT16 *enclen
    );

void
cmEncryptNTLMPassword(
    const NQ_BYTE *key,
    const NQ_BYTE *password,
    NQ_BYTE *encrypted,
    NQ_UINT16 *enclen
    );

void
cmDecryptPassword(
    const NQ_BYTE *key,
    NQ_BYTE *password,
    NQ_BOOL doMd5
    );

void
cmEncryptNTLMv2Password(
    const NQ_BYTE *key,
    const NQ_BYTE *v2hash,
    const NQ_BYTE *blob,
    NQ_UINT16 bloblen,
    NQ_BYTE   *encrypted,
    NQ_UINT16 *enclen
    );

void
cmCreateV2Hash(
    const NQ_TCHAR *domain,
    NQ_BOOL caseSensitiveDomain,
    const NQ_TCHAR *user,
    const NQ_BYTE  *password,
    NQ_UINT pwdlen,
    NQ_BYTE *hash
    );

void
cmGenerateNTLMv2SessionKey(
    const NQ_BYTE* v2hash,
    const NQ_BYTE* encrypted,
    NQ_BYTE* out
    );

/* cryptographic algorithms */

void
cmMD4(
    NQ_BYTE *out,
    NQ_BYTE *in,
    NQ_UINT   n
    );

void
cmMD5(
    NQ_BYTE *out,
    NQ_BYTE *in,
    NQ_UINT n
    );

void
cmHMACMD5(
    const NQ_BYTE *key,
    NQ_UINT key_len,
    const NQ_BYTE *data,
    NQ_UINT data_len,
    NQ_BYTE *md
    );

void 
cmDES112(
    NQ_BYTE *out, 
    const NQ_BYTE *in, 
    const NQ_BYTE *key
    );

/* message signing */

void
cmCreateMAC(
    const NQ_BYTE *key,
    NQ_COUNT       keyLen,
    NQ_UINT32      sequence,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen,
    const NQ_BYTE *data,           /* actually the packet header */
    NQ_UINT        length,
    NQ_BYTE       *signature
    );

NQ_BOOL
cmCheckMAC(
    const NQ_BYTE *key,
    NQ_COUNT       keyLen,
    NQ_UINT32      sequence,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen,
    const NQ_BYTE *data,
    NQ_UINT         length,
    NQ_BYTE       *signature
    );

/* create random byte sequence */
void
cmCreateRandomByteSequence(
    NQ_BYTE *buffer,
    NQ_UINT32 size
    );

/* create random encryption key */
#define cmGenerateRandomEncryptionKey(_key) cmCreateRandomByteSequence(_key, SMB_ENCRYPTION_LENGTH)

/*
 *====================================================================
 * PURPOSE: Calculate SMB message signature
 *--------------------------------------------------------------------
 * PARAMS:  IN  session key
 *          IN  session key length
 *          IN  buffer 1
 *          IN  buffer 1 size
 *          IN  buffer 2 (might be NULL)
 *          IN  buffer 2 size
 *          OUT signature
 *
 * RETURNS: none
 *
 * NOTES:   Signature pointer may reside inside the actual packet.
 *====================================================================
 */
void cmSmbCalculateMessageSignature(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
    NQ_UINT32      sequence,
    const NQ_BYTE *buffer1,
    NQ_UINT size1,
    const NQ_BYTE *buffer2,
    NQ_UINT size2,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen,
    NQ_BYTE *signature
    );

#ifdef UD_NQ_INCLUDESMB2
/*
 *====================================================================
 * PURPOSE: Calculate SMB2 message signature
 *--------------------------------------------------------------------
 * PARAMS:  IN  session key
 *          IN  session key length
 *          IN  buffer 1
 *          IN  buffer 1 size
 *          IN  buffer 2 (might be NULL)
 *          IN  buffer 2 size
 *          OUT signature
 *
 * RETURNS: none
 *
 * NOTES:   Signature pointer may reside inside the actual packet.
 *====================================================================
 */
void cmSmb2CalculateMessageSignature(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
    const NQ_BYTE *buffer1,
    NQ_UINT size1,
    const NQ_BYTE *buffer2,
    NQ_UINT size2,
    NQ_BYTE *signature
    );
#endif

/*
 *====================================================================
 * PURPOSE: Crypt using ARC4 algorithm
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT data
 *          IN data length
 *          IN key
 *          IN key length
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void cmArcfourCrypt(
    NQ_BYTE* data,
    NQ_UINT dataLen,
    const NQ_BYTE *key,
    NQ_UINT keyLen
    );

/*
 *====================================================================
 * PURPOSE: Generate Netlogon credentials
 *--------------------------------------------------------------------
 * PARAMS:  IN client challenge
 *          IN server challenge
 *          IN key (secret)
 *          IN/OUT new client challenge
 *          IN/OUT new server challenge
 *          IN/OUT new session key
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void cmGenerateNetlogonCredentials
(
    const NQ_BYTE *clientChallenge,
    const NQ_BYTE *serverChallenge,
    const NQ_BYTE *key,
    NQ_BYTE *clientChallengeNew,
    NQ_BYTE *serverChallengeNew,
    NQ_BYTE *sessKey
    );


/*
 *====================================================================
 * PURPOSE: Create signing context  SMB
 *--------------------------------------------------------------------
 * PARAMS:  
 *          IN/OUT MD5 context
 *          IN     session key 
 *          IN     session key length
 *          IN     client response data (password)
 *          IN     client response data length (password length)
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void 
cmCreateSigningContext(
    MD5Context    *ctx,
    const NQ_BYTE *key,
    NQ_COUNT       keyLen,
    const NQ_BYTE *password,
    NQ_COUNT       passwordLen    
);    

/*
 *====================================================================
 * PURPOSE: Create message authentication code using saved MD5 context
 *--------------------------------------------------------------------
 * PARAMS:  IN     saved MD5 context
 *          IN     message sequence number
 *          IN     data buffer
 *          IN     data length
 *          IN/OUT message signature (pointer inside data buffer)
 *
 * RETURNS: none
 *
 * NOTES:   none
 *====================================================================
 */
void
cmCreateMACByContext(
    MD5Context    *ctx,    
    NQ_UINT32      sequence,
    const NQ_BYTE *data,          
    NQ_UINT        length,
    NQ_BYTE       *signature
    );

/*
 *====================================================================
 * PURPOSE: Check message authentication code using saved MD5 context
 *--------------------------------------------------------------------
 * PARAMS:  IN     saved MD5 context
 *          IN     message sequence number
 *          IN     data buffer
 *          IN     data length
 *          IN     message signature (pointer inside data buffer)
 *
 * RETURNS: TRUE for valid signature, FALSE otherwise
 *
 * NOTES:   none
 *====================================================================
 */
NQ_BOOL
cmCheckMACByContext(
    MD5Context    *ctx,    
    NQ_UINT32      sequence,
    const NQ_BYTE *data,
    NQ_UINT        length,
    NQ_BYTE       *signature
    );


#endif
