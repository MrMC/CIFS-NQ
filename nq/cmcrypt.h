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

#define AES_PRIV_SIZE (4 * 4 * 15 + 4)
#define SHA512_CTXSIZE 720 /* u64 * 8 + U64 * 80 + 4 + 8 = 8 * 8 + 80 * 8 + 4 + 8 = 716 -> 720 */

#define CM_CRYPT_NTLM_TO_SERVER_SIGNING 1
#define CM_CRYPT_NTLM_FROM_SERVER_SIGNING 2
#define CM_CRYPT_NTLM_TO_SERVER_SEALING 4
#define CM_CRYPT_NTLM_FROM_SERVER_SEALING 8

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
    const NQ_WCHAR *domain,
    NQ_BOOL caseSensitiveDomain,
    const NQ_WCHAR *user,
    const NQ_BYTE  *password,
    NQ_UINT pwdlen,
    NQ_BYTE *hash
    );

void
cmGenerateExtSecuritySessionKey(
    const NQ_BYTE* v2hash,
    const NQ_BYTE* encrypted,
    NQ_BYTE* out
    );

void
cmCalculateNtlmSigningKey(
	NQ_BYTE	* sessionKey,
	NQ_BYTE * signingKey,
	NQ_UINT16 flag
	);

void
cmCalculateDcerpcSignature(
	NQ_BYTE	* data,
	NQ_UINT16 dataLen,
	NQ_BYTE * signingKey,
	NQ_BYTE * sealingKey,
	NQ_UINT32 sequence,
	NQ_BYTE * signature
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

/*
 *====================================================================
 * PURPOSE: Calculate SMB2 message signature
 *--------------------------------------------------------------------
 * PARAMS:  IN  buffer - full packet.
 *          IN  size - buffer size
 *          IN  digestResult - previous digest and new calculated digest.
 *
 * RETURNS: none
 *
 * NOTES:   Since SMB dialect 3.1.1 hash is calculated on negotiate and session setup packets
 *====================================================================
 */

void cmSmb311CalcMessagesHash(    
    const NQ_BYTE *buffer,
    NQ_UINT size,
    NQ_BYTE *digestResult,
	NQ_BYTE *ctxBuff
	);


/*
 *====================================================================
 * PURPOSE: Calculate SMB3 message signature
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - signing key
 * 		 	IN 	keyLen - length of key
 * 		 	IN 	buffer1 - data to calculate signature for
 * 		 	IN 	size1 - size of buffer1
 * 		 	IN 	buffer2 - additional data to calculate signature for
 * 		 	IN 	size2 - size of buffer2
 *		 	IN 	signature - message signature - where to store calculated signature
 *
 * NOTES:   Since SMB dialect 3.1.1 hash is calculated on negotiate and session setup packets
 *====================================================================
 */
void cmSmb3CalculateMessageSignature(
    const NQ_BYTE *key,
    NQ_UINT keyLen,
    const NQ_BYTE *buffer1,
    NQ_UINT size1,
    const NQ_BYTE *buffer2,
    NQ_UINT size2,
    NQ_BYTE *signature
	);

/*
 *====================================================================
 * PURPOSE: Key derivation function
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - 
 * 		 	IN 	keyLen - length of key
 * 		 	IN 	buffer1 - data to calculate signature for
 * 		 	IN 	size1 - size of buffer1
 * 		 	IN 	buffer2 - additional data to calculate signature for
 * 		 	IN 	size2 - size of buffer2
 *		 	IN 	signature - message signature - where to store calculated signature
 *
 * NOTES:   Since SMB dialect 3.1.1 hash is calculated on negotiate and session setup packets
 *====================================================================
 */

void cmKeyDerivation(
		const NQ_BYTE * key,
		NQ_UINT keyLen,
		NQ_BYTE * label,
		NQ_UINT labelLen,
		NQ_BYTE * context,
		NQ_UINT contextLen,
		NQ_BYTE * derivedKey
		);

/*
 *====================================================================
 * PURPOSE: SMB3 decrypt message
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - decryption key.
 * 		 	IN 	nonce - IV vector
 * 		 	IN 	crptMsg - pointer to encrypted message. returned decrypted message will be saved here.
 * 		 	IN 	msgLen -  Message size
 * 		 	IN 	authMsg - pointer to AAD - buffer that signature should be calculated on. this part is not enctypted. only authenticated.
 * 		 	IN 	authLen - size of authMsg
 *		 	IN 	signature - received message signature. will be compared to calculated signature
 *		 	IN  isAESGCM - choose AES GCM encryption or AES CCM
 *
 *			OUT - TRUE if calculated signature is same as received signature.
 *
 *====================================================================
 */

NQ_BOOL cmSmb3DecryptMessage(
    /*const*/ NQ_BYTE *key,
    NQ_BYTE *nonce,
    /*const*/ NQ_BYTE *crptMsg,
    NQ_UINT msgLen,
    /*const*/ NQ_BYTE *authMsg,
    NQ_UINT authLen,
    NQ_BYTE *signature,
	NQ_BOOL isAESGCM
    );

/*
 *====================================================================
 * PURPOSE: SMB3 encrypt message
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - encryption key.
 * 		 	IN 	nonce - IV vector
 * 		 	IN 	msg - pointer to message to be encrypted. also to return encrypted message.
 * 		 	IN 	msgLen -  Message size
 * 		 	IN 	authMsg - pointer to AAD - buffer that signature should be calculated on. this part is not encrypted. only authenticated.
 * 		 	IN 	authLen - size of authMsg
 *		 	IN 	signature - signature pointer. calculated signature will be saved here.
 *		 	IN  isAESGCM - choose AES GCM encryption or AES CCM
 *
 *			OUT - none.
 *
 *====================================================================
 */

void cmSmb3EncryptMessage(
    /*const*/ NQ_BYTE *key,
    NQ_BYTE *nonce,
    /*const*/ NQ_BYTE *msg,
    NQ_UINT msgLen,
    /*const*/ NQ_BYTE *authMsg,
    NQ_UINT authLen,
    NQ_BYTE *signature,
	NQ_BOOL isAESGCM
    );

/*
 *====================================================================
 * PURPOSE: AES 128 CCM decrypt message API
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - decryption key.
 * 		 	IN 	nonce - IV vector
 * 		 	IN 	crptMsg - pointer to encrypted message. returned decrypted message will be saved here.
 * 		 	IN 	msgLen -  Message size
 * 		 	IN 	addBuf - pointer to AAD - buffer that signature should be calculated on. this part is not encrypted. only authenticated.
 * 		 	IN 	addLen - size of authMsg
 *		 	IN 	signature - received message signature. will be compared to calculated signature
 *
 *			OUT - TRUE if calculated signature is same as received signature.
 *
 *====================================================================
 */

NQ_BOOL AES_128_CCM_Decrypt(NQ_BYTE * key, 
	NQ_BYTE * nonce, 
	NQ_BYTE * msgBuf, 
	NQ_UINT msgLen, 

	NQ_BYTE * addBuf,
	NQ_UINT addLen,
	NQ_BYTE * signature
	);

/*
 *====================================================================
 * PURPOSE: AES 128 CCM encrypt message API
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - decryption key.
 * 		 	IN 	nonce - IV vector
 * 		 	IN 	crptMsg - pointer to encrypted message. returned decrypted message will be saved here.
 * 		 	IN 	msgLen -  Message size
 * 		 	IN 	addBuf - pointer to AAD - buffer that signature should be calculated on. this part is not encrypted. only authenticated.
 * 		 	IN 	addLen - size of authMsg
 *		 	IN 	signature - pointer to message signature. here calculated signature is stored
 *
 *			OUT - None
 *
 *====================================================================
 */

void AES_128_CCM_Encrypt(NQ_BYTE * key, 
	NQ_BYTE * nonce, 
	NQ_BYTE * msgBuf, 
	NQ_UINT msgLen, 

	NQ_BYTE * addBuf,
	NQ_UINT addLen,
	NQ_BYTE * signature
	);

/*
 *====================================================================
 * PURPOSE: AES 128 GCM decrypt message API
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - decryption key.
 * 		 	IN 	nonce - IV vector
 * 		 	IN 	crptMsg - pointer to encrypted message. returned decrypted message will be saved here.
 * 		 	IN 	msgLen -  Message size
 * 		 	IN 	addBuf - pointer to AAD - buffer that signature should be calculated on. this part is not encrypted. only authenticated.
 * 		 	IN 	addLen - size of authMsg
 *		 	IN 	signature - received message signature. will be compared to calculated signature
 *
 *			OUT - TRUE if calculated signature is same as received signature.
 *
 *====================================================================
 */


NQ_BOOL aes128GcmDecrypt(NQ_BYTE *key,
	NQ_BYTE *nonce,
	NQ_BYTE *msgBuf,
	NQ_UINT msgLen, 

	NQ_BYTE *addBuf,
	NQ_UINT addLen,
	NQ_BYTE *authValue,
	NQ_BYTE *keyBuffer,
	NQ_BYTE *msgBuffer
	);

/*
 *====================================================================
 * PURPOSE: AES 128 GCM encrypt message API
 *--------------------------------------------------------------------
 * PARAMS:	IN	key - decryption key.
 * 		 	IN 	nonce - IV vector
 * 		 	IN 	crptMsg - pointer to encrypted message. returned decrypted message will be saved here.
 * 		 	IN 	msgLen -  Message size
 * 		 	IN 	addBuf - pointer to AAD - buffer that signature should be calculated on. this part is not encrypted. only authenticated.
 * 		 	IN 	addLen - size of authMsg
 *		 	IN 	signature - pointer to message signature. here calculated signature is stored
 *
 *			OUT - None
 *
 *====================================================================
 */

void aes128GcmEncrypt(NQ_BYTE *key,
	NQ_BYTE *nonce,
	NQ_BYTE *msgBuf,
	NQ_UINT msgLen, 

	NQ_BYTE *addBuf,
	NQ_UINT addLen,
	NQ_BYTE *authValue,
	NQ_BYTE *keyBuffer,
	NQ_BYTE *msgBuffer
	);

#ifdef NQ_DEBUG
void testAesGCM();
void testSha512();
void testCalcMessageHash();
void testSignKeyDerivationAndSigning ();
#endif

#endif
