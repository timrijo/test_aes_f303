/*
 * crypto_init.c
 *
 *  Created on: 6 сент. 2021 г.
 *      Author: pad3
 */

#include "crypto_init.h"
#include "crypto.h"
/* Private variables ---------------------------------------------------------*/

const uint8_t Plaintext[PLAINTEXT_LENGTH] =
    {
	    0x6b,
	    0xc1,
	    0xbe,
	    0xe2,
	    0x2e,
	    0x40,
	    0x9f,
	    0x96,
	    0xe9,
	    0x3d,
	    0x7e,
	    0x11,
	    0x73,
	    0x93,
	    0x17,
	    0x2a,
	    0xae,
	    0x2d,
	    0x8a,
	    0x57,
	    0x1e,
	    0x03,
	    0xac,
	    0x9c,
	    0x9e,
	    0xb7,
	    0x6f,
	    0xac,
	    0x45,
	    0xaf,
	    0x8e,
	    0x51,
	    0x30,
	    0xc8,
	    0x1c,
	    0x46,
	    0xa3,
	    0x5c,
	    0xe4,
	    0x11,
	    0xe5,
	    0xfb,
	    0xc1,
	    0x19,
	    0x1a,
	    0x0a,
	    0x52,
	    0xef,
	    0xf6,
	    0x9f,
	    0x24,
	    0x45,
	    0xdf,
	    0x4f,
	    0x9b,
	    0x17,
	    0xad,
	    0x2b,
	    0x41,
	    0x7b,
	    0xe6,
	    0x6c,
	    0x37,
	    0x10
    };

/* Key to be used for AES encryption/decryption */
uint8_t Key[CRL_AES128_KEY] =
    {
	    0x2b,
	    0x7e,
	    0x15,
	    0x16,
	    0x28,
	    0xae,
	    0xd2,
	    0xa6,
	    0xab,
	    0xf7,
	    0x15,
	    0x88,
	    0x09,
	    0xcf,
	    0x4f,
	    0x3c
    };

/* Initialization Vector, used only in non-ECB modes */
uint8_t IV[CRL_AES_BLOCK] =
    {
	    0xf0,
	    0xf1,
	    0xf2,
	    0xf3,
	    0xf4,
	    0xf5,
	    0xf6,
	    0xf7,
	    0xf8,
	    0xf9,
	    0xfa,
	    0xfb,
	    0xfc,
	    0xfd,
	    0xfe,
	    0xff
    };

/* Buffer to store the output data */
uint8_t OutputMessage[PLAINTEXT_LENGTH];

/* Size of the output data */
uint32_t OutputMessageLength = 0;

const uint8_t Expected_Ciphertext[PLAINTEXT_LENGTH] =
    {
	    0x87,
	    0x4d,
	    0x61,
	    0x91,
	    0xb6,
	    0x20,
	    0xe3,
	    0x26,
	    0x1b,
	    0xef,
	    0x68,
	    0x64,
	    0x99,
	    0x0d,
	    0xb6,
	    0xce,
	    0x98,
	    0x06,
	    0xf6,
	    0x6b,
	    0x79,
	    0x70,
	    0xfd,
	    0xff,
	    0x86,
	    0x17,
	    0x18,
	    0x7b,
	    0xb9,
	    0xff,
	    0xfd,
	    0xff,
	    0x5a,
	    0xe4,
	    0xdf,
	    0x3e,
	    0xdb,
	    0xd5,
	    0xd3,
	    0x5e,
	    0x5b,
	    0x4f,
	    0x09,
	    0x02,
	    0x0d,
	    0xb0,
	    0x3e,
	    0xab,
	    0x1e,
	    0x03,
	    0x1d,
	    0xda,
	    0x2f,
	    0xbe,
	    0x03,
	    0xd1,
	    0x79,
	    0x21,
	    0x70,
	    0xa0,
	    0xf3,
	    0x00,
	    0x9c,
	    0xee
    };

/**
 * @brief  AES CTR Encryption example.
 * @param  InputMessage: pointer to input message to be encrypted.
 * @param  InputMessageLength: input data message length in byte.
 * @param  AES128_Key: pointer to the AES key to be used in the operation
 * @param  InitializationVector: pointer to the Initialization Vector (IV)
 * @param  IvLength: IV length in bytes.
 * @param  OutputMessage: pointer to output parameter that will handle the encrypted message
 * @param  OutputMessageLength: pointer to encrypted message length.
 * @retval error status: can be AES_SUCCESS if success or one of
 *         AES_ERR_BAD_CONTEXT, AES_ERR_BAD_PARAMETER, AES_ERR_BAD_OPERATION
 *         if error occured.
 */
int32_t STM32_AES_CTR_Encrypt(uint8_t *InputMessage,
	uint32_t InputMessageLength, uint8_t *AES128_Key,
	uint8_t *InitializationVector, uint32_t IvLength,
	uint8_t *OutputMessage, uint32_t *OutputMessageLength)
    {
    AESCTRctx_stt AESctx;

    uint32_t error_status = AES_SUCCESS;

    int32_t outputLength = 0;

    /* Set flag field to default value */
    AESctx.mFlags = E_SK_DEFAULT;

    /* Set key size to 16 (corresponding to AES-128) */
    AESctx.mKeySize = 16;

    /* Set iv size field to IvLength*/
    AESctx.mIvSize = IvLength;

    /* Initialize the operation, by passing the key.
     * Third parameter is NULL because CTR doesn't use any IV */
    error_status = AES_CTR_Encrypt_Init(&AESctx, AES128_Key,
	    InitializationVector);

    /* check for initialization errors */
    if (error_status == AES_SUCCESS)
	{
	/* Encrypt Data */
	error_status = AES_CTR_Encrypt_Append(&AESctx, InputMessage,
		InputMessageLength, OutputMessage, &outputLength);

	if (error_status == AES_SUCCESS)
	    {
	    /* Write the number of data written*/
	    *OutputMessageLength = outputLength;
	    /* Do the Finalization */
	    error_status = AES_CTR_Encrypt_Finish(&AESctx,
		    OutputMessage + *OutputMessageLength, &outputLength);
	    /* Add data written to the information to be returned */
	    *OutputMessageLength += outputLength;
	    }
	}

    return error_status;
    }

/**
 * @brief  AES CTR Decryption example.
 * @param  InputMessage: pointer to input message to be decrypted.
 * @param  InputMessageLength: input data message length in byte.
 * @param  AES128_Key: pointer to the AES key to be used in the operation
 * @param  InitializationVector: pointer to the Initialization Vector (IV)
 * @param  IvLength: IV length in bytes.
 * @param  OutputMessage: pointer to output parameter that will handle the decrypted message
 * @param  OutputMessageLength: pointer to decrypted message length.
 * @retval error status: can be AES_SUCCESS if success or one of
 *         AES_ERR_BAD_CONTEXT, AES_ERR_BAD_PARAMETER, AES_ERR_BAD_OPERATION
 *         if error occured.
 */
int32_t STM32_AES_CTR_Decrypt(uint8_t *InputMessage,
		uint32_t InputMessageLength, uint8_t *AES128_Key,
		uint8_t *InitializationVector, uint32_t IvLength,
		uint8_t *OutputMessage, uint32_t *OutputMessageLength)
{
	AESCTRctx_stt AESctx;

	uint32_t error_status = AES_SUCCESS;

	int32_t outputLength = 0;

	/* Set flag field to default value */
	AESctx.mFlags = E_SK_DEFAULT;

	/* Set key size to 16 (corresponding to AES-128) */
	AESctx.mKeySize = 16;

	/* Set iv size field to IvLength*/
	AESctx.mIvSize = IvLength;

	/* Initialize the operation, by passing the key.
	 * Third parameter is NULL because CTR doesn't use any IV */
	error_status = AES_CTR_Decrypt_Init(&AESctx, AES128_Key,
			InitializationVector);

	/* check for initialization errors */
	if (error_status == AES_SUCCESS)
	{
		/* Decrypt Data */
		error_status = AES_CTR_Decrypt_Append(&AESctx, InputMessage,
				InputMessageLength, OutputMessage, &outputLength);
		if (error_status == AES_SUCCESS)
		{
			/* Write the number of data written*/
			*OutputMessageLength = outputLength;
			/* Do the Finalization */
			error_status = AES_CTR_Decrypt_Finish(&AESctx,
					OutputMessage + *OutputMessageLength, &outputLength);
			/* Add data written to the information to be returned */
			*OutputMessageLength += outputLength;
		}
	}

	return error_status;
}
