/*
 * crypto_init.h
 *
 *  Created on: 6 сент. 2021 г.
 *      Author: pad3
 */

#ifndef INC_CRYPTO_INIT_H_
#define INC_CRYPTO_INIT_H_

#include "main.h"

#define PLAINTEXT_LENGTH 64

int32_t STM32_AES_CTR_Encrypt(uint8_t *InputMessage,
	uint32_t InputMessageLength, uint8_t *AES128_Key,
	uint8_t *InitializationVector, uint32_t IvLength,
	uint8_t *OutputMessage, uint32_t *OutputMessageLength);

int32_t STM32_AES_CTR_Decrypt(uint8_t *InputMessage,
		uint32_t InputMessageLength, uint8_t *AES128_Key,
		uint8_t *InitializationVector, uint32_t IvLength,
		uint8_t *OutputMessage, uint32_t *OutputMessageLength);

#endif /* INC_CRYPTO_INIT_H_ */
