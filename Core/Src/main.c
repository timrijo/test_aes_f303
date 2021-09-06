/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2021 STMicroelectronics.
 * All rights reserved.</center></h2>
 *
 * This software component is licensed by ST under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                        opensource.org/licenses/BSD-3-Clause
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "crypto.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CRC_HandleTypeDef hcrc;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */

//флаг при появлении прерывания от нажатия кнопки
uint8_t flag_key_interrupt = 0;

/* Private typedef -----------------------------------------------------------*/
typedef enum
    {
    FAILED = 0,
    PASSED = !FAILED
    } TestStatus;
/* Private define ------------------------------------------------------------*/
#define PLAINTEXT_LENGTH 64
/* Private macro -------------------------------------------------------------*/
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

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_CRC_Init(void);
static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */
/* Private function prototypes -----------------------------------------------*/
int32_t STM32_AES_CTR_Encrypt(uint8_t *InputMessage,
	uint32_t InputMessageLength, uint8_t *AES128_Key,
	uint8_t *InitializationVector, uint32_t IvLength,
	uint8_t *OutputMessage, uint32_t *OutputMessageLength);

int32_t STM32_AES_CTR_Decrypt(uint8_t *InputMessage,
	uint32_t InputMessageLength, uint8_t *AES128_Key,
	uint8_t *InitializationVector, uint32_t IvLength,
	uint8_t *OutputMessage, uint32_t *OutputMessageLength);

TestStatus Buffercmp(const uint8_t *pBuffer, uint8_t *pBuffer1,
	uint16_t BufferLength);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */
    int32_t status = AES_SUCCESS;
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_CRC_Init();
  MX_USART1_UART_Init();
  /* USER CODE BEGIN 2 */
    /* Enable CRC clock */
    __CRC_CLK_ENABLE()
    ;

    //Убрать вхождение в режим сна после обработки последнего прерывания
    //HAL_PWR_DisableSleepOnExit();
    //отключаем прерывания от SysTick
    //HAL_SuspendTick();
    //Погружение контроллера в режим сна после инициализации
    //PWR_SLEEPENTRY_WFI выход из режима произойдёт после прерывания
    //HAL_PWR_EnterSLEEPMode(PWR_LOWPOWERREGULATOR_ON, PWR_SLEEPENTRY_WFI);

    /* Encrypt DATA with AES in CTR mode */

    if (flag_key_interrupt == 1)
	{
	status = STM32_AES_CTR_Encrypt((uint8_t*) Plaintext, PLAINTEXT_LENGTH, Key,
		    IV, sizeof(IV), OutputMessage, &OutputMessageLength);
	    if (status == AES_SUCCESS)
		{
		if (Buffercmp(Expected_Ciphertext, OutputMessage, PLAINTEXT_LENGTH)
			== PASSED)
		    {
		    /* add application traitment in case of AES CTR encryption is passed */
		    }
		else
		    {
		    Error_Handler();
		    }
		}
	    else
		{
		/* In case of encryption not success the possible values of status:
		 * AES_ERR_BAD_CONTEXT, AES_ERR_BAD_PARAMETER, AES_ERR_BAD_OPERATION
		 */
		Error_Handler();
		}
	    status = STM32_AES_CTR_Decrypt((uint8_t*) Expected_Ciphertext,
	    PLAINTEXT_LENGTH, Key, IV, sizeof(IV), OutputMessage, &OutputMessageLength);
	    if (status == AES_SUCCESS)
		{
		if (Buffercmp(Plaintext, OutputMessage, PLAINTEXT_LENGTH) == PASSED)
		    {
		    /* add application traitment in case of AES CTR decryption is passed */
		    }
		else
		    {
		    Error_Handler();
		    }
		}
	    else
		{
		/* In case of decryption not success the possible values of status:
		 * AES_ERR_BAD_CONTEXT, AES_ERR_BAD_PARAMETER, AES_ERR_BAD_OPERATION
		 */
		Error_Handler();
		}

	HAL_UART_Transmit(&huart1, (uint8_t*) "proverka\n", 8, 1000);

	HAL_Delay(100);    // защита от дребизга кнопки
	flag_key_interrupt = 0;
	}

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
    while (1)
	{
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
	}
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.HSEPredivValue = RCC_HSE_PREDIV_DIV1;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL9;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
  PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART1;
  PeriphClkInit.Usart1ClockSelection = RCC_USART1CLKSOURCE_PCLK2;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief CRC Initialization Function
  * @param None
  * @retval None
  */
static void MX_CRC_Init(void)
{

  /* USER CODE BEGIN CRC_Init 0 */

  /* USER CODE END CRC_Init 0 */

  /* USER CODE BEGIN CRC_Init 1 */

  /* USER CODE END CRC_Init 1 */
  hcrc.Instance = CRC;
  hcrc.Init.DefaultPolynomialUse = DEFAULT_POLYNOMIAL_ENABLE;
  hcrc.Init.DefaultInitValueUse = DEFAULT_INIT_VALUE_ENABLE;
  hcrc.Init.InputDataInversionMode = CRC_INPUTDATA_INVERSION_NONE;
  hcrc.Init.OutputDataInversionMode = CRC_OUTPUTDATA_INVERSION_DISABLE;
  hcrc.InputDataFormat = CRC_INPUTDATA_FORMAT_BYTES;
  if (HAL_CRC_Init(&hcrc) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN CRC_Init 2 */

  /* USER CODE END CRC_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 9600;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOE_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOF_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOE, CS_I2C_SPI_Pin|LD4_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pins : DRDY_Pin MEMS_INT3_Pin MEMS_INT4_Pin */
  GPIO_InitStruct.Pin = DRDY_Pin|MEMS_INT3_Pin|MEMS_INT4_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_EVT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOE, &GPIO_InitStruct);

  /*Configure GPIO pins : CS_I2C_SPI_Pin LD4_Pin */
  GPIO_InitStruct.Pin = CS_I2C_SPI_Pin|LD4_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOE, &GPIO_InitStruct);

  /*Configure GPIO pin : KEY_Pin */
  GPIO_InitStruct.Pin = KEY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(KEY_GPIO_Port, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */

void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin)
    {
    if (GPIO_Pin == KEY_Pin)
	{
	if (flag_key_interrupt == 0)
	    flag_key_interrupt = 1;
	//HAL_ResumeTick(); // включаем прерывания от SysTick
	}
    }

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

/**
 * @brief  Compares two buffers.
 * @param  pBuffer, pBuffer1: buffers to be compared.
 * @param  BufferLength: buffer's length
 * @retval PASSED: pBuffer identical to pBuffer1
 *         FAILED: pBuffer differs from pBuffer1
 */
TestStatus Buffercmp(const uint8_t *pBuffer, uint8_t *pBuffer1,
	uint16_t BufferLength)
    {
    while (BufferLength--)
	{
	if (*pBuffer != *pBuffer1)
	    {
	    return FAILED;
	    }

	pBuffer++;
	pBuffer1++;
	}

    return PASSED;
    }
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
    /* User can add his own implementation to report the HAL error return state */
    __disable_irq();
    while (1)
	{
	}
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
