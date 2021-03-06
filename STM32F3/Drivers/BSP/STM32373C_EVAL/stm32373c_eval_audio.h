/**
  ******************************************************************************
  * @file    stm32373c_eval_audio.h
  * @author  MCD Application Team
  * @version V2.0.0
  * @date    06-May-2014
  * @brief   This file contains all the functions prototypes for the 
  *          stm32373c_eval_audio.c driver.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT(c) 2014 STMicroelectronics</center></h2>
  *
  * Redistribution and use in source and binary forms, with or without modification,
  * are permitted provided that the following conditions are met:
  *   1. Redistributions of source code must retain the above copyright notice,
  *      this list of conditions and the following disclaimer.
  *   2. Redistributions in binary form must reproduce the above copyright notice,
  *      this list of conditions and the following disclaimer in the documentation
  *      and/or other materials provided with the distribution.
  *   3. Neither the name of STMicroelectronics nor the names of its contributors
  *      may be used to endorse or promote products derived from this software
  *      without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __STM32373C_EVAL_AUDIO_H
#define __STM32373C_EVAL_AUDIO_H

/* Includes ------------------------------------------------------------------*/
/* Include AUDIO component driver */
#include "..\Components\cs43l22\cs43l22.h"   
#include "stm32373c_eval.h"

/** @addtogroup BSP
  * @{
  */

/** @addtogroup STM32_EVAL
  * @{
  */ 

/** @addtogroup STM32373C_EVAL
  * @{
  */
    
/** @defgroup STM32373C_EVAL_AUDIO 
  * @{
  */    


/** @defgroup STM32373C_EVAL_AUDIO_Exported_Types
  * @{
  */
typedef enum 
{
  AUDIO_OK       = 0x00,
  AUDIO_ERROR    = 0x01,
  AUDIO_TIMEOUT  = 0x02

}AUDIO_StatusTypeDef;
  
/**
  * @}
  */

/** @defgroup STM32373C_EVAL_AUDIO_Exported_Constants
  * @{
  */ 
/* Audio Codec hardware I2C address */ 
#define AUDIO_I2C_ADDRESS             0x94

/*----------------------------------------------------------------------------
             AUDIO OUT CONFIGURATION
  ----------------------------------------------------------------------------*/

/* I2S peripheral configuration defines */
#define I2Sx                          SPI1
#define I2Sx_CLK_ENABLE()             __SPI1_CLK_ENABLE()
#define I2Sx_CLK_DISABLE()            __SPI1_CLK_DISABLE()
#define I2Sx_FORCE_RESET()            __SPI1_FORCE_RESET()
#define I2Sx_RELEASE_RESET()          __SPI1_RELEASE_RESET()

#define I2Sx_WS_PIN                   GPIO_PIN_6
#define I2Sx_SCK_PIN                  GPIO_PIN_7
#define I2Sx_MCK_PIN                  GPIO_PIN_8
#define I2Sx_SD_PIN                   GPIO_PIN_9

#define I2Sx_GPIO_PORT                GPIOC
#define I2Sx_GPIO_CLK_ENABLE()        __GPIOC_CLK_ENABLE()
#define I2Sx_GPIO_CLK_DISABLE()       __GPIOC_CLK_DISABLE()
#define I2Sx_AF                       GPIO_AF5_SPI1

/* I2S DMA Stream definitions */
#define I2Sx_DMAx_CLK_ENABLE()        __DMA1_CLK_ENABLE()
#define I2Sx_DMAx_CLK_DISABLE()       __DMA1_CLK_DISABLE()
#define I2Sx_DMAx_CHANNEL             DMA1_Channel3
#define I2Sx_DMAx_IRQ                 DMA1_Channel3_IRQn
#define I2Sx_DMAx_PERIPH_DATA_SIZE    DMA_PDATAALIGN_HALFWORD
#define I2Sx_DMAx_MEM_DATA_SIZE       DMA_MDATAALIGN_HALFWORD
#define DMA_MAX_SZE                   0xFFFF

/* Select the interrupt preemption priority and subpriority for the DMA interrupt */
#define AUDIO_OUT_IRQ_PREPRIO                   5   /* Select the preemption priority level(0 is the highest) */
#define AUDIO_OUT_IRQ_SUBPRIO                   0   /* Select the sub-priority level (0 is the highest) */
/*----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
                    OPTIONAL Configuration defines parameters
------------------------------------------------------------------------------*/
#define AUDIODATA_SIZE        2   /* 16-bits audio data size */

#define DMA_MAX(_X_)          (((_X_) <= DMA_MAX_SZE)? (_X_):DMA_MAX_SZE)

/**
  * @}
  */ 

/** @defgroup STM32373C_EVAL_AUDIO_Exported_Macros
  * @{
  */ 

/**
  * @}
  */ 

/** @defgroup STM32373C_EVAL_AUDIO_Exported_Functions
  * @{
  */ 

/*------------------------------------------------------------------------------
             AUDIO OUT FUNCTIONS
------------------------------------------------------------------------------*/
uint8_t        BSP_AUDIO_OUT_Init(uint16_t OutputDevice, uint8_t Volume, uint32_t AudioFreq);
uint8_t        BSP_AUDIO_OUT_Play(uint16_t* pBuffer, uint32_t Size);
uint8_t        BSP_AUDIO_OUT_ChangeBuffer(uint16_t *pData, uint16_t Size);
uint8_t        BSP_AUDIO_OUT_Pause(void);
uint8_t        BSP_AUDIO_OUT_Resume(void);
uint8_t        BSP_AUDIO_OUT_Stop(uint32_t Option);
uint8_t        BSP_AUDIO_OUT_SetVolume(uint8_t Volume);
uint8_t        BSP_AUDIO_OUT_SetFrequency(uint32_t AudioFreq);
uint8_t        BSP_AUDIO_OUT_SetMute(uint32_t Command);
uint8_t        BSP_AUDIO_OUT_SetOutputMode(uint8_t Output);

/* User Callbacks: user has to implement these functions in his code if they are needed. */
/* This function is called when the requested data has been completely transferred.*/
void           BSP_AUDIO_OUT_TransferComplete_CallBack(void);

/* This function is called when half of the requested buffer has been transferred. */
void           BSP_AUDIO_OUT_HalfTransfer_CallBack(void);

/* This function is called when an Interrupt due to transfer error on or peripheral
   error occurs. */
void           BSP_AUDIO_OUT_Error_CallBack(void);

/**
  * @}
  */ 

/**
  * @}
  */ 

/**
  * @}
  */

/**
  * @}
  */ 

/**
  * @}
  */    

#endif /* __STM32373C_EVAL_AUDIO_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
