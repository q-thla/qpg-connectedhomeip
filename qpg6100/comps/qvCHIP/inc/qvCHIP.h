/*
 * Copyright (c) 2020, Qorvo Inc
 *
 * This software is owned by Qorvo Inc
 * and protected under applicable copyright laws.
 * It is delivered under the terms of the license
 * and is intended and supplied for use solely and
 * exclusively with products manufactured by
 * Qorvo Inc.
 *
 *
 * THIS SOFTWARE IS PROVIDED IN AN "AS IS"
 * CONDITION. NO WARRANTIES, WHETHER EXPRESS,
 * IMPLIED OR STATUTORY, INCLUDING, BUT NOT
 * LIMITED TO, IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE APPLY TO THIS SOFTWARE.
 * QORVO INC. SHALL NOT, IN ANY
 * CIRCUMSTANCES, BE LIABLE FOR SPECIAL,
 * INCIDENTAL OR CONSEQUENTIAL DAMAGES,
 * FOR ANY REASON WHATSOEVER.
 *
 * $Change: 182094 $
 * $DateTime: 2021/09/23 13:36:41 $
 */

/** @file "qvCHIP.h"
 *
 *  CHIP wrapper API
 *
 *  Declarations of the public functions and enumerations of qvCHIP.
*/

#ifndef _QVCHIP_H_
#define _QVCHIP_H_

/*****************************************************************************
 *                    Includes Definitions
 *****************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*****************************************************************************
 *                    Enum Definitions
 *****************************************************************************/

/** @brief status return values */
typedef enum qvStatus_ {
    QV_STATUS_NO_ERROR = 0,
    QV_STATUS_BUFFER_TOO_SMALL = 1,
    QV_STATUS_INVALID_ARGUMENT = 2,
    QV_STATUS_KEY_LEN_TOO_SMALL = 3,
    QV_STATUS_INVALID_DATA = 4,
    QV_STATUS_NOT_IMPLEMENTED = 5,
    QV_STATUS_NVM_ERROR = 6
} qvStatus_t;

#include "qvCHIP_NVM.h"
#include "qvCHIP_KVS.h"
#include "qvCHIP_Ble.h"
#include "qvCHIP_IO.h"
#include "qvCHIP_OTA.h"

/*****************************************************************************
 *                    Macro Definitions
 *****************************************************************************/

/*****************************************************************************
 *                    Functional Macro Definitions
 *****************************************************************************/

/*****************************************************************************
 *                    Type Definitions
 *****************************************************************************/

/*****************************************************************************
 *                    Public Function Prototypes
 *****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *                    Generic API
 *****************************************************************************/

/** @brief Initialize Qorvo needed components for CHIP.
*   @return result                   0 if init was successful. -1 when failed
*/
int qvCHIP_init(void);

/** @brief Printf that outputs on Qorvo platforms.
*
*   @param module                    Module id for module producing the logging.
*   @param formattedMsg              Char buffer with formatted string message.
*/
void qvCHIP_Printf(uint8_t module, const char* formattedMsg);

/** @brief Return a sequence of random bytes.
*
*   @param outputLength              Length of the sequence to be obtained.
*   @param pOutput                   Buffer for the returned random sequence.
*/
void qvCHIP_RandomGet(uint8_t outputLength, uint8_t *pOutput);

/** @brief Trigger system reset.
*/
void qvCHIP_ResetSystem(void);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //_QVCHIP_H_
