/*******************************************************************************
*   Ledger Blue - Bitcoin Wallet
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef BTCHIP_H

#define BTCHIP_H

#include "btchip_config.h"
#include "os.h"

#include "stdlib.h"
#include "stdbool.h"

#ifdef UNITE_TARGET_DESKTOP

#include <stdio.h>

void buf_print(const char* text, const uint8_t* buf, size_t size);

#define L_DEBUG_APP(x) do { printf("DEBUG: "); printf x ; } while (0)
#define L_DEBUG_NOPREFIX(x) printf x
#define L_DEBUG_BUF(x) buf_print x
#else
#define L_DEBUG_APP(x)
#define L_DEBUG_NOPREFIX(x)
#define L_DEBUG_BUF(x)
#endif // UNITE_TARGET_DESKTOP

#define SW_TECHNICAL_DETAILS(x) BTCHIP_SW_TECHNICAL_PROBLEM

#include "btchip_secure_value.h"

#endif
