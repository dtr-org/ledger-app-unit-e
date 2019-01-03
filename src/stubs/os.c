/*******************************************************************************
*   Ledger Nano S - Secure firmware
*   (c) 2016, 2017, 2018 Ledger
*   (c) 2019 The UnitE developers
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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "os.h"


#define ABORT(text, ...) do { \
    fprintf(stderr, "ERROR: " text "\n", ##__VA_ARGS__); \
    fprintf(stderr, "\tat %s, line %d\n", __FILE__, __LINE__) ; \
    exit(-1); \
} while(0)

static try_context_t *try_ctx;

const uint8_t MASTER_KEY[32] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};

const uint8_t MASTER_CHAIN_CODE[32] = {
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

void screen_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

unsigned int os_global_pin_is_validated() {
    return 1;
}

void os_perso_derive_node_bip32(
    cx_curve_t curve, const unsigned int *path, unsigned int pathLength,
    unsigned char *privateKey, unsigned char *chain
) {
    if (pathLength != 0) {
        ABORT("BIP32 derivation not supported!\n");
    }
    if (privateKey) {
        memcpy(privateKey, MASTER_KEY, 32);
    }
    if (chain) {
        memcpy(chain, MASTER_CHAIN_CODE, 32);
    }
}

// apdu buffer must hold a complete apdu to avoid troubles
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

void os_boot(void) {
  // TODO patch entry point when romming (f)

  // set the default try context to nothing
  try_context_set(NULL);
}

void os_memmove(void * dst, const void WIDE * src, unsigned int length) {
#define DSTCHAR ((unsigned char *)dst)
#define SRCCHAR ((unsigned char WIDE *)src)
  if (dst > src) {
    while(length--) {
      DSTCHAR[length] = SRCCHAR[length];
    }
  }
  else {
    unsigned short l = 0;
    while (length--) {
      DSTCHAR[l] = SRCCHAR[l];
      l++;
    }
  }
#undef DSTCHAR
}

void os_memset(void * dst, unsigned char c, unsigned int length) {
#define DSTCHAR ((unsigned char *)dst)
  while(length--) {
    DSTCHAR[length] = c;
  }
#undef DSTCHAR
}

char os_memcmp(const void WIDE * buf1, const void WIDE * buf2, unsigned int length) {
#define BUF1 ((unsigned char const WIDE *)buf1)
#define BUF2 ((unsigned char const WIDE *)buf2)
  while(length--) {
    if (BUF1[length] != BUF2[length]) {
      return (BUF1[length] > BUF2[length])? 1:-1;
    }
  }
  return 0;
#undef BUF1
#undef BUF2

}

void os_xor(void * dst, void WIDE* src1, void WIDE* src2, unsigned int length) {
#define SRC1 ((unsigned char const WIDE *)src1)
#define SRC2 ((unsigned char const WIDE *)src2)
#define DST ((unsigned char *)dst)
  unsigned short l = length;
  // don't || to ensure all condition are evaluated
  while(!(!length && !l)) {
    length--;
    DST[length] = SRC1[length] ^ SRC2[length];
    l--;
  }
  // WHAT ??? glitch detected ?
  if (l!=length) {
    THROW(EXCEPTION);
  }
}

char os_secure_memcmp(void WIDE* src1, void WIDE* src2, unsigned int length) {
#define SRC1 ((unsigned char const WIDE *)src1)
#define SRC2 ((unsigned char const WIDE *)src2)
  unsigned short l = length;
  unsigned char xoracc=0;
  // don't || to ensure all condition are evaluated
  while(!(!length && !l)) {
    length--;
    xoracc |= SRC1[length] ^ SRC2[length];
    l--;
  }
  // WHAT ??? glitch detected ?
  if (l!=length) {
    THROW(EXCEPTION);
  }
  return xoracc;
}

try_context_t* try_context_get(void) {
  return try_ctx;
}

try_context_t* try_context_get_previous(void) {
  try_context_t* current_ctx;

  // first context reached ?
  if (current_ctx == NULL) {
    // DESIGN NOTE: if not done, then upon END_TRY a wrong context address may be use (if address 
    // à is readable in the arch, and therefore lead to faulty rethrow or worse)
    return NULL;
  }

  // return r9 content saved on the current context. It links to the previous context.
  // r4 r5 r6 r7 r8 r9 r10 r11 sp lr
  //                ^ platform register
  // return (try_context_t*) current_ctx->jmp_buf[5];
  return NULL;
}

void try_context_set(try_context_t* ctx) {
  try_ctx = ctx;
}

#ifndef HAVE_BOLOS
void os_longjmp(unsigned int exception) {
  longjmp(try_context_get()->jmp_buf, exception);
}
#endif // HAVE_BOLOS
