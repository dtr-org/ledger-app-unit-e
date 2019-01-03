#include "os.h"
#include "cx.h"

#include "btchip_filesystem.h"
#include "btchip_context.h"
#include "btchip_apdu_constants.h"
#include "btchip_bagl_extensions.h"
#include "btchip_public_ram_variables.h"

#include "apdu.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>


#define P1_FIRST 0x00
#define P1_NEXT 0x80
#define P2_NEW 0x00
#define P2_NEW_SEGWIT 0x02
#define P2_NEW_SEGWIT_CASHADDR 0x03
#define P2_CONTINUE 0x80

#define FINALIZE_P1_MORE 0x00
#define FINALIZE_P1_LAST 0x80
#define FINALIZE_P1_CHANGEINFO 0xFF
#define FINALIZE_P2_DEFAULT 0x00

#define SIGHASH_ALL 0x01


btchip_altcoin_config_t C_coin_config = {
    .p2pkh_version = COIN_P2PKH_VERSION,
    .p2sh_version = COIN_P2SH_VERSION,
    .family = COIN_FAMILY,
    .coinid = COIN_COINID,
    .name = COIN_COINID_NAME,
    .name_short = COIN_COINID_SHORT,
#ifdef COIN_NATIVE_SEGWIT_PREFIX
    .native_segwit_prefix = COIN_NATIVE_SEGWIT_PREFIX,
#endif // COIN_NATIVE_SEGWIT_PREFIX
#ifdef COIN_FORKID
    .forkid = COIN_FORKID,
#endif // COIN_FORKID
#ifdef COIN_FLAGS
    .flags = COIN_FLAGS,
#endif // COIN_FLAGS
    .kind = COIN_KIND,
};


int main() {
    uint16_t result;
    APDU apdu;

    // Initialize device
    memset(&btchip_context_D, 0, sizeof(btchip_context_D));
    memset(&N_btchip, 0, sizeof(N_btchip));
    N_btchip.bkp.config.operationMode = BTCHIP_MODE_WALLET;
    N_btchip.bkp.config.options &= BTCHIP_OPTION_UNCOMPRESSED_KEYS;

    G_coin_config = &C_coin_config;

    // Start feeding in transaction for signing
    ApduInit(&apdu, BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START,
             P1_FIRST, P2_NEW_SEGWIT, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    ApduWrite(&apdu, "db",
              0x01, // Tx version
              0x01  // Number of inputs 
    );
    result = btchip_apdu_hash_input_start();
    assert(result == BTCHIP_SW_OK);

    // Inputs
    ApduInit(&apdu, BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START,
             P1_NEXT, P2_NEW, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    ApduWrite(
        &apdu, "bxdqbXd",
        // Ledger-specific byte: This is a SegWit input
        0x02, 
        // txin
        "d0fb596bac1f838d22c553af690451aac74a6d0c106315a2137908eaf1f89e38", 0,
        // amount
        1000000,
        // previous scriptpubkey
        23, "a914cdf4fcba49b78ff9364fa4aad41cf2dbe0516b7387",
        0xffffffff // sequence
    );
    result = btchip_apdu_hash_input_start();
    assert(result == BTCHIP_SW_OK);
   
    // Outputs
    ApduInit(&apdu, BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_FINALIZE_FULL,
              FINALIZE_P1_LAST, FINALIZE_P2_DEFAULT, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    ApduWrite(
        &apdu, "bqbx",
        0x01, // Number of outputs
        900000, // amount
        0x01, // pk_script length
        "6a"  // OP_RETURN
    );
    result = btchip_apdu_hash_input_finalize_full();
    assert(result == BTCHIP_SW_OK);

    // The user must press 'Confirm'
    btchip_bagl_user_action(1);

    // Presign ready. Now we have to feed in the transaction inputs a second time
    ApduInit(&apdu, BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START,
              P1_FIRST, P2_CONTINUE, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    ApduWrite(&apdu, "db", 0x01, 0x01);
    result = btchip_apdu_hash_input_start();
    assert(result == BTCHIP_SW_OK);

    ApduInit(&apdu, BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START,
              P1_NEXT, P2_NEW, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    ApduWrite(
        &apdu, "bxdqbXd",
        0x02,
        "d0fb596bac1f838d22c553af690451aac74a6d0c106315a2137908eaf1f89e38",
        0,
        1000000,
        23,
        "a914cdf4fcba49b78ff9364fa4aad41cf2dbe0516b7387",
        0xffffffff
    );
    result = btchip_apdu_hash_input_start();
    assert(result == BTCHIP_SW_OK);

    // Sign it with a private key (BIP32-derived from the wallet master key)
    ApduInit(&apdu, BTCHIP_CLA, BTCHIP_INS_HASH_SIGN,
              0x00, 0x00, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    ApduWrite(&apdu, "XXDb",
               "00", // key path derivation
               "00", // pin
               time(NULL), // locktime
               0x01 // SIGHASH_ALL
              );
    result = btchip_apdu_hash_sign();
    assert(result == BTCHIP_SW_OK);

    printf("Input signed. Signature:\n");
    BufferDump(G_io_apdu_buffer, btchip_context_D.outLength);

    return 0;
}

