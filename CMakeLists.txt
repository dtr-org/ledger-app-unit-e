cmake_minimum_required(VERSION 3.12)
project("ledger-app-unit-e")

set(SDK_STUB_FILES src/stubs/os.c src/stubs/cx.c src/stubs/misc.c
                   src/stubs/ui.c)
set(APP_FILES
    src/btchip_apdu_hash_input_start.c src/btchip_transaction.c
    src/btchip_secure_value.c src/btchip_helpers.c src/btchip_base58.c
    src/btchip_public_ram_variables.c src/btchip_nvram.c
    src/btchip_apdu_hash_input_finalize_full.c src/btchip_apdu_hash_sign.c
    src/btchip_rom_variables.c src/btchip_public_ram_key_variables.c
)

add_subdirectory(vendor/apdu)

include_directories(include include/stubs)
include_directories(vendor/apdu/src)

# Coin parameters
add_compile_definitions(
    COIN_P2PKH_VERSION=111 COIN_P2SH_VERSION=196 COIN_FAMILY=1
    COIN_COINID=\"UnitE\" COIN_COINID_HEADER=\"UNITE\" COIN_COLOR_HDR=0xFCB653
    COIN_COLOR_DB=0xFEDBA9 COIN_COINID_NAME=\"UnitE\" COIN_COINID_SHORT=\"TEST\"
    COIN_NATIVE_SEGWIT_PREFIX=\"bcrt\" COIN_KIND=COIN_KIND_BITCOIN_TESTNET
    COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
)

# Misc defines
add_compile_definitions(
    USB_SEGMENT_SIZE=2048 PRINTF=screen_printf UNITE_TARGET_DESKTOP=1
)

# add_compile_definitions() doesn't support function-style macros
add_definitions("-D'PIC(x)=(x)'")

add_executable(sign_example ${SDK_STUB_FILES} ${APP_FILES} src/unite_sample_main.c)
target_link_libraries(sign_example apdu crypto)
