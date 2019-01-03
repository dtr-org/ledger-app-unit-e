#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#define ABORT(text, ...) do { \
    fprintf(stderr, "ERROR: " text "\n", ##__VA_ARGS__); \
    fprintf(stderr, "\tat %s, line %d\n", __FILE__, __LINE__) ; \
    exit(-1); \
} while(0)

void reset() {
}

void* pic(void* x) {
    return x;
}

unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx_len) {
    return 1;
}

void btchip_compress_public_key_value(unsigned char *value) {
    ABORT("Not implemented!");
}

void buf_print(const char* text, const uint8_t* buf, size_t size) {
    char temp[256];
    for (size_t i = 0; i < size; i++) {
        sprintf(temp + 2*i, "%02x", buf[i]);
    }

    printf("DEBUG: (%s) %s", temp, text);
}

void btchip_apdu_setup() {
}

void btchip_apdu_verify_pin() {
}

void btchip_apdu_get_operation_mode() {
}

void btchip_apdu_set_operation_mode() {
}

void btchip_apdu_get_wallet_public_key() {
}

void btchip_apdu_get_trusted_input() {
}

void btchip_apdu_sign_message() {
}

void btchip_apdu_get_random() {
}

void btchip_apdu_get_firmware_version() {
}

void btchip_apdu_set_alternate_coin_version() {
}

void btchip_apdu_get_coin_version() {
}
