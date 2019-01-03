#include <stdio.h>
#include <stdint.h>


unsigned int btchip_bagl_confirm_single_output() {
    printf("Confirming <...> Amount <...> Address <...>\n");
    printf("(call btchip_bagl_user_action() to continue.)\n");
    return 1;
}

unsigned int btchip_bagl_confirm_full_output() {  
    printf("Confirm transaction. Amount: <...>, Address: <...>, Fees: <...>\n");
    printf("(call btchip_bagl_user_action() to continue.)\n");
    return 1;
}

unsigned int btchip_bagl_finalize_tx() {
    printf("Confirm transaction. Fees: <unknown> \n");
    printf("(call btchip_bagl_user_action() to continue.)\n");
    return 1;
}

void btchip_bagl_request_change_path_approval(unsigned char* change_path) {
}

uint8_t prepare_full_output(uint8_t checkOnly) {
    printf("Preparing full output...\n");
    return 1;
}
