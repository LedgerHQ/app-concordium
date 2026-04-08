#include "apdu_response.h"

#include <io.h>
#include <status_words.h>

#include "menu.h"

void send_user_rejection(void) {
    send_user_rejection_no_idle();
    ui_menu_main();
}

void send_user_rejection_no_idle(void) {
    io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
}

void send_success(uint8_t tx) {
    io_send_response_pointer(G_io_apdu_buffer, tx, SWO_SUCCESS);
    ui_menu_main();
}

void send_success_no_idle(void) {
    send_success_result_no_idle(0);
}

void send_success_result_no_idle(uint8_t tx) {
    io_send_response_pointer(G_io_apdu_buffer, tx, SWO_SUCCESS);
}
