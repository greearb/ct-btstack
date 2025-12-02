/*
 * Copyright (C) 2014 BlueKitchen GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the names of
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 * 4. Any redistribution, use, or modification is done solely for
 *    personal benefit and not for any commercial purpose or for
 *    monetary gain.
 *
 * THIS SOFTWARE IS PROVIDED BY BLUEKITCHEN GMBH AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BLUEKITCHEN
 * GMBH OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Please inquire about commercial licensing options at 
 * contact@bluekitchen-gmbh.com
 *
 */

#define BTSTACK_FILE__ "hid_keyboard_demo.c"
 
// *****************************************************************************
/* EXAMPLE_START(hid_keyboard_demo): HID Keyboard Classic
 *
 * @text This HID Device example demonstrates how to implement
 * an HID keyboard. Without a HAVE_BTSTACK_STDIN, a fixed demo text is sent
 * If HAVE_BTSTACK_STDIN is defined, you can type from the terminal
 */
// *****************************************************************************


#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "btstack.h"
#include "shared.h"
#include <pthread.h>
#include <errno.h>
#include <stdatomic.h>

#ifdef HAVE_BTSTACK_STDIN
#include "btstack_stdin.h"
#endif

// to disable stdin keyboard input
#undef HAVE_BTSTACK_STDIN

// timing of keypresses
#define TYPING_KEYDOWN_MS  20
#define TYPING_DELAY_MS    20

// When not set to 0xffff, sniff and sniff subrating are enabled
static uint16_t host_max_latency = 1600;
static uint16_t host_min_timeout = 3200;

#define REPORT_ID 0x01

// close to USB HID Specification 1.1, Appendix B.1
const uint8_t hid_descriptor_keyboard[] = {

    0x05, 0x01,                    // Usage Page (Generic Desktop)
    0x09, 0x06,                    // Usage (Keyboard)
    0xa1, 0x01,                    // Collection (Application)

    // Report ID

    0x85, REPORT_ID,               // Report ID

    // Modifier byte (input)

    0x75, 0x01,                    //   Report Size (1)
    0x95, 0x08,                    //   Report Count (8)
    0x05, 0x07,                    //   Usage Page (Key codes)
    0x19, 0xe0,                    //   Usage Minimum (Keyboard LeftControl)
    0x29, 0xe7,                    //   Usage Maximum (Keyboard Right GUI)
    0x15, 0x00,                    //   Logical Minimum (0)
    0x25, 0x01,                    //   Logical Maximum (1)
    0x81, 0x02,                    //   Input (Data, Variable, Absolute)

    // Reserved byte (input)

    0x75, 0x01,                    //   Report Size (1)
    0x95, 0x08,                    //   Report Count (8)
    0x81, 0x03,                    //   Input (Constant, Variable, Absolute)

    // LED report + padding (output)

    0x95, 0x05,                    //   Report Count (5)
    0x75, 0x01,                    //   Report Size (1)
    0x05, 0x08,                    //   Usage Page (LEDs)
    0x19, 0x01,                    //   Usage Minimum (Num Lock)
    0x29, 0x05,                    //   Usage Maximum (Kana)
    0x91, 0x02,                    //   Output (Data, Variable, Absolute)

    0x95, 0x01,                    //   Report Count (1)
    0x75, 0x03,                    //   Report Size (3)
    0x91, 0x03,                    //   Output (Constant, Variable, Absolute)

    // Keycodes (input)

    0x95, 0x06,                    //   Report Count (6)
    0x75, 0x08,                    //   Report Size (8)
    0x15, 0x00,                    //   Logical Minimum (0)
    0x25, 0xff,                    //   Logical Maximum (1)
    0x05, 0x07,                    //   Usage Page (Key codes)
    0x19, 0x00,                    //   Usage Minimum (Reserved (no event indicated))
    0x29, 0xff,                    //   Usage Maximum (Reserved)
    0x81, 0x00,                    //   Input (Data, Array)

    0xc0,                          // End collection
};

// 
#define CHAR_ILLEGAL     0xff
#define CHAR_RETURN     '\n'
#define CHAR_ESCAPE      27
#define CHAR_TAB         '\t'
#define CHAR_BACKSPACE   0x7f

// Simplified US Keyboard with Shift modifier

/**
 * English (US)
 */
static const uint8_t keytable_us_none [] = {
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /*   0-3 */
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',                   /*  4-13 */
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',                   /* 14-23 */
    'u', 'v', 'w', 'x', 'y', 'z',                                       /* 24-29 */
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',                   /* 30-39 */
    CHAR_RETURN, CHAR_ESCAPE, CHAR_BACKSPACE, CHAR_TAB, ' ',            /* 40-44 */
    '-', '=', '[', ']', '\\', CHAR_ILLEGAL, ';', '\'', 0x60, ',',       /* 45-54 */
    '.', '/', CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,   /* 55-60 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 61-64 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 65-68 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 69-72 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 73-76 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 77-80 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 81-84 */
    '*', '-', '+', '\n', '1', '2', '3', '4', '5',                       /* 85-97 */
    '6', '7', '8', '9', '0', '.', 0xa7,                                 /* 97-100 */
}; 

static const uint8_t keytable_us_shift[] = {
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /*  0-3  */
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',                   /*  4-13 */
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',                   /* 14-23 */
    'U', 'V', 'W', 'X', 'Y', 'Z',                                       /* 24-29 */
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',                   /* 30-39 */
    CHAR_RETURN, CHAR_ESCAPE, CHAR_BACKSPACE, CHAR_TAB, ' ',            /* 40-44 */
    '_', '+', '{', '}', '|', CHAR_ILLEGAL, ':', '"', 0x7E, '<',         /* 45-54 */
    '>', '?', CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,   /* 55-60 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 61-64 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 65-68 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 69-72 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 73-76 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 77-80 */
    CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL, CHAR_ILLEGAL,             /* 81-84 */
    '*', '-', '+', '\n', '1', '2', '3', '4', '5',                       /* 85-97 */
    '6', '7', '8', '9', '0', '.', 0xb1,                                 /* 97-100 */
}; 

// STATE

static uint8_t hid_service_buffer[300];
static uint8_t device_id_sdp_service_buffer[100];
static const char hid_device_name[] = "BTstack HID Keyboard";
static btstack_packet_callback_registration_t hci_event_callback_registration;
static uint16_t hid_cid;
static uint8_t hid_boot_device = 0;

// HID Report sending
static uint8_t                send_buffer_storage[16];
static btstack_ring_buffer_t  send_buffer;
static btstack_timer_source_t send_timer;
static uint8_t                send_modifier;
static uint8_t                send_keycode;
static bool                   send_active;
atomic_bool connection_paused = false;

static bd_addr_t device_addr;

char str[20];
// Read device from File
static char * get_target_device(){
	FILE* ptr;
	ptr = fopen("test.txt", "a+");

	if (NULL == ptr) {
		printf("file can't be opened \n");
	}
	printf("content of this file are \n");
	while (fgets(str, 19, ptr) != NULL) {
		printf("%s", str);
	}
	fclose(ptr);
	return str;
}
static enum {
    APP_BOOTING,
    APP_NOT_CONNECTED,
    APP_CONNECTING,
    APP_CONNECTED,
    APP_PAUSED
} app_state = APP_BOOTING;

/* See: src/bluetooth.h // 'BLUETOOTH_ERROR_CODE' */
/* Convert common error codes to their interpreted representations */
static void toStringErrCode(char* buf, uint8_t err_code, int buf_len) {
    if (err_code == 0x66) {
        snprintf(buf, buf_len - 1, "0x%x: Authentication Refused", err_code);
    }
    else {
        snprintf(buf, buf_len - 1, "0x%x", err_code);
    }
    buf[buf_len-1] = '\0';
}

/* Notify management entity of an event via writing to output-pipe */
void notifyEvent(char* message) {
    if (events_file_path == NULL) {
        return;
    }

    char buf[150];

    int fd;
    fd = open(events_file_path, O_WRONLY);
    if (fd >= 0) {
        snprintf(buf, 149, "admin btstack_event %s %s\n", target_bt_mac_str, message);
        buf[149] = '\0';

        int rv = write(fd, buf, strlen(buf));
        if (rv < 0) {
            printf("ERROR: Writing to LANforge pipe helper failed\n");
        }
        close(fd);
    }
    else {
        printf("ERROR: notifyEvent: Opening LANforge pipe helper failed\n");
    }
}

void setAppState(uint8_t new_state, uint8_t opt_err_code) {
    if (new_state == app_state) {
        return;
    }
    uint8_t prev_state = app_state;
    app_state = new_state;

    // @TODO is it worth hardcoding str representations for known error codes?
    if (opt_err_code != 0) {
        // @UNUSED**
        // char status_readable[50];
        // toStringErrCode(status_readable, status, 50);
    }

    char state_msg[50];
    state_msg[49] = '\0';
    if (prev_state == APP_CONNECTED && app_state == APP_NOT_CONNECTED) {
        snprintf(state_msg, sizeof(state_msg), "disconnected REASON: %d\n", opt_err_code);
    }
    else if (prev_state == APP_CONNECTING && app_state == APP_NOT_CONNECTED) {
        if (opt_err_code == L2CAP_CONNECTION_BASEBAND_DISCONNECT) { //@TODO is this right??
            snprintf(state_msg, sizeof(state_msg), "connection_fail_timeout\n");
        }
        else {
            snprintf(state_msg, sizeof(state_msg), "connection_fail\n");
            //@DEBUG
            // printf("connection_failing REASON: %d\n", opt_err_code);
        }
    }
    else if (app_state == APP_CONNECTING) {
        snprintf(state_msg, sizeof(state_msg), "connecting\n");
    }
    else if (app_state == APP_CONNECTED) {
        snprintf(state_msg, sizeof(state_msg), "connected\n");
    }
    else {
        return;
    }
    state_msg[49] = '\0';
    notifyEvent(state_msg);
}

// HID Keyboard lookup
static bool lookup_keycode(uint8_t character, const uint8_t * table, int size, uint8_t * keycode){
    int i;
    for (i=0;i<size;i++){
        if (table[i] != character) continue;
        *keycode = i;
        return true;
    }
    return false;
}

static bool keycode_and_modifer_us_for_character(uint8_t character, uint8_t * keycode, uint8_t * modifier){
    bool found;
    found = lookup_keycode(character, keytable_us_none, sizeof(keytable_us_none), keycode);
    if (found) {
        *modifier = 0;  // none
        return true;
    }
    found = lookup_keycode(character, keytable_us_shift, sizeof(keytable_us_shift), keycode);
    if (found) {
        *modifier = 2;  // shift
        return true;
    }
    return false;
}

static void send_report(int modifier, int keycode){
    // setup HID message: A1 = Input Report, Report ID, Payload
    uint8_t message[] = {0xa1, REPORT_ID, modifier, 0, keycode, 0, 0, 0, 0, 0};
    hid_device_send_interrupt_message(hid_cid, &message[0], sizeof(message));
}

static void trigger_key_up(btstack_timer_source_t * ts){
    UNUSED(ts);
    hid_device_request_can_send_now_event(hid_cid);
}

static void send_next_has_mod(btstack_timer_source_t * ts, bool key_is_raw) {
    // get next key from buffer
    uint8_t character_pld[2]; // [u8 character, u8 modifier]
    uint32_t num_bytes_read = 0;
    btstack_ring_buffer_read(&send_buffer, (uint8_t*)&character_pld, 2, &num_bytes_read);
    if (num_bytes_read == 0) {
        // buffer empty, nothing to send
        send_active = false;
    } else if(num_bytes_read != 2) {
        printf("Failed to read key modifier byte -- byte 2/2");
        send_active = false;
    } else {
        send_active = true;

        bool found = false;
        if (!key_is_raw) { // lookup keycode using US layout
            found = lookup_keycode(character_pld[0], keytable_us_none, sizeof(keytable_us_none), &send_keycode);
            if (!found) {
                found = lookup_keycode(character_pld[0], keytable_us_shift, sizeof(keytable_us_shift), &send_keycode);
            }
        }
        else if ((uint8_t)character_pld[0] <= 100) { //raw HID code
            send_keycode = (uint8_t)character_pld[0];
            printf("Sending raw character w/ HID code: %d\n", character_pld[0]);
            found = true;
        }

        if (found) {
            //set modifier
            send_modifier = character_pld[1];

            // request can send now
            hid_device_request_can_send_now_event(hid_cid);
        } else {
            // restart timer for next character
            btstack_run_loop_set_timer(ts, TYPING_DELAY_MS);
            btstack_run_loop_add_timer(ts);
        }
    }
}

static void send_next(btstack_timer_source_t * ts) {
    // get next key from buffer
    uint8_t character;
    uint32_t num_bytes_read = 0;
    btstack_ring_buffer_read(&send_buffer, &character, 1, &num_bytes_read);
    if (num_bytes_read == 0) {
        // buffer empty, nothing to send
        send_active = false;
    } else {
        send_active = true;
        // lookup keycode and modifier using US layout
        bool found = keycode_and_modifer_us_for_character(character, &send_keycode, &send_modifier);
        if (found) {
            // request can send now
            hid_device_request_can_send_now_event(hid_cid);
        } else {
            // restart timer for next character
            btstack_run_loop_set_timer(ts, TYPING_DELAY_MS);
            btstack_run_loop_add_timer(ts);
        }
    }
}

static void queue_character(char character){
    btstack_ring_buffer_write(&send_buffer, (uint8_t *) &character, 1);
    if (send_active == false) {
        send_next(&send_timer);
    }
}

// queuing two bytes -- [ character (a,b, ... ', /, ...)] and [ modifier key (shift, Fn, etc...)]
static void queue_character_and_mod(char key, uint8_t modifier, bool key_is_raw){
    char key_and_mod[2] = {key, (char)modifier};
    btstack_ring_buffer_write(&send_buffer, (uint8_t *)&key_and_mod, 2);
    if (send_active == false) {
        send_next_has_mod(&send_timer, key_is_raw);
    }
}

// Demo Application

#ifdef HAVE_BTSTACK_STDIN

// On systems with STDIN, we can directly type on the console

static void stdin_process(char character){
    switch (app_state){
        case APP_BOOTING:
        case APP_CONNECTING:
            // ignore
            break;
        case APP_CONNECTED:
        	printf("Sending Char: %c\n", character);
            // add char to send buffer
        	// mkfifo, named pipe read from fifo
            queue_character(character);
            break;
        case APP_NOT_CONNECTED:
            printf("Connecting to %s...\n", bd_addr_to_str(device_addr));
            if (target_bt_mac_str == NULL) {
                target_bt_mac_str = get_target_device();
            }
            sscanf_bd_addr(target_bt_mac_str, device_addr);
            hid_device_connect(device_addr, &hid_cid);
            break;
        default:
            btstack_assert(false);
            break;
    }
}
#endif

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t * packet, uint16_t packet_size){
    UNUSED(channel);
    UNUSED(packet_size);
    uint8_t status;
    switch (packet_type){
        case HCI_EVENT_PACKET:

            if(atomic_load_explicit(&connection_paused, memory_order_acquire)) {
                // ignore all events while paused
                return;
            }

            switch (hci_event_packet_get_type(packet)){
                case BTSTACK_EVENT_STATE:
                    if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING) return;
                    setAppState(APP_NOT_CONNECTED, 0);
                    break;

                case HCI_EVENT_USER_CONFIRMATION_REQUEST:
                    // ssp: inform about user confirmation request
                    log_info("SSP User Confirmation Request with numeric value '%06"PRIu32"'\n", hci_event_user_confirmation_request_get_numeric_value(packet));
                    log_info("SSP User Confirmation Auto accept\n");                   
                    break; 

                case HCI_EVENT_HID_META:
                    switch (hci_event_hid_meta_get_subevent_code(packet)){
                        case HID_SUBEVENT_CONNECTION_OPENED:
                            status = hid_subevent_connection_opened_get_status(packet);
                            if (status != ERROR_CODE_SUCCESS) {
                                // outgoing connection failed
                                setAppState(APP_NOT_CONNECTED, status);
                                hid_cid = 0;
                                return;
                            }

                            setAppState(APP_CONNECTED, status);
                            hid_cid = hid_subevent_connection_opened_get_hid_cid(packet);
#ifdef HAVE_BTSTACK_STDIN
                            printf("HID Connected, please start typing...\n");
#else
                            printf("HID Connected, accepting text from named pipe...\n");
#endif
                            break;
                        case HID_SUBEVENT_CONNECTION_CLOSED:
                            btstack_run_loop_remove_timer(&send_timer);
                            //exit the program!!
                            printf("HID Disconnected -- shutting down.\n");
                            setAppState(APP_NOT_CONNECTED, 0); //@TODO encode that connection was closed???
                            // hid_cid = 0;
                            hci_power_control(HCI_POWER_OFF);
                            exit(1);
                            break;
                        case HID_SUBEVENT_CAN_SEND_NOW:
                            if (send_keycode){
                                send_report(send_modifier, send_keycode);
                                // schedule key up
                                send_keycode = 0;
                                send_modifier = 0;
                                btstack_run_loop_set_timer_handler(&send_timer, trigger_key_up);
                                btstack_run_loop_set_timer(&send_timer, TYPING_KEYDOWN_MS);
                            } else {
                                send_report(0, 0);
                                // schedule next key down
                                btstack_run_loop_set_timer_handler(&send_timer, send_next);
                                btstack_run_loop_set_timer(&send_timer, TYPING_DELAY_MS);
                            }
                            btstack_run_loop_add_timer(&send_timer);
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
}

/* TODO:  keyword_len is unused */
static int getMultiplier(char* hunk, int keyword_len) {
    char* asterisk_pos = strstr(hunk, "*");

    if (asterisk_pos != NULL) {
        uint16_t multiplier = (uint16_t)strtoul((asterisk_pos+1), NULL, 10);
        if (multiplier > 0) {
            printf("Sending this key x%u times\n", multiplier);
            return multiplier;
        }
    }
    return 1;
}

static void *try_conn_periodically(void* data);

static void send_serialized_input(char* input){
    //remove newline at the end of str
    size_t len = strlen(input);
    if (len && (input[len-1] == '\n')) {
        input[len-1] = '\0';
    }

    char* hunk = strtok(input, " ");
    int multiplier = 1;
    uint8_t modifier = 0x0;
    uint8_t key_to_send = 0x0;
    bool key_is_raw = false;
    while (hunk != NULL) {
        printf("Parsing hunk: '%s'\n", hunk);

        if (strncmp(hunk, "enter", strlen("enter")) == 0) {
            key_to_send = CHAR_RETURN;
        }
        else if (strncmp(hunk, "esc", strlen("esc")) == 0) {
            key_to_send = CHAR_ESCAPE;
        }
        else if (strncmp(hunk, "bs", strlen("bs")) == 0) {
            key_to_send = CHAR_BACKSPACE;
        }
        else if (strncmp(hunk, "tab", strlen("tab")) == 0) {
            key_to_send = CHAR_TAB;
        }
        else if (strncmp(hunk, "space", strlen("space")) == 0) {
            key_to_send = ' ';
        }
        else if (strncmp(hunk, "raw", strlen("raw")) == 0) {
            key_is_raw = true;
        }
        else if (strncmp(hunk, "del", strlen("del")) == 0) {
            key_is_raw = true;
            key_to_send = (char)0x4c;
        }
        else if (strncmp(hunk, "rarrow", strlen("rarrow")) == 0) {
            key_is_raw = true;
            key_to_send = (char)0x4f;
        }
        else if (strncmp(hunk, "larrow", strlen("larrow")) == 0) {
            key_is_raw = true;
            key_to_send = (char)0x50;
        }
        else if (strncmp(hunk, "dnarrow", strlen("dnarrow")) == 0) {
            key_is_raw = true;
            key_to_send = (char)0x51;
            multiplier = getMultiplier(hunk, strlen("dnarrow"));
        }
        else if (strncmp(hunk, "uparrow", strlen("uparrow")) == 0) {
            key_is_raw = true;
            key_to_send = (char)0x52;
            multiplier = getMultiplier(hunk, strlen("uparrow"));
        }
        else if (strncmp(hunk, "reconnect", strlen("reconnect")) == 0) {
            printf("Told to reconnect...\n");
            hci_power_control(HCI_POWER_OFF); // trigger reconnect attempt
        }
        else if (strncmp(hunk, "pause", strlen("pause")) == 0) {
            notifyEvent("paused");
            atomic_store_explicit(&connection_paused, true, memory_order_release);
            hci_power_control(HCI_POWER_OFF);
        }
        else if (strncmp(hunk, "resume", strlen("resume")) == 0) {
            notifyEvent("resumed");
            atomic_store_explicit(&connection_paused, false, memory_order_release);
            hci_power_control(HCI_POWER_ON);
            setAppState(APP_NOT_CONNECTED, 0);
            int interval = 1000000; // 1 second
            pthread_t conn_thread;
            pthread_create(&conn_thread, NULL, try_conn_periodically, &interval);
        }
        //modifier keys
        else if (strcmp(hunk, "ctrl") == 0) {
            modifier |= 0x01; //ctrl modifier
        }
        else if (strcmp(hunk, "shift") == 0) {
            modifier |= 0x02; //shift modifier
        }
        else if (strcmp(hunk, "alt") == 0) {
            modifier |= 0x04; //'option' (alt key) modifier
        }
        else if (strcmp(hunk, "meta") == 0) {
            modifier |= 0x08; //'command' (meta key) modifier
        }
        else if (strncmp(hunk, "sleep", 5) == 0) {
            uint16_t sleep_sec = (uint16_t)strtoul((hunk+5), NULL, 10);
            if (sleep_sec > 0) {
                printf("Sleeping between keystrokes: %d seconds", sleep_sec);
                usleep(sleep_sec * 1000000); //2 second sleep, humans can't type at light speed
            }
            else {
                printf("Failed to parse sleep string %s\n", hunk);
            }
        }
        else {
            if (key_is_raw) { //looking for raw code #
                int base = 10;
                char* hex_pref = strstr(hunk, "x");
                if (hex_pref != NULL) {
                    base = 16;
                }
                uint8_t conv = (uint8_t)strtoul(hunk, NULL, base);
                if (conv > 0 && conv <= 100) {
                    key_to_send = (char)conv;
                }
                else {
                    key_is_raw = false; //'raw' code parsing error
                }
            }
            else { //single char
                key_to_send = *hunk;
            }
        }

        if (key_to_send) {
            //check for multiplier i.e. send this key XX numer of times -'*XX'
            int i = 0;
            for(i; i < multiplier; i++) {
                if (modifier || key_is_raw) {
                    queue_character_and_mod(key_to_send, modifier, key_is_raw);
                    usleep(1000000); //1 sec sleep, assume more wait needed
                }
                else {
                    queue_character(key_to_send);
                    usleep(250000); //250ms sleep, humans can't type at light speed
                }
            }

            multiplier = 1;
            modifier = 0x0; //reset modifier
            key_is_raw = false; //reset
            key_to_send = 0x0; //reset key
        }
        hunk = strtok(NULL, " "); //get next token
    }
}

static void *try_conn_periodically(void* data) {
    int attempt_conn_cnt = 0;

    while(true) {
        switch (app_state){
        case APP_BOOTING:
        case APP_CONNECTING:
            // ignore
            break;
        case APP_PAUSED:
            return NULL;
        case APP_CONNECTED:
            return NULL;
        case APP_NOT_CONNECTED:
            if (attempt_conn_cnt == 2) {
                //exit the program!!
                printf("Unable to connect -- shutting down.\n");
                hci_power_control(HCI_POWER_OFF);
                exit(1);
            }
            if (attempt_conn_cnt > 0) {
                printf("(retry 1/1) ");
            }
            printf("Connecting to %s...\n", bd_addr_to_str(device_addr));
            hid_device_connect(device_addr, &hid_cid);
            setAppState(APP_CONNECTING, 0);
            attempt_conn_cnt++;
            break;
        default:
            btstack_assert(false);
            break;
        }
        usleep(1000000); // 1 sec
    }
    return NULL;
}

static void *do_smth_periodically(void *data)
{
    int fd1;
    int rv;
    char myfifo[101];
    myfifo[100] = '\0';
    char* suffix = "generic";
    if (target_bt_mac_str != NULL) {
        suffix = target_bt_mac_str;
    }

    snprintf(myfifo, 100, "/home/lanforge/btstack/btstack-%s", suffix);
    mkfifo(myfifo, 0666);
    char str1[4096];
    str1[4095] = '\0';
    int interval = *(int *)data;

    for (;;) {
        // Open pipe
        fd1 = open(myfifo, O_RDONLY);
        if (fd1 >= 0) {
            if (app_state == APP_CONNECTED) {
                for (;;) {
                    // Read from pipe
                    rv = read(fd1, str1, 4095);
                    if (rv < 0) {
                        printf("\nNamed pipe read failed with error: %s\n", strerror(errno));
                        close(fd1);
                        fd1 = -1;
                        break;
                    }
                    else if (rv > 0) { //if data was read, send it
                        printf("\nKeystrokes: %s\n", str1);
                        send_serialized_input(str1);
                    }
                }
            }
            else { // pause before checking again for device connection
                usleep(interval);
            }
        }
        usleep(interval);
    }
}
/* @section Main Application Setup
 *
 * @text Listing MainConfiguration shows main application code. 
 * To run a HID Device service you need to initialize the SDP, and to create and register HID Device record with it. 
 * At the end the Bluetooth stack is started.
 */

/* LISTING_START(MainConfiguration): Setup HID Device */

int btstack_main(int argc, const char * argv[]);
int btstack_main(int argc, const char * argv[]){
    (void)argc;
    (void)argv;

	// FIFO file path
	char * myfifo = "/home/lanforge/btstack/hidkey";
	// Creating the named file(FIFO)
	// mkfifo(<pathname>,<permission>)
	mkfifo(myfifo, 0666);


    // allow to get found by inquiry
    gap_discoverable_control(1);
    // use Limited Discoverable Mode; Peripheral; Keyboard as CoD
    gap_set_class_of_device(0x2540);
    // set local name to be identified - zeroes will be replaced by actual BD ADDR
    gap_set_local_name("LANForge HID Keyboard 00:00:00:00:00:00");
    // allow for role switch in general and sniff mode
    gap_set_default_link_policy_settings( LM_LINK_POLICY_ENABLE_ROLE_SWITCH | LM_LINK_POLICY_ENABLE_SNIFF_MODE );
    // allow for role switch on outgoing connections - this allow HID Host to become master when we re-connect to it
    gap_set_allow_role_switch(true);

    // L2CAP
    l2cap_init();

#ifdef ENABLE_BLE
    // Initialize LE Security Manager. Needed for cross-transport key derivation
    sm_init();
#endif

    // SDP Server
    sdp_init();
    memset(hid_service_buffer, 0, sizeof(hid_service_buffer));

    uint8_t hid_virtual_cable = 0;
    uint8_t hid_remote_wake = 1;
    uint8_t hid_reconnect_initiate = 1;
    uint8_t hid_normally_connectable = 1;

    hid_sdp_record_t hid_params = {
        // hid sevice subclass 2540 Keyboard, hid counntry code 33 US
        0x2540, 33, 
        hid_virtual_cable, hid_remote_wake, 
        hid_reconnect_initiate, hid_normally_connectable,
        hid_boot_device,
        host_max_latency, host_min_timeout,
        3200,
        hid_descriptor_keyboard,
        sizeof(hid_descriptor_keyboard),
        hid_device_name
    };
    
    hid_create_sdp_record(hid_service_buffer, sdp_create_service_record_handle(), &hid_params);
    btstack_assert(de_get_len( hid_service_buffer) <= sizeof(hid_service_buffer));
    sdp_register_service(hid_service_buffer);

    // See https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers if you don't have a USB Vendor ID and need a Bluetooth Vendor ID
    // device info: BlueKitchen GmbH, product 1, version 1
    device_id_create_sdp_record(device_id_sdp_service_buffer, sdp_create_service_record_handle(), DEVICE_ID_VENDOR_ID_SOURCE_BLUETOOTH, BLUETOOTH_COMPANY_ID_BLUEKITCHEN_GMBH, 1, 1);
    btstack_assert(de_get_len( device_id_sdp_service_buffer) <= sizeof(device_id_sdp_service_buffer));
    sdp_register_service(device_id_sdp_service_buffer);

    // HID Device
    hid_device_init(hid_boot_device, sizeof(hid_descriptor_keyboard), hid_descriptor_keyboard);
       
    // register for HCI events
    hci_event_callback_registration.callback = &packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    // register for HID events
    hid_device_register_packet_handler(&packet_handler);

    if (target_bt_mac_str != NULL) {
        sscanf_bd_addr(target_bt_mac_str, device_addr);
    }
    int interval = 1000000;

#ifdef HAVE_BTSTACK_STDIN
    btstack_stdin_setup(stdin_process);
#else
    pthread_t conn_thread;
    pthread_create(&conn_thread, NULL, try_conn_periodically, &interval);

#endif

    pthread_t thread;
    pthread_create(&thread, NULL, do_smth_periodically, &interval);

    btstack_ring_buffer_init(&send_buffer, send_buffer_storage, sizeof(send_buffer_storage));

    // turn on!
    int rv = hci_power_control(HCI_POWER_ON);
    if (rv != 0) {
        hci_power_control(HCI_POWER_OFF);
        char* curr_state = "misconfigured";
        notifyEvent(curr_state);
        exit(2);
    }

    return 0;
}
/* LISTING_END */
/* EXAMPLE_END */
