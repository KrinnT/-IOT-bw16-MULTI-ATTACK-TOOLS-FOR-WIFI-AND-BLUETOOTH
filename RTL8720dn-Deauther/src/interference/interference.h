#ifndef INTERFERENCE_H
#define INTERFERENCE_H

#include <Arduino.h>
#include "../packet-injection/packet-injection.h"

// Maximum number of simultaneous interference targets
#define MAX_INTERFERENCE_TARGETS 4

typedef enum {
    INT_STATE_IDLE,
    INT_STATE_CAPTURING,
    INT_STATE_ACTIVE
} interference_state_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t* payload;
    size_t payload_len;
    int target_channel;
    uint32_t start_time;
    interference_state_t state;
    uint16_t beacon_interval;
    uint16_t capabilities;
} BeaconClone;

// === Single-target API (backward compatible) ===
void start_interference(uint8_t* target_bssid, int channel);

// === Multi-target API ===
// Call start_interference_multi() first to initialize, then add_interference_target()
// for each additional target (up to MAX_INTERFERENCE_TARGETS).
void start_interference_multi();
bool add_interference_target(uint8_t* target_bssid, int channel);

// === Common API ===
void stop_interference();
void run_interference_cycle();
interference_state_t get_interference_state();
bool is_captured();
int get_active_target_count();

#endif
