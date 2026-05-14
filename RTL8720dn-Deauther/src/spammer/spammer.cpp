#include "spammer.h"
#include "wifi_conf.h"
#include "../../debug.h"

SSIDSpammer Spammer;

SSIDSpammer::SSIDSpammer() : _active(false), _randomMode(false), _randomCount(10), _currentChannel(1), _lastChannelHop(0) {
}

SSIDSpammer::~SSIDSpammer() {
    stop();
}

void SSIDSpammer::addSSID(String ssid) {
    if (ssid.length() > MAX_SSID_LEN) ssid = ssid.substring(0, MAX_SSID_LEN);
    SpammedNetwork net;
    net.ssid = ssid;
    _generateRandomMAC(net.bssid);
    _networks.push_back(net);
}

void SSIDSpammer::clearSSIDs() {
    _networks.clear();
}

void SSIDSpammer::setRandomMode(bool enable, int count) {
    _randomMode = enable;
    _randomCount = count;
}

void SSIDSpammer::start() {
    if (_active) return;
    
    if (_randomMode) {
        clearSSIDs();
        for (int i = 0; i < _randomCount; i++) {
            addSSID(_generateRandomSSID(8 + random(8)));
        }
    }
    
    if (_networks.empty()) {
        DEBUG_SER_PRINT("[!] Spammer: No SSIDs to spam.\n");
        return;
    }

    _active = true;
    _currentChannel = 1;
    _lastChannelHop = millis();
    DEBUG_SER_PRINT("[+] Spammer: Started flooding with " + String(_networks.size()) + " networks.\n");
}

void SSIDSpammer::stop() {
    _active = false;
    DEBUG_SER_PRINT("[-] Spammer: Stopped.\n");
}

void SSIDSpammer::run() {
    if (!_active) return;

    // Channel hopping logic
    if (millis() - _lastChannelHop > 100) { // Hop every 100ms
        _currentChannel++;
        if (_currentChannel > 13) _currentChannel = 1;
        wext_set_channel(WLAN0_NAME, _currentChannel);
        _lastChannelHop = millis();
    }

    // Broadcast cycle
    for (auto& net : _networks) {
        _craftAndSend(net.ssid, net.bssid, _currentChannel);
        
        // Anti-WDT / RTOS Yield
        delay(1); 
    }
}

void SSIDSpammer::_generateRandomMAC(uint8_t* mac) {
    for (int i = 0; i < 6; i++) mac[i] = random(256);
    // Ensure it's a Locally Administered Address (LAA) unicast
    mac[0] &= 0xFE; // Unicast
    mac[0] |= 0x02; // Locally Administered
}

String SSIDSpammer::_generateRandomSSID(int length) {
    String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    String res = "";
    for (int i = 0; i < length; i++) {
        res += chars[random(chars.length())];
    }
    return res;
}

void SSIDSpammer::_craftAndSend(const String& ssid, uint8_t* bssid, int channel) {
    uint8_t frame[MAX_BEACON_SIZE];
    size_t offset = 0;

    // 1. 802.11 MAC Header (24 bytes)
    memset(frame, 0, 24);
    frame[0] = 0x80; // Type: Management, Subtype: Beacon
    memcpy(&frame[4], "\xFF\xFF\xFF\xFF\xFF\xFF", 6); // Destination (Broadcast)
    memcpy(&frame[10], bssid, 6); // Source
    memcpy(&frame[16], bssid, 6); // BSSID
    offset = 24;

    // 2. Beacon Fixed Parameters (12 bytes)
    // Timestamp (8 bytes) - simplified as 0
    memset(&frame[offset], 0, 8); offset += 8;
    // Beacon Interval (2 bytes) - 0x0064 = 100ms
    frame[offset++] = 0x64; frame[offset++] = 0x00;
    // Capability Info (2 bytes) - 0x0411 (ESS, Privacy, Short Slot Time)
    frame[offset++] = 0x11; frame[offset++] = 0x04;

    // 3. Management Payload (Tags)
    
    // Tag 0: SSID
    frame[offset++] = 0x00; // Tag Number
    frame[offset++] = ssid.length(); // Tag Length
    memcpy(&frame[offset], ssid.c_str(), ssid.length());
    offset += ssid.length();

    // Tag 1: Supported Rates (1, 2, 5.5, 11, 6, 9, 12, 18 mbps)
    uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    memcpy(&frame[offset], rates, sizeof(rates));
    offset += sizeof(rates);

    // Tag 3: DS Parameter Set (Current Channel)
    frame[offset++] = 0x03; // Tag Number
    frame[offset++] = 0x01; // Tag Length
    frame[offset++] = (uint8_t)channel;

    // 4. Send Frame
    wifi_tx_raw_frame(frame, offset);
}
