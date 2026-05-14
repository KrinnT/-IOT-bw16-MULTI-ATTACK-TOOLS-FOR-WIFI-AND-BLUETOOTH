#ifndef SPAMMER_H
#define SPAMMER_H

#include <Arduino.h>
#undef min
#undef max
#include <vector>
#include "../packet-injection/packet-injection.h"

// Constants for 802.11 Beacon Frame
#define BEACON_FIXED_LEN 36 // 24 header + 12 fixed params
#define MAX_SSID_LEN 32
#define MAX_BEACON_SIZE 512

typedef struct {
    String ssid;
    uint8_t bssid[6];
} SpammedNetwork;

class SSIDSpammer {
public:
    SSIDSpammer();
    ~SSIDSpammer();

    void addSSID(String ssid);
    void clearSSIDs();
    void setRandomMode(bool enable, int count = 10);
    
    void start();
    void stop();
    void run();

    bool isActive() const { return _active; }

private:
    void _generateRandomMAC(uint8_t* mac);
    String _generateRandomSSID(int length);
    void _craftAndSend(const String& ssid, uint8_t* bssid, int channel);

    std::vector<SpammedNetwork> _networks;
    bool _active;
    bool _randomMode;
    int _randomCount;
    int _currentChannel;
    uint32_t _lastChannelHop;
};

extern SSIDSpammer Spammer;

#endif // SPAMMER_H
