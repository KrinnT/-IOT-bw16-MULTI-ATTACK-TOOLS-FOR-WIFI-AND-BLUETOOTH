#ifndef OLED_DISPLAY_H
#define OLED_DISPLAY_H

#include <Arduino.h>

// ===================================================================
// OLED SSD1306 128x64 I2C Display Module for RTL8720DN Deauther
// Wiring: PA25 (Arduino Pin 7) → SCL, PA26 (Arduino Pin 8) → SDA, 3V3 → VCC, GND → GND
// Software I2C (No external library required)
// ===================================================================

#define OLED_SCREEN_WIDTH   128
#define OLED_SCREEN_HEIGHT  64
#define OLED_I2C_ADDR       0x3C
#define OLED_REFRESH_MS     200   // Throttle updates to avoid attack lag

// Initialize OLED. Returns false if hardware not found (attack still works).
bool oled_init();

// Call when an attack begins — resets uptime counter
void oled_attack_start();

// ===== Screen Functions =====
void oled_show_boot();                                      // Boot splash (call once)
void oled_show_scanning();                                  // "Scanning WiFi..." (call once)
void oled_show_idle(int ap_count_24, int ap_count_5g);     // Ready screen with AP counts
void oled_show_deauth(int num_targets, uint32_t frames);   // Deauth attack HUD
void oled_show_interference(int active_targets, int max_targets); // Interference HUD
void oled_show_ble_spam(int type, uint32_t packets);       // BLE flood HUD
void oled_show_spammer(int ssid_count);                    // Beacon spammer HUD

#endif
