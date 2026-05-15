# 📡 RTL8720DN Multi-Attack Tool (Wi-Fi 2.4G/5G & Bluetooth)

![Platform](https://img.shields.io/badge/Platform-Arduino%20IDE-blue)
![Hardware](https://img.shields.io/badge/Hardware-RTL8720DN%20(BW16)-orange)
![Status](https://img.shields.io/badge/Status-Development-success)

Dự án mã nguồn mở dành cho mạch **RTL8720DN (BW16)**, cung cấp bộ công cụ kiểm thử bảo mật mạng đa chức năng. Điểm mạnh của dự án là tận dụng khả năng hỗ trợ kép (Dual-band) cho cả Wi-Fi 2.4GHz và 5GHz, cùng với chuẩn Bluetooth của phần cứng.

---

## 🚀 Các tính năng nổi bật (Features)

*   🔍 **Wi-Fi Scanner:** Quét và thu thập thông tin các mạng Wi-Fi xung quanh. *(Lưu ý: Cự ly quét xa hay gần phụ thuộc hoàn toàn vào chất lượng và dải tần của ăng-ten IPEX mà bạn gắn thêm).*
*   ⚔️ **Deauth Attack:** Tấn công Deauthentication, ngắt kết nối các thiết bị mục tiêu khỏi điểm truy cập Wi-Fi (Hoạt động tốt trên cả băng tần 2.4G và 5G).
*   🌪️ **Channel Interference:** Gây nhiễu tín hiệu trên các kênh truyền cụ thể.
*   🌊 **Bluetooth Flooding (Testing):** Gửi hàng loạt gói tin rác để làm ngập lụt (flood) các thiết bị Bluetooth xung quanh. Tính năng này hiện đang trong quá trình thử nghiệm.
*   🎮 **Bluetooth Control:** Tương tác, can thiệp và điều khiển các thiết bị Bluetooth lân cận.

---

## 🛠️ Yêu cầu phần cứng (Hardware Requirements)

*   Board mạch **RTL8720DN (Module BW16)**.
*   Ăng-ten ngoài chuẩn **IPEX** (Khuyến nghị dùng ăng-ten có độ lợi cao, hỗ trợ dual-band 2.4G/5G để tối ưu cự ly tấn công/quét).
*   Cáp kết nối dữ liệu phù hợp với board mạch.

---

## ⚙️ Cài đặt & Sử dụng (Installation)

Dự án này được viết và biên dịch thông qua môi trường **Arduino IDE**.

1. Tải và cài đặt [Arduino IDE](https://www.arduino.cc/en/software) phiên bản mới nhất.
2. Cài đặt thư viện và core hỗ trợ cho board Realtek RTL8720DN (BW16) vào Arduino IDE. 
   > 💡 **Lưu ý:** *Nếu bạn chưa biết cách setup môi trường cho mạch này trên Arduino IDE, vui lòng chủ động tìm kiếm các video hướng dẫn trên YouTube với từ khóa: **"Setup RTL8720DN BW16 Arduino IDE"** để xem các bước thao tác trực quan nhất.*
3. Mở file source code code của dự án bằng Arduino IDE.
4. Cắm mạch vào máy tính, chọn đúng cổng thiết bị và nhấn **Upload**.

---

## ⚠️ Cảnh báo trách nhiệm (Disclaimer)

Bộ công cụ này được phát triển **CHỈ DÀNH CHO MỤC ĐÍCH GIÁO DỤC VÀ NGHIÊN CỨU BẢO MẬT (Educational Purposes Only)**. 

*   Bạn chỉ được phép sử dụng công cụ này trên các hệ thống mạng/thiết bị mà bạn sở hữu, hoặc đã được sự cho phép rõ ràng bằng văn bản từ chủ sở hữu.
*   Tác giả không chịu bất kỳ trách nhiệm pháp lý nào đối với các hành vi lạm dụng đoạn mã này để tấn công phá hoại, vi phạm pháp luật hoặc gây ảnh hưởng xấu đến hệ thống của người khác. Mọi hậu quả phát sinh do người dùng tự chịu trách nhiệm.

*   ⚠️Phá mạng NHÀ NGƯỜI KHÁC ĐI TÒ ráng chịu!!!!!!!!!!⚠️

