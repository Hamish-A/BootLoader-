"""
V1.2 每个包分为前半包和后半包，发送间隔100ms
V1.3 收到 NACK 时重传整个原始包（不再区分前后半包）
"""


from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import *
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QMessageBox, QFileDialog
from collections import deque
import logging
import threading
import time
import sys
import json
import os
import queue
import zlib

from zlgcan import *
from bootloader_ui import *

MAX_RCV_NUM = 10
MAX_DISPLAY = 500
USBCANFD_TYPE = (41, 42, 43)
USBCAN_XE_U_TYPE = (20, 21, 31)
USBCAN_I_II_TYPE = (3, 4)
logger = logging.getLogger(__name__)


class MessageBuffer:
    def __init__(self, maxlen=1000):
        self._buffer = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add_message(self, msg):
        with self._lock:
            self._buffer.append(msg)

    def get_messages(self):
        with self._lock:
            return list(self._buffer)

    def clear(self):
        with self._lock:
            self._buffer.clear()


def crc8(data: bytes) -> int:
    """计算 CRC8 (多项式: 0x07, 初始值 0x00, 无输入/输出反转)"""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x07
            else:
                crc <<= 1
            crc &= 0xFF
    return crc


def crc32(data: bytes) -> int:
    """计算标准 CRC32（与 zlib.crc32 一致）"""
    return zlib.crc32(data) & 0xFFFFFFFF


class BootloaderWorker(QThread):
    # 信号：用于更新 UI
    log_message = pyqtSignal(str)          # 发送日志到 send_display
    progress_update = pyqtSignal(int, int)  # (current_packet, total_packets)
    finished = pyqtSignal(bool, str)       # (success, message)

    def __init__(self, parent, bin_path, zcan, can_handle):
        super().__init__(parent)
        self.bin_path = bin_path
        self._zcan = zcan
        self._can_handle = can_handle
        self._stop_requested = False

        self._timeout = 10.0
        self._ack_received = threading.Event()
        self._nack_info = None  # (block_index, packet_index)
        self._expected_ack_id = None
        self._current_block_index = -1
        self._retry_count = {}  # {(block, pkt): count}
        self._max_retries = 3

    def stop(self):
        self._stop_requested = True
        self._ack_received.set()  # 中断等待

    def _send_can_message_direct(self, can_id, data, is_extended=True):
        if self._stop_requested:
            return False
        msg = ZCAN_Transmit_Data()
        msg.transmit_type = 0
        msg.frame.can_id = can_id
        msg.frame.rtr = 0
        msg.frame.eff = 1 if is_extended else 0
        msg.frame.can_dlc = len(data)
        for i, b in enumerate(data):
            msg.frame.data[i] = b

        msg_array = (ZCAN_Transmit_Data * 1)()
        msg_array[0] = msg
        ret = self._zcan.Transmit(self._can_handle, msg_array, 1)
        return ret == 1

    def run(self):
        try:
            with open(self.bin_path, 'rb') as f:
                firmware = f.read()

            BLOCK_SIZE = 4096
            total_blocks = (len(firmware) + BLOCK_SIZE - 1) // BLOCK_SIZE

            # === 计算总原始包数 ===
            total_original_packets = 0
            for block_index in range(total_blocks):
                start = block_index * BLOCK_SIZE
                end = min(start + BLOCK_SIZE, len(firmware))
                block_data = firmware[start:end]
                original_packets = (len(block_data) + 7) // 8  # 向上取整
                total_original_packets += original_packets

            self.log_message.emit("📌 Bootloader V1.3（NACK 触发整包重传）")
            self.log_message.emit(f"🚀 开始 Bootloader 固件传输")
            self.log_message.emit(f"📁 文件: {os.path.basename(self.bin_path)}")
            self.log_message.emit(f"📦 大小: {len(firmware)} 字节 | 📦 原始包数: {total_original_packets}")
            self.log_message.emit("=" * 60)

            current_packet = 0

            for block_index in range(total_blocks):
                if self._stop_requested:
                    self.finished.emit(False, "用户中止")
                    return

                start = block_index * BLOCK_SIZE
                end = min(start + BLOCK_SIZE, len(firmware))
                block_data = firmware[start:end]
                block_crc32 = crc32(block_data)
                self._current_block_index = block_index
                self._nack_info = None

                self.log_message.emit(f"\n📥 发送块 {block_index} (0x{start:06X} - 0x{end - 1:06X})")

                ORIGINAL_PACKET_SIZE = 8
                original_packets = (len(block_data) + 7) // 8  # 向上取整

                orig_pkt_idx = 0
                while orig_pkt_idx < original_packets:
                    if self._stop_requested:
                        self.finished.emit(False, "用户中止")
                        return

                    # === 检查是否需要重传 ===
                    if self._nack_info and self._nack_info[0] == block_index:
                        nack_block, nack_pkt = self._nack_info
                        if nack_pkt >= original_packets:
                            self.finished.emit(False, f"无效 NACK: 包索引 {nack_pkt} 超出范围")
                            return

                        # 重传计数
                        retry_key = (nack_block, nack_pkt)
                        self._retry_count[retry_key] = self._retry_count.get(retry_key, 0) + 1
                        if self._retry_count[retry_key] > self._max_retries:
                            self.finished.emit(False, f"包 {nack_pkt} 重传超过 {self._max_retries} 次，放弃")
                            return

                        # 获取原始数据（8字节）
                        p_start = nack_pkt * ORIGINAL_PACKET_SIZE
                        original_payload = block_data[p_start:p_start + 8]
                        if len(original_payload) < 8:
                            original_payload += b'\x00' * (8 - len(original_payload))

                        self.log_message.emit(
                            f"  🔄 重传整个包 {nack_pkt} | ID=0x{0x100 + block_index:03X} | Data={' '.join(f'{b:02X}' for b in original_payload)}"
                        )

                        # 重传前半包
                        send0_data = bytearray(8)
                        send0_data[0] = (nack_pkt >> 8) & 0xFF
                        send0_data[1] = nack_pkt & 0xFF
                        send0_data[2] = 0x00
                        send0_data[3:7] = original_payload[0:4]
                        send0_data[7] = crc8(bytes(send0_data[:7]))

                        can_id = 0x100 + block_index
                        if not self._send_can_message_direct(can_id, send0_data):
                            self.finished.emit(False, f"重传失败: 块 {block_index}, 包 {nack_pkt} 前半包")
                            return

                        send0_hex = ' '.join(f"{b:02X}" for b in send0_data)
                        self.log_message.emit(f"    → 重传前半包={send0_hex}")
                        time.sleep(0.1)

                        # 重传后半包
                        send1_data = bytearray(8)
                        send1_data[0] = (nack_pkt >> 8) & 0xFF
                        send1_data[1] = nack_pkt & 0xFF
                        send1_data[2] = 0x01
                        send1_data[3:7] = original_payload[4:8]
                        send1_data[7] = crc8(bytes(send1_data[:7]))

                        if not self._send_can_message_direct(can_id, send1_data):
                            self.finished.emit(False, f"重传失败: 块 {block_index}, 包 {nack_pkt} 后半包")
                            return

                        send1_hex = ' '.join(f"{b:02X}" for b in send1_data)
                        self.log_message.emit(f"    → 重传后半包={send1_hex}")
                        time.sleep(0.1)

                        self._nack_info = None
                        # 注意：不推进 orig_pkt_idx，下轮继续检查是否还需重传
                        continue

                    # === 正常发送原始包的两个半包 ===
                    p_start = orig_pkt_idx * ORIGINAL_PACKET_SIZE
                    original_payload = block_data[p_start:p_start + 8]
                    if len(original_payload) < 8:
                        original_payload += b'\x00' * (8 - len(original_payload))

                    original_data_hex = ' '.join(f"{b:02X}" for b in original_payload)
                    self.log_message.emit(
                        f"  📦 原始包 {orig_pkt_idx}/{original_packets - 1} | ID=0x{0x100 + block_index:03X} | Data={original_data_hex}")

                    # 发送前半包
                    send0_data = bytearray(8)
                    send0_data[0] = (orig_pkt_idx >> 8) & 0xFF
                    send0_data[1] = orig_pkt_idx & 0xFF
                    send0_data[2] = 0x00
                    send0_data[3:7] = original_payload[0:4]
                    send0_data[7] = crc8(bytes(send0_data[:7]))

                    can_id = 0x100 + block_index
                    if not self._send_can_message_direct(can_id, send0_data):
                        self.finished.emit(False, f"发送失败: 块 {block_index}, 原始包 {orig_pkt_idx} 前半包")
                        return

                    send0_hex = ' '.join(f"{b:02X}" for b in send0_data)
                    self.log_message.emit(f"    → send0={send0_hex}")
                    time.sleep(0.1)

                    # 发送后半包
                    send1_data = bytearray(8)
                    send1_data[0] = (orig_pkt_idx >> 8) & 0xFF
                    send1_data[1] = orig_pkt_idx & 0xFF
                    send1_data[2] = 0x01
                    send1_data[3:7] = original_payload[4:8]
                    send1_data[7] = crc8(bytes(send1_data[:7]))

                    if not self._send_can_message_direct(can_id, send1_data):
                        self.finished.emit(False, f"发送失败: 块 {block_index}, 原始包 {orig_pkt_idx} 后半包")
                        return

                    send1_hex = ' '.join(f"{b:02X}" for b in send1_data)
                    self.log_message.emit(f"    → send1={send1_hex}")
                    time.sleep(0.1)

                    # 更新进度
                    current_packet += 1
                    self.progress_update.emit(current_packet, total_original_packets)
                    orig_pkt_idx += 1

                # === 块结束帧 ===
                end_id = 0x300 + block_index
                crc32_bytes = block_crc32.to_bytes(4, 'big')
                if not self._send_can_message_direct(end_id, crc32_bytes):
                    self.finished.emit(False, f"块结束帧发送失败: 块 {block_index}")
                    return

                self.log_message.emit(f"  🏁 块结束帧 | ID=0x{end_id:03X} | CRC32=0x{block_crc32:08X}")

                # === 等待 ACK ===
                self._expected_ack_id = 0x400 + block_index
                self._ack_received.clear()
                self._nack_info = None

                self.log_message.emit(f"  ⏳ 等待块 {block_index} 的响应 (10秒超时)...")

                start_wait = time.time()
                ack_received = False
                while time.time() - start_wait < self._timeout:
                    if self._stop_requested:
                        self.finished.emit(False, "用户中止")
                        return
                    if self._ack_received.is_set():
                        ack_received = True
                        break
                    time.sleep(0.1)

                if ack_received:
                    self.log_message.emit(f"  ✅ 块 {block_index} 确认成功")
                else:
                    if self._nack_info and self._nack_info[0] == block_index:
                        nack_block, nack_pkt = self._nack_info
                        self.log_message.emit(f"  ❌ 块 {nack_block} 收到 NACK: 包 {nack_pkt}")
                        self.finished.emit(False, f"块 {block_index} 校验失败")
                        return
                    else:
                        self.log_message.emit(f"  ⚠️ 块 {block_index} 超时未收到响应")
                        self.finished.emit(False, f"块 {block_index} 超时")
                        return

            # === 传输结束帧 ===
            if not self._send_can_message_direct(0x500, b""):
                self.finished.emit(False, "传输结束帧发送失败")
                return

            self.log_message.emit(f"\n🔚 传输结束帧已发送 (ID=0x500)")
            self.log_message.emit("\n✅ 固件传输完成！")
            self.finished.emit(True, "固件传输成功！")

        except Exception as e:
            self.finished.emit(False, f"传输错误: {str(e)}")

    # 供主窗口调用：当收到 ACK/NACK 时
    def on_can_message_received(self, can_id, data):
        if can_id == 0x200 and len(data) >= 3:
            block_idx = data[0]  # 块索引
            pkt_idx = (data[1] << 8) | data[2]  # 包索引（大端）

            if block_idx == self._current_block_index:
                self._nack_info = (block_idx, pkt_idx)
                self._ack_received.set()
                self.log_message.emit(f"  ❌ 收到 NACK: 块 {block_idx}, 包 {pkt_idx} → 将重传整个包")
        elif can_id == self._expected_ack_id:
            self._ack_received.set()


class MainWindows(QtWidgets.QMainWindow, Ui_MainWindow, QtCore.QObject):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.btnCANCtrl.clicked.connect(self.BtnOpenCAN_Click)
        self.cmbDevType.currentIndexChanged.connect(self.DeviceInfoInit)
        self.btnSelectFile.clicked.connect(self.select_file)
        self.pushButton.clicked.connect(self.start_bootloader_burn)
        self._bootloader_worker = None
        self.first_timestamp = 0
        self._isReceivePressed = True
        self.selected_bin_file_path = ""  # 存储选中的BIN文件路径
        self.DeviceInit()
        self._dev_info = None
        with open("./dev_info.json", "r") as fd:
            self._dev_info = json.load(fd)
        if self._dev_info is None:
            print("device info no exist!")
            return
        self.cmbDevType.addItems([dev_name for dev_name in self._dev_info])
        self.cmbDevType.setCurrentIndex(8)
        self.DeviceInfoInit()

        # 初始化进度条
        self.progressBar.setValue(0)

    def closeEvent(self, event):
        # 关闭设备通道
        if self._isChnOpen:
            self._zcan.ResetCAN(self._can_handle)
            self._zcan.CloseDevice(self._dev_handle)
            self._dev_handle = INVALID_DEVICE_HANDLE
            self._can_handle = INVALID_CHANNEL_HANDLE

        # 确保设备完全关闭
        if hasattr(self, '_zcan') and self._dev_handle != INVALID_DEVICE_HANDLE:
            self._zcan.CloseDevice(self._dev_handle)
            self._dev_handle = INVALID_DEVICE_HANDLE

    def DeviceInit(self):
        self._zcan       = ZCAN()
        self._dev_handle = INVALID_DEVICE_HANDLE
        self._can_handle = INVALID_CHANNEL_HANDLE

        self._isChnOpen = False

        #current device info
        self._is_canfd = False
        self._res_support = False

        self._view_cnt = 0

        #read can/canfd message thread
        self._read_thread = None
        self._lock = threading.RLock()

    def DeviceInfoInit(self):
        # 通道信息获取
        cur_dev_info = self._dev_info[self.cmbDevType.currentText()]
        cur_chn_info = cur_dev_info["chn_info"]
        # 通道
        self.cmbCANChn.clear()
        for i in range(cur_dev_info["chn_num"]):
            self.cmbCANChn.addItem(str(i))
        self.cmbCANChn.setCurrentIndex(0)

        # 波特率
        self.cmbBaudrate.clear()
        for brt in cur_chn_info["baudrate"].keys():
            self.cmbBaudrate.addItem(str(brt))
        self.cmbBaudrate.setCurrentIndex(3)

    def __dlc2len(self, dlc):
        if dlc <= 8:
            return dlc
        elif dlc == 9:
            return 12
        elif dlc == 10:
            return 16
        elif dlc == 11:
            return 20
        elif dlc == 12:
            return 24
        elif dlc == 13:
            return 32
        elif dlc == 14:
            return 48
        else:
            return 64

    def CANMsg2View(self, msg, is_transmit=True):
        # 处理时间戳
        if hasattr(msg, 'timestamp'):
            msg_timestamp = msg.timestamp / 1000000
            formatted_timestamp = f"{msg_timestamp:.6f}"
            if self.first_timestamp == 0:
                self.first_timestamp = formatted_timestamp
            view_timestamp = float(formatted_timestamp) - float(self.first_timestamp)
        else:
            view_timestamp = 0.000000

        # 格式化时间戳
        view_timestamp_str = f"{view_timestamp:.6f}"

        # 构建视图列表
        view = [str(view_timestamp_str), hex(msg.frame.can_id)[2:].upper(), "Tx" if is_transmit else "Rx"]

        # 构建帧信息字符串
        str_info = ''
        str_info += 'EXT' if msg.frame.eff else 'STD'
        if msg.frame.rtr:
            str_info += ' RTR'
        view.append(str_info)

        # 添加数据长度
        view.append(str(msg.frame.can_dlc))

        # 处理数据部分
        if msg.frame.rtr:
            # 如果是远程传输请求（RTR），数据为空
            view.append('')
        else:
            # 使用 bytes.hex() 方法高效生成带空格的十六进制字符串
            data_bytes = bytes(msg.frame.data[:msg.frame.can_dlc])
            try:
                # Python 3.8+ 支持 sep 参数
                hex_string = data_bytes.hex(' ').upper()
            except TypeError:
                # Python < 3.8 不支持 sep 参数，手动实现
                hex_string = ' '.join(f"{byte:02X}" for byte in data_bytes)
            view.append(hex_string)

        return view

    def CANFDMsg2View(self, msg, is_transmit=True):
        msg_timestamp = msg.timestamp / 1000000
        formatted_timestamp = f"{msg_timestamp:.6f}"
        if self.first_timestamp == 0:
            self.first_timestamp = formatted_timestamp
        view_timestamp = float(formatted_timestamp) - float(self.first_timestamp)
        view_timestamp_str = f"{view_timestamp:.6f}"
        view = [str(view_timestamp_str), hex(msg.frame.can_id)[2:].upper(), "Tx" if is_transmit else "Rx"]

        str_info = ''
        str_info += 'EXT' if msg.frame.eff else 'STD'
        if msg.frame.rtr:
            str_info += ' RTR'
        else:
            str_info += ' FD'
            if msg.frame.brs:
                str_info += ' BRS'
            if msg.frame.esi:
                str_info += ' ESI'
        view.append(str_info)
        view.append(str(msg.len))

        if msg.frame.rtr:
            view.append('')
        else:
            data_str = ' '.join(f"{byte:02X}" for byte in msg.frame.data[:msg.frame.len])
            view.append(data_str)
        return view

    def ViewDataUpdate(self, msgs, msgs_num, is_canfd=False, is_send=True):
        if self._isReceivePressed:
            with self._lock:
                for i in range(msgs_num):
                    if msgs[i].frame is None:
                        continue
                    can_id = msgs[i].frame.can_id
                    data = bytes(msgs[i].frame.data[:msgs[i].frame.can_dlc])

                    # 通知 Bootloader 线程
                    if self._bootloader_worker is not None:
                        self._bootloader_worker.on_can_message_received(can_id, data)

                    try:
                        if is_canfd:
                            view = self.CANFDMsg2View(msgs[i], is_send)
                        else:
                            view = self.CANMsg2View(msgs[i], is_send)
                    except Exception as e:
                        print(f"Error processing frame: {e}")
                        continue

                    self.check_and_convert_signal.emit(view)

    def show_message_box(self, title, text, icon=QMessageBox.Information):
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setText(text)
        msg_box.setIcon(icon)
        msg_box.setWindowIcon(QIcon('./res/BootLoader.ico'))
        msg_box.exec_()

    def BtnOpenCAN_Click(self):
        if self._isChnOpen:
            self._zcan.ResetCAN(self._can_handle)
            self._zcan.CloseDevice(self._dev_handle)
            self._dev_handle = INVALID_DEVICE_HANDLE
            self._can_handle = INVALID_CHANNEL_HANDLE

            self.btnCANCtrl.setText("打开通道")
            self._isChnOpen = False
            self.cmbDevType.setEnabled(True)
            self.cmbCANChn.setEnabled(True)
            self.cmbBaudrate.setEnabled(True)
            self._is_canfd = False

        else:
            if self._dev_handle != INVALID_DEVICE_HANDLE:
                self._zcan.CloseDevice(self._dev_handle)

            self._cur_dev_info = self._dev_info.get(self.cmbDevType.currentText(), {})

            self._dev_handle = self._zcan.OpenDevice(
                self._cur_dev_info.get("dev_type"),
                0,
                0
            )
            if self._dev_handle == INVALID_DEVICE_HANDLE:
                self.show_message_box("打开设备", "打开设备失败！", QMessageBox.Critical)
                return

            self._is_canfd = self._cur_dev_info.get("chn_info", {}).get("is_canfd", False)
            self._res_support = self._cur_dev_info.get("chn_info", {}).get("sf_res", [])

            if self._res_support:
                ip = self._zcan.GetIProperty(self._dev_handle)
                self._zcan.SetValue(ip,
                                    str(self.cmbCANChn.currentIndex()) + "/initenal_resistance",
                                    '1' if self.cmbResEnable.currentIndex() == 0 else '0')
                self._zcan.ReleaseIProperty(ip)

            if self._cur_dev_info["dev_type"] in USBCAN_XE_U_TYPE:
                ip = self._zcan.GetIProperty(self._dev_handle)
                self._zcan.SetValue(ip,
                                    str(self.cmbCANChn.currentIndex()) + "/baud_rate",
                                    self._cur_dev_info["chn_info"]["baudrate"][self.cmbBaudrate.currentText()])
                self._zcan.ReleaseIProperty(ip)

            if self._cur_dev_info["dev_type"] in USBCANFD_TYPE:
                ip = self._zcan.GetIProperty(self._dev_handle)
                self._zcan.SetValue(ip, str(self.cmbCANChn.currentIndex()) + "/clock", "60000000")
                self._zcan.ReleaseIProperty(ip)

            chn_cfg = ZCAN_CHANNEL_INIT_CONFIG()
            chn_cfg.can_type = ZCAN_TYPE_CANFD if self._is_canfd else ZCAN_TYPE_CAN
            chn_cfg.config.can.mode = 0
            if self._cur_dev_info["dev_type"] in USBCAN_I_II_TYPE:
                brt = self._cur_dev_info["chn_info"]["baudrate"][self.cmbBaudrate.currentText()]
                chn_cfg.config.can.timing0 = brt["timing0"]
                chn_cfg.config.can.timing1 = brt["timing1"]
                chn_cfg.config.can.acc_code = 0
                chn_cfg.config.can.acc_mask = 0xFFFFFFFF

            self._can_handle = self._zcan.InitCAN(self._dev_handle, self.cmbCANChn.currentIndex(), chn_cfg)
            if self._can_handle == INVALID_CHANNEL_HANDLE:
                self.show_message_box("打开通道", "初始化通道失败！", QMessageBox.Critical)
                return

            ret = self._zcan.StartCAN(self._can_handle)
            if ret != ZCAN_STATUS_OK:
                self.show_message_box("打开通道", "打开通道失败！", QMessageBox.Critical)
                return

            self.cmbDevType.setEnabled(False)
            self.cmbCANChn.setEnabled(False)
            self.cmbBaudrate.setEnabled(False)
            self.btnCANCtrl.setText("关闭")
            self._isChnOpen = True

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择BIN文件",
            "",
            "BIN Files (*.bin);;All Files (*)"
        )

        if file_path:
            self.selected_bin_file_path = file_path
            if hasattr(self, 'lineEdit'):
                self.lineEdit.setText(file_path)
            print(f"Selected BIN file: {file_path}")

    def start_bootloader_burn(self):
        if not self.selected_bin_file_path:
            self.show_message_box("错误", "请先选择一个BIN文件！", QMessageBox.Critical)
            return
        if not self._isChnOpen:
            self.show_message_box("错误", "请先打开CAN通道！", QMessageBox.Critical)
            return

        if self._bootloader_worker is not None and self._bootloader_worker.isRunning():
            self._bootloader_worker.stop()
            self._bootloader_worker.wait()

        self.progressBar.setValue(0)

        self._bootloader_worker = BootloaderWorker(
            self,
            self.selected_bin_file_path,
            self._zcan,
            self._can_handle
        )
        self._bootloader_worker.log_message.connect(self.send_display.append)
        self._bootloader_worker.progress_update.connect(self.update_progress_bar)
        self._bootloader_worker.finished.connect(self.on_bootloader_finished)
        self._bootloader_worker.start()

        self.pushButton.setText("中止传输")
        self.pushButton.clicked.disconnect()
        self.pushButton.clicked.connect(self.abort_bootloader_burn)

    def abort_bootloader_burn(self):
        if self._bootloader_worker is not None:
            self._bootloader_worker.stop()
            self.pushButton.setText("开始烧录")
            self.pushButton.clicked.disconnect()
            self.pushButton.clicked.connect(self.start_bootloader_burn)

    def on_bootloader_finished(self, success: bool, message: str):
        self.pushButton.setText("开始烧录")
        self.pushButton.clicked.disconnect()
        self.pushButton.clicked.connect(self.start_bootloader_burn)

        if success:
            self.show_message_box("成功", message, QMessageBox.Information)
        else:
            self.show_message_box("错误", message, QMessageBox.Critical)

    def update_progress_bar(self, current_packet: int, total_packets: int):
        percentage = int((current_packet / total_packets) * 100)
        self.progressBar.setValue(percentage)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    Ui = MainWindows()
    Ui.setWindowTitle("BootLoader烧录-V1.3")
    Ui.show()
    sys.exit(app.exec_())
    