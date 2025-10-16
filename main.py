"""
V1.2 每个包分为前半包和后半包，发送间隔100ms
V1.3 收到 NACK 时重传整个原始包（不再区分前后半包），完善接收线程，功能基本实现
V1.4 完善块结束帧数据，data[0]-[3]:CRC,data[4]-[5]:当前包总数，data[6]-[7]:00 00;日志显示包数优化。
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


class CANReceiveThread(QThread):
    update_view_signal = pyqtSignal(object, int, bool, bool)  # (msgs, count, is_canfd, is_send)

    def __init__(self, zcan, can_handle):
        super().__init__()
        self._zcan = zcan
        self._can_handle = can_handle
        self._terminated = False

    def stop(self):
        self._terminated = True
        self.wait()

    def run(self):
        try:
            while not self._terminated:
                can_num = self._zcan.GetReceiveNum(self._can_handle, ZCAN_TYPE_CAN)
                canfd_num = self._zcan.GetReceiveNum(self._can_handle, ZCAN_TYPE_CANFD)

                if not can_num and not canfd_num:
                    time.sleep(0.005)
                    continue

                # 接收 CAN 消息
                if can_num:
                    while can_num and not self._terminated:
                        read_cnt = MAX_RCV_NUM if can_num >= MAX_RCV_NUM else can_num
                        can_msgs, act_num = self._zcan.Receive(self._can_handle, read_cnt, MAX_RCV_NUM)
                        if act_num > 0:
                            self.update_view_signal.emit(can_msgs, act_num, False, False)
                            can_num -= act_num
                        else:
                            break

                # 接收 CANFD 消息
                if canfd_num:
                    while canfd_num and not self._terminated:
                        read_cnt = MAX_RCV_NUM if canfd_num >= MAX_RCV_NUM else canfd_num
                        canfd_msgs, act_num = self._zcan.ReceiveFD(self._can_handle, read_cnt, MAX_RCV_NUM)
                        if act_num > 0:
                            self.update_view_signal.emit(canfd_msgs, act_num, True, False)
                            canfd_num -= act_num
                        else:
                            break

        except Exception as e:
            print(f"❌ CAN 接收线程异常: {e}")


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
        self._total_blocks = 0

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
            self._total_blocks = total_blocks

            # === 计算总原始包数（仅用于日志）===
            total_original_packets = 0
            for block_index in range(total_blocks):
                start = block_index * BLOCK_SIZE
                end = min(start + BLOCK_SIZE, len(firmware))
                block_data = firmware[start:end]
                original_packets = (len(block_data) + 7) // 8
                total_original_packets += original_packets

            self.log_message.emit("📌 Bootloader V1.4")
            self.log_message.emit(f"🚀 开始 Bootloader 固件传输")
            self.log_message.emit(f"📁 文件: {os.path.basename(self.bin_path)}")
            self.log_message.emit(f"📦 大小: {len(firmware)} 字节 | 📦 原始包数: {total_original_packets}")
            self.log_message.emit("=" * 60)

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

                # === 缓存该块所有原始包数据 ===
                ORIGINAL_PACKET_SIZE = 8
                original_packets = (len(block_data) + 7) // 8
                block_packets = []
                for i in range(original_packets):
                    p_start = i * ORIGINAL_PACKET_SIZE
                    payload = block_data[p_start:p_start + 8]
                    if len(payload) < 8:
                        payload += b'\x00' * (8 - len(payload))
                    block_packets.append(payload)

                # === 发送所有原始包 ===
                for pkt_idx in range(original_packets):
                    self._send_original_packet(block_index, pkt_idx, block_packets[pkt_idx], original_packets)
                    # 更新进度（0% ~ 99%）
                    block_ratio = 1.0 / self._total_blocks
                    block_progress_99 = (pkt_idx + 1) / original_packets * 0.99
                    total_progress = block_index * block_ratio + block_progress_99 * block_ratio
                    percentage = int(total_progress * 100)
                    percentage = min(percentage, 99)
                    self.progress_update.emit(percentage, 100)

                # === 块校验循环（最多重试 3 次）===
                max_nack_retries = 3
                nack_retry_count = 0

                while nack_retry_count <= max_nack_retries:
                    # 1. 发送块结束帧
                    end_frame_data = bytearray(8)
                    # data[0:4]: CRC32 (大端)
                    crc32_bytes = block_crc32.to_bytes(4, 'big')
                    end_frame_data[0:4] = crc32_bytes
                    # data[4:6]: 原始包总数 (小端，2字节)
                    end_frame_data[4] = original_packets & 0xFF  # 低字节
                    end_frame_data[5] = (original_packets >> 8) & 0xFF  # 高字节
                    # data[6:7]: 0x00 0x00
                    end_frame_data[6] = 0x00
                    end_frame_data[7] = 0x00

                    # 发送块结束帧
                    end_id = 0x300 + block_index
                    if not self._send_can_message_direct(end_id, end_frame_data):
                        self.finished.emit(False, f"块结束帧发送失败: 块 {block_index}")
                        return

                    self.log_message.emit(
                        f"  🏁 块结束帧 | ID=0x{end_id:03X} | "
                        f"CRC32=0x{block_crc32:08X} | 包总数={original_packets} | Data={' '.join(f'{b:02X}' for b in end_frame_data)}"
                    )

                    # 2. 等待 ACK/NACK（10秒超时）
                    self._expected_ack_id = hex(0x400 + block_index)
                    self._ack_received.clear()
                    self._nack_info = None

                    self.log_message.emit(f"  ⏳ 等待块 {block_index} 的响应 (10秒超时)...")

                    start_wait = time.time()
                    while time.time() - start_wait < self._timeout:
                        if self._ack_received.is_set():
                            break
                        time.sleep(0.1)

                    # 3. 处理响应
                    if not self._ack_received.is_set():
                        # 超时：直接失败（不重试！）
                        self.log_message.emit(f"  ⚠️ 块 {block_index} 超时未收到响应")
                        self.finished.emit(False, f"块 {block_index} 超时")
                        return

                    if self._nack_info is not None:
                        # 收到 NACK
                        nack_block, nack_pkt = self._nack_info
                        if nack_block != block_index:
                            self.log_message.emit(f"  ⚠️ 收到非当前块 NACK: 块 {nack_block}")
                            self.finished.emit(False, f"收到非当前块 NACK")
                            return

                        if nack_pkt >= original_packets:
                            self.finished.emit(False, f"无效 NACK: 包索引 {nack_pkt} 超出范围")
                            return

                        # 重传计数
                        nack_retry_count += 1
                        if nack_retry_count > max_nack_retries:
                            self.finished.emit(False, f"块 {block_index} NACK 重试超过 {max_nack_retries} 次")
                            return

                        # 重传指定包
                        self.log_message.emit(f"  ❌ 块 {nack_block} 收到 NACK: 包 {nack_pkt}")
                        self._retry_single_packet(block_index, nack_pkt, block_packets[nack_pkt], original_packets)

                        # 继续循环：重新发送块结束帧
                        continue

                    else:
                        # 收到 ACK
                        self.log_message.emit(f"  ✅ 块 {block_index} 确认成功")
                        block_ratio = 1.0 / self._total_blocks
                        total_progress = (block_index + 1) * block_ratio
                        percentage = int(total_progress * 100)
                        self.progress_update.emit(percentage, 100)
                        break  # 成功，进入下一块

                else:
                    self.finished.emit(False, f"块 {block_index} NACK 重试超过 {max_nack_retries} 次")
                    return

            # === 传输结束帧 ===
            if not self._send_can_message_direct(0x500, b""):
                self.finished.emit(False, "传输结束帧发送失败")
                return

            self.log_message.emit(f"\n🔚 传输结束帧已发送 (ID=0x500)")
            self.log_message.emit("\n✅ 固件传输完成！")
            self.progress_update.emit(100, 100)
            self.finished.emit(True, "固件传输成功！")

        except Exception as e:
            self.finished.emit(False, f"传输错误: {str(e)}")

    def on_can_message_received(self, can_id, data):
        data_str = ' '.join(f'{b:02X}' for b in data) if data else ''
        self.log_message.emit(f"🔍 GLOBAL RX | ID={can_id} | Data={data_str}")
        if can_id == "0x200" and len(data) >= 3:
            block_idx = data[0]
            pkt_idx = data[1] | (data[2] << 8)
            if block_idx == self._current_block_index:
                self._nack_info = (int(block_idx), int(pkt_idx))
                self._ack_received.set()
                self.log_message.emit(f"  ❌ 收到 NACK: 块 {block_idx}, 包 {pkt_idx} → 将重传整个包")
        elif can_id == self._expected_ack_id:
            self.log_message.emit(f"  ✅ 收到预期 ACK: {can_id}")
            self._ack_received.set()

            # ✅ 补上该块最后 1%
            if self._current_block_index >= 0 and hasattr(self, '_total_blocks'):
                block_ratio = 1.0 / self._total_blocks
                total_progress = (self._current_block_index + 1) * block_ratio
                percentage = int(total_progress * 100)
                percentage = min(percentage, 100)
                self.progress_update.emit(percentage, 100)

    def _send_original_packet(self, block_index, pkt_idx, payload, original_packets):
        can_id = 0x100 + block_index
        # 前半包
        send0 = bytearray(8)
        send0[0] = (pkt_idx >> 8) & 0xFF
        send0[1] = pkt_idx & 0xFF
        send0[2] = 0x00
        send0[3:7] = payload[0:4]
        send0[7] = crc8(bytes(send0[:7]))
        if not self._send_can_message_direct(can_id, send0):
            raise Exception(f"发送失败: 块 {block_index}, 包 {pkt_idx} 前半包")
        time.sleep(0.1)

        # 后半包
        send1 = bytearray(8)
        send1[0] = (pkt_idx >> 8) & 0xFF
        send1[1] = pkt_idx & 0xFF
        send1[2] = 0x01
        send1[3:7] = payload[4:8]
        send1[7] = crc8(bytes(send1[:7]))
        if not self._send_can_message_direct(can_id, send1):
            raise Exception(f"发送失败: 块 {block_index}, 包 {pkt_idx} 后半包")

        payload_hex = ' '.join(f'{b:02X}' for b in payload)
        self.log_message.emit(
            f"  📦 包 {pkt_idx}/{original_packets - 1} @ 0x{can_id:03X}: {payload_hex}\n"
            f"     send0: {' '.join(f'{b:02X}' for b in send0)} | "
            f"send1: {' '.join(f'{b:02X}' for b in send1)}"
        )

        time.sleep(0.1)

    def _retry_single_packet(self, block_index, pkt_idx, payload, original_packets):
        payload_hex = ' '.join(f'{b:02X}' for b in payload)
        self.log_message.emit(f"  🔄 重传包 {pkt_idx} @ 0x{0x100 + block_index:03X}: {payload_hex}")
        self._send_original_packet(block_index, pkt_idx, payload, original_packets)


class MainWindows(QtWidgets.QMainWindow, Ui_MainWindow, QtCore.QObject):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.btnCANCtrl.clicked.connect(self.BtnOpenCAN_Click)
        self.cmbDevType.currentIndexChanged.connect(self.DeviceInfoInit)
        self.btnSelectFile.clicked.connect(self.select_file)
        self.pushButton.clicked.connect(self.start_bootloader_burn)
        self._bootloader_worker = None
        self._receive_thread = None
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
        # 停止接收线程
        if self._receive_thread is not None:
            self._receive_thread.stop()
            self._receive_thread = None

        # 关闭设备通道
        if self._isChnOpen:
            self._zcan.ResetCAN(self._can_handle)
            self._zcan.CloseDevice(self._dev_handle)
            self._dev_handle = INVALID_DEVICE_HANDLE
            self._can_handle = INVALID_CHANNEL_HANDLE

        if hasattr(self, '_zcan') and self._dev_handle != INVALID_DEVICE_HANDLE:
            self._zcan.CloseDevice(self._dev_handle)
            self._dev_handle = INVALID_DEVICE_HANDLE

    def DeviceInit(self):
        self._zcan       = ZCAN()
        self._dev_handle = INVALID_DEVICE_HANDLE
        self._can_handle = INVALID_CHANNEL_HANDLE
        self._isChnOpen = False
        self._is_canfd = False
        self._res_support = False
        self._view_cnt = 0
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

    def ViewDataUpdate(self, msgs, msgs_num, is_canfd=False, is_send=True):
        if self._isReceivePressed:
            with self._lock:
                for i in range(msgs_num):
                    if msgs[i].frame is None:
                        continue
                    can_id = hex(msgs[i].frame.can_id)
                    data = bytes(msgs[i].frame.data[:msgs[i].frame.can_dlc])

                    # 通知 Bootloader 线程（传入 clean ID）
                    if self._bootloader_worker is not None:
                        self._bootloader_worker.on_can_message_received(can_id, data)

    def show_message_box(self, title, text, icon=QMessageBox.Information):
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setText(text)
        msg_box.setIcon(icon)
        msg_box.setWindowIcon(QIcon('./res/BootLoader.ico'))
        msg_box.exec_()

    def BtnOpenCAN_Click(self):
        if self._isChnOpen:
            # 关闭逻辑
            if self._receive_thread is not None:
                self._receive_thread.stop()
                self._receive_thread = None

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

            # 启动接收线程
            self._receive_thread = CANReceiveThread(self._zcan, self._can_handle)
            self._receive_thread.update_view_signal.connect(self.ViewDataUpdate)
            self._receive_thread.start()

            self.cmbDevType.setEnabled(False)
            self.cmbCANChn.setEnabled(False)
            self.cmbBaudrate.setEnabled(False)
            self.btnCANCtrl.setText("关闭")
            self._isChnOpen = True

    def _can_read_loop(self):
        while not self._read_stop_event.is_set():
            if not self._isChnOpen or self._can_handle == INVALID_CHANNEL_HANDLE:
                time.sleep(0.1)
                continue

            try:
                can_num = self._zcan.GetReceiveNum(self._can_handle, ZCAN_TYPE_CAN)
                canfd_num = self._zcan.GetReceiveNum(self._can_handle, ZCAN_TYPE_CANFD)
                if not can_num and not canfd_num:
                    time.sleep(0.005)  # wait 5ms
                    continue

                if can_num:
                    while can_num:
                        read_cnt = MAX_RCV_NUM if can_num >= MAX_RCV_NUM else can_num
                        can_msgs, act_num = self._zcan.Receive(self._can_handle, read_cnt, MAX_RCV_NUM)
                        if act_num:
                            self.ViewDataUpdate(can_msgs, act_num, False, False)
                        else:
                            break
                        can_num -= act_num
                if canfd_num:
                    while canfd_num:
                        read_cnt = MAX_RCV_NUM if canfd_num >= MAX_RCV_NUM else canfd_num
                        canfd_msgs, act_num = self._zcan.ReceiveFD(self._can_handle, read_cnt, MAX_RCV_NUM)
                        if act_num:
                            self.ViewDataUpdate(canfd_msgs, act_num, True, False)
                        else:
                            break
                        canfd_num -= act_num
            except Exception as e:
                print(f"❌ CAN 接收线程异常: {e}")
                time.sleep(0.1)

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
        self.send_display.clear()

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
    Ui.setWindowTitle("BootLoader烧录-V1.4")
    Ui.show()
    sys.exit(app.exec_())
    