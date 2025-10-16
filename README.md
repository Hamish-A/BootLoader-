# CAN Bootloader 烧录工具 - V1.4

## 📌 简介

本工具是一个基于 **PyQt5** 和 **ZLG USBCAN 系列设备驱动（zlgcan）** 的 **CAN/CANFD 固件烧录工具**，用于通过 CAN 总线将 `.bin` 固件文件安全、可靠地传输至目标设备的 Bootloader。

支持以下关键特性：
- 分块传输（每块 4096 字节）
- 前后半包拆分发送（V1.2）
- NACK 重传机制（V1.3）：收到 NACK 后重传整个原始包（8 字节）
- 块结束帧携带 CRC32、包总数等校验信息（V1.4）
- 进度条实时显示
- 日志详细输出
- 用户可中止传输

---

## 🧩 版本更新说明

### V1.2
- 每个 8 字节原始包拆分为 **前半包** 和 **后半包**，间隔 100ms 发送，提升兼容性。

### V1.3
- 收到 **NACK**（ID=0x200）时，**重传整个原始包**（不再区分前后半包），简化重传逻辑。
- 完善接收线程，确保消息可靠捕获。
- Bootloader 功能基本实现。

### V1.4 ✅（当前版本）
- **块结束帧格式标准化**：
  - `data[0:3]`：32 位 CRC（大端）
  - `data[4:5]`：当前块的原始包总数（小端，2 字节）
  - `data[6:7]`：固定为 `0x00 0x00`
- 优化日志显示，清晰展示包总数、CRC、重传信息。
- 修复进度条跳变问题，确保平滑更新至 100%。

---

## ⚙️ 硬件与协议要求

### 支持设备
- ZLG USBCAN 系列（包括 USBCAN-I/II、USBCAN-XE/U、USBCANFD 等）
- 需安装官方 **ZLG CAN 驱动** 及 **zlgcan Python SDK**

### CAN 协议约定

| 帧类型       | CAN ID (Hex)     | 数据格式说明 |
|--------------|------------------|--------------|
| **数据包**   | `0x100 + 块索引` | 每个原始包拆为两个 8 字节帧：<br> - 前半包：`[H_idx][L_idx][0x00][D0-D3][CRC8]`<br> - 后半包：`[H_idx][L_idx][0x01][D4-D7][CRC8]` |
| **块结束帧** | `0x300 + 块索引` | `[CRC32(4B)][TotalPackets(2B)][0x00][0x00]` |
| **NACK**     | `0x200`          | `[BlockIdx][PktIdx_L][PktIdx_H]...`（目标设备发送） |
| **ACK**      | `0x400 + 块索引` | 任意数据（仅 ID 有效） |
| **结束帧**   | `0x500`          | 空数据，表示传输完成 |

> ✅ 所有 ID 均为 **标准帧（11 位）**，但工具内部按 **扩展帧（29 位）** 发送（可配置）。

---

## 📦 依赖项

- Python ≥ 3.7
- PyQt5
- `zlgcan`（ZLG 官方 Python 接口）
- `zlib`（标准库）
- `logging`, `threading`, `queue`, `json`, `os`, `sys`, `time`

安装依赖（除 `zlgcan` 外）：
```bash
pip install PyQt5
```

> ⚠️ `zlgcan.py` 需从 ZLG 官网下载并放置于项目目录。

---

## 🗂️ 项目结构

```
bootloader_tool/
├── bootloader_ui.py          # PyQt5 UI 文件（由 Qt Designer 生成）
├── zlgcan.py                 # ZLG CAN 设备驱动接口
├── dev_info.json             # 设备类型配置（波特率、通道数等）
├── res/
│   └── BootLoader.ico        # 应用图标
├── main.py                   # 本主程序（即当前脚本）
└── README.md
```

### `dev_info.json` 示例
```json
{
  "USBCAN-II":{ 
        "dev_type":4,
        "chn_num":2,
        "chn_info":{
            "is_canfd":false,
            "sf_res":false,

            "baudrate":{
                "50K":{
                    "timing0":9,
                    "timing1":28
                },
                "100K":{
                    "timing0":4,
                    "timing1":28
                },

                "125K":{
                    "timing0":3,
                    "timing1":28
                },

                "250K":{
                    "timing0":1,
                    "timing1":28
                },

                "500K":{
                    "timing0":0,
                    "timing1":28
                },

                "800K":{
                    "timing0":0,
                    "timing1":22
                },

                "1M":{
                    "timing0":191,
                    "timing1":255
                }
            }
        }
    }
}
```

---

## ▶️ 使用步骤

1. **连接硬件**  
   将 USBCAN 设备通过 USB 连接电脑，并连接至目标板 CAN 总线。

2. **配置设备**  
   - 打开软件
   - 选择设备型号（如 USBCAN-2A）
   - 选择通道（0 或 1）
   - 设置波特率（需与目标 Bootloader 一致）

3. **打开 CAN 通道**  
   点击 **“打开通道”** 按钮，成功后按钮变为 **“关闭”**。

4. **选择固件**  
   点击 **“选择BIN文件”**，加载 `.bin` 固件。

5. **开始烧录**  
   点击 **“开始烧录”**，工具将自动分块传输，并等待每块的 ACK/NACK。

6. **查看日志**  
   - ✅ 成功：显示 “固件传输完成！”
   - ❌ 失败：显示错误原因（超时、NACK 重试超限等）

7. **中止传输**  
   传输中可点击按钮 **“中止传输”** 立即停止。

---

## 🛠️ 编译与运行

```bash
python main.py
```

> 确保 `zlgcan.dll`（Windows）或对应动态库已安装至系统路径。

---

## 📝 注意事项

- 固件最大支持 **任意大小**（自动分块）
- 每块最大 **4096 字节**（可修改 `BLOCK_SIZE`）
- NACK 重试上限：**3 次/包**
- 超时等待 ACK/NACK：**10 秒**
- 所有 CRC 计算：
  - **CRC8**：多项式 `0x07`，初始值 `0x00`，无反转
  - **CRC32**：标准 `zlib.crc32`（与常见 Bootloader 一致）

---

## 📬 联系与支持

如有问题，请联系开发者或提交 Issue。

> 本工具仅用于开发与测试，请确保目标设备 Bootloader 协议与本工具兼容！

---

**© 2025 Bootloader Tool Team**  
**Version: 1.4**