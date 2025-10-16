Bootloader 烧录工具 - V1.4
📌 简介
本工具是一个基于 PyQt5 和 ZLG CAN 接口库（zlgcan）开发的 CAN/CANFD 固件烧录工具，用于通过 CAN 总线将 .bin 格式的固件文件烧录到支持 Bootloader 协议的目标设备中。

当前版本为 V1.4，已实现以下关键功能：

分块传输（每块 4096 字节）
每个原始数据包拆分为前后半包（间隔 100ms 发送）
支持 NACK 重传机制（收到 NACK 后重传整个原始包）
块结束帧包含 CRC32 校验、包总数等信息
实时日志显示与进度条反馈
用户可中止烧录过程
🔧 硬件与依赖
支持设备类型
USBCANFD 系列：设备类型 (41, 42, 43)
USBCAN-XE/U 系列：设备类型 (20, 21, 31)
USBCAN-I/II 系列：设备类型 (3, 4)
设备配置信息通过 dev_info.json 文件加载，支持自定义波特率、CANFD 时钟、终端电阻等参数。 

软件依赖
Python ≥ 3.7
PyQt5
zlgcan SDK（需安装官方驱动及 Python 封装）
标准库：threading, queue, zlib, json, os, sys, time, logging
安装依赖示例：
pip install PyQt5

zlgcan 需从 ZLG 官网 (https://www.zlg.cn/ ) 下载并安装对应驱动及 Python 接口。 

📂 项目结构
bootloader_tool/
├── bootloader_ui.py # PyQt5 UI 文件（由 Qt Designer 生成）
├── dev_info.json # 设备类型与通道配置信息
├── BootLoader.ico # 应用图标
├── main.py # 本脚本（入口）
└── README.md

⚙️ 使用说明
1. 准备工作
确保目标设备已进入 Bootloader 模式，并监听 CAN 总线。
连接 ZLG USBCAN 设备到 PC，并安装驱动。
准备好待烧录的 .bin 固件文件。
2. 启动工具
python main.py

3. 操作流程
选择设备类型：在下拉菜单中选择你的 USBCAN 设备型号。
配置通道与波特率：根据硬件连接选择 CAN 通道和波特率。
打开 CAN 通道：点击“打开通道”按钮，建立通信。
选择 BIN 文件：点击“选择文件”按钮，加载固件。
开始烧录：点击“开始烧录”按钮，启动传输。
查看日志：右侧文本框实时显示传输状态、ACK/NACK、CRC 等信息。
中止烧录：传输过程中可随时点击“中止传输”停止操作。
📡 通信协议（V1.4）
数据包格式
原始包大小：8 字节
每个原始包拆分为两个 CAN 帧：
前半包：[pkt_hi, pkt_lo, 0x00, d0, d1, d2, d3, CRC8]
后半包：[pkt_hi, pkt_lo, 0x01, d4, d5, d6, d7, CRC8]
发送间隔：100ms
CAN ID 分配
数据包
0x100 + block_index
每块使用独立 ID
NACK
0x200
固定 ID，携带 block_idx, pkt_lo, pkt_hi
ACK
0x400 + block_index
每块对应一个 ACK ID
块结束帧
0x300 + block_index
包含 CRC32、包总数
传输结束帧
0x500
空数据，表示烧录完成

块结束帧结构（8 字节）
0-3
CRC32 (Big-Endian)
当前块数据的 CRC32 校验值
4-5
包总数 (Little-Endian)
该块包含的原始包数量
6-7
0x00 0x00
保留

重传机制
收到 NACK 后，重传整个原始包（即前后两个半包）。
每个 NACK 最多重试 3 次，超时或重试失败则终止烧录。
块结束帧发送后，等待 10 秒 超时。
📝 日志示例
📌 Bootloader V1.4
🚀 开始 Bootloader 固件传输
📁 文件: firmware.bin
📦 大小: 123456 字节 | 📦 原始包数: 15432
📥 发送块 0 (0x000000 - 0x000FFF)
📦 包 0/511 @ 0x100: A1 B2 C3 D4 E5 F6 00 00
send0: 00 00 00 A1 B2 C3 D4 8F | send1: 00 00 01 E5 F6 00 00 12
📦 包 1/511 @ 0x100: ...
🏁 块结束帧 | ID=0x300 | CRC32=0x12345678 | 包总数=512
⏳ 等待块 0 的响应 (10秒超时)...
❌ 收到 NACK: 块 0, 包 10 → 将重传整个包
🔄 重传包 10 @ 0x100: ...
✅ 块 0 确认成功
...
🔚 传输结束帧已发送 (ID=0x500)

✅ 固件传输完成！

🛑 注意事项
确保 CAN 总线终端电阻已正确接入（120Ω），避免通信异常。
若使用 CANFD，请确认目标设备与 USBCAN 设备均支持并配置正确。
dev_info.json 中的设备类型必须与实际硬件一致，否则无法打开设备。
烧录过程中请勿断开 CAN 连接或复位目标设备。
📜 版本历史
V1.2：每个包分为前半包和后半包，发送间隔 100ms。
V1.3：收到 NACK 时重传整个原始包（不再区分前后半包），完善接收线程。
V1.4：完善块结束帧数据格式（CRC32 + 包总数 + 保留字段），优化日志显示。
