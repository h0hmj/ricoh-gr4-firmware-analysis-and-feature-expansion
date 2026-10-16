# Open questions / 待研究问题

These are research directions, not supported features or promises. Start with offline analysis and add evidence to the linked report before proposing a device experiment.

以下是研究方向，不是已支持功能或开发承诺。先做离线分析，补充证据后再设计设备实验。

| Question / 问题 | Existing evidence / 已有依据 | Useful next result / 后续可提交内容 |
| --- | --- | --- |
| Complete update validation / 完整升级校验路径 | [Container](../firmware-and-shutdown-image-research.md#固件更新包) has version fields, checksum and error strings | Trace validation and version comparisons; separate checksum from authenticity checks / 追踪校验及版本比较，区分校验和与真实性检查 |
| Memory partitioning across processing domains / 各处理域内存划分 | [1 GiB audit](2026-10-13-gr4-linux-1gib-memory.md) maps 15 RTOS pools and boots the original Linux kernel with a candidate split layout in QEMU / 已还原 15 个池，候选分段布局离线启动成功 | Verify IMAGE2 minimum capacity, DMA ownership and actual DDR windows before repartitioning / 核对 IMAGE2 容量下限、DMA 所有权及实际 DDR 窗口 |
| Debug-mode consumers and hidden pages / Debug 消费者及隐藏页 | [Debug report](../gr4-debug-mode-analysis.md) traces direct consumers and Version entry | Check indirect consumers, timer units and page destinations / 核对间接访问、定时单位及页面目的地 |
| Serial and engineering interfaces / 串口与工程接口 | [Factory-interface report](../firmware-and-shutdown-image-research.md#工厂菜单与启动脚本) records strings and partial paths | Trace transport, command dispatch and permissions; strings alone are insufficient / 追踪传输、命令分派及权限 |
| TTL file-operation semantics / TTL 文件操作语义 | [Issue #1 findings](gr4-ttl-filecopy-filesystems.md), [GR IV](../firmware-and-shutdown-image-research.md) and [Urban](../gr3x-urban-160-shutdown-image.md) differ in copy behavior | Explain return values, truncation and failure behavior for a specific sample / 说明特定样本的返回值、截断及失败行为 |
| Interfaces usable for feature extensions / 可用于扩展的接口 | Resource writes and model routing are documented | Identify a bounded interface, build a host-side proof, and specify state restoration / 找到明确接口、建立离线验证并说明状态恢复 |

There is no published general-purpose extension loader or modified firmware installer. New feature work should identify the firmware path it changes and demonstrate how existing behavior is preserved and restored.

目前没有公开的通用扩展加载器或修改版固件安装器。功能实验需明确修改的固件路径，以及如何保留和恢复原有行为。
