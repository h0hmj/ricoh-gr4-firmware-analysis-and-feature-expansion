# GR IV Linux 扩到 1 GiB 的离线可行性检查

2026-10-13。研究对象是 Linux 可用内存的扩容，样本为 GR IV 1.11 / 内部版本 1.11.10.7。

**结论：原厂内核能使用 1 GiB，固件中也找到了可重新分区的图像池配置点；但不能仅把 Linux 的容量值改大。目前没有验证相机在缩小图像池后是否还能完整工作，也没有生成可刷入固件。**

## 样本与方法

| 项目 | 值 |
| --- | --- |
| 原始更新包 | `fwdc248b.bin`，38,648,776 字节 |
| 更新包 SHA-256 | `a2f664dfca034059eb0fd6e18ab08684c326b4a034d85c164dad7e1ec9b5655f` |
| 解包载荷 SHA-256 | `c4e597c7c9ca1bc181b30e35139ed90a4fd876ddcca14f12be0e00b6702233ae` |
| 设备树载荷偏移 / 大小 | `0x13F28A0` / 32,690 字节 |
| zImage 载荷偏移 / 大小 | `0x13FB7E0` / 5,709,552 字节 |
| 原厂内核 | Linux 5.15.190，2025-09-11 编译 |

新增工具：

- [`audit_gr4_linux_memory.py`](../../tools/audit_gr4_linux_memory.py)：只读解析原始 FDT、内核内嵌配置及 RTOS 的 15 个池初始化调用；检查初始页表的同地址映射；输出冲突与候选分区。
- 历史 QEMU 内存布局验证结果及日志保留；对应运行工具已按用户要求移除。

静态审计需要 Capstone。内核 LZ4 解码复用项目的 initfs 解码器，并检查 Linux 压缩流的原始长度尾字段及 gzip 配置的完整性。解压后的内核 SHA-256 为 `e56cf6f1966e65fe705f475e660d4cc4921af6292deb7a818a86bf240874402e`；内嵌配置 SHA-256 为 `68c1078da306a0d791c66ed591200f11637dbbd355d6dcec74c16acd05b624d6`。

```sh
python3 tools/audit_gr4_linux_memory.py samples/gr4_decoded.bin
```

2026-10-13 按用户要求移除模拟器及开发工具。以上只读静态审计仍可运行；下文保留历史内存布局实验结果，不再提供模拟器启动入口。

## 256 MiB 的来源与原厂布局

公开拆解样机的芯片丝印 `NT6CL256T64AJ-H1` 对应南亚原厂 **16Gb / 2 GiB LPDDR3** 规格；这是颗粒容量证据，不能代替用户相机的控制器、地址窗口与实际启用容量读回。资料和丝印冲突的说明见[原有容量核对](../firmware-and-shutdown-image-research.md)。[南亚型号页](https://www.nanya.com/cn/Product/4497/NT6CL256T64AJ-H1)本轮再次核对。

原厂 FDT `/memory/reg` 的数据位于**解包载荷偏移** `0x13F2BD0`，内容为 `40000000 03000000 44f00000 07000000`（大端 u32）。以下区间终点均不包含在区域内。

| 区域 | 基址 → 终点 | 大小 | 证据 |
| --- | --- | --- | --- |
| Linux bank 0 | `0x40000000 → 0x43000000` | 48 MiB | 原始 FDT |
| 根文件系统 slram | `0x43000000 → 0x44F00000` | 31 MiB | 原始 `bootargs`，不计入 Linux 普通分配器 RAM |
| Linux bank 1 | `0x44F00000 → 0x4BF00000` | 112 MiB | 原始 FDT |
| RTOS/Linux 共享页及字段 | `0x4FF00000` 附近 | 部分字段及区域已知 | FDT `snrtos`、帧指针等；不是可空闲分配空间 |
| RTOS 初始只读区 | `0x53000000 → 0x55000000` | 32 MiB 映射 | 初始一级页表；并非全部都是有效代码 |
| RTOS 初始化数据 / BSS | `0x55000000 → 0x558372D4` | 约 8.22 MiB | 原始启动搬运 / 清零边界 |
| RTOS 池 1–13 | `0x59100000 → 0x5D8A0000` | 71.625 MiB | 原始池初始化参数 |
| RTOS 池 14 `IMAGE1` | `0x5D8A0000 → 0x80000000` | 551.375 MiB | 原始池初始化参数 |
| RTOS 池 15 `IMAGE2` | `0xA0000000 → 0xE0000000` | 1024 MiB | 原始池初始化参数 |

Linux 普通 RAM **合计 160 MiB**，加 slram 也只有 191 MiB 的地址图。此前的 `256M` 和 `512M` 都是 **QEMU** 虚拟机配置。它们不说明量产相机分给 Linux 的容量。

把 `0x40000000 → 0x80000000` 全交给 Linux，会把 slram、共享数据、RTOS 和图像池纳入 Linux 页分配器。即使单独保留 slram，仍会与 RTOS 重叠。只扩大第二个 bank 到凑足 1 GiB，也会造成相同冲突。

## 可重新分区的配置点

RTOS `0x538E3924 → 0x538E3C50` 是展开的池初始化代码，通过 `0x538DE8C0` 注册：`r1=池 ID`、`r2=名称`、`r3=大小`、栈 `+4=基址`。构造函数将 arena 长度减去自身尾部元数据，之后内核建立池边界；本报告表中的大小为初始化时声明的完整区间。

| 池 | 初始化调用 | 基址 | 大小 |
| --- | --- | --- | --- |
| 14 / `IMAGE1` | `0x538E3C24` | `0x5D8A0000` | `0x22760000` |
| 15 / `IMAGE2` | `0x538E3C4C` | `0xA0000000` | `0x40000000` |

`IMAGE2` 大小由运行地址 `0x538E3C44` 的 ARM 指令 `mov r3, #0x40000000` 提供，原字节 `01 31 A0 E3`，对应解包载荷偏移 `0x8FB954`。名称字符串在 `0x53FE1510`。`IMAGE1` 名称在 `0x53FE1508`。

全部 15 个静态参数与既有 UI 初始化报告中，原厂指令在 `0x5307A56C` 建立池尾哨兵时观察到的基址 / 大小逐项一致。这是**原厂指令在虚拟硬件模型中的执行证据**，不是机身实时容量或空闲量读回。初始 RTOS 页表对这些池采用同地址映射，后续页表、控制器通道及别名仍需确认。

一个避免搬移 RTOS 的候选设计是：

| 项目 | 原始 | 候选 |
| --- | --- | --- |
| Linux 低地址 banks | 48 + 112 MiB | 保留 |
| `IMAGE1` | 551.375 MiB | 保留 |
| `IMAGE2` | `0xA0000000 → 0xE0000000`，1024 MiB | `0xA0000000 → 0xAA000000`，160 MiB |
| 新 Linux bank | 无 | `0xAA000000 → 0xE0000000`，864 MiB |
| Linux 声明总 RAM | 160 MiB | **1024 MiB** |

这会把 `IMAGE2` 缩小 **84.375%**，总图像池声明容量从 1575.375 MiB 降到 711.375 MiB。它是候选地址设计，不能据此断言拍照、连拍、录像或回放仍然可用。

FDT 的显示配置 `draw_addrss` 包括 `0xA93D4000/0x00384000` 与 `0xA962C000/0x00546000`。这些配置区间都留在拟保留的 160 MiB 内；该检查只排除了这些静态地址的直接冲突，不证明实际显示路径、动态分配或 DMA 需求已经满足。

## 原厂内核的 1 GiB 验证

提取原厂 zImage 的内嵌配置后确认：

```text
CONFIG_VMSPLIT_2G=y
CONFIG_PAGE_OFFSET=0x80000000
CONFIG_HIGHMEM=y
# CONFIG_ARM_LPAE is not set
CONFIG_FLATMEM=y
CONFIG_OF_RESERVED_MEM=y
CONFIG_CMA_SIZE_MBYTES=16
```

使用原厂内核、已有开发 guest 的原厂 BusyBox / 库和合成 UART 桥，在 QEMU `virt,gic-version=2`、Cortex-A7 上验证。

| 布局 | 声明 RAM | 用户空间 | `/proc/meminfo` |
| --- | --- | --- | --- |
| 连续 `0x40000000 → 0x80000000` | 1024 MiB | 成功进入 shell | `MemTotal: 1027832 kB`，约 1003.74 MiB |
| 原有两段 + `0xAA000000 → 0xE0000000` | 48 + 112 + 864 MiB | 成功进入 shell | `MemTotal: 1028408 kB`，约 1004.30 MiB；`HighTotal: 786432 kB` |

分段实验为覆盖高地址，给 QEMU 提供 2560 MiB 的**合成物理 backing**，再使用早期参数仅将目标三个区间交给 Linux：

```text
mem=48M@0x40000000 mem=112M@0x44f00000 mem=864M@0xaa000000
```

核对实际 `/proc/iomem` 而不是只相信输入参数：

```text
40000000-42ffffff : System RAM
44f00000-4befffff : System RAM
aa000000-dfffffff : System RAM
```

初次用定制 QEMU DTB 的试验被 QEMU 自动重写 RAM 节点，识别了全部 2560 MiB，因此**不能作为分段成功证据**。上述表采用后续早期参数试验和工具核验结果。机身实现应修改原厂设备树并协调 RTOS；QEMU 参数不是机身补丁。

这些测试只确认原厂内核能够管理 1 GiB 及目标分段布局。没有执行并发 RTOS、原厂 ISP、实际 DDR、DMA 或相机驱动的硬件协同测试。

本地报告保存在被 Git 忽略的 `devkit-output/gr4-memory-audit-20261013/`：`static-audit.json`、`split-verified.json`、`split-verified.log`。原始固件和解包载荷没有改写。

随报告公开的[精简验证证据](evidence/gr4-linux-memory-20261013.json)包含静态审计输出、历史启动结果及日志哈希；不包含固件、解包内核、完整内核配置或机身读回件。2026-10-16 发布前复跑静态审计，结果与原报告逐项一致。

## 还缺少的机身证据

在提供可刷入版本前，需要确定 `IMAGE2` 的最大单次分配、必要的并发分配、是否存在绕过池分配器的 DMA 用户，以及各拍摄模式的最小容量；读取机身真实 DDR / 内存分区；核对 bootloader 与 Linux 驱动是否有独立固定窗口；建立启动失败时的恢复路径，并核验更新包完整校验。

当前的下一步应是追踪池 15 的申请者及容量下限，而不是扩大原厂 `/memory/reg` 后直接刷机。空闲量也不能代替已分配区域的所有权。

## English

The pinned GR IV 1.11.10.7 Linux kernel can boot with 1 GiB, including the proposed discontiguous 48 + 112 + 864 MiB layout on synthetic QEMU hardware. Stock Linux is declared only 160 MiB; 256 MiB belongs to an earlier emulator configuration.

Original RTOS pool initialization declares IMAGE1 at 551.375 MiB and IMAGE2 at 1024 MiB. A candidate preserves the original Linux banks and RTOS positions, shrinks IMAGE2 to 160 MiB, and gives its upper 864 MiB to Linux. That removes 84.375% of IMAGE2 and is **not validated for a camera**. Minimum image-pool requirements, DMA ownership, DDR windows, bootloader/driver contracts, update validation and recovery remain unresolved. No firmware patch or device write was produced.
