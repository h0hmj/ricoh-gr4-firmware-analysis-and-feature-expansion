<!-- License: see LICENSE (earlier Apache-2.0 grants remain in force) -->

# Ricoh GR IV Firmware Analysis and Feature Expansion

[English](#english) · [简体中文](#中文) · [Documentation / 文档](docs/README.md) · [Issues](https://github.com/radium-wang/ricoh-gr4-firmware-analysis-and-feature-expansion/issues)

## English

Research into Ricoh GR IV firmware, internal interfaces and possible feature extensions. This repository collects analysis notes, offline tools, device probes and experiments, with evidence and limits recorded for each finding. Most detailed reports are in Chinese.

### Start here

| What you want to do | Where to start |
| --- | --- |
| Understand the firmware and current findings | [Research index](docs/research/README.md) · [Developer guide](docs/research/developer-guide.md) |
| Replace a shutdown image | [Model-specific workflows](docs/extensions/README.md) |
| Find a tool or example | [Tool reference](tools/README.md) · [Examples](examples/README.md) |
| Share a finding or propose an experiment | [Research log](docs/research-log.md) · [Open questions](docs/research/open-questions.md) · [Contributing](CONTRIBUTING.md) |

### Research overview

| Topic | Findings and status |
| --- | --- |
| [Firmware container and system layout](docs/firmware-and-shutdown-image-research.md) | Header/version fields, frame decoding, checksum, RTOS mapping and embedded Linux components |
| [Linux RAM and the 1 GiB proposal](docs/research/2026-10-13-gr4-linux-1gib-memory.md) | Stock Linux is declared 160 MiB; the original kernel booted with 1 GiB in an offline experiment. The proposed image-pool repartition is untested on a camera. |
| [USB / MTP](docs/firmware-and-shutdown-image-research.md#usbmtp-调查) | Device enumeration and the capabilities of the tested interfaces |
| [Factory and debug interfaces](docs/gr4-debug-mode-analysis.md) | Camera Mode, the verified Version-page shortcut, key-event paths and factory-script entry points |
| [GR IV / GF-2 flash and hotshoe](docs/research/gr4-flash-research-summary.md) | Protocol, accessory identification and power experiments; the tested wake sequence was ineffective. Nikon bridging remains a proposal. |
| [Model identification](docs/gr4-model-identification.md) | GR IV, HDF and Monochrome product IDs and resource routing |

### Feature expansion

Custom shutdown images use the camera's factory-script interface. Follow the [shutdown-image guides](docs/extensions/README.md) for the selected model: GR IV family, GR IIIx Urban Edition 1.60, or the [GR IIIx HDF 1.60 contributor record](docs/gr3x-hdf-160-shutdown-image.md).

Keep a computer backup of each body's original image and follow its backup, write, readback and restore procedure. The HDF record documents one body's replacement; restoration was not tested. Newer combined templates and wrappers are not fully camera-qualified.

Firmware, extracted system files, device readbacks and private artwork are not distributed. No installable modified firmware or general-purpose camera SDK is provided. Offline and host-side results do not establish camera compatibility.

## 中文

本项目研究理光 GR IV 的固件结构、内部接口和功能扩展可能性，收录分析记录、离线工具、设备探针及实验。各项发现分别记录证据、验证范围和未解决问题。

### 阅读入口

| 你想做什么 | 从这里开始 |
| --- | --- |
| 了解固件结构和已有发现 | [研究索引](docs/research/README.md) · [开发者入门](docs/research/developer-guide.md) |
| 更换关机画面 | [按机型查看操作流程](docs/extensions/README.md) |
| 查找工具或示例 | [工具说明](tools/README.md) · [示例说明](examples/README.md) |
| 分享发现或提出实验 | [研究日志](docs/research-log.md) · [待研究问题](docs/research/open-questions.md) · [贡献指南](CONTRIBUTING.md) |

### 研究概览

| 主题 | 已有发现与验证状态 |
| --- | --- |
| [固件容器与系统布局](docs/firmware-and-shutdown-image-research.md) | 包头、版本字段、帧解码、校验和、RTOS 映射及内嵌 Linux 组件 |
| [Linux 内存与 1 GiB 扩容方案](docs/research/2026-10-13-gr4-linux-1gib-memory.md) | Linux 原始分配为 160 MiB；原厂内核已在离线实验中以 1 GiB 启动，候选图像池分区尚未验证机身功能。 |
| [USB / MTP](docs/firmware-and-shutdown-image-research.md#usbmtp-调查) | 设备枚举及已测试接口的能力范围 |
| [工厂与调试接口](docs/gr4-debug-mode-analysis.md) | Camera Mode、已验证的 Version 页面入口、按键事件路径和工厂脚本入口 |
| [GR IV / GF-2 闪光灯与热靴](docs/research/gr4-flash-research-summary.md) | 协议、附件识别和电源实验；已测唤醒序列无效，尼康闪光灯桥接仍是研究方案。 |
| [机型识别](docs/gr4-model-identification.md) | GR IV、HDF、Monochrome 产品 ID 与资源路由 |

### 功能扩展

自定义关机画面通过相机的工厂脚本接口实现。请按[关机图片指南](docs/extensions/README.md)选择对应机型：GR IV 系列、GR IIIx Urban Edition 1.60，或 [GR IIIx HDF 1.60 贡献者记录](docs/gr3x-hdf-160-shutdown-image.md)。

每台机身单独保留电脑端原图备份，按对应流程完成备份、写入、读回和恢复。HDF 记录来自单台机身的更换实验，恢复未实测；新组合模板及工具包装尚未整套上机验证。

仓库不分发固件、解包系统文件、机身读回数据或私人图稿，目前没有可安装的修改版固件或通用相机 SDK。离线及电脑端结果不代表已验证机身兼容性。

## Offline analysis / 离线分析

Obtain a firmware file yourself and run these commands from the repository root. They inspect or decode a local container without connecting to a camera.

自行取得固件文件，在仓库根目录运行。以下命令只检查或解码本地容器，不连接相机。

```sh
python3 tools/inspect_firmware.py /path/to/fwdc248b.bin
python3 tools/inspect_firmware.py /path/to/fwdc248b.bin --unpack /tmp/gr4-decoded.bin
```

Record the model, firmware version and sample SHA-256. The [developer guide](docs/research/developer-guide.md) explains sample checks, address mapping and evidence requirements. Additional dependencies are listed in the [tool reference](tools/README.md).

记录机型、固件版本及样本 SHA-256。[开发者入门](docs/research/developer-guide.md)说明样本核对、地址映射及证据要求；各工具的额外依赖见[工具说明](tools/README.md)。

## Repository layout / 仓库结构

| Path / 路径 | Contents / 内容 |
| --- | --- |
| [docs/research/](docs/research/README.md) | Firmware reports, evidence and open questions / 固件报告、证据与待研究问题 |
| [docs/extensions/](docs/extensions/README.md) | Feature workflows by model / 按机型整理的功能操作流程 |
| [docs/](docs/README.md) | Documentation entry and existing technical reports / 文档入口及现有技术报告 |
| [tools/](tools/README.md) | Offline analysis, device probes and workflow generators / 离线分析、设备探测及操作包生成工具 |
| [examples/](examples/README.md) | TTL experiments and workflow templates / TTL 实验与操作模板 |
| [tests/](tests/) | Host-side checks and script control-flow models / 电脑端检查及脚本控制流模型 |

## Development / 开发

The full host test suite requires Python 3.10+ and Pillow. These checks cover host tools and script models; they do not validate camera hardware.

整套电脑端测试需要 Python 3.10+ 和 Pillow，覆盖工具及脚本模型，不验证相机硬件。

```sh
python3 -m pip install Pillow
python3 -m unittest discover -s tests -v
```

## Discussion and contributions / 交流与贡献

Discussion, research findings and feedback are welcome. Use [Issues](https://github.com/radium-wang/ricoh-gr4-firmware-analysis-and-feature-expansion/issues) for questions and suggestions, or submit [Pull Requests](https://github.com/radium-wang/ricoh-gr4-firmware-analysis-and-feature-expansion/pulls) for code, documentation and tests. Include the sample identity, evidence and verification limits described in [CONTRIBUTING.md](CONTRIBUTING.md).

欢迎交流、分享研究发现和使用反馈。问题与建议可提交到 [Issues](https://github.com/radium-wang/ricoh-gr4-firmware-analysis-and-feature-expansion/issues)，代码、文档和测试改进可提交 [Pull Requests](https://github.com/radium-wang/ricoh-gr4-firmware-analysis-and-feature-expansion/pulls)。请按[贡献指南](CONTRIBUTING.md)附上样本身份、证据及验证范围。

<a id="许可证"></a>
<a id="免责声明和许可证"></a>

## License

Newly licensed project material is released under the [GR IV Project Noncommercial Source License 1.0](LICENSE). Commercial use requires written permission; this is not an OSI-approved open-source license. Revisions through [`a55a2c7`](https://github.com/radium-wang/ricoh-gr4-firmware-analysis-and-feature-expansion/tree/a55a2c7) and unchanged material from those revisions retain their Apache-2.0 grants. See [NOTICE](NOTICE) and [CONTRIBUTING.md](CONTRIBUTING.md).

新授权的项目内容采用 [GR IV Project Noncommercial Source License 1.0](LICENSE)，商业使用须取得书面许可；这不是 OSI 定义下的开源许可证。截至 [`a55a2c7`](https://github.com/radium-wang/ricoh-gr4-firmware-analysis-and-feature-expansion/tree/a55a2c7) 的旧版本及其保留的未修改内容仍适用原有 Apache-2.0 授权。详见 [NOTICE](NOTICE) 和[贡献指南](CONTRIBUTING.md)。

Camera modifications carry a risk of data loss or malfunction. Results apply only to the documented test setups. No rights to third-party firmware, artwork or trademarks are granted.

改机存在数据丢失或设备故障风险，实测结果仅对应文档记录的环境。项目许可证不授予第三方固件、图稿或商标的使用权。
