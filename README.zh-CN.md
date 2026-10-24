# UniXNU-lemonades（简体中文）

**在 OnePlus 9R（`lemonades`，SM8250-AC / 骁龙870）上运行 UniXNU。**

本仓库派生自 [reAAAq 的小米10（umi）移植](https://github.com/reAAAq/UniXNU-umi)
（第 80 次尝试：iPadOS 17.7.11 已在同为 SM8250 平台的硬件上进入设置助手且触摸可用）。
OnePlus 9R 使用完全相同的 kona 硅片、完全相同的 DRAM 分条映射和完全相同的 XBL
"UEFI FD" 加载区域，因此本移植直接复用 umi 的板级描述、内核配置、ADT 生成器和
设备包，仅保留 9R 特有的差异。**目前所有内容都尚未在真机上验证。**

## 仓库结构

| 仓库 | 内容 |
| --- | --- |
| `UniXNU-lemonades`（本仓库） | 板级描述、内核 defconfig、ADT 生成器、设备包、bring-up 工具 |
| `uefi-lemonades` | Mu-Silicium UEFI 移植：`Platforms/OnePlus/lemonadesPkg`、继承式帧缓冲 GOP、PON/TLMM 按键、RAM FAT 载荷 |

两者与 [UniXNU](https://github.com/UniXNU/UniXNU) 和
[UniXNU-sheng](https://github.com/UniXNU/UniXNU-sheng) 并列克隆，
提交锁定见 `source-lock.json`。

## 与 umi（小米10）的硬件差异

| 项目 | umi | lemonades（OnePlus 9R） |
| --- | --- | --- |
| SoC | SM8250 | SM8250-AC（骁龙870），kona MMIO 相同，PSCI `0,0x100..0x700` |
| DRAM 分条 | 0x39900000@0x80000000、0x140000000@0xc0000000、0x180000000@0x200000000 | 完全相同（合计 0x2f9900000） |
| UEFI FD 区域 | 0x9fc00000 + 0x300000 | 相同（xbl uefiplat.cfg） |
| TZApps / PIL 保留区 | 0x82400000+0x3a00000 / 0x86000000+0xd200000 | 0x82400000+0x0B400000 / 0x8DA00000+0x0AD00000 |
| 帧缓冲（继承式） | 0x9c000000 1080x2340 | 0x9c000000 1080x2400（三星 AMB655X，DSC 命令模式） |
| 音量键 | PON bit1 / PMIC GPIO6 | TLMM GPIO 7 / GPIO 6（SOUTH tile，低电平有效） |
| UFS 主控 / ICE | 0x1d84000 / 0x1d90000 | 相同 |
| GIC / 定时器 | GICD 0x17a00000、GICR 0x17a60000、19.2 MHz | 相同 |
| 触摸 | ST FTM5（umi 第80次尝试已可用） | **Synaptics S3908**——需要另写驱动，尚未开始 |
| 启动镜像 | header v1，`fastboot boot` 可用 | **header v2，无 vendor_boot，ABL 拒绝 `fastboot boot`** |
| 引导方式 | `fastboot boot boot.img` | 刷写 `boot_b`（保留 `backups/boot_b.img` 用于还原） |
| ramoops 控制台 | 0xB0000000 | 相同 |
| 供体 IPSW | iPad7,1 iPadOS 17.7.11（21H461） | 相同 |

## Bring-up 顺序

1. **真机上的 UEFI 菜单。** 在 Linux 上构建固件和启动镜像（见 `docs/BUILD.md`），
   刷入 `boot_b`，在继承的开机画面上观察 UniXNU 菜单，音量键选择、电源键确认。
   0xB0000000 的 ramoops 控制台记录 UEFI 日志，可通过 recovery adb 读取。
2. **载荷阶段。** RAM FAT 载荷、`unixnu.toml`、`PayloadCheck` 入口。
3. **内核入口。** 源码构建的 XNU（macOS 或 GitHub Actions runner），配合
   `lemonades_defconfig`；平台专家对生成的 ADT。
4. **存储与根文件系统。** 原生 UFS（与 umi 同主控），然后 iPadOS 供体的
   OS / SystemOS 窗口，然后 launchd。需要先测量 `userdata` 的 LBA
   （`scripts/measure-userdata-gpt.sh`）。
5. **触摸与后续。** Synaptics S3908 驱动（见 `package/touch/README.lemonades`），
   然后 Wi-Fi、音频、GPU（Adreno 650），对照 umi 的尝试历史逐项补齐。

## 刷机安全

本机的 OnePlus ABL 不支持 `fastboot boot`；每次测试都要刷写 `boot_b` 并重启。
务必备份原厂镜像：

```sh
# 还原（来自 stage-0 备份 ~/ROm/hw/9r/backups，已做 SHA256 校验）
fastboot flash boot_b backups/boot_b.img
```

`recovery_b` 中已刷入 OrangeFox R12.0 OPKONA V34，可提供 root adb 读取
ramoops 控制台（`/sys/fs/pstore`）和分区测量。安装 iOS 载荷会替换
`userdata` 分区内容。

## 状态

- [x] 板级描述、defconfig、ADT 生成器、设备包骨架（派生自 umi）
- [x] `uefi-lemonades` 平台骨架（派生自 umiPkg attempt-15 基线）
- [x] 从原厂 `boot_b` 提取的 kona v2.1 DTB
- [ ] Linux 上的 `unixnu build firmware`（工具链见 `docs/BUILD.md`）
- [ ] 真机阶段 1-2：继承式帧缓冲下的 UEFI 菜单
- [ ] 阶段 3-7：内核、存储、用户态、触摸
