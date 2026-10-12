# 最终验收记录

日期: 2026-10-01
仓库: github.com:Cattafish/ApkSignatureKillerEx.git

## 一、自研 detector 闭环（v13 纯净版）
- killer 处理 v13 detector 后 11 行全绿：
  From API / From APK / From SVC / From SigningInfo /
  hasSigningCertificate / From ArchiveInfo / ch4 / ch5 / ch7 / ch9 / Expected[auto]
- SVC 绿：LoadedApk.mResDir/mCodePath/mAppDir 指向 signed.apk，原生 syscall 打开原包
- hasSigningCertificate 绿：IPackageManager 动态代理拦截（期望证书从 signed.apk 提取）

## 二、第三方实战验证：com.sina.syscall
- 项目: android-assembly-signature-verification
       https://github.com/UltraSina/android-assembly-signature-verification/releases/download/apk/app-release.apk
- 检测方式（native 源码公开，全部绕过 Java 层）:
  - 内联汇编 raw syscall 读 /proc/self/maps -> 提取 /base.apk 路径
  - raw syscall openat/read 读 base.apk
  - 手动解析 ZIP（EOCD->CentralDir->LocalHeader->inflate）
  - 找 META-INF/*.RSA -> OpenSSL 解析证书 -> SHA-256 对比硬编码
  - 不匹配 -> quick_exit(0)
- 破解方案:
  - apktool 重打包 + Provider/签名注入
  - 注入原版 META-INF/MANIFEST.MF + CERT.SF + CERT.RSA（三件套）
  - zipalign
  - apksig 官方引擎签 V2-only（保留 V1 文件）
  - 产物签名结构: v1 false（壳，V1 校验失败） + v2 true（有效，免 root 安装）
  - 目标从 maps 路径读到的 base.apk 内 CERT.RSA 为原证书 -> SHA-256 匹配 -> 不自杀
- 结果: 免 root 安装成功，App 正常启动，目标 native 校验通过

## 三、关键文件
- signature-killer/process_apk.py: 主管线
- signature-killer/finalize_sign.py: 注入 V1 三件套 + zipalign + apksig 签名
- signature-killer/KeepV1Signer.java: apksig V2-only + setOtherSignersSignaturesPreserved(true)
- signature-killer/killer/src/main/java/r/s/sign/KillerApplication.java: 三阶段能力
- signature-detector/.../MainActivity.java: v13 检测探针

## 四、签名方案对比
| 方案 | v1 | v2/v3 | 免root | native META-INF |
|---|---|---|---|---|
| apksigner 默认 | 新证书(有效) | 有效 | 装得上 | 读到 fake 证书 -> 校验失败 |
| apksigner V2-only | 无 | 有效 | 装得上 | 无 META-INF -> 校验失败 |
| 自研 v2_sign.py | 保留 | 无效(格式踩坑多轮) | 装不上 | - |
| **finalize_sign.py (最终)** | **原版(校验失败=壳)** | **有效** | **装得上** | **读原证书 -> 通过** |

## 五、经验教训
- native 直读文件（raw syscall + maps）时，Java 层所有 hook 无效
- 让磁盘上的 base.apk 内容自带原版证书，是唯一系统性解法
- apksigner 会删已有 V1 文件；必须用 apksig 引擎 API + setOtherSignersSignaturesPreserved(true)
- V3 也要关掉：原包已有 V3 块，再加新 V3 会冲突，只签 V2

## 三、QQ dexonly 验证（2026-10-01）
- QQ 9.3.70（41 dex / 约 394MB）dexonly 模式构建成功；
- onLoaded 直接读 base.apk 的 META-INF/CERT.RSA，不解包 signed.apk（避免大包启动卡死）；
- finalize_sign 注入原版 V1 三件套 + V2 有效签名；
- 产物可安装（安装后是否通过 QQ 隐蔽检测需实机观察）。

## 四、QQ dexonly 构建成功（2026-10-01）
- QQ 9.3.70（41 dex / ~394MB）dexonly 模式成功构建；
- onLoaded 轻量版直接读 base.apk 的 META-INF/CERT.RSA（不解包 signed.apk）；
- finalize_sign 注入原版 V1 三件套 + V2 有效签名；
- 产物可安装（QQ 检测隐蔽，是否完全通过需实机观测）。

## 五、数据复用优化（dedup，默认关闭）
- workflow 提供 dedup 选项（默认 false）；
- 不再复制 assets/SignedByRS/input.apk 副本（运行时已不需要它）；
- 产物大小 ≈ 原包，而非 2 倍原包；
- 开启 dedup 后 killer 链降级（见 README 风险清单），追求最强过签时禁用。

## 六、V2Block 外部解析探针（2026-10-01）
- detector 新增 From V2Block（正常读，验证 xhook 重定向）与 From V2Block SVC（raw syscall 直读 base.apk，模拟外部 native 直解析 APK Signing Block v2/v3）；
- From V2Block SVC 在 killer 处理后的 APK 上必然红：V2 块内是新证书（免 root 结构性死穴），该探针用于自证方案边界。
## 七、13 行探针闭环（2026-10-01，killer dexonly 非 dedup）
- detector v13.1 处理闭环：11 行添加 From V2Block / From V2Block SVC 后全链路验证；
- 绿（12/13）：From API / From APK / From SVC / From SigningInfo / hasSigningCertificate /
  From ArchiveInfo / From V2Block / ch4 / ch5(HOOKED) / ch7(HOOKED) / ch9 / Expected[auto]；
- 红（1/13，预期）：From V2Block SVC = 0dddcddc…（raw syscall 直读 base.apk V2 块 → fake 证书）；
- 边界结论：xhook 全链（open/stat/maps）与 PmProxy（hasSigningCertificate/getPackageArchiveInfo）
  已覆盖所有用户态路径；raw syscall 解析 V2 块是免 root 架构结构性死角，非代码可修。
