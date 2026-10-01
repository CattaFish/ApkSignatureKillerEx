# ApkSignatureKillerEx

两个独立项目：

- `signature-detector/` — 签名检测 APK（自研 11 项探针，验证去签效果）
- `signature-killer/` — 去签处理工具（输入 APK → 处理 → 输出 APK）

构建与产物下载均通过 GitHub Actions 完成，详见各项目 README。

## 去签能力总览

### 三层能力（全部自研，无 ART hook、无 Xposed、无外部框架）

| 层 | 能力 | 原理 |
|---|---|---|
| Java API | PackageInfo 签名深度替换（signatures/signingInfo history/mSigningDetails） | `PackageInfo.CREATOR` 反射替换 |
| | `hasSigningCertificate` 返回 true | `IPackageManager` 动态代理 |
| 路径层 | `getPackageResourcePath/CodePath` 指向原包 | `LoadedApk.mResDir/mCodePath/mAppDir` + `ApplicationInfo` 全字段改写 |
| Native 兜底 | open/stat/fopen 等 libc 调用重定向 | xhook GOT hook + maps/stat 清洗 |

### 最终签名方案（关键突破）

针对 native 直读 `base.apk` 的检测（raw syscall + `/proc/self/maps` 提取路径 + 手动 ZIP 解析 + `META-INF/*.RSA` 证书比对）：

```
重打包 → 注入原版 META-INF/MANIFEST.MF + CERT.SF + CERT.RSA
       → zipalign
       → apksig 官方引擎签 V2-only（保留 V1 文件）
产物: v1 false（壳，校验失败）+ v2 true（有效，免 root 安装）
目标从磁盘 base.apk 读到原证书 → 校验通过
```

实现文件：
- `signature-killer/finalize_sign.py` — 注入三件套 + zipalign + 签名
- `signature-killer/KeepV1Signer.java` — apksig V2-only + `setOtherSignersSignaturesPreserved(true)`

### 检测工具（signature-detector）

11 行探针：From API / From APK / From SVC / From SigningInfo /
hasSigningCertificate / From ArchiveInfo / ch4（native fopen）/
ch5（stat norm/raw）/ ch7（maps 敏感词+inode）/ ch9（.so 敏感词）/ Expected[auto]

killer 处理后 11 行全绿（含 SVC + hasSigningCertificate）。

## 使用方式（GitHub Actions）

1. 把要处理的 APK 传到 Release，例如：
   `https://github.com/<owner>/<repo>/releases/download/<tag>/app.apk`
2. Actions → **Build Signature Killer** → **Run workflow** → 粘贴 `apk_url`。
3. 下载 `processed-apk`（`work_out/processed_*.apk`）。

push 触发时只构建并上传 `killer-aar`；`workflow_dispatch` 时执行完整流程。

## 验证记录

详见 `TEST_RESULT.md`。要点：

- 自研 detector 处理闭环 11/11 全绿；
- 第三方目标 `com.sina.syscall`（native raw syscall + maps + META-INF 检测）免 root 安装后正常启动；
- 最终签名结构：`v1: false`（壳）、`v2: true`（有效）。

## 已知限制

- `hasSigningCertificate`：仅自研 IPackageManager 代理覆盖，不适用于直接读系统侧签名的极端场景；
- 目标若校验磁盘 base.apk 的完整字节摘要（而非仅证书），现有方案无法覆盖；
- 仅 Android 7.0+ 且系统支持 V2 签名验证的设备上免 root 安装成立。

## dexonly 模式（大包/资源混淆）

入口：workflow 的 mode 选 `dexonly`（默认）。

- 不解码/重编资源，不动 AndroidManifest；
- 直接在目标 Application 的 `<clinit>` 第一条指令插入 `KillerApplication.onLoaded()`（manifest 零改动）；
- 重打包时追加 killer dex；
- finalize_sign 把原版 META-INF/CERT.RSA/SF/MF 注入 + V2 有效签名；
- 适合 QQ/微信类资源混淆大包。

## 数据复用优化（dedup，默认关闭）

- workflow 的「数据复用优化」默认**不勾选**，追求最强过签请保持关闭；
- 开启后会跳过 `assets/SignedByRS/input.apk` 副本，产物与原始 APK 相当，但 killer 能力降级；
- **开启 dedup 后会新增以下无法过签的场景**：
  - `init()` 全链失效：`OriginApkCache.prepare()` 因 assets 里没有 input.apk 返回 null，`killOpen`（xhook 路径重定向）、`redirectApkPaths`（LoadedApk 路径改写）、`killPM`（签名替换）、`installPmProxy`（hasSigningCertificate 代理）全部提前 return；
  - native 直读失效：目标用 raw syscall 读 `/proc/self/maps` + base.apk 路径时，无 xhook 可重定向到 signed.apk，也没有 maps/stat 清洗兜底；
  - SVC 类检测退化：原始 syscall 读到的内容与正常路径不再一致，stat 无 hook 痕迹可隐藏；
  - 期望证书来源变弱：只能从 base.apk 的 META-INF 壳读取，壳注入失败时会回落到 v2/v3 block 的 fake 证书，`hasSigningCertificate` 判断颠倒；
  - 产物体积收益：默认产物 ≈ 2 倍原包（含 input.apk 副本），仅体积敏感时才开 dedup。
