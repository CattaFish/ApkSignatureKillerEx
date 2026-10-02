# ApkSignatureKillerEx

两个独立项目：

- `signature-detector/` — 签名检测 APK（自研 13 项探针，验证去签效果）
- `signature-killer/` — 去签处理工具（输入 APK → 处理 → 输出 APK）

构建与产物下载均通过 GitHub Actions 完成，详见各项目 README。

## 去签能力总览

### 三层能力（全部自研，无 ART hook、无 Xposed、无外部框架）

| 层 | 能力 | 原理 |
|---|---|---|
| Java API | PackageInfo 签名深度替换（signatures/signingInfo history/mSigningDetails） | `PackageInfo.CREATOR` 反射替换 |
| | `hasSigningCertificate` 返回 true | `IPackageManager` 动态代理 |
| 路径层 | `getPackageResourcePath/CodePath` 指向原包 | `LoadedApk.mResDir/mCodePath/mAppDir` + `ApplicationInfo` 全字段改写 |
| Native 兜底 | open/stat/fopen 等 libc 调用重定向 | xhook GOT hook + maps/stat 清洗 + dlopen 后自动刷新 |

## 最终签名方案（v2.0：MT 式数据复用 + 不重排双阶段签名）

### 为什么

- native 直读 `base.apk` 的检测（raw syscall + `/proc/self/maps` + 手动 ZIP 解析 + `META-INF/*.RSA` 比对）要求**磁盘上的 base.apk 自带原证书**；
- 免 root 安装要求 **V2 签名真实有效**；
- 直接把原包塞进资产（旧版全量副本）会让产物体积 ≈ 2× 原包。

### 产物结构

```
产物 APK
├── assets/SignedByRS/input.apk   ← 原包完整副本（STORE 存储，不压缩）
├── lib/<abi>/libSignedByRS.so    ← killer native（新增）
├── classes2.dex                  ← killer dex（新增）
├── classes.dex                   ← 修改（注入 Activity <clinit>）
├── res/**, assets/**, ...        ← 与原包相同的文件：
│     中央目录数据偏移直接指向 input.apk 内部数据段，物理不重复
└── META-INF/MANIFEST.MF + CERT.SF + CERT.RSA
     ← 原版 V1 三件套（v1 校验失败=壳；native 直读 META-INF 拿到原证书）
```

体积实测（com.sina.syscall 原包 11MB）：23MB → **13MB**（-46%），killer 能力不降级。

### 签名流程（关键）

```
apksig（KeepV1Signer）签有效 V2（保留 V1 壳）
        ↓
data_multiplexing.py   ← MT 式数据复用（必须 STORE + 字节保留）
        ↓
v2_sign.py             ← 不重排结构 V2 重签（apksig 会重排导致复用失效，必须自研）
        ↓
apksigner verify --min-sdk-version 24   ← 真实验签，失败即中止
```

**为什么复用后不能用 apksig 直接签**：apksig 签名时会重排 ZIP entry 偏移，导致 MT 式复用（跨条目共享数据段）失效、体积膨胀回去。因此必须在复用后做**不重排 V2 重签**。

`v2_sign.py` 严格按 apksig 源码实现：

- v2 block：`value = LP(LP(signer))`，pair size = 4 + len(value)，block size = len(pairs) + 24；
- signer：`LP(signed_data) + LP(signatures) + LP(public_key)`；
- digests / signatures：`LP(LP(alg_id + LP(data)))`；
- chunked digest：内容区 / CentralDir / EOCD 三区**独立 1MB 切块**；
  块摘要 = `SHA256(0xA5 + uint32块长LE + 块内容)`；
  顶级摘要 = `SHA256(0x5A + uint32块数LE + 全部块摘要串联)`；
- EOCD 参与摘要时 cd_offset 字段视为"APK 签名分块起始偏移"（保持原值）。

每一步都有自检，失败会保留 `.debug` 调试产物（workflow 自动上传）。

## 数据复用优化（dedup，默认开启）

workflow 的「数据复用优化」**默认勾选**。

- 原理（MT 管理器同款）：ZIP 中央目录允许不同条目指向同一数据段 → 产物中与原包完全相同的文件（文件名/压缩方式/CRC/压缩大小/压缩字节全一致）直接指向 `assets/SignedByRS/input.apk` 内部对应偏移，删除产物中的重复数据段；
- 最大节省 50%（原包体积），实测约 -46%；
- **能力不降级**：input.apk 完整保留，运行时 `OriginApkCache.prepare()` 解出的 `signed.apk` 仍是原包字节，xhook / 路径重定向 / 签名替换全链可用；
- 关闭 dedup 则产物为完整副本（≈2× 原包），兼容性最好但体积大。

## dexonly 模式（大包/资源混淆）

入口：workflow 的 mode 选 `dexonly`（默认）。

- 不解码/重编资源，不动 AndroidManifest；
- 直接在目标 Activity 的 `<clinit>` 第一条指令插入 `KillerApplication.onLoaded()`（manifest 零改动）；
- 重打包基于原包字节增量构建：未修改 entry 原段拷贝（压缩字节不变，保证复用命中），只替换 patched dex、追加 killer dex/lib、追加 input.apk；
- 适合 QQ/微信类资源混淆大包。

## 使用方式（GitHub Actions）

1. 把要处理的 APK 传到 Release，例如：
   `https://github.com/<owner>/<repo>/releases/download/<tag>/app.apk`
2. Actions → **Build Signature Killer** → **Run workflow** → 粘贴 `apk_url`；
3. 「数据复用优化」默认勾选（MT 式复用），保持默认即可；
4. 下载 `processed-apk`（`work_out/processed_*.apk`）。

push 触发时只构建并上传 `killer-aar`；`workflow_dispatch` 时执行完整流程。

## 已知限制

- `hasSigningCertificate`：仅自研 IPackageManager 代理覆盖，不适用于直接读系统侧签名的极端场景；
- 目标若校验磁盘 base.apk 的完整字节摘要（而非仅证书），现有方案无法覆盖；
- `From V2Block SVC`（detector 红线）：raw syscall 直读 base.apk 的 APK Signing Block v2，读到的是新证书，必然红 —— 免 root 架构结构性死穴；
- 外部重签后 `From API` / `From SigningInfo` 会露馅，除非保留原版 V1 三件套；`onLoaded()` 已内置从 `signed.apk` 刷新预期证书的逻辑；
- 仅 Android 7.0+ 且系统支持 V2 签名验证的设备上免 root 安装成立；
- 复用优化要求原包以 STORE 打包、中央目录共享数据段；对优化包二次签名/增删文件大概率失效，需重新跑 pipeline。
