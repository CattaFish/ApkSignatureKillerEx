# Signature Killer

输入 APK → 注入签名旁路 → 输出已处理 APK。

## 使用方式（GitHub Actions）

1. 把要处理的 APK 上传到本仓库 Release，例如：
   `https://github.com/<owner>/<repo>/releases/download/<tag>/app.apk`
2. Actions → **Build Signature Killer** → **Run workflow** → 把直链粘贴到 `apk_url`。
3. 下载 `processed-apk` artifact（`work_out/processed_*.apk`）。

push 触发时只构建并上传 `killer-aar`，不处理 APK；`workflow_dispatch` 时执行完整流程。

## 原理

- `KillerProvider`（ContentProvider）在进程启动早期执行 `KillerApplication.init`：
  - 从 `assets/SignedByRS/input.apk` 解包出替换文件 `signed.apk` 到 dataDir；
  - killPM：经 `PackageInfo.CREATOR` 注入把签名替换成 input.apk 的签名；
  - killOpen：xhook 重定向 open/fopen/stat/access/readlink/realpath/statx 路径族到 `signed.apk`。
- `dlopen` / `android_dlopen_ext` 被 hook，任何 .so 新加载后自动同步刷新 hook，
  覆盖目标 app 启动后 `loadLibrary` 的检测库。
- pipeline 会把输入 APK 的签名 MD5 写入 `MainActivity.smali` 的 `signatureExpected`，
  保证红蓝判断与输入 APK 动态匹配。

## dedup 警告

workflow 的「数据复用优化」默认关闭。开启后 `assets/SignedByRS/input.apk` 会被移除，
`KillerApplication.init()` 依赖它解包出 `signed.apk`；一旦开启，killOpen（xhook）、
redirectApkPaths（路径重定向）、killPM、PmProxy 全链失效，开启会新增多处无法过签的场景。

## 输入要求

- 任何可被 apktool 正常解包的 APK；
- 目标 app 的 `Application` 不需要有 `onCreate`（Provider 入口不依赖它）。
