# Signature Detector

签名检测演示 APK。

## 构建方式（GitHub Actions）

- 推送到 `main` 自动触发 `Build Signature Detector APK`；
- 产物：Actions 页下载 `detector-apk`（`app-debug.apk`）。

## 各检测行含义

| 行 | 原理 | 被 killer 处理后 |
|---|---|---|
| From API | `PackageManager.GET_SIGNATURES` | 显示内嵌 input.apk 的签名（蓝） |
| From APK | 直接读 APK 内 META-INF 证书 | open 重定向到替换 APK（蓝） |
| From SVC | 原始 syscall 读文件，绕过用户态 hook | 显示 fake.jks 真签名（红） |
| ch4 | native fopen 读证书 | PASS（蓝） |
| ch5 | stat normal vs raw syscall inode | HOOKED（蓝） |
| ch7 | maps 敏感词 + APK inode 一致性 | HOOKED（蓝） |
| ch9 | maps 中敏感 .so 列表 | PASS（蓝） |

## 本地构建

```bash
cd signature-detector
./gradlew :app:assembleDebug
```
