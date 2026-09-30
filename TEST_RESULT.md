# 验收记录 2026-10-01

## 版本
- detector: v12-20260930（含实验路径改写+PMS代理）
- killer: 含三阶段全部能力（deep sig replace + path redirect + PMS proxy + xhook）

## 测试输入
- v12 detector APK，签名 1fb11e...（origin.jks）
- killer workflow 处理产物

## 结果（11/11 蓝）
From API / From APK / From SVC / From SigningInfo / hasSigningCertificate /
From ArchiveInfo / ch4 / ch5 / ch7 / ch9 / Expected[auto]

## 关键日志
- LoadedApk.mResDir -> /data/user/0/r.s.sign/signed.apk
- PmProxy: hasSigningCertificate -> true
