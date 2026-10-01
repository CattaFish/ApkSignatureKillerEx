#!/usr/bin/env bash
set -euo pipefail
cd ~/app/ApkSignatureKillerEx
git checkout -- signature-killer/killer/src/main/c/sigbypass_core.c \
  signature-killer/killer/src/main/java/r/s/sign/KillerApplication.java \
  signature-detector/app/src/main/java/r/s/test/MainActivity.java
echo ROLLBACK_OK
