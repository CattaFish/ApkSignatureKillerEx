#!/usr/bin/env bash
set -euo pipefail
cd ~/app/ApkSignatureKillerEx
git checkout -- signature-killer/killer/src/main/c/sigbypass_core.c \
  signature-detector/app/src/main/java/r/s/test/MainActivity.java
python3 -c "s=open('signature-killer/killer/src/main/c/sigbypass_core.c', encoding='utf-8').read(); assert s.count('{')==s.count('}')"
python3 -c "s=open('signature-detector/app/src/main/java/r/s/test/MainActivity.java', encoding='utf-8').read(); assert s.count('{')==s.count('}')"
echo ROLLBACK_OK
