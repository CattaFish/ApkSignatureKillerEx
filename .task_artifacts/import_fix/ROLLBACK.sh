#!/usr/bin/env bash
set -euo pipefail
cd ~/app/ApkSignatureKillerEx
git checkout -- signature-killer/finalize_sign.py
python3 -m py_compile signature-killer/finalize_sign.py
echo ROLLBACK_OK
