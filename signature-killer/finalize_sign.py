#!/usr/bin/env python3
"""Final signing stage: inject original V1 trio -> zipalign -> apksig V2-only (preserve V1)."""
import argparse, base64, hashlib, os, re, shutil, struct, subprocess, sys, tempfile, zipfile

KEY_DIR = "work_killer"

def run(cmd):
    print("+", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-3000:])
        print(r.stderr[-3000:])
        sys.exit(f"FAIL: {cmd[0]}")
    return r

def find_zipalign():
    h = os.environ.get("ANDROID_HOME", "")
    if h:
        bt = os.path.join(h, "build-tools")
        if os.path.isdir(bt):
            for v in sorted(os.listdir(bt), reverse=True):
                p = os.path.join(bt, v, "zipalign")
                if os.path.isfile(p): return p
    return shutil.which("zipalign")

def find_apksig_jar():
    candidates = []
    h = os.environ.get("ANDROID_HOME", "")
    if h:
        bt = os.path.join(h, "build-tools")
        if os.path.isdir(bt):
            for v in sorted(os.listdir(bt), reverse=True):
                candidates.append(os.path.join(bt, v, "lib", "apksigner.jar"))
    candidates.append("/data/data/com.termux/files/usr/share/java/apksigner.jar")
    for c in candidates:
        if os.path.isfile(c): return c
    return None

def ensure_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    key = os.path.join(KEY_DIR, "v2_key.pem")
    cert_pem = os.path.join(KEY_DIR, "v2_cert.pem")
    cert_der = os.path.join(KEY_DIR, "v2_cert.der")
    pk8 = os.path.join(KEY_DIR, "v2_key_pk8.der")
    if not (os.path.isfile(key) and os.path.isfile(cert_pem) and os.path.isfile(cert_der) and os.path.isfile(pk8)):
        run(["openssl", "genrsa", "-out", key, "2048"])
        run(["openssl", "req", "-new", "-x509", "-key", key, "-out", cert_pem,
             "-days", "10950", "-subj", "/CN=K"])
        run(["openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert_der])
        run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", key,
             "-outform", "DER", "-out", pk8])
    return key, pk8, cert_der

def inject_v1(input_apk, orig_apk):
    """Copy original META-INF/MANIFEST.MF, CERT.SF, CERT.RSA into unsigned APK."""
    with zipfile.ZipFile(orig_apk) as z:
        trio = {}
        for n in z.namelist():
            if re.match(r"META-INF/(MANIFEST\.MF|CERT\.SF|CERT\.RSA)$", n, re.I):
                trio[n] = z.read(n)
        if not trio:
            print("[warn] original has no V1 trio")
            return
    tmp = input_apk + ".tmp"
    with zipfile.ZipFile(input_apk, "r") as zin, zipfile.ZipFile(tmp, "w") as zout:
        for it in zin.infolist():
            if re.match(r"META-INF/(MANIFEST\.MF|CERT\.SF|CERT\.RSA)$", it.filename, re.I):
                continue
            zout.writestr(it, zin.read(it.filename))
        for name, data in trio.items():
            zi = zipfile.ZipInfo(name)
            zi.external_attr = 0o644 << 16
            zout.writestr(zi, data)
    os.replace(tmp, input_apk)
    print("[ok] V1 trio injected:", list(trio.keys()))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--orig", required=True)
    a = ap.parse_args()

    zipalign = find_zipalign()
    if not zipalign:
        sys.exit("zipalign not found")
    apksig_jar = find_apksig_jar()
    if not apksig_jar:
        sys.exit("apksig jar not found")

    inject_v1(a.input, a.orig)

    aligned = a.input + ".aligned"
    run([zipalign, "-f", "4", a.input, aligned])

    key, pk8, cert_der = ensure_keys()

    # compile KeepV1Signer
    src_dir = os.path.dirname(os.path.abspath(__file__))
    classes_dir = os.path.join(KEY_DIR, "classes")
    os.makedirs(classes_dir, exist_ok=True)
    java_src = os.path.join(src_dir, "KeepV1Signer.java")
    run(["javac", "-cp", apksig_jar, "-d", classes_dir, java_src])

    run(["java", "-cp", apksig_jar + os.pathsep + classes_dir,
         "KeepV1Signer", aligned, a.output, pk8, cert_der])
    print("[ok] final signed (V2 valid, V1 preserved)")


