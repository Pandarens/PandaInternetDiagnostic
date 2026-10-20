"""Build release files into dist/:
  PandaInternetDiagnostic.exe   one-file exe (no console, asks for administrator rights)
  panda_diag-<ver>.zip          application code (hot-update bundle; also embedded into the exe)
  update.json                   versions + SHA-256 for the in-app updater

  python build.py            # needs: pip install pyinstaller
  python build.py --zip-only # only the code bundle + update.json (code-only release)
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
BUILD = os.path.join(ROOT, "build")
EXE_NAME = "PandaInternetDiagnostic"


def read_version(path, name):
    with open(path, encoding="utf-8") as f:
        return re.search(rf'{name}\s*=\s*"([^"]+)"', f.read()).group(1)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def make_bundle(version):
    out = os.path.join(DIST, f"panda_diag-{version}.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for dp, dirs, files in os.walk(os.path.join(ROOT, "panda_diag")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in sorted(files):
                if f.endswith((".pyc", ".pyo")):
                    continue
                full = os.path.join(dp, f)
                z.write(full, os.path.relpath(full, ROOT).replace(os.sep, "/"))
    return out


def version_file(version):
    nums = (list(map(int, re.findall(r"\d+", version))) + [0, 0, 0, 0])[:4]
    path = os.path.join(BUILD, "version_info.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tuple(nums)}, prodvers={tuple(nums)}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('041904B0', [
    StringStruct('CompanyName', 'Pandarens'),
    StringStruct('FileDescription', 'Panda Internet Diagnostic — диагностика интернета'),
    StringStruct('FileVersion', '{version}'),
    StringStruct('InternalName', '{EXE_NAME}'),
    StringStruct('OriginalFilename', '{EXE_NAME}.exe'),
    StringStruct('ProductName', 'Panda Internet Diagnostic'),
    StringStruct('ProductVersion', '{version}')])]),
  VarFileInfo([VarStruct('Translation', [1049, 1200])])])
""")
    return path


def build_exe(bundle, version):
    embedded = os.path.join(BUILD, "panda_diag.zip")
    shutil.copyfile(bundle, embedded)
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--noconsole", "--uac-admin",
            "--name", EXE_NAME, "--icon", os.path.join(ROOT, "panda_diag", "web", "icon.ico"),
            "--version-file", version_file(version),
            "--add-data", f"{embedded}{os.pathsep}.",
            "--distpath", DIST, "--workpath", os.path.join(BUILD, "pyi"), "--specpath", BUILD,
            # the app is loaded from the zip at runtime; keep PyInstaller from freezing a second copy
            "--exclude-module", "panda_diag",
            "--exclude-module", "tkinter", "--exclude-module", "unittest", "--exclude-module", "pydoc",
            "--exclude-module", "lib2to3", "--exclude-module", "test",
            os.path.join(ROOT, "launcher.py")]
    subprocess.check_call(args, cwd=ROOT)
    return os.path.join(DIST, EXE_NAME + ".exe")


def main():
    zip_only = "--zip-only" in sys.argv
    version = read_version(os.path.join(ROOT, "panda_diag", "__init__.py"), "__version__")
    min_launcher = read_version(os.path.join(ROOT, "panda_diag", "__init__.py"), "MIN_LAUNCHER")
    launcher_version = read_version(os.path.join(ROOT, "launcher.py"), "LAUNCHER_VERSION")
    shutil.rmtree(DIST, ignore_errors=True)
    os.makedirs(DIST)
    os.makedirs(BUILD, exist_ok=True)
    bundle = make_bundle(version)
    manifest = {"version": version, "min_launcher": min_launcher,
                "bundle": {"name": os.path.basename(bundle), "sha256": sha256(bundle)}}
    notes = os.path.join(ROOT, "CHANGELOG.md")
    if os.path.exists(notes):
        with open(notes, encoding="utf-8") as f:
            m = re.search(rf"##\s*v?{re.escape(version)}\s*\n(.*?)(?=\n##\s|\Z)", f.read(), re.S)
            manifest["notes"] = m.group(1).strip() if m else ""
    if not zip_only:
        exe = build_exe(bundle, version)
        manifest["exe"] = {"name": os.path.basename(exe), "sha256": sha256(exe), "launcher_version": launcher_version}
    with open(os.path.join(DIST, "update.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    for name in sorted(os.listdir(DIST)):
        p = os.path.join(DIST, name)
        if os.path.isfile(p):
            print(f"{name:<36} {os.path.getsize(p) / 1e6:6.2f} MB")


if __name__ == "__main__":
    main()
