#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包 nmapgui 的 arm64 deb（复用 build_deb.py 的 ar 组装思路，不依赖 dpkg-deb）。"""
import hashlib
import io
import lzma
import os
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
STAGE = os.path.join(ROOT, 'stage')
OUT = os.path.join(os.path.dirname(ROOT), 'nmapgui_1.0.0+kylin1_arm64.deb')

EXEC_FILES = {
    'opt/nmapgui/run.sh',
    'opt/nmapgui/bin/nmapgui',
    'opt/nmapgui/bin/nmap',
    'usr/bin/nmapgui',
}
BIN_EXT = ('.so', '.so.0', '.so.1', '.so.2', '.so.3', '.so.4', '.so.6', '.so.8')


def norm_text(path):
    """把 CRLF 归一成 LF；二进制文件原样返回。"""
    with open(path, 'rb') as f:
        data = f.read()
    if b'\r\n' in data and b'\x00' not in data[:4096]:
        return data.replace(b'\r\n', b'\n')
    return data


def collect(base):
    dirs, files = [], []
    for dp, dn, fn in os.walk(base):
        dn.sort()
        fn.sort()
        rel_dir = os.path.relpath(dp, base).replace(os.sep, '/')
        if rel_dir != '.':
            dirs.append(rel_dir)
        for f in fn:
            files.append(os.path.relpath(os.path.join(dp, f), base).replace(os.sep, '/'))
    return sorted(dirs, key=lambda p: (p.count('/'), p)), sorted(files)


def build_tar(base, arc_prefix='', use_exec=False):
    buf = io.BytesIO()
    now = int(os.environ.get('SOURCE_DATE_EPOCH', int(time.time())))
    dirs, files = collect(base)
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.GNU_FORMAT) as tf:
        rt = tarfile.TarInfo('.')
        rt.type, rt.mode, rt.uid, rt.gid = tarfile.DIRTYPE, 0o755, 0, 0
        rt.uname = rt.gname = 'root'
        rt.mtime = now
        tf.addfile(rt)
        for d in dirs:
            ti = tarfile.TarInfo(d)
            ti.type, ti.mode, ti.uid, ti.gid = tarfile.DIRTYPE, 0o755, 0, 0
            ti.uname = ti.gname = 'root'
            ti.mtime = now
            tf.addfile(ti)
        for rel in files:
            data = norm_text(os.path.join(base, rel))
            ti = tarfile.TarInfo(rel)
            ti.size = len(data)
            ti.mode = 0o755 if (use_exec and rel in EXEC_FILES) else 0o644
            if use_exec and rel == 'usr/share/icons/hicolor/scalable/apps/nmapgui.svg':
                ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = 'root'
            ti.mtime = now
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue(), files


def ar_member(name, payload, mtime):
    hdr = ((name + '/').ljust(16) + str(mtime).ljust(12) + '0'.ljust(6) + '0'.ljust(6)
           + '100644'.ljust(8) + str(len(payload)).ljust(10) + '`\n').encode('ascii')
    out = hdr + payload
    if len(payload) % 2:
        out += b'\n'
    return out


def main():
    ctrl_dir = os.path.join(STAGE, 'DEBIAN')
    # 统计安装体积（KB，向上取整）
    total = 0
    for dp, _, fn in os.walk(STAGE):
        if os.path.relpath(dp, STAGE).replace(os.sep, '/').startswith('DEBIAN'):
            continue
        for f in fn:
            total += os.path.getsize(os.path.join(dp, f))
    size_kb = (total + 1023) // 1024

    # 组装控制目录
    work = os.path.join(ROOT, '_ctrl')
    if os.path.isdir(work):
        import shutil
        shutil.rmtree(work)
    os.makedirs(work)
    with open(os.path.join(ctrl_dir, 'control.in'), 'r', encoding='utf-8') as f:
        control = f.read().replace('@SIZE@', str(size_kb))
    with open(os.path.join(work, 'control'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(control)
    for s in ('postinst', 'postrm'):
        src = os.path.join(ctrl_dir, s)
        if os.path.exists(src):
            with open(os.path.join(work, s), 'wb') as f:
                f.write(norm_text(src))
            os.chmod(os.path.join(work, s), 0o755)

    # md5sums
    dirs, files = collect(STAGE)
    lines = []
    for rel in files:
        if rel.startswith('DEBIAN'):
            continue
        with open(os.path.join(STAGE, rel), 'rb') as f:
            h = hashlib.md5(norm_text(os.path.join(STAGE, rel))).hexdigest()
        lines.append('%s  %s' % (h, rel))
    with open(os.path.join(work, 'md5sums'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')

    print('[*] 安装体积 %d KB, 文件数 %d' % (size_kb, len(files)))

    data_raw = build_data()

    ctrl_raw, _ = build_tar(work)
    now = int(os.environ.get('SOURCE_DATE_EPOCH', int(time.time())))
    blob = (b'!<arch>\n'
            + ar_member('debian-binary', b'2.0\n', now)
            + ar_member('control.tar.xz', lzma.compress(ctrl_raw, preset=6), now)
            + ar_member('data.tar.xz', lzma.compress(data_raw, preset=6), now))
    with open(OUT, 'wb') as f:
        f.write(blob)
    print('[OK] %s  %d 字节' % (OUT, len(blob)))
    return 0


def build_data():
    buf = io.BytesIO()
    now = int(os.environ.get('SOURCE_DATE_EPOCH', int(time.time())))
    dirs, files = collect(STAGE)
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.GNU_FORMAT) as tf:
        rt = tarfile.TarInfo('.')
        rt.type, rt.mode, rt.uid, rt.gid = tarfile.DIRTYPE, 0o755, 0, 0
        rt.uname = rt.gname = 'root'
        rt.mtime = now
        tf.addfile(rt)
        for d in dirs:
            if d == 'DEBIAN' or d.startswith('DEBIAN/'):
                continue
            ti = tarfile.TarInfo(d)
            ti.type, ti.mode, ti.uid, ti.gid = tarfile.DIRTYPE, 0o755, 0, 0
            ti.uname = ti.gname = 'root'
            ti.mtime = now
            tf.addfile(ti)
        for rel in files:
            if rel.startswith('DEBIAN'):
                continue
            data = norm_text(os.path.join(STAGE, rel))
            ti = tarfile.TarInfo(rel)
            ti.size = len(data)
            ti.mode = 0o755 if rel in EXEC_FILES else 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = 'root'
            ti.mtime = now
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


if __name__ == '__main__':
    sys.exit(main())
