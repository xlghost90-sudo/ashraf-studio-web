#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║      Ashraf Studio — Web Edition                             ║
║      Sunplus Firmware Editor (1506 + Vanilla)                ║
║      Developed by: Ashraf Bedair                             ║
║      © 2025 Ashraf Bedair — All Rights Reserved              ║
╚══════════════════════════════════════════════════════════════╝
"""

from flask import Flask, render_template, request, send_file, jsonify
import io
import os
import hashlib
import zlib
import time
import logging

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB

logging.basicConfig(level=logging.INFO)


# ==============================================================
# دوال مساعدة
# ==============================================================
def to_hex_str(data):
    return " ".join("{:02X}".format(b) for b in data)


def hashes_of(data):
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
        "CRC32": "{:08X}".format(zlib.crc32(data) & 0xFFFFFFFF),
    }


# ==============================================================
# CRC-32/MPEG-2
# ==============================================================
def crc32_mpeg2(data):
    """poly=0x04C11DB7, init=0xFFFFFFFF, no reflect, xorout=0"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= (byte << 24) & 0xFFFFFFFF
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc & 0xFFFFFFFF


def fix_sphe_crc(data):
    """يعيد حساب CRC-32/MPEG-2 ويحطه في مكانه."""
    sphe = data.find(b"SPHE")
    if sphe == -1:
        return None
    crc_pos = sphe + 0xFC
    if crc_pos + 4 > len(data):
        return None
    old_crc = int.from_bytes(data[crc_pos:crc_pos + 4], "little")
    block = data[sphe:sphe + 0xFC]
    new_crc = crc32_mpeg2(block)
    data[crc_pos:crc_pos + 4] = new_crc.to_bytes(4, "little")
    return (new_crc, old_crc, sphe)


# ==============================================================
# البصمات
# ==============================================================
BIN0S_SIG = b"BIN_0S"
BIN0S_ID_OFFSET = 0x09
SPHE_SIG = b"SPHE"
SPHE_ID_OFFSET = 0x17
VANILLA_ID_LENGTH = 5


def find_signature(data):
    """يبحث عن أول بصمة معروفة."""
    for name, sig, off in [
        ("BIN_0S", BIN0S_SIG, BIN0S_ID_OFFSET),
        ("SPHE",   SPHE_SIG,   SPHE_ID_OFFSET),
    ]:
        pos = data.find(sig)
        if pos != -1:
            return (name, pos, off)
    return None


# ==============================================================
# Routes
# ==============================================================
@app.route('/')
def index():
    return render_template('index.html')


# ==============================================================
# فحص ملف
# ==============================================================
@app.route('/api/inspect', methods=['POST'])
def api_inspect():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "لا يوجد ملف"}), 400

        f = request.files['file']
        if not f.filename:
            return jsonify({"error": "اسم الملف فارغ"}), 400

        data = bytearray(f.read())
        size = len(data)

        sig = find_signature(data)
        sig_name = "—"
        sig_off_hex = "—"
        id_off_hex = "—"
        id_val = "—"
        crc_val = "—"

        if sig:
            sig_name, pos, off = sig
            id_start = pos + off
            if id_start + VANILLA_ID_LENGTH <= size:
                id_val = to_hex_str(data[id_start:id_start + VANILLA_ID_LENGTH])
            sig_off_hex = "0x{:08X}".format(pos)
            id_off_hex = "0x{:08X}".format(id_start)

        sphe = data.find(SPHE_SIG)
        if sphe != -1 and sphe + 0xFC + 4 <= size:
            crc_val = "0x{:08X}".format(
                int.from_bytes(data[sphe + 0xFC:sphe + 0xFC + 4], "little"))

        header_hex = to_hex_str(data[:16])
        hashes = hashes_of(bytes(data))

        return jsonify({
            "ok": True,
            "size": size,
            "size_mb": round(size / (1024.0 * 1024.0), 2),
            "signature": sig_name,
            "signature_offset": sig_off_hex,
            "id_offset": id_off_hex,
            "id_value": id_val,
            "crc_value": crc_val,
            "header": header_hex,
            "hashes": hashes,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================
# معالجة Vanilla (تلقائي)
# ==============================================================
@app.route('/api/process-vanilla', methods=['POST'])
def api_process_vanilla():
    t_start = time.time()
    try:
        if 'original' not in request.files or 'target' not in request.files:
            return jsonify({"error": "الرجاء رفع السوفتين"}), 400

        orig_file = request.files['original']
        target_file = request.files['target']

        if not orig_file.filename or not target_file.filename:
            return jsonify({"error": "الرجاء اختيار السوفتين"}), 400

        orig_data = bytearray(orig_file.read())
        target_data = bytearray(target_file.read())

        orig_sig = find_signature(orig_data)
        target_sig = find_signature(target_data)

        if not orig_sig:
            return jsonify({
                "error": "لم يتم العثور على بصمة معروفة في السوفت الأصلي (BIN_0S أو SPHE)"
            }), 400
        if not target_sig:
            return jsonify({
                "error": "لم يتم العثور على بصمة معروفة في السوفت الهدف (BIN_0S أو SPHE)"
            }), 400

        orig_name, orig_pos, orig_off = orig_sig
        target_name, target_pos, target_off = target_sig

        id_len = VANILLA_ID_LENGTH
        orig_id_start = orig_pos + orig_off
        target_id_start = target_pos + target_off

        if orig_id_start + id_len > len(orig_data):
            return jsonify({"error": "الآيدي خارج نطاق الأصلي"}), 400
        if target_id_start + id_len > len(target_data):
            return jsonify({"error": "الآيدي خارج نطاق الهدف"}), 400

        old_id = bytes(target_data[target_id_start:target_id_start + id_len])
        new_id = bytes(orig_data[orig_id_start:orig_id_start + id_len])

        target_data[target_id_start:target_id_start + id_len] = new_id

        crc_info = "None"
        crc_result = fix_sphe_crc(target_data)
        if crc_result:
            new_crc, old_crc, sphe = crc_result
            # مهم: نستخدم -> بدل → لتجنب مشاكل HTTP Headers
            crc_info = "0x{:08X} -> 0x{:08X}".format(old_crc, new_crc)

        output = io.BytesIO(bytes(target_data))
        output.seek(0)

        filename = "Modified_Vanilla_" + target_file.filename

        response = send_file(
            output,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )

        # كل القيم ASCII-safe
        response.headers['X-Sig-Original'] = orig_name
        response.headers['X-Sig-Target'] = target_name
        response.headers['X-Old-ID'] = old_id.hex().upper()
        response.headers['X-New-ID'] = new_id.hex().upper()
        response.headers['X-CRC-Info'] = crc_info
        response.headers['X-Orig-Offset'] = "0x{:08X}".format(orig_id_start)
        response.headers['X-Target-Offset'] = "0x{:08X}".format(target_id_start)

        elapsed = time.time() - t_start
        app.logger.info("Vanilla processed in {:.2f}s".format(elapsed))

        return response

    except Exception as e:
        app.logger.error("Vanilla error: {}".format(str(e)))
        return jsonify({"error": str(e)}), 500


# ==============================================================
# معالجة 1506 (يدوي)
# ==============================================================
@app.route('/api/process-1506', methods=['POST'])
def api_process_1506():
    t_start = time.time()
    try:
        if 'original' not in request.files or 'target' not in request.files:
            return jsonify({"error": "الرجاء رفع السوفتين"}), 400

        orig_file = request.files['original']
        target_file = request.files['target']

        if not orig_file.filename or not target_file.filename:
            return jsonify({"error": "الرجاء اختيار السوفتين"}), 400

        # العنوان والطول
        try:
            offset_str = request.form.get('offset', '0').strip()
            offset_str = offset_str.replace('0x', '').replace('0X', '')
            offset = int(offset_str, 16)
            length = int(request.form.get('length', '5'))
        except ValueError:
            return jsonify({"error": "العنوان أو الطول غير صحيح"}), 400

        if length < 1 or length > 64:
            return jsonify({"error": "الطول لازم بين 1 و 64 بايت"}), 400

        orig_data = bytearray(orig_file.read())
        target_data = bytearray(target_file.read())

        if offset + length > len(orig_data):
            return jsonify({
                "error": "العنوان خارج نطاق السوفت الأصلي "
                         "(الحجم: {:,} بايت)".format(len(orig_data))
            }), 400
        if offset + length > len(target_data):
            return jsonify({
                "error": "العنوان خارج نطاق السوفت الهدف "
                         "(الحجم: {:,} بايت)".format(len(target_data))
            }), 400

        old_id = bytes(target_data[offset:offset + length])
        new_id = bytes(orig_data[offset:offset + length])

        target_data[offset:offset + length] = new_id

        crc_info = "None"
        crc_result = fix_sphe_crc(target_data)
        if crc_result:
            new_crc, old_crc, sphe = crc_result
            crc_info = "0x{:08X} -> 0x{:08X}".format(old_crc, new_crc)

        output = io.BytesIO(bytes(target_data))
        output.seek(0)

        filename = "Modified_1506_" + target_file.filename

        response = send_file(
            output,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )

        response.headers['X-Old-ID'] = old_id.hex().upper()
        response.headers['X-New-ID'] = new_id.hex().upper()
        response.headers['X-CRC-Info'] = crc_info
        response.headers['X-Offset'] = "0x{:08X}".format(offset)
        response.headers['X-Length'] = str(length)

        elapsed = time.time() - t_start
        app.logger.info("1506 processed in {:.2f}s".format(elapsed))

        return response

    except Exception as e:
        app.logger.error("1506 error: {}".format(str(e)))
        return jsonify({"error": str(e)}), 500


# ==============================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)