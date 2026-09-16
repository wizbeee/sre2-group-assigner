# -*- coding: utf-8 -*-
"""명렬 xlsx -> index.html(명단 암호화) 재생성 스크립트.

사용법
    python build.py [명렬 폴더 경로]

  * 폴더 안의 '과학탐구실험2NN_교사_실험실(N명).xlsx' 를 모두 읽어 팩(NN)별 명단을 만들고,
    비밀번호로 암호화해 template.html 에 넣어 index.html 을 새로 씁니다.
    -> index.html 에는 암호문만 들어가므로 공개 저장소에 올려도 명단이 노출되지 않습니다.
  * 명렬 폴더: 인자 > 환경변수 SRE2_ROSTER_DIR > roster_dir.local.txt > ./rosters 순으로 찾습니다.
  * 비밀번호: 환경변수 SRE2_PASSWORD 가 있으면 그것을, 없으면 입력받습니다.
  * 수업에 들어오지 않는 학생은 exclude.local.json 에 적으면 빠집니다(exclude.example.json 참고).
  * index.plain.html(비밀번호 없이 열리는 로컬 전용본)도 같이 만듭니다.
    -> .gitignore 에 있습니다. 학생 이름이 그대로 들어 있으니 절대 커밋하지 마세요.

  필요 패키지: pip install openpyxl cryptography
"""
import base64
import getpass
import hashlib
import io
import json
import os
import re
import secrets
import sys

import openpyxl
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
ITERATIONS = 600_000          # PBKDF2-SHA256 반복 횟수 (브라우저 복호화와 동일해야 함)


def roster_dir():
    if len(sys.argv) > 1:
        return sys.argv[1]
    if os.environ.get("SRE2_ROSTER_DIR"):
        return os.environ["SRE2_ROSTER_DIR"]
    local = os.path.join(HERE, "roster_dir.local.txt")
    if os.path.exists(local):
        return io.open(local, encoding="utf-8").read().strip()
    return os.path.join(HERE, "rosters")


def load_exclude():
    """{"팩번호2자리": ["학번", ...]} — 조 편성에서 뺄 학생."""
    p = os.path.join(HERE, "exclude.local.json")
    if not os.path.exists(p):
        return {}
    raw = json.load(io.open(p, encoding="utf-8"))
    return {k: {str(x) for x in v} for k, v in raw.items() if not k.startswith("_")}


def read_packs(src, exclude):
    packs = {}
    for fn in sorted(os.listdir(src)):
        if not (fn.endswith(".xlsx") and "과학탐구실험2" in fn):
            continue
        m = re.search(r"과학탐구실험2(\d{2})", fn)
        if not m:
            continue
        pack = m.group(1)
        parts = fn.split("_")
        teacher, room = parts[2], parts[3].split("(")[0]
        ws = openpyxl.load_workbook(os.path.join(src, fn), data_only=True).worksheets[0]
        students = []
        for r in ws.iter_rows(min_row=2, values_only=True):   # 학년,학과,반,번호,성명 = 3,4,5,6,7
            if r[7] is None:
                continue
            grade, cls, num = int(r[3]), int(r[5]), int(r[6])
            students.append({"id": f"{grade}{cls:02d}{num:02d}", "cls": cls,
                             "num": num, "name": str(r[7]).strip()})
        drop = exclude.get(pack, set())
        dropped = [s for s in students if s["id"] in drop]
        students = [s for s in students if s["id"] not in drop]
        missing = drop - {s["id"] for s in dropped}
        if missing:
            raise SystemExit(f"팩 {pack} 제외 대상 학번이 명렬에 없음: {sorted(missing)}")
        if pack in packs:
            raise SystemExit(f"팩 {pack} 중복: {fn} / {packs[pack]['file']}")
        packs[pack] = {"teacher": teacher, "room": room, "students": students,
                       "file": fn, "dropped": dropped}
    if not packs:
        raise SystemExit(f"명렬 파일을 찾지 못했습니다: {src}")
    return packs


def encrypt(plaintext, password):
    """브라우저(Web Crypto)에서 PBKDF2-SHA256 + AES-GCM 으로 풀 수 있는 형태로 암호화."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32)
    iv = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)   # 암호문 + 인증 태그
    b = lambda x: base64.b64encode(x).decode("ascii")
    return {"enc": True, "iterations": ITERATIONS, "salt": b(salt), "iv": b(iv), "ct": b(ct)}


def main():
    src = roster_dir()
    packs = read_packs(src, load_exclude())
    data = {k: {"teacher": v["teacher"], "room": v["room"], "students": v["students"]}
            for k, v in sorted(packs.items())}
    data_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    if "</script" in data_json:
        raise SystemExit("데이터에 </script 문자열이 있어 중단합니다.")

    password = os.environ.get("SRE2_PASSWORD") or getpass.getpass("명단 비밀번호: ")
    if not password:
        raise SystemExit("비밀번호가 비어 있습니다.")

    tpl = io.open(os.path.join(HERE, "template.html"), encoding="utf-8").read()
    if "/*__DATA__*/" not in tpl:
        raise SystemExit("template.html 에 /*__DATA__*/ 자리가 없습니다.")

    enc_env = json.dumps(encrypt(data_json, password), separators=(",", ":"))
    io.open(os.path.join(HERE, "index.html"), "w", encoding="utf-8").write(
        tpl.replace("/*__DATA__*/", enc_env))

    plain_env = json.dumps({"enc": False, "data": data}, ensure_ascii=False, separators=(",", ":"))
    io.open(os.path.join(HERE, "index.plain.html"), "w", encoding="utf-8").write(
        tpl.replace("/*__DATA__*/", plain_env))

    total = sum(len(v["students"]) for v in data.values())
    print(f"index.html(암호화) / index.plain.html(로컬 전용) 생성 - 팩 {len(data)}개 / 총 {total}명")
    for k, v in data.items():
        mark = ""
        if packs[k]["dropped"]:
            mark = " [제외: " + ", ".join(f"{s['id']} {s['name']}" for s in packs[k]["dropped"]) + "]"
        print(f"  {int(k):>2}팩 {v['teacher']} {v['room']} {len(v['students'])}명{mark}"
              f"  <- {packs[k]['file']}")


if __name__ == "__main__":
    main()
