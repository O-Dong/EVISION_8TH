"""
설명:
- 이 파일은 과제/포트폴리오 용도로 안전하게 공개할 수 있는 버전입니다.
- 실제 HTTP 요청을 전혀 보내지 않습니다. (retrieve 함수가 요청을 시뮬레이트함)
- 파라미터 패치, 마커 생성, 응답 내 반사 탐지 로직은 학습용으로 유지됩니다.
- 로컬에서 실제 스캔을 실행하려면 네트워크 가능한 원본 파일로 교체해야 합니다.
"""

import argparse
import time
import random
import string
import json
import sys
import uuid
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# ----------------------------
# 기본 설정 (안전 토큰 사용)
DEFAULT_PAYLOAD = f"__XSS_TEST_{uuid.uuid4().hex[:8]}__"   # 안전한 기본 토큰(실행 불가)
SMALL_POOL = ('<', '>')                         # 기본 마커에 쓸 안전한 문자들
LARGE_POOL = ("'", '"', '>', '<', ';')          # 공격적 풀

# ----------------------------
# CLI 파싱: 사용자 입력(옵션)을 처리
def parse_args():
    p = argparse.ArgumentParser(description="Mini XSS scanner (public-safe stub).")
    p.add_argument("--url", "-u", required=True, help="Target URL (include query if GET test)")
    p.add_argument("--data", help="POST data (e.g. q=1&x=2)")
    p.add_argument("--payload", default=DEFAULT_PAYLOAD, help="Payload to inject")
    p.add_argument("--repeats", type=int, default=2, help="How many runs to perform for confidence")
    p.add_argument("--delay", type=float, default=0.15, help="Delay between runs (seconds)")
    p.add_argument("--aggressive", action="store_true", help="Use larger char pool (may break some servers)")
    p.add_argument("--json", dest="jsonfile", help="Write JSON result to file")
    p.add_argument("--allow-remote", action="store_true", help="Allow non-local targets (DANGEROUS)")
    return p.parse_args()

# ----------------------------
# 유틸: 호스트가 로컬인지 확인 (악용 방지)
def is_local_host(host):
    return host in ("127.0.0.1", "localhost")

# ----------------------------
# URL에서 특정 파라미터 하나만 변경(마커 붙이기)
def add_marker_to_url(orig_url, param, marker):
    u = urlsplit(orig_url)
    pairs = parse_qsl(u.query, keep_blank_values=True)
    new_pairs = []
    patched = False
    for k, v in pairs:
        if (not patched) and (k == param):
            new_pairs.append((k, v + marker))
            patched = True
        else:
            new_pairs.append((k, v))
    new_qs = urlencode(new_pairs)
    return urlunsplit((u.scheme, u.netloc, u.path, new_qs, u.fragment))

# ----------------------------
# POST 바디에서 특정 파라미터 하나만 변경
def add_marker_to_data(orig_data, param, marker):
    pairs = parse_qsl(orig_data or "", keep_blank_values=True)
    new_pairs = []
    patched = False
    for k, v in pairs:
        if (not patched) and (k == param):
            new_pairs.append((k, v + marker))
            patched = True
        else:
            new_pairs.append((k, v))
    return urlencode(new_pairs)

# ----------------------------
# HTTP 요청 수행: requests가 있으면 편하게, 없으면 urllib 사용
def retrieve(session, method, url, data=None, timeout=6):
    """
    Public stub: 실제 네트워크 I/O는 수행하지 않습니다.
    대신 요청 정보를 설명하는 JSON 문자열을 '응답 본문'으로 반환합니다.
    반환값 형식은 (status, body)이며 status는 None(실제 요청 없음)을 의미합니다.
    """
    info = {
        "note": "network-disabled-public-stub",
        "method": method,
        "url": url,
        "data": data,
        "timeout": timeout,
        "hint": "This repository's public version does not perform real HTTP requests."
    }
    body = json.dumps(info, ensure_ascii=False)
    return None, body

# ----------------------------
# 응답 본문에서 "있는지" 확인: raw인지 escaped인지 판정
def find_in_body(body, marker):
    if marker in body:
        return "raw"
    import html
    if html.escape(marker) in body:
        return "escaped"
    return None

# ----------------------------
# 한 번의 검사(모든 파라미터에 대해 시도)
def scan_once(session, base_url, data, payload, aggressive=False):
    findings = []
    pool = LARGE_POOL if aggressive else SMALL_POOL

    parsed_get = parse_qsl(urlsplit(base_url).query, keep_blank_values=True)
    parsed_post = parse_qsl(data or "", keep_blank_values=True)

    for phase, params in (("GET", parsed_get), ("POST", parsed_post)):
        for k, v in params:
            prefix = ''.join(random.choices(string.ascii_lowercase, k=4))
            suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
            marker = prefix + ''.join(pool) + suffix
            injected = marker + payload + marker[::-1]

            if phase == "GET":
                target = add_marker_to_url(base_url, k, injected)
                status, body = retrieve(session, "GET", target)
            else:
                patched = add_marker_to_data(data or "", k, injected)
                status, body = retrieve(session, "POST", base_url, data=patched)

            if body is None:
                continue

            # 시뮬레이션 바디에는 요청 정보(JSON)가 들어 있으므로 injected 문자열이 포함
            ctx = find_in_body(body, injected)
            if ctx:
                findings.append({
                    "phase": phase,
                    "param": k,
                    "context": ctx,
                    "status": status,
                    "marker": marker,
                })
    return findings

# ----------------------------
# 여러 번 검사한 결과들을 합쳐서 confidence 체크
def aggregate_findings(all_findings, repeats):
    agg = {}
    for f in all_findings:
        key = (f["phase"], f["param"], f["context"])
        agg.setdefault(key, 0)
        agg[key] += 1
    results = []
    for key, count in agg.items():
        phase, param, context = key
        confidence = "high" if count == repeats else ("medium" if count > 1 else "low")
        results.append({
            "phase": phase, "param": param, "context": context,
            "observed": count, "repeats": repeats, "confidence": confidence
        })
    return results

# ----------------------------
# 메인 스캔 로직
def scan(base_url, data=None, payload=DEFAULT_PAYLOAD, repeats=2, delay=0.15, aggressive=False, allow_remote=False):
    host = urlsplit(base_url).hostname
    if not allow_remote and not is_local_host(host):
        print("[!] Target is not local. Use --allow-remote to override (DANGEROUS).")
        sys.exit(1)

    # public stub에서는 네트워크가 비활성화되어 있으므로 allow_remote의 위험은 감소
    # 사용자가 실제 네트워크 버전으로 바꿀 경우를 대비해 경고는 유지
    if allow_remote:
        print("[!] NOTE: --allow-remote passed, but this public stub does NOT perform network requests.")

    session = None  # 네트워크 스텁이므로 session 불필요
    all_findings = []
    for i in range(repeats):
        found = scan_once(session, base_url, data, payload, aggressive=aggressive)
        all_findings.extend(found)
        if i < repeats - 1:
            time.sleep(delay)
    return aggregate_findings(all_findings, repeats)

# ----------------------------
# 커맨드라인 진입점
def main():
    args = parse_args()
    results = scan(args.url, data=args.data, payload=args.payload,
                   repeats=args.repeats, delay=args.delay,
                   aggressive=args.aggressive, allow_remote=args.allow_remote)
    out = {"target": args.url, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "findings": results}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if args.jsonfile:
        with open(args.jsonfile, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
        print("[+] Saved JSON ->", args.jsonfile)

if __name__ == "__main__":
    print("NOTICE: This is a PUBLIC-SAFE stub. No network requests will be performed.")
    print("To run real scans, replace retrieve() with a network-enabled implementation in a private/local copy.")
    main()
