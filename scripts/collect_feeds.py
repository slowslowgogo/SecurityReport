#!/usr/bin/env python3
"""
Security Feed Collector & AI Analyzer
수집 → NVD/KEV 보강 → 분석 → HTML 브리핑 생성
"""

import os
import re
import json
import hashlib
import feedparser
import anthropic
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── 팀 컨텍스트 (분류 기준) ───────────────────────────────────────────────
TEAM_CONTEXT = """
당신은 스마트폰 제조사의 보안 취약점 관리팀을 위한 분석 에이전트입니다.

## 팀 관심 도메인
- 제품군: Android/AOSP, NFC, 스마트폰 펌웨어, 모바일 SoC
- 빌드 시스템: Soong/Android.bp, Gradle, CMake, Bazel, SCons
- 보안 산출물: SBOM (SPDX 2.3, CycloneDX), 취약점 관리
- 규제 프레임워크: EU CRA (Cyber Resilience Act), NIS2, EN 18031, RED
- 위협 유형: 공급망 공격, OSS 취약점, AI/MCP 보안, DPRK 위협 행위자
- 도구: Trivy, Syft, Grype, OSSF Scorecard, OpenChain

## 관련성 판단 기준 (high)
- Android/AOSP/Linux 커널 취약점 (특히 NFC, Bluetooth, WiFi, Media)
- 공급망 공격 (npm, PyPI, GitHub Actions, Docker Hub)
- EU CRA / SBOM 관련 규제 동향
- AI 에이전트·MCP 프로토콜 보안 이슈
- DPRK(북한) IT 위협 행위자 캠페인
- CISA KEV (Known Exploited Vulnerabilities) 신규 추가

## 관련성 판단 기준 (medium)
- 일반 Linux/오픈소스 취약점 (CVSS 7.0+)
- 소프트웨어 보안 모범 사례·도구 업데이트
- 국제 사이버보안 규제 및 정책 변화
- 모바일 위협 인텔리전스

## 관련성 판단 기준 (low / 제외)
- Windows 전용 취약점
- 금융·암호화폐 해킹 (기술적 연관 없는 경우)
- 기업 M&A, 채용 공고
"""

# ─── RSS 피드 목록 ──────────────────────────────────────────────────────────
FEEDS = [
    # CISA / 미국 정부
    {"url": "https://www.cisa.gov/feeds/alerts.xml",                         "source": "CISA Alerts"},
    {"url": "https://www.cisa.gov/feeds/kev.xml",                            "source": "CISA KEV"},
    # NVD
    {"url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",  "source": "NVD CVE"},
    # Android Security
    {"url": "https://source.android.com/feed.xml",                           "source": "Android Security"},
    # 주요 보안 미디어
    {"url": "https://feeds.feedburner.com/TheHackersNews",                   "source": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/",                        "source": "BleepingComputer"},
    {"url": "https://krebsonsecurity.com/feed/",                             "source": "KrebsOnSecurity"},
    {"url": "https://www.darkreading.com/rss.xml",                           "source": "Dark Reading"},
    {"url": "https://threatpost.com/feed/",                                  "source": "Threatpost"},
    {"url": "https://www.securityweek.com/feed",                             "source": "SecurityWeek"},
    # 취약점 / 익스플로잇
    {"url": "https://www.exploit-db.com/rss.xml",                            "source": "Exploit-DB"},
    {"url": "https://seclists.org/rss/fulldisclosure.rss",                   "source": "Full Disclosure"},
    # 공급망 / OSS 보안
    {"url": "https://openssf.org/feed/",                                     "source": "OpenSSF"},
    {"url": "https://socket.dev/rss.xml",                                    "source": "Socket.dev"},
    # EU / 규제
    {"url": "https://www.enisa.europa.eu/publications/rss",                  "source": "ENISA"},
    # 위협 인텔리전스
    {"url": "https://feeds.feedburner.com/rssfeed_mandiant",                 "source": "Mandiant"},
    {"url": "https://www.recordedfuture.com/feed",                           "source": "Recorded Future"},
    {"url": "https://unit42.paloaltonetworks.com/feed/",                     "source": "Unit 42"},
    # GitHub Security
    {"url": "https://github.blog/category/security/feed/",                   "source": "GitHub Security Blog"},
    # 추가 보안 미디어
    {"url": "https://www.cybersecuritydive.com/feeds/news/",                 "source": "Cybersecurity Dive"},
    {"url": "https://blog.google/threat-analysis-group/rss/",               "source": "Google Security Blog"},
    {"url": "https://cyble.com/feed/",                                       "source": "Cyble"},
    # 위협 인텔리전스 (추가)
    {"url": "https://isc.sans.edu/rssfeed_full.xml",                        "source": "SANS ISC"},
    {"url": "https://googleprojectzero.blogspot.com/feeds/posts/default",   "source": "Google Project Zero"},
]

# CVE ID 추출 정규식
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ─── RSS 피드 수집 ──────────────────────────────────────────────────────────
def fetch_feed(feed_info: dict, cutoff_hours: int = 24) -> list[dict]:
    """단일 RSS 피드 수집. cutoff_hours 이내 항목만 반환."""
    items = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)

    try:
        parsed = feedparser.parse(
            feed_info["url"],
            request_headers={"User-Agent": "SecurityBriefBot/1.0"}
        )
        for entry in parsed.entries:
            pub = None
            for attr in ("published_parsed", "updated_parsed", "created_parsed"):
                t = getattr(entry, attr, None)
                if t:
                    pub = datetime(*t[:6], tzinfo=timezone.utc)
                    break
            if pub and pub < cutoff:
                continue

            title   = getattr(entry, "title",   "").strip()
            link    = getattr(entry, "link",    "").strip()
            summary = getattr(entry, "summary", getattr(entry, "description", ""))[:800]

            if not title or not link:
                continue

            # 제목+본문에서 CVE ID 미리 추출
            cve_ids = list(set(
                c.upper() for c in CVE_PATTERN.findall(title + " " + summary)
            ))

            uid = hashlib.md5(link.encode()).hexdigest()
            items.append({
                "uid":      uid,
                "source":   feed_info["source"],
                "title":    title,
                "link":     link,
                "summary":  summary,
                "pub_date": pub.isoformat() if pub else None,
                "cve_ids":  cve_ids,
                "cvss":     None,
                "kev":      False,   # CISA KEV 플래그
                "nvd_data": None,    # NVD 보강 데이터
            })
    except Exception as e:
        print(f"  [WARN] {feed_info['source']}: {e}")

    return items


def collect_all_feeds(cutoff_hours: int = 24) -> list[dict]:
    """모든 피드 병렬 수집 + 중복 제거"""
    all_items = []
    seen_uids = set()

    print(f"[1/4] RSS 피드 수집 중 ({len(FEEDS)}개 소스)...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_feed, f, cutoff_hours): f for f in FEEDS}
        for future in as_completed(futures):
            for item in future.result():
                if item["uid"] not in seen_uids:
                    seen_uids.add(item["uid"])
                    all_items.append(item)

    print(f"  → 총 {len(all_items)}건 수집 (중복 제거 완료)")
    return all_items


# ─── NVD API ────────────────────────────────────────────────────────────────
def fetch_nvd_recent(cutoff_hours: int = 24) -> dict[str, dict]:
    """
    NVD API v2로 최근 CVE 수집.
    반환: {CVE-ID: {cvss, description, affected}} 딕셔너리
    """
    nvd_map: dict[str, dict] = {}
    now   = datetime.now(timezone.utc)
    start = (now - timedelta(hours=cutoff_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end   = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start}&pubEndDate={end}&resultsPerPage=200"
    )

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityBriefBot/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())

        for vuln in data.get("vulnerabilities", []):
            cve    = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # CVSS 점수 추출 (v3.1 → v3.0 → v2 순서)
            cvss_score = None
            metrics    = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_score = entries[0].get("cvssData", {}).get("baseScore")
                    break

            # 영문 설명
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:300]
                    break

            # 영향 받는 제품 (CPE vendor)
            affected = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        parts = match.get("criteria", "").split(":")
                        if len(parts) > 3:
                            affected.append(parts[3])
            affected = list(set(affected))[:5]

            nvd_map[cve_id.upper()] = {
                "cvss":        cvss_score,
                "description": desc,
                "affected":    affected,
            }

        print(f"  → NVD: {len(nvd_map)}개 CVE 수집")
    except Exception as e:
        print(f"  [WARN] NVD API 호출 실패: {e}")

    return nvd_map


# ─── CISA KEV API ───────────────────────────────────────────────────────────
def fetch_cisa_kev(cutoff_hours: int = 24) -> set[str]:
    """
    CISA KEV 카탈로그에서 최근 추가된 CVE ID 집합 반환.
    """
    kev_ids: set[str] = set()
    cutoff  = datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)
    url     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityBriefBot/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())

        for vuln in data.get("vulnerabilities", []):
            date_added = vuln.get("dateAdded", "")
            try:
                added_dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if added_dt >= cutoff:
                    cve_id = vuln.get("cveID", "").upper()
                    if cve_id:
                        kev_ids.add(cve_id)
            except ValueError:
                pass

        print(f"  → CISA KEV: {len(kev_ids)}개 신규 항목")
    except Exception as e:
        print(f"  [WARN] CISA KEV API 호출 실패: {e}")

    return kev_ids


# ─── NVD/KEV 보강 ───────────────────────────────────────────────────────────
def enrich_with_nvd_kev(
    items: list[dict],
    nvd_map: dict[str, dict],
    kev_ids: set[str],
) -> list[dict]:
    """
    RSS 항목에 NVD CVSS, 영향 제품, CISA KEV 플래그를 주입.
    CVE 없는 기사(공급망, 캠페인 등)는 그대로 통과.
    """
    enriched_count = 0
    kev_count      = 0

    for item in items:
        cve_ids = item.get("cve_ids", [])

        if any(c in kev_ids for c in cve_ids):
            item["kev"] = True
            kev_count  += 1

        for cve_id in cve_ids:
            if cve_id in nvd_map:
                nvd = nvd_map[cve_id]
                if nvd["cvss"] is not None:
                    item["cvss"]     = nvd["cvss"]
                    item["nvd_data"] = nvd
                    enriched_count  += 1
                break

    print(f"  → NVD 보강: {enriched_count}건 / KEV 플래그: {kev_count}건")
    return items


# ─── AI 분류 ────────────────────────────────────────────────────────────────
def analyze_batch(items: list[dict], client: anthropic.Anthropic) -> list[dict]:
    """Claude API로 배치 분류. 10건씩 묶어 처리."""
    BATCH_SIZE = 5
    results    = []
    total      = len(items)

    print(f"[3/4] AI 분류 중 ({total}건, {(total-1)//BATCH_SIZE+1}배치)...")

    for i in range(0, total, BATCH_SIZE):
        batch      = items[i:i + BATCH_SIZE]
        batch_text = "\n\n".join(
            (
                f"[{j+1}] 제목: {it['title']}\n"
                f"출처: {it['source']}\n"
                f"내용: {it['summary'][:300]}\n"
                + (f"CVE: {', '.join(it['cve_ids'])} / CVSS: {it['cvss']}\n" if it.get('cve_ids') else "")
                + ("⚠️ CISA KEV 등재 (실제 악용 중)\n" if it.get('kev') else "")
            )
            for j, it in enumerate(batch)
        )

        prompt = f"""다음 {len(batch)}개의 보안 뉴스/취약점 항목을 분석하여 JSON 배열로만 응답하세요.
다른 텍스트나 마크다운 없이 JSON만 출력하세요.

각 항목은 다음 형식:
{{
  "idx": 1,
  "relevance": "high|medium|low",
  "category": "vuln|supply_chain|regulatory|threat_intel|tool|other",
  "affected_component": "Android|NFC|SBOM|CRA|Linux|Supply_Chain|AI_Security|기타",
  "action_required": true/false,
  "action_type": "patch|monitor|regulatory_review|none",
  "summary_ko": "한국어 한줄 요약 (50자 이내)",
  "cve_ids": [],
  "cvss": null
}}

규칙:
- CISA KEV 등재 항목은 relevance를 반드시 high로 설정
- CVSS 9.0 이상이면 relevance를 high로 설정
- CVE 없어도 공급망 공격·캠페인·규제 이슈는 내용 기반으로 분류

항목 목록:
{batch_text}"""

        try:
            response = client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=4000,
                system=TEAM_CONTEXT,
                messages=[{"role": "user", "content": prompt}]
            )
            raw = response.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            parsed = json.loads(raw)
            for result in parsed:
                idx = result.get("idx", 1) - 1
                if 0 <= idx < len(batch):
                    # NVD 실제 CVSS 값 보존
                    if batch[idx].get("cvss") is not None:
                        result["cvss"] = batch[idx]["cvss"]
                    # CVE ID 병합
                    ai_cves  = result.get("cve_ids", [])
                    existing = batch[idx].get("cve_ids", [])
                    result["cve_ids"] = list(set(existing + ai_cves))
                    batch[idx].update(result)
                    results.append(batch[idx])
        except Exception as e:
            print(f"  [WARN] 배치 {i//BATCH_SIZE+1} 분석 실패: {e}")
            for item in batch:
                item.setdefault("relevance",       "low")
                item.setdefault("category",        "other")
                item.setdefault("summary_ko",      item["title"][:50])
                item.setdefault("action_required", False)
                item.setdefault("action_type",     "none")
                results.append(item)

        print(f"  → 배치 {i//BATCH_SIZE+1}/{(total-1)//BATCH_SIZE+1} 완료")

    return results


# ─── HTML 생성 ───────────────────────────────────────────────────────────────
def generate_html(items: list[dict], output_path: Path, feed_count: int) -> None:
    """분석 결과를 보안 브리핑 HTML로 변환"""

    high   = [x for x in items if x.get("relevance") == "high"]
    medium = [x for x in items if x.get("relevance") == "medium"]
    low    = [x for x in items if x.get("relevance") == "low"]
    action = [x for x in items if x.get("action_required")]
    kev    = [x for x in items if x.get("kev")]

    cat_counts: dict[str, int] = {}
    for item in items:
        c = item.get("category", "other")
        cat_counts[c] = cat_counts.get(c, 0) + 1

    cat_labels = {
        "vuln": "취약점", "supply_chain": "공급망", "regulatory": "규제",
        "threat_intel": "위협 인텔", "tool": "도구·기술", "other": "기타"
    }

    now_kst  = datetime.now(timezone(timedelta(hours=9)))
    date_str = now_kst.strftime("%Y년 %m월 %d일 %H:%M KST")

    def cvss_color(score) -> str:
        if score is None:  return "var(--text3)"
        if score >= 9.0:   return "var(--red)"
        if score >= 7.0:   return "var(--orange)"
        return "var(--blue)"

    def item_card(item: dict) -> str:
        rel       = item.get("relevance", "low")
        rel_class = {"high": "rel-high", "medium": "rel-medium", "low": "rel-low"}.get(rel, "rel-low")
        rel_label = {"high": "긴급", "medium": "모니터링", "low": "참고"}.get(rel, "참고")
        cat       = cat_labels.get(item.get("category", "other"), "기타")
        cves      = item.get("cve_ids", [])
        cvss      = item.get("cvss")
        is_kev    = item.get("kev", False)
        nvd       = item.get("nvd_data")

        cve_html = " ".join(
            f'<a class="cve-tag" href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank">{c}</a>'
            for c in cves
        ) if cves else ""

        cvss_html   = (
            f'<span class="cvss-badge" style="color:{cvss_color(cvss)}">CVSS {cvss}</span>'
            if cvss else ""
        )
        kev_html    = '<span class="kev-badge">🔥 KEV</span>' if is_kev else ""
        action_html = '<span class="action-badge">⚡ 조치 필요</span>' if item.get("action_required") else ""
        pub         = item.get("pub_date", "")
        pub_display = pub[:10] if pub else ""

        affected_html = ""
        if nvd and nvd.get("affected"):
            tags = " ".join(
                f'<span class="affected-tag">{v}</span>' for v in nvd["affected"]
            )
            affected_html = f'<div class="affected-row">영향 제품: {tags}</div>'

        return f"""
        <div class="item-card {rel_class}">
          <div class="item-header">
            <span class="rel-badge">{rel_label}</span>
            <span class="cat-badge">{cat}</span>
            {kev_html}{action_html}{cvss_html}
          </div>
          <div class="item-title">
            <a href="{item.get('link','#')}" target="_blank" rel="noopener">{item.get('title','')}</a>
          </div>
          <div class="item-summary">{item.get('summary_ko', '')}</div>
          {affected_html}
          <div class="item-meta">
            <span class="source-tag">📡 {item.get('source','')}</span>
            {cve_html}
            <span class="date-tag">{pub_display}</span>
          </div>
        </div>"""

    def section_html(title: str, icon: str, items_list: list[dict], cls: str) -> str:
        if not items_list:
            return ""
        cards = "\n".join(item_card(i) for i in items_list)
        return f"""
      <section class="brief-section {cls}">
        <h2 class="section-title"><span class="section-icon">{icon}</span>{title} <span class="count-badge">{len(items_list)}</span></h2>
        <div class="items-grid">{cards}</div>
      </section>"""

    cat_stats_html = "".join(
        f'<div class="stat-item"><span class="stat-num">{v}</span><span class="stat-label">{cat_labels.get(k,k)}</span></div>'
        for k, v in sorted(cat_counts.items(), key=lambda x: -x[1])
    )

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>보안 브리핑 — {now_kst.strftime('%Y.%m.%d')}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+KR:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

  :root {{
    --bg:         #0d1117;
    --bg2:        #161b22;
    --bg3:        #21262d;
    --border:     #30363d;
    --text:       #e6edf3;
    --text2:      #8b949e;
    --text3:      #6e7681;
    --red:        #f85149;
    --red-dim:    #3d1f1f;
    --orange:     #e3b341;
    --orange-dim: #3d2f0d;
    --blue:       #58a6ff;
    --blue-dim:   #0d2140;
    --green:      #3fb950;
    --green-dim:  #122920;
    --purple:     #bc8cff;
    --purple-dim: #1f1340;
    --accent:     #1f6feb;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'IBM Plex Sans KR', sans-serif;
    background: var(--bg); color: var(--text);
    font-size: 14px; line-height: 1.6; min-height: 100vh;
  }}

  .site-header {{
    background: var(--bg2); border-bottom: 1px solid var(--border);
    padding: 24px 32px; display: flex; align-items: center;
    justify-content: space-between; position: sticky; top: 0; z-index: 100;
  }}
  .header-left  {{ display: flex; align-items: center; gap: 14px; }}
  .logo-mark {{
    width: 36px; height: 36px; background: var(--accent); border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'IBM Plex Mono', monospace; font-weight: 500; font-size: 14px; color: #fff;
  }}
  .header-title {{ font-size: 16px; font-weight: 600; letter-spacing: -0.3px; }}
  .header-date  {{ font-size: 12px; color: var(--text2); font-family: 'IBM Plex Mono', monospace; }}

  .stats-bar {{
    background: var(--bg2); border-bottom: 1px solid var(--border);
    padding: 16px 32px; display: flex; gap: 32px; align-items: center; overflow-x: auto;
  }}
  .stats-group   {{ display: flex; gap: 24px; align-items: center; }}
  .stats-divider {{ width: 1px; height: 32px; background: var(--border); flex-shrink: 0; }}
  .big-stat      {{ display: flex; flex-direction: column; align-items: center; }}
  .big-stat .num {{ font-family: 'IBM Plex Mono', monospace; font-size: 24px; font-weight: 500; line-height: 1; }}
  .big-stat .label {{ font-size: 11px; color: var(--text2); margin-top: 3px; }}
  .num-red    {{ color: var(--red); }}
  .num-orange {{ color: var(--orange); }}
  .num-blue   {{ color: var(--blue); }}
  .num-purple {{ color: var(--purple); }}
  .num-white  {{ color: var(--text); }}
  .stat-item  {{ display: flex; flex-direction: column; align-items: center; }}
  .stat-num   {{ font-family: 'IBM Plex Mono', monospace; font-size: 18px; font-weight: 500; color: var(--text); }}
  .stat-label {{ font-size: 11px; color: var(--text3); margin-top: 2px; }}

  .main {{ padding: 32px; max-width: 1400px; margin: 0 auto; }}

  .brief-section {{ margin-bottom: 40px; }}
  .section-title {{
    font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px;
    margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border);
  }}
  .section-icon {{ font-size: 16px; }}
  .count-badge {{
    margin-left: auto; font-family: 'IBM Plex Mono', monospace;
    font-size: 12px; font-weight: 500;
    background: var(--bg3); color: var(--text2); padding: 2px 8px; border-radius: 10px;
  }}

  .items-grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 12px;
  }}

  .item-card {{
    background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
    padding: 14px 16px; transition: border-color .15s, transform .15s;
    border-left: 3px solid transparent;
  }}
  .item-card:hover {{ transform: translateY(-1px); border-color: var(--accent); }}
  .rel-high   {{ border-left-color: var(--red); }}
  .rel-medium {{ border-left-color: var(--orange); }}
  .rel-low    {{ border-left-color: var(--border); }}

  .item-header {{ display: flex; gap: 6px; margin-bottom: 8px; flex-wrap: wrap; align-items: center; }}

  .rel-badge {{
    font-size: 10px; font-weight: 600; letter-spacing: .5px;
    padding: 2px 7px; border-radius: 4px; text-transform: uppercase;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .rel-high   .rel-badge {{ background: var(--red-dim);    color: var(--red); }}
  .rel-medium .rel-badge {{ background: var(--orange-dim); color: var(--orange); }}
  .rel-low    .rel-badge {{ background: var(--bg3);        color: var(--text3); }}

  .cat-badge    {{ font-size: 10px; padding: 2px 7px; border-radius: 4px; background: var(--blue-dim);   color: var(--blue); }}
  .kev-badge    {{ font-size: 10px; padding: 2px 7px; border-radius: 4px; background: #3d1a00;           color: #ff6b35; font-weight: 700; }}
  .action-badge {{ font-size: 10px; padding: 2px 7px; border-radius: 4px; background: #2d1f0d;           color: var(--orange); font-weight: 600; }}
  .cvss-badge   {{ font-size: 10px; font-family: 'IBM Plex Mono', monospace; padding: 2px 7px; border-radius: 4px; background: var(--bg3); }}

  .item-title {{ font-size: 13px; font-weight: 500; margin-bottom: 6px; line-height: 1.45; }}
  .item-title a {{ color: var(--text); text-decoration: none; }}
  .item-title a:hover {{ color: var(--blue); }}
  .item-summary {{ font-size: 12px; color: var(--text2); line-height: 1.5; margin-bottom: 6px; }}

  .affected-row {{ font-size: 11px; color: var(--text3); margin-bottom: 6px; }}
  .affected-tag {{
    display: inline-block; font-size: 10px; font-family: 'IBM Plex Mono', monospace;
    padding: 1px 5px; border-radius: 3px;
    background: var(--purple-dim); color: var(--purple); margin-right: 3px;
  }}

  .item-meta {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }}
  .source-tag, .date-tag {{ font-size: 11px; color: var(--text3); font-family: 'IBM Plex Mono', monospace; }}
  .cve-tag {{
    font-size: 10px; font-family: 'IBM Plex Mono', monospace;
    padding: 1px 6px; border-radius: 3px;
    background: var(--green-dim); color: var(--green); text-decoration: none;
  }}
  .cve-tag:hover {{ background: var(--green); color: #000; }}

  .empty-note {{
    padding: 32px; text-align: center; color: var(--text3); font-size: 13px;
    border: 1px dashed var(--border); border-radius: 8px;
  }}

  .site-footer {{
    margin-top: 40px; padding: 24px 32px; border-top: 1px solid var(--border);
    color: var(--text3); font-size: 11px; font-family: 'IBM Plex Mono', monospace;
    display: flex; justify-content: space-between;
  }}

  @media (max-width: 768px) {{
    .stats-bar, .site-header {{ padding: 14px 16px; }}
    .main {{ padding: 16px; }}
    .items-grid {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>

<header class="site-header">
  <div class="header-left">
    <div class="logo-mark">SB</div>
    <div>
      <div class="header-title">Security Briefing</div>
      <div class="header-date">{date_str}</div>
    </div>
  </div>
</header>

<div class="stats-bar">
  <div class="stats-group">
    <div class="big-stat"><span class="num num-white">{len(items)}</span><span class="label">총 수집</span></div>
    <div class="big-stat"><span class="num num-red">{len(high)}</span><span class="label">긴급</span></div>
    <div class="big-stat"><span class="num num-orange">{len(medium)}</span><span class="label">모니터링</span></div>
    <div class="big-stat"><span class="num num-blue">{len(action)}</span><span class="label">조치 필요</span></div>
    <div class="big-stat"><span class="num num-purple">{len(kev)}</span><span class="label">KEV 등재</span></div>
  </div>
  <div class="stats-divider"></div>
  <div class="stats-group">{cat_stats_html}</div>
</div>

<main class="main">
  {section_html("긴급 — 즉시 검토 필요", "🔴", high, "section-high") or
   '<section class="brief-section"><p class="empty-note">긴급 항목 없음</p></section>'}
  {section_html("모니터링 — 추이 관찰", "🟡", medium, "section-medium") or
   '<section class="brief-section"><p class="empty-note">모니터링 항목 없음</p></section>'}
  {section_html("참고", "⚪", low, "section-low")}
</main>

<footer class="site-footer">
  <span>Security Briefing · AI-augmented · RSS {feed_count}개 + NVD API + CISA KEV API</span>
  <span>생성: {date_str}</span>
</footer>

</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    print(f"  → HTML 저장: {output_path}")


# ─── 아카이브 뷰어 생성 ─────────────────────────────────────────────────────
def generate_archive(output_dir: Path) -> None:
    """output/ 폴더의 JSON 파일들을 읽어 날짜별 아카이브 HTML 생성"""

    # brief_YYYY-MM-DD.json 파일 목록 수집 (최신순)
    json_files = sorted(output_dir.glob("brief_*.json"), reverse=True)
    if not json_files:
        return

    entries = []
    for jf in json_files:
        date_str = jf.stem.replace("brief_", "")   # "2026-04-14"
        try:
            with open(jf, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        total  = len(data)
        high   = sum(1 for x in data if x.get("relevance") == "high")
        medium = sum(1 for x in data if x.get("relevance") == "medium")
        action = sum(1 for x in data if x.get("action_required"))
        kev    = sum(1 for x in data if x.get("kev"))

        # 카테고리 분포
        cat_counts: dict[str, int] = {}
        for item in data:
            c = item.get("category", "other")
            cat_counts[c] = cat_counts.get(c, 0) + 1

        entries.append({
            "date":       date_str,
            "html_file":  f"brief_{date_str}.html",
            "total":      total,
            "high":       high,
            "medium":     medium,
            "action":     action,
            "kev":        kev,
            "cat_counts": cat_counts,
        })

    if not entries:
        return

    cat_labels = {
        "vuln": "취약점", "supply_chain": "공급망", "regulatory": "규제",
        "threat_intel": "위협 인텔", "tool": "도구·기술", "other": "기타"
    }

    now_kst  = datetime.now(timezone(timedelta(hours=9)))
    date_str_now = now_kst.strftime("%Y년 %m월 %d일 %H:%M KST")

    def entry_row(e: dict) -> str:
        # 날짜 포맷
        try:
            d    = datetime.strptime(e["date"], "%Y-%m-%d")
            disp = d.strftime("%Y.%m.%d (%a)").replace(
                "Mon","월").replace("Tue","화").replace("Wed","수").replace(
                "Thu","목").replace("Fri","금").replace("Sat","토").replace("Sun","일")
        except ValueError:
            disp = e["date"]

        kev_html    = f'<span class="kev-pill">{e["kev"]} KEV</span>' if e["kev"] > 0 else ""
        action_html = f'<span class="action-pill">⚡ {e["action"]}</span>' if e["action"] > 0 else ""

        # 카테고리 바
        cat_html = "".join(
            f'<span class="cat-dot" title="{cat_labels.get(k,k)}: {v}건" style="flex:{v}">'
            f'</span>'
            for k, v in sorted(e["cat_counts"].items(), key=lambda x: -x[1])
        )

        # high 건수에 따라 행 강조
        row_cls = "row-high" if e["high"] >= 3 else ("row-mid" if e["high"] >= 1 else "")

        return f"""
        <tr class="entry-row {row_cls}" onclick="location.href='{e['html_file']}'">
          <td class="td-date">{disp}</td>
          <td class="td-total">{e['total']}</td>
          <td class="td-high"><span class="num-high">{e['high']}</span></td>
          <td class="td-medium"><span class="num-medium">{e['medium']}</span></td>
          <td class="td-badges">{kev_html}{action_html}</td>
          <td class="td-bar"><div class="cat-bar">{cat_html}</div></td>
          <td class="td-link"><a href="{e['html_file']}" onclick="event.stopPropagation()">열기 →</a></td>
        </tr>"""

    rows_html = "\n".join(entry_row(e) for e in entries)

    # 전체 누적 통계
    total_days   = len(entries)
    total_items  = sum(e["total"]  for e in entries)
    total_high   = sum(e["high"]   for e in entries)
    total_kev    = sum(e["kev"]    for e in entries)
    total_action = sum(e["action"] for e in entries)

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Briefing — 아카이브</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+KR:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

  :root {{
    --bg:         #0d1117;
    --bg2:        #161b22;
    --bg3:        #21262d;
    --border:     #30363d;
    --text:       #e6edf3;
    --text2:      #8b949e;
    --text3:      #6e7681;
    --red:        #f85149;
    --red-dim:    #3d1f1f;
    --orange:     #e3b341;
    --orange-dim: #3d2f0d;
    --blue:       #58a6ff;
    --blue-dim:   #0d2140;
    --green:      #3fb950;
    --green-dim:  #122920;
    --purple:     #bc8cff;
    --purple-dim: #1f1340;
    --accent:     #1f6feb;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'IBM Plex Sans KR', sans-serif;
    background: var(--bg); color: var(--text);
    font-size: 14px; line-height: 1.6; min-height: 100vh;
  }}

  /* ── 헤더 ── */
  .site-header {{
    background: var(--bg2); border-bottom: 1px solid var(--border);
    padding: 24px 32px; display: flex; align-items: center; gap: 14px;
    position: sticky; top: 0; z-index: 100;
  }}
  .logo-mark {{
    width: 36px; height: 36px; background: var(--accent); border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'IBM Plex Mono', monospace; font-weight: 500; font-size: 14px; color: #fff;
    flex-shrink: 0;
  }}
  .header-title {{ font-size: 16px; font-weight: 600; }}
  .header-sub   {{ font-size: 12px; color: var(--text2); font-family: 'IBM Plex Mono', monospace; }}
  .header-nav   {{ margin-left: auto; display: flex; gap: 12px; }}
  .nav-link {{
    font-size: 12px; color: var(--text2); text-decoration: none;
    padding: 5px 12px; border: 1px solid var(--border); border-radius: 6px;
    transition: all .15s;
  }}
  .nav-link:hover {{ color: var(--text); border-color: var(--accent); }}

  /* ── 누적 통계 ── */
  .summary-bar {{
    background: var(--bg2); border-bottom: 1px solid var(--border);
    padding: 20px 32px; display: flex; gap: 40px; align-items: center;
  }}
  .sum-item  {{ display: flex; flex-direction: column; align-items: center; }}
  .sum-num   {{ font-family: 'IBM Plex Mono', monospace; font-size: 28px; font-weight: 500; line-height: 1; }}
  .sum-label {{ font-size: 11px; color: var(--text2); margin-top: 4px; }}
  .sum-divider {{ width: 1px; height: 40px; background: var(--border); }}

  /* ── 메인 ── */
  .main {{ padding: 32px; max-width: 1200px; margin: 0 auto; }}

  .section-header {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border);
  }}
  .section-title {{ font-size: 15px; font-weight: 600; }}

  /* ── 테이블 ── */
  .archive-table {{
    width: 100%; border-collapse: collapse;
    background: var(--bg2); border-radius: 8px; overflow: hidden;
    border: 1px solid var(--border);
  }}
  .archive-table thead tr {{
    background: var(--bg3); border-bottom: 1px solid var(--border);
  }}
  .archive-table th {{
    padding: 10px 14px; font-size: 11px; font-weight: 600;
    color: var(--text2); text-align: left; letter-spacing: .5px; text-transform: uppercase;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .entry-row {{
    border-bottom: 1px solid var(--border);
    cursor: pointer; transition: background .1s;
  }}
  .entry-row:last-child {{ border-bottom: none; }}
  .entry-row:hover      {{ background: var(--bg3); }}
  .row-high {{ border-left: 3px solid var(--red); }}
  .row-mid  {{ border-left: 3px solid var(--orange); }}

  .archive-table td {{ padding: 12px 14px; vertical-align: middle; }}

  .td-date  {{ font-family: 'IBM Plex Mono', monospace; font-size: 13px; white-space: nowrap; }}
  .td-total {{ font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: var(--text2); text-align: center; }}
  .num-high   {{ font-family: 'IBM Plex Mono', monospace; font-size: 14px; font-weight: 600; color: var(--red); }}
  .num-medium {{ font-family: 'IBM Plex Mono', monospace; font-size: 14px; color: var(--orange); }}
  .td-high, .td-medium {{ text-align: center; }}

  .td-badges {{ white-space: nowrap; }}
  .kev-pill {{
    display: inline-block; font-size: 10px; font-weight: 700;
    padding: 2px 7px; border-radius: 4px;
    background: #3d1a00; color: #ff6b35; margin-right: 4px;
  }}
  .action-pill {{
    display: inline-block; font-size: 10px;
    padding: 2px 7px; border-radius: 4px;
    background: var(--orange-dim); color: var(--orange);
  }}

  /* ── 카테고리 바 ── */
  .cat-bar {{
    display: flex; height: 6px; border-radius: 3px; overflow: hidden;
    min-width: 120px; background: var(--bg3);
  }}
  .cat-dot:nth-child(1) {{ background: var(--red); }}
  .cat-dot:nth-child(2) {{ background: var(--orange); }}
  .cat-dot:nth-child(3) {{ background: var(--blue); }}
  .cat-dot:nth-child(4) {{ background: var(--green); }}
  .cat-dot:nth-child(5) {{ background: var(--purple); }}
  .cat-dot:nth-child(6) {{ background: var(--text3); }}

  .td-link a {{
    font-size: 12px; color: var(--blue); text-decoration: none;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .td-link a:hover {{ text-decoration: underline; }}

  /* ── 범례 ── */
  .legend {{
    display: flex; gap: 16px; margin-top: 12px; flex-wrap: wrap;
  }}
  .legend-item {{
    display: flex; align-items: center; gap: 6px;
    font-size: 11px; color: var(--text3);
  }}
  .legend-dot {{
    width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0;
  }}

  /* ── 푸터 ── */
  .site-footer {{
    margin-top: 40px; padding: 24px 32px; border-top: 1px solid var(--border);
    color: var(--text3); font-size: 11px; font-family: 'IBM Plex Mono', monospace;
    display: flex; justify-content: space-between;
  }}

  @media (max-width: 768px) {{
    .site-header, .summary-bar {{ padding: 14px 16px; gap: 16px; }}
    .main {{ padding: 16px; }}
    .td-bar, .td-badges {{ display: none; }}
  }}
</style>
</head>
<body>

<header class="site-header">
  <div class="logo-mark">SB</div>
  <div>
    <div class="header-title">Security Briefing</div>
    <div class="header-sub">아카이브 — {date_str_now}</div>
  </div>
  <nav class="header-nav">
    <a href="index.html" class="nav-link">최신 브리핑 →</a>
  </nav>
</header>

<div class="summary-bar">
  <div class="sum-item">
    <span class="sum-num" style="color:var(--text)">{total_days}</span>
    <span class="sum-label">수집일</span>
  </div>
  <div class="sum-divider"></div>
  <div class="sum-item">
    <span class="sum-num" style="color:var(--text2)">{total_items}</span>
    <span class="sum-label">총 항목</span>
  </div>
  <div class="sum-item">
    <span class="sum-num" style="color:var(--red)">{total_high}</span>
    <span class="sum-label">긴급 누적</span>
  </div>
  <div class="sum-item">
    <span class="sum-num" style="color:#ff6b35">{total_kev}</span>
    <span class="sum-label">KEV 누적</span>
  </div>
  <div class="sum-item">
    <span class="sum-num" style="color:var(--orange)">{total_action}</span>
    <span class="sum-label">조치 필요 누적</span>
  </div>
</div>

<main class="main">
  <div class="section-header">
    <span class="section-title">📅 날짜별 브리핑</span>
  </div>

  <table class="archive-table">
    <thead>
      <tr>
        <th>날짜</th>
        <th>총계</th>
        <th>긴급</th>
        <th>모니터링</th>
        <th>배지</th>
        <th>카테고리 분포</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:var(--red)"></div>취약점</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--orange)"></div>공급망</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--blue)"></div>규제</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--green)"></div>위협 인텔</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--purple)"></div>도구·기술</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--text3)"></div>기타</div>
  </div>
</main>

<footer class="site-footer">
  <span>Security Briefing · Archive</span>
  <span>업데이트: {date_str_now}</span>
</footer>

</body>
</html>"""

    archive_path = output_dir / "archive.html"
    archive_path.write_text(html, encoding="utf-8")
    print(f"  → 아카이브 저장: {archive_path} ({total_days}일치)")


# ─── 메인 ───────────────────────────────────────────────────────────────────
def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY 환경 변수가 설정되지 않았습니다.")

    client       = anthropic.Anthropic(api_key=api_key)
    cutoff_hours = int(os.environ.get("CUTOFF_HOURS", "24"))

    # 1. RSS 수집
    items = collect_all_feeds(cutoff_hours=cutoff_hours)
    if not items:
        print("[!] 수집된 항목 없음. 종료.")
        return

    # 2. NVD + CISA KEV 병렬 호출
    print("[2/4] NVD API + CISA KEV API 호출 중...")
    with ThreadPoolExecutor(max_workers=2) as executor:
        f_nvd = executor.submit(fetch_nvd_recent, cutoff_hours)
        f_kev = executor.submit(fetch_cisa_kev,   cutoff_hours)
        nvd_map = f_nvd.result()
        kev_ids = f_kev.result()

    items = enrich_with_nvd_kev(items, nvd_map, kev_ids)

    # 3. AI 분류
    analyzed = analyze_batch(items, client)

    # 4. HTML 생성
    print("[4/4] HTML 브리핑 생성 중...")
    output_dir = Path(os.environ.get("OUTPUT_DIR", "output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    today     = datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d")
    html_path = output_dir / f"brief_{today}.html"
    generate_html(analyzed, html_path, feed_count=len(FEEDS))

    latest_path = output_dir / "index.html"
    latest_path.write_text(html_path.read_text(encoding="utf-8"), encoding="utf-8")

    json_path = output_dir / f"brief_{today}.json"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(analyzed, f, ensure_ascii=False, indent=2)

    # 아카이브 뷰어 갱신
    generate_archive(output_dir)

    high_count   = sum(1 for x in analyzed if x.get("relevance") == "high")
    medium_count = sum(1 for x in analyzed if x.get("relevance") == "medium")
    action_count = sum(1 for x in analyzed if x.get("action_required"))
    kev_count    = sum(1 for x in analyzed if x.get("kev"))

    print(f"""
╔════════════════════════════════════════════════╗
║  브리핑 생성 완료
║  총 {len(analyzed):>3}건 | 긴급 {high_count:>2} | 모니터링 {medium_count:>2} | 조치필요 {action_count:>2} | KEV {kev_count:>2}
║  {html_path}
╚════════════════════════════════════════════════╝""")

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write(f"""## 🔐 보안 브리핑 완료 — {today}

| 구분 | 건수 |
|------|------|
| 총 수집 | {len(analyzed)} |
| 🔴 긴급 | {high_count} |
| 🟡 모니터링 | {medium_count} |
| ⚡ 조치 필요 | {action_count} |
| 🔥 KEV 등재 | {kev_count} |

📄 `output/brief_{today}.html` 에 저장되었습니다.
""")


if __name__ == "__main__":
    main()
