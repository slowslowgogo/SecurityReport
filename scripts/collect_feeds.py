#!/usr/bin/env python3
"""
Security Feed Collector & AI Analyzer
수집 → 분석 → HTML 브리핑 생성
"""

import os
import json
import hashlib
import feedparser
import anthropic
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

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
    {"url": "https://www.cisa.gov/feeds/alerts.xml",           "source": "CISA Alerts"},
    {"url": "https://www.cisa.gov/feeds/kev.xml",              "source": "CISA KEV"},
    # NVD
    {"url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml", "source": "NVD CVE"},
    # Android Security
    {"url": "https://source.android.com/feed.xml",             "source": "Android Security"},
    # 주요 보안 미디어
    {"url": "https://feeds.feedburner.com/TheHackersNews",     "source": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/",          "source": "BleepingComputer"},
    {"url": "https://krebsonsecurity.com/feed/",               "source": "KrebsOnSecurity"},
    {"url": "https://www.darkreading.com/rss.xml",             "source": "Dark Reading"},
    {"url": "https://threatpost.com/feed/",                    "source": "Threatpost"},
    {"url": "https://www.securityweek.com/feed",               "source": "SecurityWeek"},
    # 취약점 / 익스플로잇
    {"url": "https://www.exploit-db.com/rss.xml",              "source": "Exploit-DB"},
    {"url": "https://seclists.org/rss/fulldisclosure.rss",     "source": "Full Disclosure"},
    # 공급망 / OSS 보안
    {"url": "https://openssf.org/feed/",                       "source": "OpenSSF"},
    {"url": "https://socket.dev/rss.xml",                      "source": "Socket.dev"},
    # EU / 규제
    {"url": "https://www.enisa.europa.eu/publications/rss",    "source": "ENISA"},
    # 위협 인텔리전스
    {"url": "https://feeds.feedburner.com/rssfeed_mandiant",   "source": "Mandiant"},
    {"url": "https://www.recordedfuture.com/feed",             "source": "Recorded Future"},
    {"url": "https://unit42.paloaltonetworks.com/feed/",       "source": "Unit 42"},
    # GitHub Security
    {"url": "https://github.blog/category/security/feed/",     "source": "GitHub Security Blog"},
]


# ─── 피드 수집 ──────────────────────────────────────────────────────────────
def fetch_feed(feed_info: dict, cutoff_hours: int = 48) -> list[dict]:
    """단일 RSS 피드 수집. cutoff_hours 이내 항목만 반환."""
    items = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)

    try:
        parsed = feedparser.parse(
            feed_info["url"],
            request_headers={"User-Agent": "SecurityBriefBot/1.0"}
        )
        for entry in parsed.entries:
            # 날짜 파싱
            pub = None
            for attr in ("published_parsed", "updated_parsed", "created_parsed"):
                t = getattr(entry, attr, None)
                if t:
                    pub = datetime(*t[:6], tzinfo=timezone.utc)
                    break
            if pub and pub < cutoff:
                continue  # 오래된 항목 스킵

            title = getattr(entry, "title", "").strip()
            link  = getattr(entry, "link",  "").strip()
            summary = getattr(entry, "summary", getattr(entry, "description", ""))[:800]

            if not title or not link:
                continue

            uid = hashlib.md5(link.encode()).hexdigest()
            items.append({
                "uid":     uid,
                "source":  feed_info["source"],
                "title":   title,
                "link":    link,
                "summary": summary,
                "pub_date": pub.isoformat() if pub else None,
            })
    except Exception as e:
        print(f"  [WARN] {feed_info['source']}: {e}")

    return items


def collect_all_feeds(cutoff_hours: int = 48) -> list[dict]:
    """모든 피드 병렬 수집 + 중복 제거"""
    all_items = []
    seen_uids = set()

    print(f"[1/3] 피드 수집 중 ({len(FEEDS)}개 소스)...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_feed, f, cutoff_hours): f for f in FEEDS}
        for future in as_completed(futures):
            for item in future.result():
                if item["uid"] not in seen_uids:
                    seen_uids.add(item["uid"])
                    all_items.append(item)

    print(f"  → 총 {len(all_items)}건 수집 (중복 제거 완료)")
    return all_items


# ─── AI 분류 ────────────────────────────────────────────────────────────────
def analyze_batch(items: list[dict], client: anthropic.Anthropic) -> list[dict]:
    """Claude API로 배치 분류. 10건씩 묶어 처리."""
    BATCH_SIZE = 10
    results = []

    print(f"[2/3] AI 분류 중 ({len(items)}건, {(len(items)-1)//BATCH_SIZE+1}배치)...")

    for i in range(0, len(items), BATCH_SIZE):
        batch = items[i:i + BATCH_SIZE]
        batch_text = "\n\n".join(
            f"[{j+1}] 제목: {it['title']}\n출처: {it['source']}\n내용: {it['summary'][:300]}"
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

항목 목록:
{batch_text}"""

        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                system=TEAM_CONTEXT,
                messages=[{"role": "user", "content": prompt}]
            )
            raw = response.content[0].text.strip()
            # JSON 펜스 제거
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            parsed = json.loads(raw)
            for result in parsed:
                idx = result.get("idx", 1) - 1
                if 0 <= idx < len(batch):
                    batch[idx].update(result)
                    results.append(batch[idx])
        except Exception as e:
            print(f"  [WARN] 배치 {i//BATCH_SIZE+1} 분석 실패: {e}")
            for item in batch:
                item["relevance"] = "low"
                item["category"] = "other"
                item["summary_ko"] = item["title"][:50]
                item["action_required"] = False
                item["action_type"] = "none"
                item["cve_ids"] = []
                item["cvss"] = None
                results.append(item)

        print(f"  → 배치 {i//BATCH_SIZE+1}/{(len(items)-1)//BATCH_SIZE+1} 완료")

    return results


# ─── HTML 생성 ───────────────────────────────────────────────────────────────
def generate_html(items: list[dict], output_path: Path) -> None:
    """분석 결과를 보안 브리핑 HTML로 변환"""

    high   = [x for x in items if x.get("relevance") == "high"]
    medium = [x for x in items if x.get("relevance") == "medium"]
    low    = [x for x in items if x.get("relevance") == "low"]
    action = [x for x in items if x.get("action_required")]

    # 카테고리 통계
    cat_counts: dict[str, int] = {}
    for item in items:
        c = item.get("category", "other")
        cat_counts[c] = cat_counts.get(c, 0) + 1

    cat_labels = {
        "vuln": "취약점", "supply_chain": "공급망", "regulatory": "규제",
        "threat_intel": "위협 인텔", "tool": "도구·기술", "other": "기타"
    }

    now_kst = datetime.now(timezone(timedelta(hours=9)))
    date_str = now_kst.strftime("%Y년 %m월 %d일 %H:%M KST")

    def item_card(item: dict) -> str:
        rel = item.get("relevance", "low")
        rel_class = {"high": "rel-high", "medium": "rel-medium", "low": "rel-low"}.get(rel, "rel-low")
        rel_label = {"high": "긴급", "medium": "모니터링", "low": "참고"}.get(rel, "참고")
        cat = cat_labels.get(item.get("category", "other"), "기타")
        cves = item.get("cve_ids", [])
        cve_html = " ".join(f'<span class="cve-tag">{c}</span>' for c in cves) if cves else ""
        cvss = item.get("cvss")
        cvss_html = f'<span class="cvss-badge">CVSS {cvss}</span>' if cvss else ""
        action_html = '<span class="action-badge">⚡ 조치 필요</span>' if item.get("action_required") else ""
        pub = item.get("pub_date", "")
        pub_display = pub[:10] if pub else ""

        return f"""
        <div class="item-card {rel_class}">
          <div class="item-header">
            <span class="rel-badge">{rel_label}</span>
            <span class="cat-badge">{cat}</span>
            {action_html}
            {cvss_html}
          </div>
          <div class="item-title">
            <a href="{item.get('link','#')}" target="_blank" rel="noopener">{item.get('title','')}</a>
          </div>
          <div class="item-summary">{item.get('summary_ko', '')}</div>
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
    --bg:        #0d1117;
    --bg2:       #161b22;
    --bg3:       #21262d;
    --border:    #30363d;
    --text:      #e6edf3;
    --text2:     #8b949e;
    --text3:     #6e7681;
    --red:       #f85149;
    --red-dim:   #3d1f1f;
    --orange:    #e3b341;
    --orange-dim:#3d2f0d;
    --blue:      #58a6ff;
    --blue-dim:  #0d2140;
    --green:     #3fb950;
    --green-dim: #122920;
    --purple:    #bc8cff;
    --teal:      #39d353;
    --accent:    #1f6feb;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'IBM Plex Sans KR', sans-serif;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── 헤더 ── */
  .site-header {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 24px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(8px);
  }}
  .header-left {{ display: flex; align-items: center; gap: 14px; }}
  .logo-mark {{
    width: 36px; height: 36px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 500; font-size: 14px; color: #fff;
    flex-shrink: 0;
  }}
  .header-title {{ font-size: 16px; font-weight: 600; letter-spacing: -0.3px; }}
  .header-date {{ font-size: 12px; color: var(--text2); font-family: 'IBM Plex Mono', monospace; }}
  .header-right {{ display: flex; gap: 8px; align-items: center; }}

  /* ── 통계 바 ── */
  .stats-bar {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 16px 32px;
    display: flex;
    gap: 32px;
    align-items: center;
    overflow-x: auto;
  }}
  .stats-group {{ display: flex; gap: 24px; align-items: center; }}
  .stats-divider {{ width: 1px; height: 32px; background: var(--border); flex-shrink: 0; }}

  .big-stat {{ display: flex; flex-direction: column; align-items: center; }}
  .big-stat .num {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 24px; font-weight: 500; line-height: 1;
  }}
  .big-stat .label {{ font-size: 11px; color: var(--text2); margin-top: 3px; }}
  .num-red {{ color: var(--red); }}
  .num-orange {{ color: var(--orange); }}
  .num-blue {{ color: var(--blue); }}
  .num-white {{ color: var(--text); }}

  .stat-item {{ display: flex; flex-direction: column; align-items: center; }}
  .stat-num {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 18px; font-weight: 500; color: var(--text);
  }}
  .stat-label {{ font-size: 11px; color: var(--text3); margin-top: 2px; }}

  /* ── 메인 레이아웃 ── */
  .main {{ padding: 32px; max-width: 1400px; margin: 0 auto; }}

  /* ── 필터 바 ── */
  .filter-bar {{
    display: flex; gap: 8px; margin-bottom: 24px;
    flex-wrap: wrap; align-items: center;
  }}
  .filter-btn {{
    padding: 6px 14px;
    border-radius: 20px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--text2);
    font-size: 12px;
    font-family: 'IBM Plex Sans KR', sans-serif;
    cursor: pointer;
    transition: all .15s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent); border-color: var(--accent);
    color: #fff;
  }}

  /* ── 섹션 ── */
  .brief-section {{ margin-bottom: 40px; }}
  .section-title {{
    font-size: 15px; font-weight: 600;
    display: flex; align-items: center; gap: 8px;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }}
  .section-icon {{ font-size: 16px; }}
  .count-badge {{
    margin-left: auto;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px; font-weight: 500;
    background: var(--bg3); color: var(--text2);
    padding: 2px 8px; border-radius: 10px;
  }}

  /* ── 카드 그리드 ── */
  .items-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
    gap: 12px;
  }}

  /* ── 아이템 카드 ── */
  .item-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    transition: border-color .15s, transform .15s;
    border-left: 3px solid transparent;
  }}
  .item-card:hover {{
    transform: translateY(-1px);
    border-color: var(--accent);
  }}
  .rel-high  {{ border-left-color: var(--red); }}
  .rel-medium{{ border-left-color: var(--orange); }}
  .rel-low   {{ border-left-color: var(--border); }}

  .item-header {{
    display: flex; gap: 6px; margin-bottom: 8px;
    flex-wrap: wrap; align-items: center;
  }}

  .rel-badge {{
    font-size: 10px; font-weight: 600; letter-spacing: .5px;
    padding: 2px 7px; border-radius: 4px; text-transform: uppercase;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .rel-high  .rel-badge {{ background: var(--red-dim);    color: var(--red); }}
  .rel-medium .rel-badge {{ background: var(--orange-dim); color: var(--orange); }}
  .rel-low   .rel-badge {{ background: var(--bg3);         color: var(--text3); }}

  .cat-badge {{
    font-size: 10px; padding: 2px 7px; border-radius: 4px;
    background: var(--blue-dim); color: var(--blue);
  }}
  .action-badge {{
    font-size: 10px; padding: 2px 7px; border-radius: 4px;
    background: #2d1f0d; color: var(--orange);
    font-weight: 600;
  }}
  .cvss-badge {{
    font-size: 10px; font-family: 'IBM Plex Mono', monospace;
    padding: 2px 7px; border-radius: 4px;
    background: var(--red-dim); color: var(--red);
  }}

  .item-title {{
    font-size: 13px; font-weight: 500;
    margin-bottom: 6px; line-height: 1.45;
  }}
  .item-title a {{
    color: var(--text);
    text-decoration: none;
  }}
  .item-title a:hover {{ color: var(--blue); }}

  .item-summary {{
    font-size: 12px; color: var(--text2);
    line-height: 1.5; margin-bottom: 8px;
  }}

  .item-meta {{
    display: flex; gap: 6px; flex-wrap: wrap; align-items: center;
  }}
  .source-tag, .date-tag {{
    font-size: 11px; color: var(--text3);
    font-family: 'IBM Plex Mono', monospace;
  }}
  .cve-tag {{
    font-size: 10px; font-family: 'IBM Plex Mono', monospace;
    padding: 1px 6px; border-radius: 3px;
    background: var(--green-dim); color: var(--green);
  }}

  /* ── 빈 섹션 ── */
  .empty-note {{
    padding: 32px; text-align: center;
    color: var(--text3); font-size: 13px;
    border: 1px dashed var(--border); border-radius: 8px;
  }}

  /* ── 푸터 ── */
  .site-footer {{
    margin-top: 40px; padding: 24px 32px;
    border-top: 1px solid var(--border);
    color: var(--text3); font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
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
  </div>
  <div class="stats-divider"></div>
  <div class="stats-group">
    {cat_stats_html}
  </div>
</div>

<main class="main">
  {section_html("긴급 — 즉시 검토 필요", "🔴", high, "section-high") or
   '<section class="brief-section"><p class="empty-note">긴급 항목 없음</p></section>'}
  {section_html("모니터링 — 추이 관찰", "🟡", medium, "section-medium") or
   '<section class="brief-section"><p class="empty-note">모니터링 항목 없음</p></section>'}
  {section_html("참고", "⚪", low, "section-low")}
</main>

<footer class="site-footer">
  <span>Security Briefing · AI-augmented threat monitoring</span>
  <span>생성: {date_str} · 수집 소스: {len(FEEDS)}개 피드</span>
</footer>

</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    print(f"  → HTML 저장: {output_path}")


# ─── 메인 ───────────────────────────────────────────────────────────────────
def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY 환경 변수가 설정되지 않았습니다.")

    client = anthropic.Anthropic(api_key=api_key)

    # 1. 수집
    items = collect_all_feeds(cutoff_hours=48)
    if not items:
        print("[!] 수집된 항목 없음. 종료.")
        return

    # 2. AI 분류
    analyzed = analyze_batch(items, client)

    # 3. HTML 생성
    print("[3/3] HTML 브리핑 생성 중...")
    output_dir = Path(os.environ.get("OUTPUT_DIR", "output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d")
    html_path = output_dir / f"brief_{today}.html"
    generate_html(analyzed, html_path)

    # 최신 파일도 덮어쓰기 (GitHub Pages index용)
    latest_path = output_dir / "index.html"
    latest_path.write_text(html_path.read_text(encoding="utf-8"), encoding="utf-8")

    # JSON 저장 (아카이브)
    json_path = output_dir / f"brief_{today}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(analyzed, f, ensure_ascii=False, indent=2)

    high_count   = sum(1 for x in analyzed if x.get("relevance") == "high")
    medium_count = sum(1 for x in analyzed if x.get("relevance") == "medium")
    action_count = sum(1 for x in analyzed if x.get("action_required"))

    print(f"""
╔══════════════════════════════════════╗
║  브리핑 생성 완료
║  총 {len(analyzed):>3}건 | 긴급 {high_count:>2} | 모니터링 {medium_count:>2} | 조치필요 {action_count:>2}
║  {html_path}
╚══════════════════════════════════════╝""")

    # GitHub Actions summary 출력
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

📄 `output/brief_{today}.html` 에 저장되었습니다.
""")


if __name__ == "__main__":
    main()
