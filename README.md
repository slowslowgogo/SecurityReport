# 🔐 Security Briefing — AI 보안 브리핑 자동화

매일 수십~수백 건의 보안 피드를 AI가 자동 수집·분류하여 팀 관련 항목만 추린 HTML 브리핑을 생성합니다.

## 아키텍처

```
[GitHub Actions cron]
       ↓
[collect_feeds.py]
  1. RSS/Atom 피드 수집 (19개+ 소스, 병렬)
  2. Claude API로 관련성 분류 (high/medium/low)
  3. HTML 브리핑 생성
       ↓
[output/brief_YYYY-MM-DD.html]  ← 저장소에 커밋
[output/index.html]              ← GitHub Pages
```

## 셋업

### 1. Secrets 설정
GitHub 저장소 → Settings → Secrets and variables → Actions

```
ANTHROPIC_API_KEY = sk-ant-...
```

### 2. GitHub Pages 활성화
Settings → Pages → Source: `GitHub Actions`

### 3. 스케줄
기본값: 평일 오전 8시 KST 자동 실행
수동 실행: Actions 탭 → `Security Briefing` → `Run workflow`

## 출력물

| 파일 | 설명 |
|------|------|
| `output/brief_YYYY-MM-DD.html` | 일별 브리핑 |
| `output/index.html` | 최신 브리핑 (GitHub Pages) |
| `output/brief_YYYY-MM-DD.json` | 원본 데이터 (아카이브) |

## 분류 기준

| 등급 | 기준 |
|------|------|
| 🔴 긴급 | Android/NFC 취약점, 공급망 공격, CRA 규제 변경, CISA KEV |
| 🟡 모니터링 | Linux/OSS 취약점 (CVSS 7+), 보안 도구 업데이트 |
| ⚪ 참고 | 일반 보안 뉴스 |

## 피드 추가

`scripts/collect_feeds.py` 상단의 `FEEDS` 리스트에 추가:

```python
{"url": "https://example.com/feed.xml", "source": "Example Feed"},
```

## 팀 컨텍스트 커스터마이징

`TEAM_CONTEXT` 상수를 수정하여 관심 도메인, 제품군, 분류 기준을 팀에 맞게 조정하세요.
