import React, { FormEvent, useEffect, useState } from 'react'

export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type ScanState = 'idle' | 'scanning' | 'completed' | 'error'
export type PageRoute = 'scanner' | 'analysis' | 'how-it-works' | 'capabilities' | 'education' | 'about' | 'support'

export interface UrlQueryParam {
  key: string
  value: string
  isSensitive: boolean
}

export interface UrlParts {
  scheme: string
  subdomain: string
  domain: string
  tld: string
  port: string
  path: string
  queryString: string
  querySeparator: string
  fragment: string
  queryParams: UrlQueryParam[]
}

export interface IpResolution {
  ips: string[]
  primaryIp: string | null
  lookupError?: string
}

export interface IpIntel {
  ip: string | null
  city?: string
  region?: string
  country?: string
  countryCode?: string
  latitude?: number
  longitude?: number
  timezone?: string
  asn?: string
  org?: string
  rdapAvailable?: boolean
  source?: string
  error?: string
}

export interface DnsIntel {
  A: string[]
  AAAA: string[]
  CNAME: string[]
  MX: string[]
  NS: string[]
  TXT: string[]
  SOA: string[]
  source?: string
  error?: string
}

export interface OsintIntel {
  subdomains: string[]
  reverseIpDomains: string[]
  urlscanSightings: Array<{
    uuid?: string
    pageUrl?: string
    taskTime?: string
    country?: string
    ip?: string
  }>
  phishtank?: {
    inDatabase: boolean | null
    verified: boolean | null
    phishId?: string
    submissionUrl?: string
    source?: string
    error?: string
  }
  urlhaus?: {
    listed: boolean | null
    threat?: string
    urlStatus?: string
    lastSeen?: string
    source?: string
    error?: string
  }
  virustotal?: {
    malicious: number | null
    suspicious: number | null
    harmless: number | null
    undetected: number | null
    source?: string
    error?: string
  }
  abuseIpdb?: {
    confidenceScore: number | null
    totalReports: number | null
    lastReportedAt?: string | null
    source?: string
    error?: string
  }
  sources: string[]
  notes: string[]
}

export interface WhoisIntel {
  domain: string
  registrar: string
  creationDate: string
  expirationDate?: string
  updatedDate?: string
  domainAgeDays: number | null
  domainAgeFormatted: string
  status: string[]
  nameservers: string[]
  isNewlyRegistered: boolean
  dnssec?: string
  source: string
  cautionNote?: string
  error?: string
}

export interface AnalysisDetails {
  url: string
  normalizedUrl: string
  protocol: string
  hostname: string
  domain: string
  tld: string
  path: string
  fragment: string
  port: string
  urlParts: UrlParts
  queryParams: UrlQueryParam[]
  entropy: {
    domainEntropy: number
    urlEntropy: number
    level: 'Low' | 'Moderate' | 'High' | 'Suspiciously High'
    explanation: string
  }
  typosquatting: {
    detected: boolean
    targetBrand?: string
    similarityScore?: number
    patternType?: string
    explanation: string
  }
  homoglyphs: {
    detected: boolean
    characters: Array<{ char: string; codePoint: string; lookalike: string; script: string }>
    explanation: string
  }
  structure: {
    hasSuspiciousPath: boolean
    suspiciousKeywords: string[]
    hasEncodedChars: boolean
    hasObfuscatedQuery: boolean
    hasIpHostname: boolean
    isHttps: boolean
    explanation: string
  }
  resolution: IpResolution
  ipIntel: IpIntel
  dns: DnsIntel
  osint: OsintIntel
  whois: WhoisIntel
  threatScore: number
  verdict: Verdict
  reasons: Array<{ title: string; detail: string; severity: 'high' | 'medium' | 'low' | 'info' }>
  generatedAt: string
  backendSource: string
}

const CONFIGURED_API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/$/, '')

// When the frontend is served over HTTPS (including the PhishGuard preview on
// localhost:8443), a direct HTTP call to 127.0.0.1:8000 is blocked by the
// browser as mixed content. In development Vite proxies /api to FastAPI, so
// prefer the same-origin endpoint in that situation. An explicit HTTPS backend
// URL is still respected for production deployments.
function getAnalysisEndpoint(): string {
  if (typeof window === 'undefined') return `${CONFIGURED_API_BASE_URL}/api/analyze`
  const pageIsHttps = window.location.protocol === 'https:'
  const configuredIsHttp = /^http:\/\//i.test(CONFIGURED_API_BASE_URL)

  if (!CONFIGURED_API_BASE_URL || (pageIsHttps && configuredIsHttp)) {
    return '/api/analyze'
  }

  return `${CONFIGURED_API_BASE_URL}/api/analyze`
}

function calculateShannonEntropy(str: string): number {
  if (!str) return 0
  const freq: Record<string, number> = {}
  for (const char of str) freq[char] = (freq[char] || 0) + 1
  let entropy = 0
  for (const count of Object.values(freq)) {
    const p = count / str.length
    entropy -= p * Math.log2(p)
  }
  return Number(entropy.toFixed(3))
}

export interface LocalUrlPreview {
  normalizedUrl: string
  urlParts: UrlParts
  protocol: string
  hostname: string
  domain: string
  tld: string
  path: string
  fragment: string
  port: string
  queryParams: UrlQueryParam[]
  entropy: number
}

const COMMON_MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'firm.in', 'net.in', 'org.in', 'gen.in', 'ind.in',
  'com.br', 'com.cn', 'com.hk', 'com.sg', 'co.jp', 'co.kr', 'co.nz', 'co.za', 'com.mx', 'com.tr', 'com.tw', 'com.ar', 'com.ua', 'com.pl',
])

function parseDomainParts(hostname: string) {
  const labels = hostname.split('.').filter(Boolean)
  if (labels.length <= 1) return { subdomain: '', domain: hostname, tld: '' }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return { subdomain: '', domain: hostname, tld: '' }
  const suffix2 = labels.slice(-2).join('.').toLowerCase()
  const suffixLabels = COMMON_MULTI_LABEL_SUFFIXES.has(suffix2) ? 2 : 1
  const tld = `.${labels.slice(-suffixLabels).join('.')}`
  const domainIndex = labels.length - suffixLabels - 1
  const domain = labels.slice(Math.max(0, domainIndex), labels.length).join('.')
  const subdomain = labels.slice(0, Math.max(0, domainIndex)).join('.')
  return { subdomain, domain, tld }
}

function isSensitiveQueryKey(key: string) {
  return ['token', 'auth', 'pass', 'password', 'key', 'session', 'redirect', 'url', 'return', 'code', 'secret'].some(term => key.toLowerCase().includes(term))
}

export function parseUrlLocally(rawInputUrl: string): LocalUrlPreview {
  let candidate = rawInputUrl.trim()
  if (!/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`
  const parsed = new URL(candidate)
  const hostname = parsed.hostname
  const { subdomain, domain, tld } = parseDomainParts(hostname)
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : parsed.protocol === 'http:' ? '80' : '')
  const queryParams: UrlQueryParam[] = []
  parsed.searchParams.forEach((value, key) => queryParams.push({ key, value, isSensitive: isSensitiveQueryKey(key) }))
  const urlParts: UrlParts = {
    scheme: parsed.protocol.replace(':', ''),
    subdomain: subdomain || '—',
    domain: domain || hostname,
    tld: tld || '—',
    port: port || '—',
    path: parsed.pathname || '/',
    queryString: parsed.search ? parsed.search.slice(1) : '—',
    querySeparator: parsed.search ? '?' : '—',
    fragment: parsed.hash ? parsed.hash.slice(1) : '—',
    queryParams,
  }
  return {
    normalizedUrl: parsed.toString(), urlParts, protocol: parsed.protocol, hostname, domain, tld,
    path: parsed.pathname || '/', fragment: parsed.hash.slice(1), port, queryParams,
    entropy: calculateShannonEntropy(parsed.toString()),
  }
}

async function fetchRemoteAnalysis(url: string): Promise<AnalysisDetails> {
  const endpoint = getAnalysisEndpoint()

  let response: Response
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Network request failed'
    throw new Error(
      `Could not reach the FastAPI analysis service. ${reason}. Start the backend with ` +
      `python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000 and keep the /api proxy enabled.`
    )
  }

  let payload: any = null
  try { payload = await response.json() } catch { /* handled below */ }

  if (!response.ok) {
    const detail = payload?.detail || `Backend returned HTTP ${response.status}`
    throw new Error(detail)
  }

  return payload as AnalysisDetails
}

// Preset Samples for quick testing
const SAMPLE_URLS = [
  { label: 'PayPal Spoof', url: 'https://secure-paypa1-login.com/account/verify?token=8f9a2b1c', type: 'Typosquatting' },
  { label: 'Google Homoglyph', url: 'https://googӏe.com/signin/oauth', type: 'Homoglyph' },
  { label: 'Encoded Token', url: 'https://auth-verification-service.net/portal/session?auth=cGFzc3dvcmRfcmVzZXRfdG9rZW49OTk4MTIz', type: 'High Entropy' },
  { label: 'Fresh Domain', url: 'https://fresh-domain-2026-verify.xyz/update', type: 'New Domain' },
  { label: 'Official GitHub', url: 'https://github.com/features/security', type: 'Safe Origin' },
]

// Inspection Steps for Scanner Flow
const SCAN_STEPS = [
  { id: '01', name: 'Inspecting URL Structure', desc: 'Scheme, host, subdomain, port, path & query' },
  { id: '02', name: 'Resolving Network Identity', desc: 'DNS A/AAAA records and destination IPs' },
  { id: '03', name: 'Checking WHOIS / RDAP', desc: 'Registration, registrar, age & nameservers' },
  { id: '04', name: 'Running OSINT Lookups', desc: 'Subdomains, reverse-IP & public scan sightings' },
  { id: '05', name: 'Inspecting Characters', desc: 'Unicode homoglyphs and lookalike indicators' },
  { id: '06', name: 'Analyzing Query Semantics', desc: 'Sensitive keys, encoding & entropy signals' },
  { id: '07', name: 'Building Risk Assessment', desc: 'Evidence-based score from returned signals' },
]

// SVG Icons & UI Graphics
function ArrowUpRight() {
  return (
    <svg className="icon-arr" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="7" y1="17" x2="17" y2="7" />
      <polyline points="7 7 17 7 17 17" />
    </svg>
  )
}

function ShieldCheckIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  )
}

function LockSafetyIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  )
}

function SearchPulseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  )
}

// Brand Logo
function Logo({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  return (
    <button
      type="button"
      className="brand-logo-btn"
      onClick={() => onNavigate('scanner')}
      aria-label="PhishGuard Home"
    >
      <div className="brand-mark">
        <span className="mark-bar mark-bar-1" />
        <span className="mark-bar mark-bar-2" />
        <span className="mark-bar mark-bar-3" />
      </div>
      <div className="brand-text">
        <span className="brand-name">PHISHGUARD</span>
        <span className="brand-tagline">URL &amp; DOMAIN AUDIT</span>
      </div>
    </button>
  )
}

// Navbar Component
function Navbar({
  currentRoute,
  onNavigate,
}: {
  currentRoute: PageRoute
  onNavigate: (route: PageRoute) => void
}) {
  const [mobileOpen, setMobileOpen] = useState(false)
  const navItems: Array<{ id: PageRoute; label: string }> = [
    { id: 'scanner', label: 'Scanner' },
    { id: 'analysis', label: 'Analysis' },
    { id: 'how-it-works', label: 'How It Works' },
    { id: 'capabilities', label: 'Capabilities' },
    { id: 'education', label: 'Education' },
    { id: 'about', label: 'About' },
    { id: 'support', label: 'Support' },
  ]

  const handleLinkClick = (id: PageRoute) => {
    onNavigate(id)
    setMobileOpen(false)
  }

  return (
    <header className="site-header">
      <div className="header-inner">
        <Logo onNavigate={onNavigate} />

        <nav className={`desktop-nav ${mobileOpen ? 'nav-open' : ''}`}>
          {navItems.map(item => (
            <button
              key={item.id}
              type="button"
              className={`nav-link-btn ${currentRoute === item.id ? 'nav-link-active' : ''}`}
              onClick={() => handleLinkClick(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="header-actions">
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => handleLinkClick('scanner')}
          >
            <span>Scan a URL</span>
            <ArrowUpRight />
          </button>

          <button
            type="button"
            className="mobile-toggle"
            onClick={() => setMobileOpen(v => !v)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileOpen}
          >
            <span className={`bar ${mobileOpen ? 'bar-top-open' : ''}`} />
            <span className={`bar ${mobileOpen ? 'bar-bot-open' : ''}`} />
          </button>
        </div>
      </div>
    </header>
  )
}

// Threat Gauge Circular Meter Component with Animated Score
function ThreatScoreGauge({ score, verdict }: { score: number; verdict: Verdict }) {
  const [displayedScore, setDisplayedScore] = useState(0)
  const radius = 86
  const stroke = 12
  const normalizedRadius = radius - stroke / 2
  const circumference = normalizedRadius * 2 * Math.PI

  useEffect(() => {
    // Respect reduced-motion preferences
    if (typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setDisplayedScore(score)
      return
    }

    const duration = 440
    const startTime = performance.now()

    const animateNumber = (now: number) => {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      // Ease out cubic
      const ease = 1 - Math.pow(1 - progress, 3)
      const current = Math.round(ease * score)
      setDisplayedScore(current)

      if (progress < 1) {
        requestAnimationFrame(animateNumber)
      } else {
        setDisplayedScore(score)
      }
    }

    const frameId = requestAnimationFrame(animateNumber)
    return () => cancelAnimationFrame(frameId)
  }, [score])

  const strokeDashoffset = circumference - (displayedScore / 100) * circumference
  const verdictColorClass =
    verdict === 'SAFE' ? 'color-safe' : verdict === 'SUSPICIOUS' ? 'color-suspicious' : 'color-malicious'

  return (
    <div className={`threat-gauge-container ${verdictColorClass} threat-gauge-scale-in`}>
      <div className="gauge-svg-wrapper">
        <svg height={radius * 2} width={radius * 2} viewBox={`0 0 ${radius * 2} ${radius * 2}`} className="gauge-svg">
          <circle
            className="gauge-bg-track"
            stroke="currentColor"
            fill="transparent"
            strokeWidth={stroke}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
          />
          <circle
            className="gauge-value-bar"
            stroke="currentColor"
            fill="transparent"
            strokeWidth={stroke}
            strokeDasharray={`${circumference} ${circumference}`}
            style={{ strokeDashoffset, transition: 'stroke-dashoffset 0.1s linear' }}
            strokeLinecap="round"
            r={normalizedRadius}
            cx={radius}
            cy={radius}
          />
        </svg>
        <div className="gauge-center-content">
          <span className="gauge-score-value">{displayedScore}</span>
          <span className="gauge-score-total">/ 100</span>
          <span className="gauge-score-badge">{verdict}</span>
        </div>
      </div>
      <div className="gauge-scale-legend">
        <span className="scale-item scale-safe"><i />0–20 Safe</span>
        <span className="scale-item scale-suspicious"><i />21–60 Suspicious</span>
        <span className="scale-item scale-malicious"><i />61–100 Malicious</span>
      </div>
    </div>
  )
}

// Cybersecurity Educational Carousel (5 Editorial Slides)
const CAROUSEL_SLIDES = [
  {
    id: '01',
    tag: 'TYPOSQUATTING & BRAND SPOOFING',
    title: 'Spot the Spoof',
    description: 'Phishing domains often imitate legitimate brands by changing, adding, or rearranging characters.',
    bullets: [
      'Lookalike character substitutions (e.g., number "1" for letter "l")',
      'Prepended/appended security keywords (e.g., "secure-login")',
      'Levenshtein distance & brand keyword analysis',
    ],
    renderVisual: () => (
      <div className="carousel-visual-box">
        <div className="visual-slide-header">
          <span className="visual-slide-tag">DOMAIN SPOOF COMPARISON</span>
          <span className="visual-slide-badge">Signal 01</span>
        </div>
        <div className="spoof-compare-visual">
          <div className="spoof-row spoof-bad">
            <div className="spoof-pill-label bad">Deceptive Link</div>
            <code className="spoof-url-code">
              secure-<span className="char-highlight-bad">paypa1</span>-login.com
            </code>
            <span className="spoof-detail-label">⚠️ '1' substituted for 'l'</span>
          </div>
          <div className="spoof-vs-divider">
            <span>vs</span>
          </div>
          <div className="spoof-row spoof-good">
            <div className="spoof-pill-label good">Legitimate Brand</div>
            <code className="spoof-url-code">
              <span className="char-highlight-good">paypal</span>.com
            </code>
            <span className="spoof-detail-label">✓ Official Domain Origin</span>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: '02',
    tag: 'URL PATH & PARAMETER ANATOMY',
    title: 'Look Beyond the Domain',
    description: 'A trustworthy-looking hostname does not guarantee that the entire URL is safe.',
    bullets: [
      'Sensitive action keywords (/login, /verify, /wallet, /session)',
      'High-entropy tokens & obfuscated redirect parameters',
      'Percent-encoded hex strings and hidden destinations',
    ],
    renderVisual: () => (
      <div className="carousel-visual-box">
        <div className="visual-slide-header">
          <span className="visual-slide-tag">URL STRUCTURE DECOMPOSITION</span>
          <span className="visual-slide-badge">Signal 02</span>
        </div>
        <div className="url-anatomy-visual">
          <div className="anatomy-block">
            <span className="anatomy-label">PROTOCOL</span>
            <code className="anatomy-code proto">https://</code>
          </div>
          <div className="anatomy-block">
            <span className="anatomy-label">HOSTNAME</span>
            <code className="anatomy-code host">auth-service.net</code>
          </div>
          <div className="anatomy-block highlight-warn">
            <span className="anatomy-label">PATH (SENSITIVE)</span>
            <code className="anatomy-code path">/portal/session/verify</code>
          </div>
          <div className="anatomy-block highlight-danger">
            <span className="anatomy-label">QUERY PARAMETERS</span>
            <code className="anatomy-code query">?token=cGFzc3dvcmR...</code>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: '03',
    tag: 'DOMAIN REGISTRATION & WHOIS',
    title: 'New Domains Need Context',
    description: 'A recently registered domain can be an additional risk signal when combined with other suspicious indicators.',
    bullets: [
      'Rapid infrastructure provisioning hours before phishing blasts',
      'Audit of domain creation dates, tenure, and registrar profile',
      'Context-aware signal weighting without fabricating records',
    ],
    renderVisual: () => (
      <div className="carousel-visual-box">
        <div className="visual-slide-header">
          <span className="visual-slide-tag">REGISTRATION TENURE TIMELINE</span>
          <span className="visual-slide-badge">Signal 03</span>
        </div>
        <div className="timeline-visual">
          <div className="timeline-track">
            <div className="timeline-point past">
              <span className="point-dot" />
              <span className="point-label">Created</span>
              <span className="point-sub">2026-09-16</span>
            </div>
            <div className="timeline-connector active" />
            <div className="timeline-point current">
              <span className="point-dot active" />
              <span className="point-label">14 Days Old</span>
              <span className="point-sub highlight">Recently Registered</span>
            </div>
          </div>
          <div className="timeline-note-box">
            <span className="note-badge">CAUTIONARY SIGNAL</span>
            <p>Recently registered domains can require additional caution when combined with brand keywords.</p>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: '04',
    tag: 'UNICODE & HOMOGLYPH AUDIT',
    title: 'Characters Can Deceive',
    description: 'Homoglyphs use visually similar characters to make deceptive domains resemble legitimate ones.',
    bullets: [
      'Cyrillic & Greek lookalike character detection',
      'Punycode decomposition (e.g. xn--...)',
      'Precise Unicode code point identification (U+04CF vs U+006C)',
    ],
    renderVisual: () => (
      <div className="carousel-visual-box">
        <div className="visual-slide-header">
          <span className="visual-slide-tag">UNICODE CHARACTER ANALYSIS</span>
          <span className="visual-slide-badge">Signal 04</span>
        </div>
        <div className="homoglyph-visual">
          <div className="homo-card fraud">
            <span className="homo-type">Lookalike Impostor</span>
            <code className="homo-domain">goog<span className="homo-char-bad">ӏ</span>e.com</code>
            <div className="homo-detail-tag">
              <span>Cyrillic Palochka</span>
              <code>U+04CF</code>
            </div>
          </div>
          <div className="homo-vs">VS</div>
          <div className="homo-card legit">
            <span className="homo-type">Standard Latin</span>
            <code className="homo-domain">goog<span className="homo-char-good">l</span>e.com</code>
            <div className="homo-detail-tag">
              <span>Latin Small Letter L</span>
              <code>U+006C</code>
            </div>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: '05',
    tag: 'MULTI-SIGNAL SYNTHESIS',
    title: 'Understand the Risk',
    description: 'PhishGuard combines multiple signals to produce an explainable threat assessment.',
    bullets: [
      'Transparent, deterministic score weights (0–100 scale)',
      'Clear risk categorization: Safe, Suspicious, or Malicious',
      'Actionable evidence explaining every contributing factor',
    ],
    renderVisual: () => (
      <div className="carousel-visual-box">
        <div className="visual-slide-header">
          <span className="visual-slide-tag">SIGNAL AGGREGATION PIPELINE</span>
          <span className="visual-slide-badge">Signal 05</span>
        </div>
        <div className="pipeline-visual">
          <div className="pipeline-signals-grid">
            <span className="pipe-pill">Domain Syntax</span>
            <span className="pipe-pill">Typosquatting</span>
            <span className="pipe-pill">Homoglyphs</span>
            <span className="pipe-pill">Entropy</span>
            <span className="pipe-pill">URL Path</span>
            <span className="pipe-pill">WHOIS Age</span>
          </div>
          <div className="pipeline-arrow-down">↓ Synthesized Weighting</div>
          <div className="pipeline-score-result">
            <div className="pipe-score-left">
              <span className="pipe-score-num">0–100</span>
              <span className="pipe-score-label">Threat Index</span>
            </div>
            <div className="pipe-score-badges">
              <span className="pipe-band safe">Safe (0-20)</span>
              <span className="pipe-band susp">Suspicious (21-60)</span>
              <span className="pipe-band mal">Malicious (61-100)</span>
            </div>
          </div>
        </div>
      </div>
    ),
  },
]

function CybersecurityCarousel() {
  const [activeSlide, setActiveSlide] = useState(0)
  const [isPaused, setIsPaused] = useState(false)

  useEffect(() => {
    if (isPaused) return
    const timer = setInterval(() => {
      setActiveSlide(prev => (prev + 1) % CAROUSEL_SLIDES.length)
    }, 6000)
    return () => clearInterval(timer)
  }, [isPaused])

  const nextSlide = () => {
    setActiveSlide(prev => (prev + 1) % CAROUSEL_SLIDES.length)
  }

  const prevSlide = () => {
    setActiveSlide(prev => (prev - 1 + CAROUSEL_SLIDES.length) % CAROUSEL_SLIDES.length)
  }

  const current = CAROUSEL_SLIDES[activeSlide]

  return (
    <div
      className="cybersecurity-carousel-card"
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      <div className="carousel-slide-layout" key={current.id}>
        <div className="carousel-text-col">
          <div className="carousel-pill-row">
            <span className="carousel-slide-idx">{current.id} / 05</span>
            <span className="carousel-slide-tag-pill">{current.tag}</span>
          </div>

          <h4 className="carousel-slide-title">{current.title}</h4>
          <p className="carousel-slide-desc">{current.description}</p>

          <ul className="carousel-bullet-list">
            {current.bullets.map((b, i) => (
              <li key={i}>
                <span className="carousel-check-icon">✓</span>
                <span>{b}</span>
              </li>
            ))}
          </ul>

          <div className="carousel-controls-bar">
            <button
              type="button"
              className="carousel-ctrl-btn"
              onClick={prevSlide}
              aria-label="Previous slide"
            >
              ←
            </button>

            <div className="carousel-dots-wrap">
              {CAROUSEL_SLIDES.map((s, idx) => (
                <button
                  key={s.id}
                  type="button"
                  className={`carousel-dot ${activeSlide === idx ? 'dot-active' : ''}`}
                  onClick={() => setActiveSlide(idx)}
                  aria-label={`Go to slide ${idx + 1}`}
                />
              ))}
            </div>

            <button
              type="button"
              className="carousel-ctrl-btn"
              onClick={nextSlide}
              aria-label="Next slide"
            >
              →
            </button>
          </div>
        </div>

        <div className="carousel-visual-col">
          {current.renderVisual()}
        </div>
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------
// REUSABLE URL INSPECTOR CARD COMPONENT
// --------------------------------------------------------------------------
export function UrlInspectorCard({
  initialUrl = '',
  onInspect,
  isInspecting = false,
  className = '',
}: {
  initialUrl?: string
  onInspect: (url: string) => void
  isInspecting?: boolean
  className?: string
}) {
  const [inputUrl, setInputUrl] = useState(initialUrl)

  useEffect(() => {
    setInputUrl(initialUrl)
  }, [initialUrl])

  const handleScanSubmit = (e: FormEvent) => {
    e.preventDefault()
    const trimmed = inputUrl.trim()
    if (!trimmed || isInspecting) return
    onInspect(trimmed)
  }

  const handlePresetSelect = (presetUrl: string) => {
    if (isInspecting) return
    setInputUrl(presetUrl)
  }

  return (
    <div className={`scanner-hero-card ${className}`}>
      <div className="scanner-card-header">
        <div className="scanner-header-left">
          <span className="status-indicator-dot" />
          <span className="scanner-header-title">LIVE URL INSPECTOR</span>
        </div>
        <div className="scanner-safe-pill">
          <ShieldCheckIcon />
          <span>Non-Executing Sandbox</span>
        </div>
      </div>

      <form onSubmit={handleScanSubmit} className="scanner-input-form">
        <div className="input-row">
          <div className="input-prefix-icon">
            <SearchPulseIcon />
          </div>
          <div className="input-field-wrap">
            <span className="input-eyebrow">ENTER SUSPICIOUS URL OR SPOOFED DOMAIN</span>
            <input
              type="text"
              value={inputUrl}
              onChange={e => setInputUrl(e.target.value)}
              placeholder="Paste a URL to inspect..."
              className="scanner-url-input"
              spellCheck={false}
              autoComplete="off"
              disabled={isInspecting}
            />
          </div>
          <button
            type="submit"
            disabled={!inputUrl.trim() || isInspecting}
            className={`btn btn-primary btn-scan ${isInspecting ? 'btn-inspecting-state' : ''}`}
          >
            {isInspecting ? (
              <>
                <span className="btn-inline-pulse" />
                <span>Inspecting...</span>
              </>
            ) : (
              <>
                <span>Inspect URL</span>
                <ArrowUpRight />
              </>
            )}
          </button>
        </div>
      </form>

      <div className="sample-urls-row">
        <span className="sample-label">Try an example:</span>
        <div className="sample-tags">
          {SAMPLE_URLS.map(s => (
            <button
              key={s.label}
              type="button"
              disabled={isInspecting}
              className={`sample-tag-btn ${inputUrl === s.url ? 'tag-active' : ''}`}
              onClick={() => handlePresetSelect(s.url)}
            >
              <span className="sample-tag-type">{s.type}</span>
              <span className="sample-tag-name">{s.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="scanner-footer-notice">
        <LockSafetyIcon />
        <p>
          <strong>Safe Inspection Guarantee:</strong> PhishGuard inspects the URL without opening the destination as a webpage in your browser. Client-side page scripts and potentially malicious payloads are never executed.
        </p>
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------
// PAGE 1: SCANNER PAGE (/scanner)
// --------------------------------------------------------------------------
function ScannerPage({
  onStartInspection,
}: {
  onStartInspection: (url: string) => void
}) {
  const [isInspecting, setIsInspecting] = useState(false)

  const handleInspect = (url: string) => {
    setIsInspecting(true)
    setTimeout(() => {
      onStartInspection(url)
    }, 180)
  }

  return (
    <div className="page-view scanner-page-view">
      <section className="hero-editorial-section">
        <div className="hero-container">
          <div className="hero-grid">
            <div className="hero-editorial-copy">
              <div className="hero-eyebrow-pill">
                <span className="pulse-dot" />
                <span>DEEP URL FORENSICS &amp; DOMAIN AUDIT</span>
              </div>

              <h1 className="hero-main-title">
                Inspect a URL <br />
                <span className="title-highlight">Before You Trust It.</span>
              </h1>

              <p className="hero-description">
                PhishGuard analyzes suspicious URLs, spoofed domains, domain registration data, URL structure, entropy, typosquatting, and homoglyph indicators before you interact with the destination.
              </p>

              <div className="hero-trust-block">
                <ShieldCheckIcon />
                <div className="trust-text">
                  <strong>Safe URL Sandbox</strong>
                  <span>Inspect links safely without browser script execution.</span>
                </div>
              </div>
            </div>

            <div className="hero-scanner-col">
              <UrlInspectorCard onInspect={handleInspect} isInspecting={isInspecting} />
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

// --------------------------------------------------------------------------
// PAGE 2: ANALYSIS PAGE (/analysis)
// --------------------------------------------------------------------------
function AnalysisPage({
  activeUrl,
  analysisState,
  analysisResult,
  analysisError,
  onStartInspection,
  onCompleteScan,
  onResetScan,
}: {
  activeUrl: string | null
  analysisState: ScanState
  analysisResult: AnalysisDetails | null
  analysisError: string | null
  onStartInspection: (url: string) => void
  onCompleteScan: (url: string) => void
  onResetScan: () => void
}) {
  const [activeStepIndex, setActiveStepIndex] = useState(0)
  const [scanProgress, setScanProgress] = useState(0)

  useEffect(() => {
    if (analysisState !== 'scanning' || !activeUrl) return

    setActiveStepIndex(0)
    setScanProgress(0)

    const stepInterval = 300
    const totalSteps = SCAN_STEPS.length
    let currentStep = 0

    const timer = setInterval(() => {
      currentStep++
      if (currentStep < totalSteps) {
        setActiveStepIndex(currentStep)
        setScanProgress(Math.round((currentStep / totalSteps) * 100))
      } else {
        clearInterval(timer)
        setActiveStepIndex(totalSteps - 1)
        setScanProgress(100)
        onCompleteScan(activeUrl)
      }
    }, stepInterval)

    return () => clearInterval(timer)
  }, [analysisState, activeUrl])

  const renderList = (items: string[], empty = 'Unavailable') => (
    items.length ? items.map((item, index) => <code key={`${item}-${index}`} className="intel-chip">{item}</code>) : <span className="intel-muted">{empty}</span>
  )

  return (
    <div className="page-view analysis-page-view">
      <section className="section analysis-hub-section">
        <div className="section-container">
          <div className="section-intro reveal-stagger-1">
            <span className="editorial-eyebrow">ANALYSIS &amp; THREAT INTELLIGENCE</span>
            <h2 className="section-title">Security intelligence for the URL you're inspecting.</h2>
            <p className="section-subtitle">
              The browser parses URL structure locally; the FastAPI enrichment service adds live RDAP, DNS, IP geolocation, and OSINT intelligence. The destination URL is never opened by PhishGuard.
            </p>
          </div>

          <div className="analysis-inspector-wrapper reveal-stagger-2">
            <UrlInspectorCard
              initialUrl={activeUrl || ''}
              onInspect={onStartInspection}
              isInspecting={analysisState === 'scanning'}
            />
          </div>

          {analysisState === 'scanning' && activeUrl && (
            <div className="analysis-live-scanning-card reveal-stagger-2" aria-live="polite">
              <div className="scanning-card-header">
                <div className="scanning-pulse-box reveal-stagger-3"><SearchPulseIcon /></div>
                <div className="scanning-header-titles reveal-stagger-2">
                  <span className="scanning-status-pill">LIVE INSPECTION IN PROGRESS</span>
                  <h3 className="scanning-target-url"><code>{activeUrl}</code></h3>
                </div>
                <div className="scanning-pct-badge">{scanProgress}%</div>
              </div>
              <div className="progress-track-bar"><div className="progress-fill-bar" style={{ width: `${scanProgress}%` }} /></div>
              <div className="sequence-steps-grid reveal-stagger-4">
                {SCAN_STEPS.map((step, idx) => {
                  const isDone = idx < activeStepIndex
                  const isCurrent = idx === activeStepIndex
                  return (
                    <div key={step.id} className={`step-item ${isDone ? 'step-done' : ''} ${isCurrent ? 'step-active' : ''}`}>
                      <div className="step-num-badge">{isDone ? '✓' : step.id}</div>
                      <div className="step-text-wrap"><span className="step-name">{step.name}</span><span className="step-desc">{step.desc}</span></div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {analysisState === 'idle' && !analysisResult && (
            <div className="analysis-empty-compact-card reveal-stagger-2">
              <div className="empty-compact-content">
                <div className="empty-compact-badge-row"><span className="empty-status-dot" /><span className="empty-compact-pill">STANDBY MODE</span></div>
                <h3 className="empty-compact-title">No URL inspected yet.</h3>
                <p className="empty-compact-desc">Enter a URL above. The report will only show values returned by the live analysis service; unavailable sources are clearly marked.</p>
              </div>
              <div className="empty-compact-action"><button type="button" className="btn btn-primary btn-sm" onClick={onResetScan}><span>Go to Scanner</span><ArrowUpRight /></button></div>
            </div>
          )}

          {analysisState === 'error' && (
            <div className="analysis-error-card reveal-stagger-2" role="alert">
              <div>
                <span className="editorial-eyebrow">ANALYSIS SERVICE UNAVAILABLE</span>
                <h3 className="empty-compact-title">The URL was not enriched with live intelligence.</h3>
                <p className="empty-compact-desc">{analysisError || 'The backend analysis service returned an unexpected error.'}</p>
                <p className="intel-muted">Local URL parsing remains safe; connect the FastAPI backend and try again. No static WHOIS, IP, or OSINT values are substituted.</p>
              </div>
              <button type="button" className="btn btn-primary btn-sm" onClick={() => activeUrl && onStartInspection(activeUrl)}>Retry analysis <ArrowUpRight /></button>
            </div>
          )}

          {analysisState === 'completed' && analysisResult && (
            <div className="active-analysis-report-wrapper">
              <div className="analysis-report-toolbar">
                <div className="report-source-status">
                  <span className="status-indicator-dot" />
                  <span>LIVE DATA REPORT · {analysisResult.backendSource}</span>
                </div>
                <button type="button" className="btn btn-primary btn-sm" onClick={onResetScan}><span>← Scan Another URL</span></button>
              </div>

              <div className={`verdict-hero-card verdict-${analysisResult.verdict.toLowerCase()} reveal-stagger-1`}>
                <div className="verdict-card-left">
                  <div className="verdict-badge-row">
                    <span className="verdict-tag">{analysisResult.verdict} VERDICT</span>
                    <span className="verdict-score-pill">Threat Index: {analysisResult.threatScore}/100</span>
                  </div>
                  <h3 className="scanned-url-heading"><code>{analysisResult.url}</code></h3>
                  <p className="verdict-summary-text">
                    This assessment is derived from the URL's observed structure plus the external enrichment returned at scan time. It is an indicator, not proof that a destination is safe or malicious.
                  </p>
                  <div className="url-telemetry-meta">
                    <div className="telemetry-item"><span className="telemetry-label">Hostname:</span><code className="telemetry-value">{analysisResult.hostname}</code></div>
                    <div className="telemetry-item"><span className="telemetry-label">Protocol:</span><code className="telemetry-value">{analysisResult.protocol} ({analysisResult.structure.isHttps ? 'HTTPS' : 'HTTP'})</code></div>
                    <div className="telemetry-item"><span className="telemetry-label">Resolved IP:</span><code className="telemetry-value">{analysisResult.resolution.primaryIp || 'Unavailable'}</code></div>
                    <div className="telemetry-item"><span className="telemetry-label">Generated:</span><span className="telemetry-value">{new Date(analysisResult.generatedAt).toLocaleString()}</span></div>
                  </div>
                </div>
                <div className="verdict-card-right"><ThreatScoreGauge score={analysisResult.threatScore} verdict={analysisResult.verdict} /></div>
              </div>

              {/* URL parts: intentionally mirrors the decomposition shown in the supplied reference image. */}
              <article className="analysis-card url-parts-card reveal-stagger-2">
                <div className="card-top-bar"><span className="card-num">01</span><span className="card-category">URL DECOMPOSITION</span></div>
                <h4 className="card-title">Every structural part, parsed from the raw input.</h4>
                <div className="url-breakdown-string" aria-label="Parsed URL parts">
                  <span className="url-part-token token-scheme">{analysisResult.urlParts.scheme}://</span>
                  <span className="url-part-token token-subdomain">{analysisResult.urlParts.subdomain === '—' ? '' : `${analysisResult.urlParts.subdomain}.`}</span>
                  <span className="url-part-token token-domain">{analysisResult.urlParts.domain}</span>
                  <span className="url-part-token token-tld">{analysisResult.urlParts.tld}</span>
                  <span className="url-part-token token-port">{analysisResult.port ? `:${analysisResult.port}` : ''}</span>
                  <span className="url-part-token token-path">{analysisResult.path}</span>
                  {analysisResult.urlParts.querySeparator !== '—' && <span className="url-part-token token-query-separator">?</span>}
                  {analysisResult.urlParts.queryString !== '—' && <span className="url-part-token token-query">{analysisResult.urlParts.queryString}</span>}
                  {analysisResult.fragment && <span className="url-part-token token-fragment">#{analysisResult.fragment}</span>}
                </div>
                <div className="url-parts-label-grid">
                  {[
                    ['Scheme', analysisResult.urlParts.scheme],
                    ['Subdomain', analysisResult.urlParts.subdomain],
                    ['Domain', analysisResult.urlParts.domain],
                    ['Top Level Domain', analysisResult.urlParts.tld],
                    ['Port Number', analysisResult.urlParts.port],
                    ['Path', analysisResult.urlParts.path],
                    ['Query String', analysisResult.urlParts.queryString],
                    ['Query Parameters', `${analysisResult.queryParams.length} parsed`],
                    ['Fragment', analysisResult.urlParts.fragment],
                  ].map(([label, value]) => (
                    <div key={label} className="url-part-field"><span className="data-key">{label}</span><code className="data-val">{value || '—'}</code></div>
                  ))}
                </div>
              </article>

              <div className="intel-grid-2">
                <article className="analysis-card reveal-stagger-2">
                  <div className="card-top-bar"><span className="card-num">02</span><span className="card-category">WHOIS / RDAP</span></div>
                  <h4 className="card-title">Live registration intelligence.</h4>
                  {analysisResult.whois.error ? <p className="intel-error">{analysisResult.whois.error}</p> : (
                    <div className="card-data-table">
                      <div className="data-row"><span className="data-key">Domain</span><code className="data-val">{analysisResult.whois.domain || 'Unavailable'}</code></div>
                      <div className="data-row"><span className="data-key">Registrar</span><span className="data-val">{analysisResult.whois.registrar || 'Not disclosed'}</span></div>
                      <div className="data-row"><span className="data-key">Creation Date</span><code className="data-val">{analysisResult.whois.creationDate || 'Not returned'}</code></div>
                      <div className="data-row"><span className="data-key">Expiration Date</span><code className="data-val">{analysisResult.whois.expirationDate || 'Not returned'}</code></div>
                      <div className="data-row"><span className="data-key">Domain Age</span><span className={`data-val font-semibold ${analysisResult.whois.isNewlyRegistered ? 'highlight-warning' : ''}`}>{analysisResult.whois.domainAgeFormatted}</span></div>
                      <div className="data-row"><span className="data-key">Status</span><span className="data-val text-xs font-mono">{analysisResult.whois.status.length ? analysisResult.whois.status.join(', ') : 'Not returned'}</span></div>
                      <div className="data-row"><span className="data-key">DNSSEC</span><span className="data-val">{analysisResult.whois.dnssec || 'Not returned'}</span></div>
                      <div className="data-row"><span className="data-key">Nameservers</span><span className="data-val">{analysisResult.whois.nameservers.length ? analysisResult.whois.nameservers.join(', ') : 'Not returned'}</span></div>
                    </div>
                  )}
                  <p className="card-narrative">Source: {analysisResult.whois.source}. Registration privacy can limit registrar/owner fields.</p>
                </article>

                <article className="analysis-card reveal-stagger-2">
                  <div className="card-top-bar"><span className="card-num">03</span><span className="card-category">IP &amp; GEOLOCATION</span></div>
                  <h4 className="card-title">Where the hostname resolves.</h4>
                  <div className="card-data-table">
                    <div className="data-row"><span className="data-key">Resolved IPv4/IPv6</span><span className="data-val">{renderList(analysisResult.resolution.ips)}</span></div>
                    <div className="data-row"><span className="data-key">Primary IP</span><code className="data-val">{analysisResult.ipIntel.ip || analysisResult.resolution.primaryIp || 'Unavailable'}</code></div>
                    <div className="data-row"><span className="data-key">Location</span><span className="data-val">{[analysisResult.ipIntel.city, analysisResult.ipIntel.region, analysisResult.ipIntel.country].filter(Boolean).join(', ') || 'Unavailable'}</span></div>
                    <div className="data-row"><span className="data-key">Coordinates</span><span className="data-val">{analysisResult.ipIntel.latitude != null && analysisResult.ipIntel.longitude != null ? `${analysisResult.ipIntel.latitude}, ${analysisResult.ipIntel.longitude}` : 'Unavailable'}</span></div>
                    <div className="data-row"><span className="data-key">ASN</span><span className="data-val">{analysisResult.ipIntel.asn || 'Unavailable'}</span></div>
                    <div className="data-row"><span className="data-key">Organization</span><span className="data-val">{analysisResult.ipIntel.org || 'Unavailable'}</span></div>
                    <div className="data-row"><span className="data-key">Timezone</span><span className="data-val">{analysisResult.ipIntel.timezone || 'Unavailable'}</span></div>
                  </div>
                  <p className="card-narrative">Source: {analysisResult.ipIntel.source || 'No geolocation source returned'}.</p>
                </article>
              </div>

              <article className="analysis-card osint-card reveal-stagger-2">
                <div className="card-top-bar"><span className="card-num">04</span><span className="card-category">OSINT LOOKUP</span></div>
                <h4 className="card-title">Passive pivots and public intelligence.</h4>
                <div className="osint-section-grid">
                  <div className="osint-block"><span className="intel-block-label">Known Subdomains</span><div className="intel-chip-wrap">{renderList(analysisResult.osint.subdomains, 'No results returned')}</div></div>
                  <div className="osint-block"><span className="intel-block-label">Reverse-IP Domains</span><div className="intel-chip-wrap">{renderList(analysisResult.osint.reverseIpDomains, 'No results returned')}</div></div>
                  <div className="osint-block"><span className="intel-block-label">Public URLscan Sightings</span><div className="intel-chip-wrap">{analysisResult.osint.urlscanSightings.length ? analysisResult.osint.urlscanSightings.map((s, i) => <span key={`${s.uuid}-${i}`} className="intel-sighting">{s.taskTime || 'Observed'} · {s.ip || s.country || 'public scan'}</span>) : <span className="intel-muted">No public sightings returned</span>}</div></div>
                  <div className="osint-block"><span className="intel-block-label">DNS Records</span><div className="dns-mini-grid"><span>A: {analysisResult.dns.A.length}</span><span>AAAA: {analysisResult.dns.AAAA.length}</span><span>MX: {analysisResult.dns.MX.length}</span><span>NS: {analysisResult.dns.NS.length}</span><span>TXT: {analysisResult.dns.TXT.length}</span><span>CNAME: {analysisResult.dns.CNAME.length}</span></div></div>
                </div>
                {(analysisResult.osint.notes.length || analysisResult.osint.sources.length) ? <p className="card-narrative">{analysisResult.osint.notes.join(' ')} {analysisResult.osint.sources.length ? `Sources: ${analysisResult.osint.sources.join(', ')}.` : ''}</p> : <p className="card-narrative">No OSINT source returned additional notes for this scan.</p>}
              </article>

              <div className="cards-grid-6">
                <article className="analysis-card stagger-card-1">
                  <div className="card-top-bar"><span className="card-num">05</span><span className="card-category">TYPOSQUATTING CHECK</span></div>
                  <h4 className="card-title">Lookalike domain detection.</h4>
                  <div className="card-data-table">
                    <div className="data-row"><span className="data-key">Target Brand</span><span className="data-val font-semibold">{analysisResult.typosquatting.targetBrand || 'None identified'}</span></div>
                    <div className="data-row"><span className="data-key">Pattern</span><span className="data-val">{analysisResult.typosquatting.patternType || 'No pattern'}</span></div>
                    <div className="data-row"><span className="data-key">Similarity</span><span className="data-val font-mono">{analysisResult.typosquatting.similarityScore != null ? `${analysisResult.typosquatting.similarityScore}%` : 'Not calculated'}</span></div>
                  </div>
                  <p className="card-narrative">{analysisResult.typosquatting.explanation}</p>
                </article>

                <article className="analysis-card stagger-card-2">
                  <div className="card-top-bar"><span className="card-num">06</span><span className="card-category">HOMOGLYPH AUDIT</span></div>
                  <h4 className="card-title">Unicode &amp; character spoofing.</h4>
                  <div className="card-data-table">
                    <div className="data-row"><span className="data-key">Status</span><span className={`data-val font-semibold ${analysisResult.homoglyphs.detected ? 'text-malicious' : 'text-safe'}`}>{analysisResult.homoglyphs.detected ? 'Deceptive characters found' : 'No non-ASCII hostname chars'}</span></div>
                    {analysisResult.homoglyphs.characters.map((c, i) => <div key={i} className="data-row"><span className="data-key">Character #{i + 1}</span><span className="data-val"><code className="char-badge">{c.char}</code> {c.codePoint} → '{c.lookalike}' ({c.script})</span></div>)}
                  </div>
                  <p className="card-narrative">{analysisResult.homoglyphs.explanation}</p>
                </article>

                <article className="analysis-card stagger-card-3">
                  <div className="card-top-bar"><span className="card-num">07</span><span className="card-category">URL STRUCTURE</span></div>
                  <h4 className="card-title">Path &amp; query semantics.</h4>
                  <div className="card-data-table">
                    <div className="data-row"><span className="data-key">Path</span><code className="data-val">{analysisResult.path || '/'}</code></div>
                    <div className="data-row"><span className="data-key">Port</span><code className="data-val">{analysisResult.port || 'Default'}</code></div>
                    <div className="data-row"><span className="data-key">Suspicious Keywords</span><span className="data-val">{analysisResult.structure.suspiciousKeywords.length ? analysisResult.structure.suspiciousKeywords.map(k => <code key={k} className="keyword-chip">{k}</code>) : 'None'}</span></div>
                    <div className="data-row"><span className="data-key">Encoded Bytes</span><span className="data-val">{analysisResult.structure.hasEncodedChars ? 'Detected (%xx)' : 'None'}</span></div>
                    <div className="data-row"><span className="data-key">Query Parameters</span><span className="data-val">{analysisResult.queryParams.length}</span></div>
                  </div>
                  <p className="card-narrative">{analysisResult.structure.explanation}</p>
                </article>

                <article className="analysis-card stagger-card-4">
                  <div className="card-top-bar"><span className="card-num">08</span><span className="card-category">QUERY PARAMETER AUDIT</span></div>
                  <h4 className="card-title">Key/value pairs from the query string.</h4>
                  <div className="query-audit-table">
                    {analysisResult.queryParams.length ? analysisResult.queryParams.map((param, index) => <div key={`${param.key}-${index}`} className={`query-audit-row ${param.isSensitive ? 'query-sensitive' : ''}`}><code>{param.key}</code><span>=</span><code className="query-value">{param.value || '(empty)'}</code>{param.isSensitive && <span className="query-sensitive-badge">SENSITIVE KEY</span>}</div>) : <span className="intel-muted">No query parameters present.</span>}
                  </div>
                </article>

                <article className="analysis-card stagger-card-5">
                  <div className="card-top-bar"><span className="card-num">09</span><span className="card-category">ENTROPY ANALYSIS</span></div>
                  <h4 className="card-title">Algorithmic randomness.</h4>
                  <div className="entropy-meter-wrap">
                    <div className="entropy-val-header"><span className="entropy-number">{analysisResult.entropy.urlEntropy} <small>bits/char</small></span><span className={`entropy-badge badge-${analysisResult.entropy.level.toLowerCase().replace(' ', '-')}`}>{analysisResult.entropy.level}</span></div>
                    <div className="entropy-track"><div className="entropy-bar-fill" style={{ width: `${Math.min(100, (analysisResult.entropy.urlEntropy / 6.0) * 100)}%` }} /></div>
                    <div className="entropy-scale-labels"><span>0.0</span><span>3.5</span><span>4.5</span><span>6.0+</span></div>
                  </div>
                  <p className="card-narrative">{analysisResult.entropy.explanation}</p>
                </article>

                <article className="analysis-card stagger-card-6">
                  <div className="card-top-bar"><span className="card-num">10</span><span className="card-category">THREAT INTELLIGENCE</span></div>
                  <h4 className="card-title">External reputation signals.</h4>
                  <div className="card-data-table">
                    <div className="data-row"><span className="data-key">URLhaus</span><span className="data-val">{analysisResult.osint.urlhaus?.listed == null ? 'Not configured / unavailable' : analysisResult.osint.urlhaus.listed ? 'Listed' : 'Not listed'}</span></div>
                    <div className="data-row"><span className="data-key">PhishTank</span><span className="data-val">{analysisResult.osint.phishtank?.inDatabase == null ? 'Not configured / unavailable' : analysisResult.osint.phishtank.inDatabase ? 'Found in database' : 'Not found'}</span></div>
                    <div className="data-row"><span className="data-key">VirusTotal</span><span className="data-val">{analysisResult.osint.virustotal?.malicious == null ? 'Not configured / unavailable' : `${analysisResult.osint.virustotal.malicious} malicious / ${analysisResult.osint.virustotal.suspicious} suspicious`}</span></div>
                    <div className="data-row"><span className="data-key">AbuseIPDB</span><span className="data-val">{analysisResult.osint.abuseIpdb?.confidenceScore == null ? 'Not configured / unavailable' : `${analysisResult.osint.abuseIpdb.confidenceScore}% confidence`}</span></div>
                  </div>
                  <p className="card-narrative">Optional providers are only queried when their API keys are configured in the backend. No placeholder reputation values are generated.</p>
                </article>
              </div>

              <article className="analysis-card threat-reasoning-card">
                <div className="card-top-bar"><span className="card-num">11</span><span className="card-category">THREAT REASONING</span></div>
                <h4 className="card-title">Score contributing factors.</h4>
                <div className="findings-bullet-list">
                  {analysisResult.reasons.map((item, idx) => <div key={idx} className={`finding-bullet-item severity-${item.severity}`}><span className="finding-bullet-index">{String(idx + 1).padStart(2, '0')}</span><div className="finding-bullet-content"><strong className="finding-bullet-title">{item.title}</strong><p className="finding-bullet-desc">{item.detail}</p></div></div>)}
                </div>
              </article>
            </div>
          )}

          <div className="analysis-carousel-section-wrap">
            <div className="carousel-section-header">
              <span className="editorial-eyebrow">CYBERSECURITY CAROUSEL</span>
              <h3 className="carousel-main-heading">Know what you're looking for.</h3>
              <p className="carousel-main-desc">Understand the visual and technical indicators used to detect lookalike domains, obfuscated paths, and deceptive URLs.</p>
            </div>
            <CybersecurityCarousel />
          </div>
        </div>
      </section>
    </div>
  )
}

// --------------------------------------------------------------------------
// PAGE 3: HOW IT WORKS (/how-it-works)
// --------------------------------------------------------------------------
function HowItWorksPage({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  const steps = [
    {
      num: '01',
      title: 'PASTE',
      desc: 'Paste any suspicious link, message attachment URL, or lookalike domain into the safe inspector input.',
    },
    {
      num: '02',
      title: 'INSPECT',
      desc: 'PhishGuard decomposes the hostname, analyzes character scripts, computes Shannon entropy, and queries WHOIS registry signals.',
    },
    {
      num: '03',
      title: 'ASSESS',
      desc: 'All structural and registration signals are synthesized into an explainable 0–100 threat score and risk category.',
    },
    {
      num: '04',
      title: 'UNDERSTAND',
      desc: 'Review transparent findings detailing why the URL is flagged and receive actionable safety recommendations.',
    },
  ]

  return (
    <div className="page-view how-it-works-page-view">
      <section className="section process-editorial-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">THE INSPECTION PROCESS</span>
            <h2 className="section-title">A security analysis flow without the noise.</h2>
            <p className="section-subtitle">
              PhishGuard moves from raw URL input to transparent evidence, turning complex cybersecurity telemetry into clear, actionable intelligence.
            </p>
          </div>

          <div className="process-cards-row">
            {steps.map(s => (
              <div key={s.num} className="process-editorial-card">
                <span className="process-step-number">{s.num}</span>
                <div className="process-divider-dot" />
                <h3 className="process-step-title">{s.title}</h3>
                <p className="process-step-desc">{s.desc}</p>
              </div>
            ))}
          </div>

          <div className="page-bottom-cta-banner">
            <div className="cta-banner-text">
              <h3>Ready to inspect a link?</h3>
              <p>Test suspicious URLs instantly using PhishGuard's non-executing sandbox engine.</p>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate('scanner')}
            >
              <span>Launch Scanner</span>
              <ArrowUpRight />
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

// --------------------------------------------------------------------------
// PAGE 4: CAPABILITIES (/capabilities)
// --------------------------------------------------------------------------
function CapabilitiesPage({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  const featureStories = [
    {
      tag: 'TYPOSQUATTING & BRAND SPOOFING',
      headline: 'Attackers don\'t invent new names. They misspell familiar ones.',
      copy: 'Typosquatting takes advantage of small typos, character insertions, or digit swaps (such as substituting "1" for "l" or "0" for "o"). PhishGuard tests domains against known corporate targets to uncover brand impersonation before you type your credentials.',
      bullets: ['Levenshtein edit-distance calculations', 'Leet-speak & numeric substitution detection', 'Subdomain brand trickery verification'],
      badge: 'Signal 01',
    },
    {
      tag: 'HOMOGLYPH & UNICODE AUDIT',
      headline: 'One lookalike character can deceive the human eye.',
      copy: 'Internationalized Domain Names (IDNs) allow foreign alphabets in web addresses. Cybercriminals exploit this by swapping Latin letters for visually indistinguishable Cyrillic or Greek characters. PhishGuard checks the exact Unicode code points to detect hidden impostor domains.',
      bullets: ['Cyrillic & Greek lookalike mapping', 'Punycode and ASCII decomposition', 'Visual homoglyph alert generation'],
      badge: 'Signal 02',
    },
    {
      tag: 'REGISTRY & DOMAIN AGE',
      headline: 'Newly registered domains demand additional caution.',
      copy: 'Malicious infrastructure is often stood up hours before a spear-phishing campaign launches. PhishGuard audits public WHOIS/RDAP signals, highlighting newly created domains (under 30 days) and evaluating registrar reputation without fabricating telemetry.',
      bullets: ['Domain creation & expiration dates', 'Public registrar organization telemetry', 'Domain tenure risk factor weighting'],
      badge: 'Signal 03',
    },
  ]

  return (
    <div className="page-view capabilities-page-view">
      <section className="section editorial-story-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">CORE CAPABILITIES</span>
            <h2 className="section-title">Look beyond the URL.</h2>
            <p className="section-subtitle">
              Phishing links disguise their true intent behind clever domain tricks and encoded paths. PhishGuard exposes every layer.
            </p>
          </div>

          <div className="story-rows-container">
            {featureStories.map((story, i) => (
              <div key={story.tag} className={`story-row ${i % 2 === 1 ? 'story-reversed' : ''}`}>
                <div className="story-content-col">
                  <span className="story-tag-pill">{story.tag}</span>
                  <h3 className="story-headline">{story.headline}</h3>
                  <p className="story-copy">{story.copy}</p>
                  <ul className="story-bullet-list">
                    {story.bullets.map((b, bi) => (
                      <li key={bi}>
                        <span className="bullet-check">✓</span>
                        <span>{b}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="story-visual-col">
                  <div className="story-visual-card">
                    <div className="visual-card-top">
                      <span className="visual-dot" />
                      <span className="visual-badge">{story.badge}</span>
                    </div>
                    <div className="visual-display-body">
                      {i === 0 && (
                        <div className="visual-mock mock-typo">
                          <div className="mock-row spoofed">
                            <span className="mock-label">Spoofed:</span>
                            <code>secure-paypa1-login.com</code>
                            <span className="mock-flag">⚠️ '1' used for 'l'</span>
                          </div>
                          <div className="mock-arrow">↓ Target Brand Comparison</div>
                          <div className="mock-row legit">
                            <span className="mock-label">Legitimate:</span>
                            <code>paypal.com</code>
                            <span className="mock-tag-clean">Official Origin</span>
                          </div>
                        </div>
                      )}
                      {i === 1 && (
                        <div className="visual-mock mock-homo">
                          <div className="mock-char-compare">
                            <div className="char-box fraud">
                              <span className="char-display">googӏe.com</span>
                              <span className="char-sub">Cyrillic Small Letter Palochka (U+04CF)</span>
                            </div>
                            <div className="char-vs">VS</div>
                            <div className="char-box safe">
                              <span className="char-display">google.com</span>
                              <span className="char-sub">Latin Small Letter L (U+006C)</span>
                            </div>
                          </div>
                        </div>
                      )}
                      {i === 2 && (
                        <div className="visual-mock mock-whois">
                          <div className="whois-metric-pill">
                            <span className="whois-num">14</span>
                            <span className="whois-unit">Days Old</span>
                          </div>
                          <div className="whois-alert-banner">
                            <strong>Newly Registered Domain Signal</strong>
                            <p>Created on 2026-09-16. Recent registrations warrant elevated caution.</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="page-bottom-cta-banner">
            <div className="cta-banner-text">
              <h3>Experience deep URL forensics</h3>
              <p>Audit domains across all six signals in seconds.</p>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate('scanner')}
            >
              <span>Start Scanning</span>
              <ArrowUpRight />
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

// --------------------------------------------------------------------------
// PAGE 5: EDUCATION (/education)
// --------------------------------------------------------------------------
function EducationPage({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  const eduCards = [
    {
      tag: 'TYPOSQUATTING',
      title: 'A familiar name can hide a completely different domain.',
      body: 'Attackers register domains that closely resemble legitimate services by inserting hyphens, repeating letters, or substituting numbers for vowels.',
      tip: 'Check the domain name character by character before entering passwords.',
    },
    {
      tag: 'HOMOGLYPHS',
      title: 'Some non-Latin characters look identical on screen.',
      body: 'Unicode characters from other writing systems (like Cyrillic or Greek) can look identical to Latin letters in modern browsers.',
      tip: 'Inspect the raw Punycode or verify the domain origin in PhishGuard.',
    },
    {
      tag: 'URL ENTROPY',
      title: 'Entropy measures the mathematical randomness of text.',
      body: 'High entropy in URL parameters often points to session harvesting tokens, base64 payload strings, or obfuscated redirect endpoints.',
      tip: 'Be wary of unusually long, chaotic URL parameter strings in unsolicited messages.',
    },
    {
      tag: 'DOMAIN AGE',
      title: 'Recently registered infrastructure deserves extra scrutiny.',
      body: 'Attackers create throwaway domains right before launching phishing blasts. A domain under 30 days old is a notable risk indicator.',
      tip: 'Always verify important notifications directly on the provider\'s official portal.',
    },
  ]

  return (
    <div className="page-view education-page-view">
      <section className="section education-editorial-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">KNOWLEDGE &amp; PRECAUTION</span>
            <h2 className="section-title">Technical evidence made easy to understand.</h2>
            <p className="section-subtitle">
              PhishGuard translates deep cybersecurity metrics into accessible concepts, empowering every user to recognize deceptive links.
            </p>
          </div>

          <div className="education-cards-grid">
            {eduCards.map((card, idx) => (
              <article key={card.tag} className={`edu-card ${idx % 2 === 0 ? 'edu-card-dark' : 'edu-card-light'}`}>
                <div className="edu-card-header">
                  <span className="edu-tag">{card.tag}</span>
                  <span className="edu-idx">0{idx + 1}</span>
                </div>
                <h3 className="edu-title">{card.title}</h3>
                <p className="edu-body">{card.body}</p>
                <div className="edu-tip-box">
                  <span className="edu-tip-label">SAFETY TAKEAWAY:</span>
                  <p className="edu-tip-text">{card.tip}</p>
                </div>
              </article>
            ))}
          </div>

          <div className="page-bottom-cta-banner">
            <div className="cta-banner-text">
              <h3>Put your knowledge into practice</h3>
              <p>Inspect suspicious links safely in PhishGuard.</p>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate('scanner')}
            >
              <span>Open Scanner</span>
              <ArrowUpRight />
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

// --------------------------------------------------------------------------
// PAGE 6: ABOUT (/about)
// --------------------------------------------------------------------------
function AboutPage({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  return (
    <div className="page-view about-page-view">
      <section className="section about-editorial-section">
        <div className="section-container">
          <div className="about-editorial-wrap">
            <div className="about-left-col">
              <span className="editorial-eyebrow">ABOUT PHISHGUARD</span>
              <h2 className="about-title">A focused URL intelligence tool.</h2>
            </div>
            <div className="about-right-col">
              <p className="about-lead">
                PhishGuard is engineered around a single mission: helping individuals and teams inspect suspicious web addresses safely using deterministic technical signals, rather than vague AI guesses or generic warnings.
              </p>
              <p className="about-sub">
                By combining syntactic URL parsing, Shannon entropy scoring, typosquatting pattern matching, Unicode homoglyph detection, and public WHOIS/RDAP data, PhishGuard delivers transparent risk assessments you can trust.
              </p>
            </div>
          </div>

          <div className="about-principles-grid">
            <div className="principle-card">
              <span className="principle-num">01</span>
              <h4>Explainable Security</h4>
              <p>Every threat index is backed by verifiable findings so users understand why a URL is dangerous.</p>
            </div>
            <div className="principle-card">
              <span className="principle-num">02</span>
              <h4>Zero Client Execution</h4>
              <p>Inspection happens safely on metadata. Malicious destination scripts are never executed in the browser.</p>
            </div>
            <div className="principle-card">
              <span className="principle-num">03</span>
              <h4>Unfabricated Data</h4>
              <p>We audit real registry timelines and cryptographic entropy without inventing synthetic records.</p>
            </div>
          </div>

          <div className="page-bottom-cta-banner">
            <div className="cta-banner-text">
              <h3>Test PhishGuard Today</h3>
              <p>Safe, transparent, and deterministic URL analysis.</p>
            </div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onNavigate('scanner')}
            >
              <span>Go to Scanner</span>
              <ArrowUpRight />
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

// --------------------------------------------------------------------------
// PAGE 7: SUPPORT (/support)
// --------------------------------------------------------------------------
function SupportPage({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  return (
    <div className="page-view support-page-view">
      <section className="section support-editorial-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">SUPPORT &amp; INQUIRIES</span>
            <h2 className="section-title">We're here to help you stay safe online.</h2>
            <p className="section-subtitle">
              Have questions about a flagged URL, suspicious domain, or need assistance with PhishGuard? Reach out directly.
            </p>
          </div>

          <div className="support-channels-grid">
            <div className="support-card">
              <div className="support-icon-circle">✉</div>
              <h4>Direct Support Email</h4>
              <p>For threat intelligence questions, false-positive reports, or general assistance.</p>
              <a href="mailto:support@phishguard.io" className="support-action-link">
                <span>support@phishguard.io</span>
                <ArrowUpRight />
              </a>
            </div>

            <div className="support-card">
              <div className="support-icon-circle">in</div>
              <h4>Professional Network</h4>
              <p>Connect with the security research and development team on LinkedIn.</p>
              <a href="https://www.linkedin.com/" target="_blank" rel="noopener noreferrer" className="support-action-link">
                <span>PhishGuard on LinkedIn</span>
                <ArrowUpRight />
              </a>
            </div>
          </div>

          <div className="support-faq-block">
            <span className="editorial-eyebrow">FREQUENTLY ASKED QUESTIONS</span>
            <div className="faq-items-list">
              <div className="faq-item">
                <h5>Does PhishGuard open the webpage in my browser?</h5>
                <p>No. PhishGuard inspects the URL syntactically and evaluates external DNS/WHOIS records. Malicious client-side scripts are never loaded or executed.</p>
              </div>
              <div className="faq-item">
                <h5>What makes a domain "Newly Registered"?</h5>
                <p>Domains created less than 30 days prior are classified as newly registered. While not inherently malicious, recent registrations require elevated scrutiny.</p>
              </div>
              <div className="faq-item">
                <h5>How is Shannon Entropy calculated?</h5>
                <p>Entropy measures the algorithmic randomness of characters in the URL string. High entropy often indicates obfuscated session tokens or generated subdomains.</p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

// --------------------------------------------------------------------------
// FOOTER COMPONENT
// --------------------------------------------------------------------------
function Footer({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  return (
    <footer id="support" className="site-footer">
      <div className="footer-container">
        <div className="footer-top-grid">
          <div className="footer-brand-col">
            <Logo onNavigate={onNavigate} />
            <p className="footer-mission-text">
              Inspect suspicious URLs, spoofed domains, and deceptive lookalikes before you trust them.
            </p>
            <div className="footer-status-pill">
              <span className="status-live-dot" />
              <span>Inspection Engine Live</span>
            </div>
          </div>

          <div className="footer-links-col">
            <span className="footer-col-title">NAVIGATION</span>
            <ul className="footer-link-list">
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('scanner')}>Scanner</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('analysis')}>Analysis Dossier</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('how-it-works')}>How It Works</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('capabilities')}>Core Capabilities</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('education')}>Education &amp; Guides</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('about')}>About PhishGuard</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('support')}>Support</button></li>
            </ul>
          </div>

          <div className="footer-links-col">
            <span className="footer-col-title">SUPPORT &amp; CONNECT</span>
            <ul className="footer-link-list">
              <li>
                <a href="mailto:support@phishguard.io" className="footer-contact-link">
                  <span>support@phishguard.io</span>
                </a>
              </li>
              <li>
                <a href="https://www.linkedin.com/" target="_blank" rel="noopener noreferrer" className="footer-contact-link">
                  <span>LinkedIn</span>
                  <ArrowUpRight />
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="footer-bottom-bar">
          <span className="footer-copy">© 2026 PhishGuard. Phishing URL &amp; Spoofed Domain Detection with WHOIS/RDAP Inspection.</span>
          <div className="footer-meta-tags">
            <span>Explainable Threat Intelligence</span>
            <span>·</span>
            <span>Non-Executing Sandbox</span>
          </div>
        </div>
      </div>
    </footer>
  )
}

// --------------------------------------------------------------------------
// MOUSE AURORA COMPONENT (#F8BB2B)
// --------------------------------------------------------------------------
function AuroraSpotlight() {
  const bgRef = React.useRef<HTMLDivElement>(null)
  const fgRef = React.useRef<HTMLDivElement>(null)

  useEffect(() => {
    const mediaQuery = window.matchMedia('(hover: hover) and (pointer: fine)')
    if (!mediaQuery.matches) return

    const bgEl = bgRef.current
    const fgEl = fgRef.current
    if (!bgEl && !fgEl) return

    let targetX = window.innerWidth / 2
    let targetY = window.innerHeight / 3
    let currentX = targetX
    let currentY = targetY
    let isVisible = false
    let targetScale = 1.0
    let currentScale = 1.0
    let targetOpacity = 0
    let currentOpacity = 0
    let prevMouseX = targetX
    let prevMouseY = targetY
    let animFrameId: number

    const lerp = (a: number, b: number, n: number) => a + (b - a) * n

    const onPointerMove = (e: PointerEvent) => {
      targetX = e.clientX
      targetY = e.clientY

      if (!isVisible) {
        isVisible = true
        currentX = targetX
        currentY = targetY
      }
      targetOpacity = 1

      const dx = targetX - prevMouseX
      const dy = targetY - prevMouseY
      const speed = Math.sqrt(dx * dx + dy * dy)
      prevMouseX = targetX
      prevMouseY = targetY

      const target = e.target as HTMLElement | null
      const isInteractive = Boolean(
        target && (
          target.closest('button') ||
          target.closest('a') ||
          target.closest('input') ||
          target.closest('.sample-tag-btn') ||
          target.closest('.analysis-card') ||
          target.closest('.scanner-hero-card') ||
          target.closest('.process-editorial-card') ||
          target.closest('.edu-card') ||
          target.closest('.story-visual-card') ||
          target.closest('.verdict-hero-card')
        )
      )

      const baseScale = isInteractive ? 1.28 : 1.0
      const velocityBonus = Math.min(speed * 0.002, 0.15)
      targetScale = baseScale + velocityBonus

      if (isInteractive) {
        targetOpacity = 1.0
        bgEl?.classList.add('aurora-interactive-active')
        fgEl?.classList.add('aurora-interactive-active')
      } else {
        bgEl?.classList.remove('aurora-interactive-active')
        fgEl?.classList.remove('aurora-interactive-active')
      }
    }

    const onPointerLeave = () => {
      targetOpacity = 0
    }

    const animate = () => {
      currentX = lerp(currentX, targetX, 0.09)
      currentY = lerp(currentY, targetY, 0.09)
      currentScale = lerp(currentScale, targetScale, 0.07)
      currentOpacity = lerp(currentOpacity, targetOpacity, 0.08)

      const transformStr = `translate3d(${currentX}px, ${currentY}px, 0) translate(-50%, -50%) scale(${currentScale.toFixed(3)})`
      const opacityStr = currentOpacity.toFixed(3)

      if (bgEl) {
        bgEl.style.transform = transformStr
        bgEl.style.opacity = opacityStr
      }
      if (fgEl) {
        fgEl.style.transform = transformStr
        fgEl.style.opacity = opacityStr
      }

      animFrameId = requestAnimationFrame(animate)
    }

    window.addEventListener('pointermove', onPointerMove, { passive: true })
    document.addEventListener('pointerleave', onPointerLeave, { passive: true })
    animFrameId = requestAnimationFrame(animate)

    return () => {
      window.removeEventListener('pointermove', onPointerMove)
      document.removeEventListener('pointerleave', onPointerLeave)
      cancelAnimationFrame(animFrameId)
    }
  }, [])

  return (
    <>
      <div ref={bgRef} className="aurora-spotlight-bg" aria-hidden="true" />
      <div ref={fgRef} className="aurora-spotlight-fg" aria-hidden="true" />
    </>
  )
}

export type TransitionDirection = 'forward' | 'backward'

// --------------------------------------------------------------------------
// MAIN PRODUCT APPLICATION COMPONENT (ROUTER & TRANSITIONS)
// --------------------------------------------------------------------------
export default function App() {
  const [currentRoute, setCurrentRoute] = useState<PageRoute>('scanner')
  const [isTransitioning, setIsTransitioning] = useState(false)
  const [transitionDirection, setTransitionDirection] = useState<TransitionDirection>('forward')
  const [activeUrl, setActiveUrl] = useState<string | null>(null)
  const [analysisState, setAnalysisState] = useState<ScanState>('idle')
  const [analysisResult, setAnalysisResult] = useState<AnalysisDetails | null>(null)
  const [analysisError, setAnalysisError] = useState<string | null>(null)

  // Set and lock document title to PhishGuard
  useEffect(() => {
    document.title = 'PhishGuard'
  }, [])

  // Listen to browser back/forward and hash changes
  useEffect(() => {
    document.title = 'PhishGuard'
    const handleHashOrPopState = () => {
      document.title = 'PhishGuard'
      const hash = window.location.hash.replace('#/', '').replace('#', '')
      const validRoutes: PageRoute[] = ['scanner', 'analysis', 'how-it-works', 'capabilities', 'education', 'about', 'support']
      if (validRoutes.includes(hash as PageRoute)) {
        setCurrentRoute(hash as PageRoute)
      } else {
        setCurrentRoute('scanner')
      }
    }

    window.addEventListener('popstate', handleHashOrPopState)
    window.addEventListener('hashchange', handleHashOrPopState)

    handleHashOrPopState()

    return () => {
      window.removeEventListener('popstate', handleHashOrPopState)
      window.removeEventListener('hashchange', handleHashOrPopState)
    }
  }, [])

  // Smooth page transition navigation
  const navigate = (newRoute: PageRoute, direction: TransitionDirection = 'forward') => {
    if (newRoute === currentRoute && !isTransitioning) {
      window.scrollTo({ top: 0, behavior: 'smooth' })
      return
    }

    setTransitionDirection(direction)
    setIsTransitioning(true)
    window.scrollTo({ top: 0, behavior: 'instant' })

    setTimeout(() => {
      setCurrentRoute(newRoute)
      window.location.hash = `#/${newRoute}`
      setTimeout(() => {
        setIsTransitioning(false)
      }, 50)
    }, 220)
  }

  // Triggered when user clicks "Inspect URL" on Scanner page (smooth navigation to analysis)
  const handleStartInspectionFromScanner = (url: string) => {
    setActiveUrl(url)
    setAnalysisState('scanning')
    setAnalysisResult(null)
    setAnalysisError(null)
    navigate('analysis', 'forward')
  }

  // Triggered when user clicks "Inspect URL" directly on Analysis page (in-place scan without route reload)
  const handleStartInspectionOnAnalysis = (url: string) => {
    setActiveUrl(url)
    setAnalysisState('scanning')
    setAnalysisResult(null)
    setAnalysisError(null)
  }

  // Fetch live backend enrichment. The destination URL is never opened by the frontend.
  const handleCompleteScan = (url: string) => {
    void fetchRemoteAnalysis(url)
      .then(result => {
        setAnalysisResult(result)
        setAnalysisError(null)
        setAnalysisState('completed')
      })
      .catch(error => {
        setAnalysisResult(null)
        setAnalysisError(error instanceof Error ? error.message : 'Unable to reach the URL analysis backend.')
        setAnalysisState('error')
      })
  }

  // Triggered when user clicks "← Scan Another URL" / "New Scan"
  const handleResetScan = () => {
    setAnalysisState('idle')
    setActiveUrl(null)
    setAnalysisResult(null)
    setAnalysisError(null)
    navigate('scanner', 'backward')
  }

  const transitionClass = isTransitioning
    ? (transitionDirection === 'backward' ? 'page-transitioning-backward-out' : 'page-transitioning-forward-out')
    : (transitionDirection === 'backward' ? 'page-transitioning-backward-in' : 'page-transitioning-forward-in')

  return (
    <div className="phishguard-app">
      <div className={`transition-ambient-beam ${isTransitioning ? 'beam-active' : ''}`} aria-hidden="true" />
      <AuroraSpotlight />
      <Navbar currentRoute={currentRoute} onNavigate={navigate} />

      <main className={`main-content page-transition-wrapper ${transitionClass}`}>
        {currentRoute === 'scanner' && (
          <ScannerPage onStartInspection={handleStartInspectionFromScanner} />
        )}

        {currentRoute === 'analysis' && (
          <AnalysisPage
            activeUrl={activeUrl}
            analysisState={analysisState}
            analysisResult={analysisResult}
            analysisError={analysisError}
            onStartInspection={handleStartInspectionOnAnalysis}
            onCompleteScan={handleCompleteScan}
            onResetScan={handleResetScan}
          />
        )}

        {currentRoute === 'how-it-works' && (
          <HowItWorksPage onNavigate={navigate} />
        )}

        {currentRoute === 'capabilities' && (
          <CapabilitiesPage onNavigate={navigate} />
        )}

        {currentRoute === 'education' && (
          <EducationPage onNavigate={navigate} />
        )}

        {currentRoute === 'about' && (
          <AboutPage onNavigate={navigate} />
        )}

        {currentRoute === 'support' && (
          <SupportPage onNavigate={navigate} />
        )}
      </main>

      <Footer onNavigate={navigate} />
    </div>
  )
}
