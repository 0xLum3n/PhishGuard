import React, { FormEvent, useEffect, useMemo, useState } from 'react'

// Shows muted styling for values the registry/providers did not return
const isMissing = (v?: string | null) => !v || /^(Unavailable|Not published|Not registered)/i.test(v)

// Types
export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
export type ScanState = 'idle' | 'scanning' | 'completed' | 'error'
export type PageRoute = 'scanner' | 'analysis' | 'blog' | 'education' | 'about' | 'support'

export interface DomainStatus {
  state: 'live' | 'nonexistent' | 'subdomain_missing' | 'registered_no_dns' | 'unknown' | 'ip_host'
  exists: boolean
  title: string
  detail: string
  confidence: 'high' | 'medium' | 'low'
  evidence: string[]
  ips: string[]
}


export interface OSINTDetails {
  url: string
  hostname: string
  domain: string
  subdomain?: string
  tld?: string
  scheme: string
  dnsStatus: string
  resolvedIps: string[]
  ipv6: string[]
  cname: string[]
  domainState?: string
  domainExists?: boolean
  domainConfidence?: string
  queryParameterCount: number
}

export interface AnalysisDetails {
  url: string
  maskedUrl: string
  osint: OSINTDetails
  normalizedUrl: string
  protocol: string
  hostname: string
  domain: string
  tld: string
  path: string
  queryParams: Array<{ key: string; value: string; maskedValue: string; isSensitive: boolean; decoded?: string | null }>
  score?: number
  threatScore: number
  confidence?: number
  summary: string
  verdict: Verdict | 'UNREACHABLE'
  providers?: Record<string, any>
  providerRows?: Array<{ name: string; state: string; detail: string }>
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
    isOfficialDomain?: boolean
    officialBrand?: string
    officialDomain?: string
    confidence?: string
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
    hasOpaquePath?: boolean
    hasRedirectParameter?: boolean
    isTrackingOrRedirectService?: boolean
    isUrlShortener?: boolean
    encodedSegments?: Array<{ raw: string; decoded: string }>
    doubleEncoded?: boolean
    hasUserInfo?: boolean
    subdomainDepth?: number
    redirectTargets?: Array<{ param: string; target: string; host: string; crossDomain: boolean }>
    explanation: string
  }
  whois: {
    domain: string
    registrar: string
    creationDate: string
    domainAgeDays: number
    domainAgeFormatted: string
    status: string
    isNewlyRegistered: boolean
    dnssec: string
    cautionNote?: string
    expirationDate?: string | null
    updatedDate?: string | null
    nameservers?: string[]
    source?: string
    lookupStatus?: 'ok' | 'partial' | 'failed'
    lookupNote?: string | null
    registered?: boolean | null
  }
  intelligence?: {
    dns: { ips: string[]; ipv6: string[]; cname: string[]; status?: string; checks?: Array<{ resolver: string; result: string }> }
    reputation: {
      virustotal?: { found: boolean; malicious: number; suspicious: number; harmless: number; undetected: number; error?: string }
      urlhaus?: { found: boolean; status?: string; threat?: string; tags?: string[]; error?: string }
      otx?: { found: boolean; pulses: number; reputation?: number; error?: string }
      threatfox?: { found: boolean; matches: number; error?: string }
      urlscan?: { found: boolean; total: number; error?: string }
    }
    ipIntelligence: {
      ip?: string
      geolocation?: { country?: string; region?: string; city?: string; latitude?: number; longitude?: number; asn?: string; org?: string; isp?: string }
      shodan?: { ports: number[]; vulns: string[]; tags: string[]; error?: string }
      abuseipdb?: { abuseConfidenceScore: number; totalReports: number; countryCode?: string; isp?: string; error?: string }
      greynoise?: { classification?: string; noise?: boolean; riot?: boolean; name?: string; error?: string }
    }
    signals: Array<{ name: string; score: number; detail: string; severity: 'high' | 'medium' | 'low' | 'info' }>
    providers?: Array<{ name: string; state: string; detail: string }>
    providerTotal?: number
  }
  domainStatus?: DomainStatus
  reasons: Array<{ title: string; detail: string; severity: 'high' | 'medium' | 'low' | 'info' }>
}

// Backend-only analysis pipeline.
// The frontend does not calculate threat scores, entropy, typosquatting,
// registration facts, DNS facts, or IP intelligence. It sends the URL to
// the local FastAPI server and renders only the returned payload.
const BACKEND_ANALYSIS_URL = '/api/analysis'

// Cleans common paste/typing variations so the backend gets a parseable URL:
// "example.com", "//example.com", "http:/x.com", "<https://x.com>", "hxxps://evil[.]com", trailing dots/spaces.
export function normalizeUserUrl(input: string): string {
  let u = (input || '').trim()
  for (let i = 0; i < 3; i++) {
    if (u.length >= 2 && ['<>', '""', "''", '()', '[]'].includes(u[0] + u[u.length - 1])) u = u.slice(1, -1).trim()
  }
  u = u.replace(/[\u200b-\u200d\ufeff]/g, '').replace(/[.,;]+$/, '')
  u = u.replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)/g, '.').replace(/\[:\]/g, ':')
  u = u.replace(/^(https?):\/?(?!\/)(?=[^/])/i, '$1://').replace(/^(https?)\/\//i, '$1://')
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) return u
  if (u.startsWith('//')) return 'https:' + u
  return 'https://' + u.replace(/^\/+/, '')
}

const ANALYSIS_TIMEOUT_MS = 90000

interface BackendEntropy {
  domain_entropy: number
  url_entropy: number
  level: 'Low' | 'Moderate' | 'High' | 'Suspiciously High'
  explanation: string
}

interface BackendTyposquatting {
  detected: boolean
  target_brand?: string | null
  similarity_score?: number | null
  pattern_type?: string | null
  is_official_domain?: boolean | null
  official_brand?: string | null
  official_domain?: string | null
  confidence?: string | null
  explanation: string
}

interface BackendHomoglyph {
  detected: boolean
  characters: Array<{ char: string; code_point: string; lookalike: string; script: string }>
  explanation: string
}

interface BackendStructure {
  has_suspicious_path: boolean
  suspicious_keywords: string[]
  has_encoded_chars: boolean
  has_obfuscated_query: boolean
  has_ip_hostname: boolean
  is_https: boolean
  has_opaque_path?: boolean
  has_redirect_parameter?: boolean
  is_tracking_or_redirect_service?: boolean
  is_url_shortener?: boolean
  encoded_segments?: Array<{ raw: string; decoded: string }>
  double_encoded?: boolean
  has_user_info?: boolean
  subdomain_depth?: number
  redirect_targets?: Array<{ param: string; target: string; host: string; cross_domain: boolean }>
  explanation: string
}

interface BackendSecurityFinding {
  rule_id: string
  category: string
  title: string
  severity: 'info' | 'low' | 'medium' | 'high'
  confidence: 'low' | 'medium' | 'high'
  description: string
  evidence?: Record<string, unknown>
}

interface BackendSecurityResult {
  status: 'completed'
  total_findings: number
  findings: BackendSecurityFinding[]
  observations: string[]
}

interface BackendOSINTProvider {
  source: string
  status: string
  query: string
  matched: boolean
  match_count: number
  matches: Array<{
    source: string
    match_type: string
    indicator: string
    reference?: string | null
    details?: Record<string, unknown>
  }>
  metadata?: Record<string, unknown>
  error?: string | null
}

interface BackendAnalysisResponse {
  success: boolean
  url: {
    original: string
    normalized: string
    scheme: string
    username?: string | null
    password?: string | null
    hostname: string
    port?: number | null
    subdomain?: string | null
    domain?: string | null
    registrable_domain?: string | null
    tld?: string | null
    path: string
    query?: string | null
    query_parameters: Array<{ name: string; value: string; values: string[] }>
    fragment?: string | null
    has_credentials: boolean
    has_query: boolean
    has_fragment: boolean
    is_ip_address: boolean
  }
  dns: {
    hostname: string
    registrable_domain?: string | null
    status: string
    resolved_ips: string[]
    hostname_records?: Record<string, { record_type: string; queried_name: string; status: string; records: string[]; error?: string | null }>
    domain_records?: Record<string, { record_type: string; queried_name: string; status: string; records: string[]; error?: string | null }>
    hostname_txt_records?: { record_type: string; queried_name: string; status: string; records: string[]; error?: string | null } | null
    records?: Record<string, { record_type: string; queried_name: string; status: string; records: string[]; error?: string | null }>
  }
  ip_intelligence: {
    status: string
    total_ips: number
    public_ips: number
    enriched_ips: number
    lookup_limit: number
    limit_reached: boolean
    results: Array<{
      ip: string
      version: 4 | 6
      classification: string
      status: string
      source?: string | null
      country_code?: string | null
      country_name?: string | null
      region?: string | null
      region_code?: string | null
      city?: string | null
      postal?: string | null
      latitude?: number | null
      longitude?: number | null
      timezone?: string | null
      asn?: string | null
      organization?: string | null
      hostname?: string | null
      error?: string | null
    }>
  }
  whois?: {
    domain: string
    status: string
    source?: string | null
    rdap_server?: string | null
    registration_date?: string | null
    expiration_date?: string | null
    last_updated_date?: string | null
    events?: Array<{ action: string; date?: string | null }>
    registrar_name?: string | null
    registrar_id?: string | null
    registry_name?: string | null
    registry_id?: string | null
    domain_status: string[]
    nameservers: Array<{ hostname: string; ipv4?: string[]; ipv6?: string[] }>
    dnssec?: string | null
    redacted: boolean
    error?: string | null
  } | null
  osint?: {
    status: string
    providers: BackendOSINTProvider[]
    matches: Array<{
      source: string
      match_type: string
      indicator: string
      reference?: string | null
      details?: Record<string, unknown>
    }>
    total_matches: number
  } | null
  security?: BackendSecurityResult | null
  dns_security?: BackendSecurityResult | null
  ip_security?: BackendSecurityResult | null
  whois_security?: BackendSecurityResult | null
  osint_security?: BackendSecurityResult | null
  correlation_security?: BackendSecurityResult | null
  final_assessment?: {
    status: 'completed'
    verdict: 'confirmed_threat_evidence' | 'suspicious_indicators' | 'no_significant_evidence' | 'inconclusive'
    confidence: 'low' | 'medium' | 'high'
    risk_score: number
    risk_score_version?: string
    risk_factors?: Record<string, unknown>
    risk_dimensions?: Record<string, number>
    risk_events?: Array<Record<string, unknown>>
    summary: string
    rationale: string[]
    evidence_summary: Record<string, unknown>
    coverage: Record<string, unknown>
  } | null
}


function humanizeToken(value: string): string {
  return value.replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function isLikelySensitiveParam(name: string): boolean {
  return /^(access[_-]?token|api[_-]?key|auth(?:orization)?|code|credential|id[_-]?token|otp|pass(?:word|wd)?|pin|refresh[_-]?token|secret|session(?:id)?|sid|token)$/i.test(name.trim())
}

function maskUrlForDisplay(url: string, queryParameters: Array<{ name: string; value: string; values: string[] }>, hasCredentials: boolean): string {
  try {
    const parsed = new URL(url)
    if (hasCredentials) {
      parsed.username = '••••'
      parsed.password = '••••'
    }
    const sensitiveNames = new Set([
      'access_token', 'apikey', 'api_key', 'auth', 'authorization', 'code', 'credential', 'credentials',
      'id_token', 'otp', 'pass', 'passwd', 'password', 'pin', 'refresh_token', 'secret', 'session', 'sessionid',
      'sid', 'token',
    ])
    for (const param of queryParameters) {
      if (sensitiveNames.has(param.name.trim().toLowerCase())) {
        parsed.searchParams.delete(param.name)
        parsed.searchParams.append(param.name, '••••••••')
      }
    }
    return parsed.toString()
  } catch {
    return url
  }
}


function formatDate(value?: string | null): string {
  if (!value) return 'Not published'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toISOString().slice(0, 10)
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
  { id: '01', name: 'Inspecting URL Structure', desc: 'Protocol, Host, Subdomains, Query Tokens' },
  { id: '02', name: 'Checking Domain & TLD', desc: 'Syntax validation, DNS origin structure' },
  { id: '03', name: 'Detecting Typosquatting', desc: 'Brand imitation, leet-speak & edit distance' },
  { id: '04', name: 'Detecting Homoglyphs', desc: 'Unicode lookalike and Cyrillic character scanner' },
  { id: '05', name: 'Analyzing Shannon Entropy', desc: 'Randomness metrics & payload obfuscation' },
  { id: '06', name: 'Inspecting URL Path & Query', desc: 'Credential harvesting keywords & hex encoding' },
  { id: '07', name: 'Querying Network Intelligence', desc: 'DNS resolution, RDAP registration & IP geolocation' },
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

// Cybersecurity Shield Logo Mark
function PhishGuardShieldLogo({ size = 32 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="brand-shield-svg"
      aria-hidden="true"
    >
      <defs>
        {/* Shield Deep Navy Gradient */}
        <linearGradient id="pgShieldDarkBg" x1="18" y1="2" x2="18" y2="34" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0F1B36" />
          <stop offset="60%" stopColor="#080E1E" />
          <stop offset="100%" stopColor="#040711" />
        </linearGradient>

        {/* Shield Border Gradient with Cyan and Deep Navy */}
        <linearGradient id="pgShieldBorder" x1="4" y1="2" x2="32" y2="34" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.85" />
          <stop offset="45%" stopColor="#00F5D4" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#1E3A8A" stopOpacity="0.9" />
        </linearGradient>

        {/* Cyan/Teal Emblem Gradient */}
        <linearGradient id="pgCyanTeal" x1="9" y1="8" x2="27" y2="28" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00F5D4" />
          <stop offset="50%" stopColor="#00E5FF" />
          <stop offset="100%" stopColor="#0284C7" />
        </linearGradient>

        <linearGradient id="pgCoreGlow" x1="18" y1="11" x2="18" y2="25" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#5EEAD4" />
          <stop offset="100%" stopColor="#06B6D4" />
        </linearGradient>

        {/* Subtle Cyber Glow Filter */}
        <filter id="pgShieldGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="0" stdDeviation="1.2" floodColor="#00F5D4" floodOpacity="0.45" />
        </filter>
      </defs>

      {/* Outer Shield Plate */}
      <path
        d="M18 2.5C24.8 2.5 31.5 5 31.5 5C31.5 5 32.5 18.2 18 33.5C3.5 18.2 4.5 5 4.5 5C4.5 5 11.2 2.5 18 2.5Z"
        fill="url(#pgShieldDarkBg)"
        stroke="url(#pgShieldBorder)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />

      {/* Inner Subtle Shield Rim */}
      <path
        d="M18 5C23.2 5 28.5 7 28.5 7C28.5 7 29.2 17.5 18 29.8C6.8 17.5 7.5 7 7.5 7C7.5 7 12.8 5 18 5Z"
        fill="none"
        stroke="#1E293B"
        strokeWidth="0.8"
        strokeDasharray="2 2"
        opacity="0.6"
      />

      {/* Cyber Security Emblem: Interlocking PhishGuard Geometric Crest */}
      <g filter="url(#pgShieldGlow)">
        {/* Core Shield Emblem Contour */}
        <path
          d="M18 9C21.8 9 25 10.6 25 14.5C25 19.8 18 25 18 25C18 25 11 19.8 11 14.5C11 10.6 14.2 9 18 9Z"
          fill="none"
          stroke="url(#pgCyanTeal)"
          strokeWidth="1.8"
          strokeLinejoin="round"
        />

        {/* Inner Node Crosshair & Radar Lines */}
        <path
          d="M18 12.5V21.5"
          stroke="url(#pgCoreGlow)"
          strokeWidth="1.8"
          strokeLinecap="round"
        />
        <path
          d="M14.5 16H21.5"
          stroke="url(#pgCoreGlow)"
          strokeWidth="1.8"
          strokeLinecap="round"
        />

        {/* Center Node Core */}
        <circle cx="18" cy="16" r="2.2" fill="#00F5D4" />
        <circle cx="18" cy="16" r="0.9" fill="#040711" />
      </g>
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
      <div className="brand-mark brand-shield-mark">
        <PhishGuardShieldLogo size={32} />
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
    { id: 'scanner', label: 'Home' },
    { id: 'analysis', label: 'Analysis' },
    { id: 'blog', label: 'Blog' },
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
function ThreatScoreGauge({ score, verdict }: { score: number; verdict: Verdict | 'UNREACHABLE' }) {
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
    verdict === 'SAFE' ? 'color-safe' : verdict === 'SUSPICIOUS' ? 'color-suspicious' : verdict === 'UNREACHABLE' ? 'color-unreachable' : 'color-malicious'

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
          <span className="gauge-score-badge">{verdict === 'UNREACHABLE' ? 'NOT FOUND' : verdict}</span>
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
// --------------------------------------------------------------------------
// PAGE 1: FULL AUTOMARK-INSPIRED LANDING PAGE (/scanner / home)
// --------------------------------------------------------------------------
function ScannerPage({
  onStartInspection,
  onNavigate,
}: {
  onStartInspection: (url: string) => void
  onNavigate: (route: PageRoute) => void
}) {
  const [isInspecting, setIsInspecting] = useState(false)
  const [activeExplodedPart, setActiveExplodedPart] = useState<'protocol' | 'subdomain' | 'brand' | 'tld' | 'path' | 'query'>('brand')
  const [demoGaugeVerdict, setDemoGaugeVerdict] = useState<'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'>('MALICIOUS')
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(0)

  // Scroll reveal & glow response
  const capabilitiesSectionRef = React.useRef<HTMLElement>(null)
  const [capabilitiesInView, setCapabilitiesInView] = useState(false)
  const [scrollGlowScale, setScrollGlowScale] = useState(1)

  useEffect(() => {
    const el = capabilitiesSectionRef.current
    if (!el) return

    // If user prefers reduced motion, reveal immediately
    if (typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setCapabilitiesInView(true)
      return
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setCapabilitiesInView(true)
          }
        })
      },
      { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
    )

    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  // Passive subtle scroll response for the golden transition glow
  useEffect(() => {
    let animFrame = 0
    const onScroll = () => {
      const el = capabilitiesSectionRef.current
      if (!el) return
      const rect = el.getBoundingClientRect()
      const vh = window.innerHeight
      const dist = Math.abs(rect.top - vh * 0.45)
      const maxDist = vh * 0.75
      const factor = Math.max(0, 1 - dist / maxDist)
      setScrollGlowScale(1 + factor * 0.15)
    }

    window.addEventListener('scroll', onScroll, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll)
      cancelAnimationFrame(animFrame)
    }
  }, [])

  const handleInspect = (url: string) => {
    if (!url.trim() || isInspecting) return
    setIsInspecting(true)
    onStartInspection(url.trim())
  }

  const scrollToScanner = () => {
    const scannerEl = document.getElementById('hero-scanner-card-anchor')
    if (scannerEl) {
      scannerEl.scrollIntoView({ behavior: 'smooth', block: 'center' })
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }

  const demoScores = {
    SAFE: { score: 6, verdict: 'SAFE' as Verdict, title: 'github.com', desc: 'Legitimate domain registered over 16 years ago. Clean ASCII characters, authentic certificate, and standard lexical entropy.' },
    SUSPICIOUS: { score: 48, verdict: 'SUSPICIOUS' as Verdict, title: 'account-security-update-2026.net', desc: 'Domain created 14 days ago with sensitive action keywords (/verify/session) and elevated parameter entropy.' },
    MALICIOUS: { score: 94, verdict: 'MALICIOUS' as Verdict, title: 'secure-paypa1-verification.com', desc: 'Critical brand typosquatting detected. Character substitution ("1" for "l") combined with high-entropy credential harvesting token.' },
  }

  const faqItems = [
    {
      q: 'Does PhishGuard open the suspicious webpage in my browser?',
      a: 'No. PhishGuard operates in a strictly non-executing sandbox. It parses the URL syntactically, evaluates Unicode character code points, computes mathematical Shannon entropy, and queries public WHOIS/RDAP registry databases. Malicious JavaScript, executable binaries, and tracking cookies from the target site are never loaded or executed on your machine.',
    },
    {
      q: 'What is the difference between typosquatting and homoglyphs?',
      a: 'Typosquatting involves registering domains with common typing errors, character substitutions (such as substituting the number "1" for the letter "l"), or prepending deceptive security words. Homoglyphs, on the other hand, exploit Internationalized Domain Names (IDNs) by swapping Latin characters with visually identical characters from Cyrillic or Greek alphabets (e.g. Cyrillic "а" U+0430 vs Latin "a" U+0061).',
    },
    {
      q: 'Why does domain age matter when evaluating a URL?',
      a: 'Cybercriminals frequently stand up disposable domain infrastructure hours or days before launching targeted phishing attacks to bypass traditional static blocklists. A domain registered under 30 days ago that uses brand keywords or asks for credentials is significantly more risky than established domains with years of tenure.',
    },
    {
      q: 'What is Shannon Entropy and how does PhishGuard calculate it?',
      a: 'Shannon entropy measures the mathematical unpredictability and information density of characters within a text string (measured in bits per character). Standard human-readable URLs typically exhibit low entropy (2.5–3.8 bits/char), while base64 tokens, hash strings, and obfuscated credential-smuggling parameters produce high entropy (4.5–6.0+ bits/char).',
    },
    {
      q: 'Does PhishGuard store or share the URLs I inspect?',
      a: 'No. Inspections are performed in-memory during your active session. We do not sell URL logs, store credential payloads, or share telemetry with third-party advertising networks.',
    },
    {
      q: 'Can PhishGuard detect phishing links that use valid HTTPS certificates?',
      a: 'Yes. Modern phishing sites almost universally use free automated SSL/TLS certificates (e.g., Let\'s Encrypt) to display the padlock icon. PhishGuard looks far beyond SSL encryption by analyzing lexical structure, brand imitation, homoglyphs, entropy, and domain tenure.',
    },
  ]

  const explodedPartsData = {
    protocol: {
      label: 'PROTOCOL SCHEME',
      snippet: 'https://',
      status: 'Encrypted Transport',
      badge: 'Transport Layer',
      desc: 'Indicates the communication protocol. While HTTPS ensures transport encryption, modern phishing campaigns routinely utilize automated SSL certificates to project false authenticity.',
    },
    subdomain: {
      label: 'SUBDOMAIN PREFIX',
      snippet: 'secure-login.',
      status: 'Deceptive Keyword Framing',
      badge: 'Social Engineering',
      desc: 'Attackers frequently prepend words like "secure", "login", "verify", or "auth" into the subdomain to trick users into believing they are interacting with an official authentication service.',
    },
    brand: {
      label: 'SLD (SECOND-LEVEL DOMAIN)',
      snippet: 'paypa1',
      status: 'Typosquatting Detected',
      badge: 'Critical Brand Mimicry',
      desc: 'The actual registered name. In this example, the number "1" has been substituted for the lowercase letter "l" to deceive readers into thinking it is the official PayPal domain.',
    },
    tld: {
      label: 'TLD (TOP-LEVEL DOMAIN)',
      snippet: '.com',
      status: 'Commercial Registry',
      badge: 'DNS Zone',
      desc: 'The top-level registry. PhishGuard audits registry reputation and queries WHOIS/RDAP to inspect the exact registration timestamp and registrar profile.',
    },
    path: {
      label: 'URI PATH',
      snippet: '/portal/session/verify',
      status: 'Credential Harvesting Target',
      badge: 'Action Intent',
      desc: 'The path points to the specific server resource. Paths containing phrases like "/session/verify" or "/wallet/auth" suggest an active authentication interception workflow.',
    },
    query: {
      label: 'QUERY PARAMETERS',
      snippet: '?token=cGFzc3dvcmRfZGF0YQ%3D%3D',
      status: 'High-Entropy Payload (4.92 bits/char)',
      badge: 'Encoded Payload',
      desc: 'Query strings carry dynamic data. High-entropy encoded strings frequently conceal base64 payloads, victim identifiers, or multi-hop redirect endpoints.',
    },
  }

  return (
    <div className="page-view scanner-page-view automark-landing-view">
      {/* ------------------------------------------------------------------
          HERO SECTION (Automark Composition + Live URL Inspector)
          ------------------------------------------------------------------ */}
      <section className="hero-editorial-section" id="hero-scanner-card-anchor">
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

              <div className="hero-actions-row">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={scrollToScanner}
                >
                  <span>Launch URL Inspector</span>
                  <ArrowUpRight />
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => onNavigate('blog')}
                >
                  <span>Read Security Blog</span>
                </button>
              </div>

              <div className="hero-trust-block">
                <ShieldCheckIcon />
                <div className="trust-text">
                  <strong>Safe Non-Executing Sandbox</strong>
                  <span>Links are parsed syntactically. Malicious destination scripts never execute in your browser.</span>
                </div>
              </div>
            </div>

            <div className="hero-scanner-col">
              <UrlInspectorCard onInspect={handleInspect} isInspecting={isInspecting} />
            </div>
          </div>

          {/* Automark-Style Hero Telemetry Stats Strip */}
          <div className="hero-stats-strip">
            <div className="hero-stat-item">
              <span className="hero-stat-number">0%</span>
              <span className="hero-stat-label">Client Script Execution</span>
              <span className="hero-stat-desc">Zero browser execution risk</span>
            </div>
            <div className="hero-stat-item">
              <span className="hero-stat-number">6</span>
              <span className="hero-stat-label">Forensic Audit Layers</span>
              <span className="hero-stat-desc">Lexical, Unicode, WHOIS &amp; Entropy</span>
            </div>
            <div className="hero-stat-item">
              <span className="hero-stat-number">0–100</span>
              <span className="hero-stat-label">Explainable Risk Index</span>
              <span className="hero-stat-desc">Deterministic scoring with findings</span>
            </div>
            <div className="hero-stat-item">
              <span className="hero-stat-number">Live</span>
              <span className="hero-stat-label">WHOIS / RDAP Intelligence</span>
              <span className="hero-stat-desc">Domain age &amp; registrar scrutiny</span>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 01: THE PROBLEM / THREAT LANDSCAPE
          ------------------------------------------------------------------ */}
      <section className="section threat-landscape-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">THE THREAT LANDSCAPE</span>
            <h2 className="section-title">Would you know a phishing URL when you see one?</h2>
            <p className="section-subtitle">
              Modern attacks no longer look like obvious spam. Attackers exploit subtle human cognitive blind spots, lookalike character scripts, throwaway DNS infrastructure, and obfuscated parameters.
            </p>
          </div>

          <div className="threat-cards-grid">
            <div className="threat-card">
              <div className="threat-card-num">01</div>
              <span className="threat-card-badge">VISUAL SPOOFING</span>
              <h3 className="threat-card-title">Lookalike Characters &amp; Homoglyphs</h3>
              <p className="threat-card-desc">
                Attackers use Unicode characters from Cyrillic or Greek alphabets (like Cyrillic 'а' or 'ӏ') that render identically to Latin letters on standard screens.
              </p>
              <div className="threat-card-demo">
                <code>goog<span className="text-malicious font-bold">ӏ</span>e.com</code>
                <span className="threat-demo-note">U+04CF Cyrillic Palochka</span>
              </div>
            </div>

            <div className="threat-card">
              <div className="threat-card-num">02</div>
              <span className="threat-card-badge">THROWAWAY INFRASTRUCTURE</span>
              <h3 className="threat-card-title">Newly Registered Domains</h3>
              <p className="threat-card-desc">
                Phishing campaigns stand up disposable domains hours before sending spear-phishing emails, evading static blocklists that take days to update.
              </p>
              <div className="threat-card-demo">
                <span className="threat-demo-highlight">14 Days Active</span>
                <span className="threat-demo-note">Fresh domain flagged for caution</span>
              </div>
            </div>

            <div className="threat-card">
              <div className="threat-card-num">03</div>
              <span className="threat-card-badge">PAYLOAD OBFUSCATION</span>
              <h3 className="threat-card-title">High Entropy &amp; Token Smuggling</h3>
              <p className="threat-card-desc">
                Deceptive query parameters conceal base64 payloads, victim tracking tokens, and multi-stage redirect targets inside long, randomized strings.
              </p>
              <div className="threat-card-demo">
                <code>?token=<span className="text-suspicious">cGFzc3dvcm...</span></code>
                <span className="threat-demo-note">Entropy: 4.88 bits/char</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 02: THE PHISHGUARD SOLUTION
          ------------------------------------------------------------------ */}
      <section className="section solution-editorial-section">
        <div className="section-container">
          <div className="solution-overview-box">
            <div className="solution-copy">
              <span className="editorial-eyebrow">DETERMINISTIC FORENSICS</span>
              <h2 className="section-title">Look beyond the URL.</h2>
              <p className="section-subtitle">
                PhishGuard operates as a non-executing security analyzer. It evaluates every component of a web address using mathematical algorithms, registry telemetry, and character mapping.
              </p>
              <div className="solution-pills-row">
                <span className="sol-pill">✓ Levenshtein Typosquatting</span>
                <span className="sol-pill">✓ Unicode Homoglyph Audit</span>
                <span className="sol-pill">✓ WHOIS / RDAP Domain Age</span>
                <span className="sol-pill">✓ Shannon Entropy Scoring</span>
                <span className="sol-pill">✓ Path Semantics &amp; Keywords</span>
                <span className="sol-pill">✓ Transparent 0–100 Verdict</span>
              </div>
            </div>

            <div className="solution-graphic-card">
              <div className="sol-graphic-header">
                <span className="sol-dot" />
                <span className="sol-graphic-title">INSPECTION PIPELINE</span>
              </div>
              <div className="sol-pipeline-list">
                <div className="pipeline-item">
                  <span className="pipeline-step-idx">L1</span>
                  <div className="pipeline-step-info">
                    <strong>Lexical &amp; Script Parser</strong>
                    <span>Decomposes hostname, checks Punycode &amp; non-ASCII Unicode code points.</span>
                  </div>
                </div>
                <div className="pipeline-item">
                  <span className="pipeline-step-idx">L2</span>
                  <div className="pipeline-step-info">
                    <strong>Algorithmic Entropy Engine</strong>
                    <span>Computes Shannon entropy across hostname, URI path, and query tokens.</span>
                  </div>
                </div>
                <div className="pipeline-item">
                  <span className="pipeline-step-idx">L3</span>
                  <div className="pipeline-step-info">
                    <strong>Registry &amp; WHOIS Telemetry</strong>
                    <span>Verifies domain birth dates, registrar profile, and DNS configuration.</span>
                  </div>
                </div>
                <div className="pipeline-item highlight-item">
                  <span className="pipeline-step-idx">L4</span>
                  <div className="pipeline-step-info">
                    <strong>Explainable Threat Scoring</strong>
                    <span>Synthesizes all factors into an audited 0–100 score and verdict badge.</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Soft Animated Golden Transition with 3 Overlapping Glow Layers */}
        <div
          className="section-atmospheric-glow-transition"
          style={{ '--scroll-glow-scale': scrollGlowScale } as React.CSSProperties}
          aria-hidden="true"
        >
          <div className="glow-layer glow-layer-3" />
          <div className="glow-layer glow-layer-2" />
          <div className="glow-layer glow-layer-1" />
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 03: CAPABILITIES (6 ALTERNATING STORYTELLING ROWS)
          ------------------------------------------------------------------ */}
      <section
        ref={capabilitiesSectionRef}
        className={`section editorial-story-section ${capabilitiesInView ? 'capabilities-revealed' : 'capabilities-hidden'}`}
      >
        <div className="section-container">
          <div className="section-intro capability-intro-reveal">
            <span className="editorial-eyebrow capability-eyebrow-reveal">INSPECTION LAYERS &amp; TELEMETRY</span>
            <h2 className="section-title capability-heading-reveal">Six layers of technical intelligence.</h2>
            <p className="section-subtitle capability-desc-reveal">
              Phishing links disguise their true intent behind clever domain tricks and encoded paths. PhishGuard exposes every layer.
            </p>
          </div>

          <div className="story-rows-container">
            {/* Row 1: Typosquatting */}
            <div className="story-row">
              <div className="story-content-col">
                <span className="story-tag-pill">TYPOSQUATTING &amp; BRAND SPOOFING</span>
                <h3 className="story-headline">Attackers don't invent new names. They misspell familiar ones.</h3>
                <p className="story-copy">
                  Typosquatting takes advantage of small typos, character insertions, or digit swaps (such as substituting "1" for "l" or "0" for "o"). PhishGuard tests domains against known corporate targets to uncover brand impersonation before you type your credentials.
                </p>
                <ul className="story-bullet-list">
                  <li><span className="bullet-check">✓</span><span>Levenshtein edit-distance calculations</span></li>
                  <li><span className="bullet-check">✓</span><span>Leet-speak &amp; numeric substitution detection</span></li>
                  <li><span className="bullet-check">✓</span><span>Subdomain brand trickery verification</span></li>
                </ul>
              </div>
              <div className="story-visual-col">
                <div className="story-visual-card">
                  <div className="visual-card-top">
                    <span className="visual-dot" />
                    <span className="visual-badge">Signal 01</span>
                  </div>
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
                </div>
              </div>
            </div>

            {/* Row 2: Homoglyphs (Reversed) */}
            <div className="story-row story-reversed">
              <div className="story-content-col">
                <span className="story-tag-pill">HOMOGLYPH &amp; UNICODE AUDIT</span>
                <h3 className="story-headline">One lookalike character can deceive the human eye.</h3>
                <p className="story-copy">
                  Internationalized Domain Names (IDNs) allow foreign alphabets in web addresses. Cybercriminals exploit this by swapping Latin letters for visually indistinguishable Cyrillic or Greek characters. PhishGuard checks the exact Unicode code points to detect hidden impostor domains.
                </p>
                <ul className="story-bullet-list">
                  <li><span className="bullet-check">✓</span><span>Cyrillic &amp; Greek lookalike mapping</span></li>
                  <li><span className="bullet-check">✓</span><span>Punycode (xn--) and ASCII decomposition</span></li>
                  <li><span className="bullet-check">✓</span><span>Visual homoglyph alert generation</span></li>
                </ul>
              </div>
              <div className="story-visual-col">
                <div className="story-visual-card">
                  <div className="visual-card-top">
                    <span className="visual-dot" />
                    <span className="visual-badge">Signal 02</span>
                  </div>
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
              </div>
            </div>

            {/* Row 3: WHOIS / Domain Age */}
            <div className="story-row">
              <div className="story-content-col">
                <span className="story-tag-pill">REGISTRY &amp; DOMAIN AGE</span>
                <h3 className="story-headline">Newly registered domains demand additional caution.</h3>
                <p className="story-copy">
                  Malicious infrastructure is often stood up hours before a spear-phishing campaign launches. PhishGuard audits public WHOIS/RDAP signals, highlighting newly created domains (under 30 days) and evaluating registrar reputation without fabricating telemetry.
                </p>
                <ul className="story-bullet-list">
                  <li><span className="bullet-check">✓</span><span>Domain creation &amp; expiration dates</span></li>
                  <li><span className="bullet-check">✓</span><span>Public registrar organization telemetry</span></li>
                  <li><span className="bullet-check">✓</span><span>Domain tenure risk factor weighting</span></li>
                </ul>
              </div>
              <div className="story-visual-col">
                <div className="story-visual-card">
                  <div className="visual-card-top">
                    <span className="visual-dot" />
                    <span className="visual-badge">Signal 03</span>
                  </div>
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
                </div>
              </div>
            </div>

            {/* Row 4: Shannon Entropy (Reversed) */}
            <div className="story-row story-reversed">
              <div className="story-content-col">
                <span className="story-tag-pill">SHANNON ENTROPY AUDIT</span>
                <h3 className="story-headline">Mathematical randomness uncovers hidden tokens.</h3>
                <p className="story-copy">
                  Natural domain names and clean paths follow linguistic frequency patterns. Phishing URLs with generated tokens, encoded hash strings, or base64 payloads exhibit high entropy (over 4.5 bits/character).
                </p>
                <ul className="story-bullet-list">
                  <li><span className="bullet-check">✓</span><span>Bit-per-character lexical distribution</span></li>
                  <li><span className="bullet-check">✓</span><span>Query parameter entropy calculation</span></li>
                  <li><span className="bullet-check">✓</span><span>Automated token smuggling classification</span></li>
                </ul>
              </div>
              <div className="story-visual-col">
                <div className="story-visual-card">
                  <div className="visual-card-top">
                    <span className="visual-dot" />
                    <span className="visual-badge">Signal 04</span>
                  </div>
                  <div className="entropy-visual-demo">
                    <div className="entropy-demo-header">
                      <span className="entropy-demo-val">4.92 <small>bits/char</small></span>
                      <span className="entropy-demo-badge badge-suspiciously-high">Suspiciously High</span>
                    </div>
                    <div className="entropy-track">
                      <div className="entropy-bar-fill" style={{ width: '82%' }} />
                    </div>
                    <div className="entropy-scale-labels">
                      <span>0.0 Natural</span>
                      <span>3.5 Normal</span>
                      <span>4.5 Suspicious</span>
                      <span>6.0+ Encrypted</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Row 5: Path & Query Forensics */}
            <div className="story-row">
              <div className="story-content-col">
                <span className="story-tag-pill">URL PATH &amp; PARAMETER FORENSICS</span>
                <h3 className="story-headline">Sensitive keyword paths reveal malicious intent.</h3>
                <p className="story-copy">
                  Phishing websites structure their paths to mimic authentication gates. PhishGuard highlights sensitive keywords like "/login", "/verify", "/update-billing", and flags URL-encoded obfuscations (%xx).
                </p>
                <ul className="story-bullet-list">
                  <li><span className="bullet-check">✓</span><span>Keyword intent analysis (/auth, /wallet, /verify)</span></li>
                  <li><span className="bullet-check">✓</span><span>Percent-encoded hex string decoding</span></li>
                  <li><span className="bullet-check">✓</span><span>Suspicious parameter nesting detection</span></li>
                </ul>
              </div>
              <div className="story-visual-col">
                <div className="story-visual-card">
                  <div className="visual-card-top">
                    <span className="visual-dot" />
                    <span className="visual-badge">Signal 05</span>
                  </div>
                  <div className="path-decomp-demo">
                    <div className="decomp-row">
                      <span className="decomp-label">Target URI:</span>
                      <code>/portal/verify/session-auth</code>
                    </div>
                    <div className="decomp-chips-row">
                      <span className="keyword-chip">verify</span>
                      <span className="keyword-chip">session-auth</span>
                      <span className="keyword-chip">portal</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Row 6: Explainable Threat Scoring (Reversed) */}
            <div className="story-row story-reversed">
              <div className="story-content-col">
                <span className="story-tag-pill">EXPLAINABLE THREAT INDEX</span>
                <h3 className="story-headline">Transparent scores backed by verifiable evidence.</h3>
                <p className="story-copy">
                  Instead of ambiguous warnings, PhishGuard outputs an explainable 0–100 Threat Index where each factor is clearly itemized: domain age, homoglyphs, typosquatting, entropy, and sensitive keywords.
                </p>
                <ul className="story-bullet-list">
                  <li><span className="bullet-check">✓</span><span>Weighted factor aggregation</span></li>
                  <li><span className="bullet-check">✓</span><span>Deterministic Safe / Suspicious / Malicious verdicts</span></li>
                  <li><span className="bullet-check">✓</span><span>Actionable takeaway guidance</span></li>
                </ul>
              </div>
              <div className="story-visual-col">
                <div className="story-visual-card">
                  <div className="visual-card-top">
                    <span className="visual-dot" />
                    <span className="visual-badge">Signal 06</span>
                  </div>
                  <div className="threat-summary-demo">
                    <div className="threat-verdict-pill-mini verdict-malicious">
                      <span>MALICIOUS VERDICT (94/100)</span>
                    </div>
                    <div className="findings-bullet-list">
                      <div className="finding-bullet-item severity-high">
                        <span className="finding-bullet-index">01</span>
                        <div className="finding-bullet-content">
                          <strong className="finding-bullet-title">Typosquatting Detected</strong>
                          <p className="finding-bullet-desc">Imitates PayPal with '1' substituted for 'l'.</p>
                        </div>
                      </div>
                      <div className="finding-bullet-item severity-medium">
                        <span className="finding-bullet-index">02</span>
                        <div className="finding-bullet-content">
                          <strong className="finding-bullet-title">High Query Entropy</strong>
                          <p className="finding-bullet-desc">Entropy 4.92 indicates encoded session token.</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 04: CYBERSECURITY VISUAL / IMAGE CAROUSEL
          ------------------------------------------------------------------ */}
      <section className="section carousel-editorial-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">CYBERSECURITY CAROUSEL</span>
            <h2 className="section-title">Know what you're looking for.</h2>
            <p className="section-subtitle">
              Understand the visual and technical indicators used to detect lookalike domains, obfuscated paths, and deceptive URLs.
            </p>
          </div>

          <CybersecurityCarousel />
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 05: HOW PHISHGUARD WORKS (NUMBERED 01–04)
          ------------------------------------------------------------------ */}
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
            <div className="process-editorial-card">
              <span className="process-step-number">01</span>
              <div className="process-divider-dot" />
              <h3 className="process-step-title">PASTE</h3>
              <p className="process-step-desc">
                Paste any suspicious link, message attachment URL, or lookalike domain into the safe inspector input.
              </p>
            </div>
            <div className="process-editorial-card">
              <span className="process-step-number">02</span>
              <div className="process-divider-dot" />
              <h3 className="process-step-title">INSPECT</h3>
              <p className="process-step-desc">
                PhishGuard decomposes the hostname, analyzes character scripts, computes Shannon entropy, and queries WHOIS registry signals.
              </p>
            </div>
            <div className="process-editorial-card">
              <span className="process-step-number">03</span>
              <div className="process-divider-dot" />
              <h3 className="process-step-title">ASSESS</h3>
              <p className="process-step-desc">
                All structural and registration signals are synthesized into an explainable 0–100 threat score and risk category.
              </p>
            </div>
            <div className="process-editorial-card">
              <span className="process-step-number">04</span>
              <div className="process-divider-dot" />
              <h3 className="process-step-title">UNDERSTAND</h3>
              <p className="process-step-desc">
                Review transparent findings detailing why the URL is flagged and receive actionable safety recommendations.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 06: DEEP URL INSPECTION (EXPLODED URL INTERACTIVE VISUAL)
          ------------------------------------------------------------------ */}
      <section className="section exploded-url-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">DEEP URL INSPECTION</span>
            <h2 className="section-title">Every part of the URL tells a story.</h2>
            <p className="section-subtitle">
              Click through the individual anatomy segments below to see how PhishGuard evaluates each element of a web address.
            </p>
          </div>

          <div className="exploded-inspector-card">
            {/* Exploded Segment Bar */}
            <div className="exploded-bar-container">
              <button
                type="button"
                className={`exploded-segment-btn ${activeExplodedPart === 'protocol' ? 'active-segment' : ''}`}
                onClick={() => setActiveExplodedPart('protocol')}
              >
                <span className="segment-sub">PROTOCOL</span>
                <span className="segment-text">https://</span>
              </button>
              <button
                type="button"
                className={`exploded-segment-btn ${activeExplodedPart === 'subdomain' ? 'active-segment' : ''}`}
                onClick={() => setActiveExplodedPart('subdomain')}
              >
                <span className="segment-sub">SUBDOMAIN</span>
                <span className="segment-text">secure-login.</span>
              </button>
              <button
                type="button"
                className={`exploded-segment-btn ${activeExplodedPart === 'brand' ? 'active-segment' : ''}`}
                onClick={() => setActiveExplodedPart('brand')}
              >
                <span className="segment-sub">SLD / BRAND</span>
                <span className="segment-text text-malicious">paypa1</span>
              </button>
              <button
                type="button"
                className={`exploded-segment-btn ${activeExplodedPart === 'tld' ? 'active-segment' : ''}`}
                onClick={() => setActiveExplodedPart('tld')}
              >
                <span className="segment-sub">TLD</span>
                <span className="segment-text">.com</span>
              </button>
              <button
                type="button"
                className={`exploded-segment-btn ${activeExplodedPart === 'path' ? 'active-segment' : ''}`}
                onClick={() => setActiveExplodedPart('path')}
              >
                <span className="segment-sub">PATH</span>
                <span className="segment-text">/portal/session/verify</span>
              </button>
              <button
                type="button"
                className={`exploded-segment-btn ${activeExplodedPart === 'query' ? 'active-segment' : ''}`}
                onClick={() => setActiveExplodedPart('query')}
              >
                <span className="segment-sub">QUERY</span>
                <span className="segment-text">?token=cGFzc3...</span>
              </button>
            </div>

            {/* Exploded Details Box */}
            <div className="exploded-details-panel">
              <div className="exploded-panel-header">
                <div>
                  <span className="exploded-badge">{explodedPartsData[activeExplodedPart].badge}</span>
                  <h4 className="exploded-panel-title">{explodedPartsData[activeExplodedPart].label}</h4>
                </div>
                <code className="exploded-panel-code">{explodedPartsData[activeExplodedPart].snippet}</code>
              </div>
              <div className="exploded-status-strip">
                <span className="status-label">Forensic Status:</span>
                <strong>{explodedPartsData[activeExplodedPart].status}</strong>
              </div>
              <p className="exploded-panel-desc">{explodedPartsData[activeExplodedPart].desc}</p>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 07: DOMAIN INTELLIGENCE & REGISTRY AUDIT
          ------------------------------------------------------------------ */}
      <section className="section whois-showcase-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">DOMAIN INTELLIGENCE</span>
            <h2 className="section-title">Know when a domain was born.</h2>
            <p className="section-subtitle">
              Spear-phishing campaigns frequently rely on disposable domains registered hours before launch. PhishGuard audits registry records to detect fresh infrastructure.
            </p>
          </div>

          <div className="whois-cards-grid">
            <div className="whois-showcase-card">
              <div className="whois-showcase-header">
                <span className="whois-card-tag">AGE TELEMETRY</span>
                <span className="whois-card-num">01</span>
              </div>
              <h3 className="whois-card-title">Registration Lifecycle</h3>
              <p className="whois-card-desc">
                Tracking domain birth timestamps to calculate exact domain tenure. Domains under 30 days old are prioritized for heightened scrutiny.
              </p>
              <div className="whois-stat-box">
                <span className="stat-big font-mono">&lt; 30 Days</span>
                <span className="stat-label">Elevated Risk Window</span>
              </div>
            </div>

            <div className="whois-showcase-card">
              <div className="whois-showcase-header">
                <span className="whois-card-tag">REGISTRAR VERIFICATION</span>
                <span className="whois-card-num">02</span>
              </div>
              <h3 className="whois-card-title">Public Registry Profiling</h3>
              <p className="whois-card-desc">
                Auditing the sponsoring registrar, DNSSEC validation status, and registry locks without relying on synthetic data.
              </p>
              <div className="whois-stat-box">
                <span className="stat-big font-mono">ICANN / RDAP</span>
                <span className="stat-label">Standardized Public Query Protocol</span>
              </div>
            </div>

            <div className="whois-showcase-card">
              <div className="whois-showcase-header">
                <span className="whois-card-tag">CORRELATION</span>
                <span className="whois-card-num">03</span>
              </div>
              <h3 className="whois-card-title">Multi-Signal Risk Weighting</h3>
              <p className="whois-card-desc">
                A newly registered domain is not inherently malicious, but combined with typosquatting or sensitive keywords, it warrants an immediate alert.
              </p>
              <div className="whois-stat-box">
                <span className="stat-big font-mono">+35 Pts</span>
                <span className="stat-label">Threat Factor Contribution</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 08: EXPLAINABLE THREAT SCORE DEMO
          ------------------------------------------------------------------ */}
      <section className="section threat-demo-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">TRANSPARENT SCORING</span>
            <h2 className="section-title">Turn signals into an explainable risk score.</h2>
            <p className="section-subtitle">
              No black boxes. PhishGuard maps every detected anomaly directly to the overall threat verdict. Try the live presets below:
            </p>
          </div>

          <div className="threat-demo-container">
            <div className="threat-demo-controls">
              <button
                type="button"
                className={`demo-preset-btn ${demoGaugeVerdict === 'SAFE' ? 'active-preset safe' : ''}`}
                onClick={() => setDemoGaugeVerdict('SAFE')}
              >
                <span>Safe Origin (0–20)</span>
                <code>github.com</code>
              </button>
              <button
                type="button"
                className={`demo-preset-btn ${demoGaugeVerdict === 'SUSPICIOUS' ? 'active-preset suspicious' : ''}`}
                onClick={() => setDemoGaugeVerdict('SUSPICIOUS')}
              >
                <span>Suspicious Link (21–60)</span>
                <code>account-security-update.net</code>
              </button>
              <button
                type="button"
                className={`demo-preset-btn ${demoGaugeVerdict === 'MALICIOUS' ? 'active-preset malicious' : ''}`}
                onClick={() => setDemoGaugeVerdict('MALICIOUS')}
              >
                <span>Malicious Phish (61–100)</span>
                <code>secure-paypa1-verification.com</code>
              </button>
            </div>

            <div className="threat-demo-display-card">
              <div className="demo-card-left">
                <div className="demo-verdict-header">
                  <span className={`verdict-tag verdict-badge-${demoGaugeVerdict.toLowerCase()}`}>
                    {demoGaugeVerdict} VERDICT
                  </span>
                  <span className="demo-score-chip font-mono">
                    Score: {demoScores[demoGaugeVerdict].score}/100
                  </span>
                </div>
                <h3 className="demo-target-url">
                  <code>{demoScores[demoGaugeVerdict].title}</code>
                </h3>
                <p className="demo-target-desc">{demoScores[demoGaugeVerdict].desc}</p>
              </div>

              <div className="demo-card-right">
                <ThreatScoreGauge
                  score={demoScores[demoGaugeVerdict].score}
                  verdict={demoScores[demoGaugeVerdict].verdict}
                />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 09: EDUCATION ACADEMY
          ------------------------------------------------------------------ */}
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
            <article className="edu-card edu-card-dark">
              <div className="edu-card-header">
                <span className="edu-tag">TYPOSQUATTING</span>
                <span className="edu-idx">01</span>
              </div>
              <h3 className="edu-title">A familiar name can hide a completely different domain.</h3>
              <p className="edu-body">Attackers register domains that closely resemble legitimate services by inserting hyphens, repeating letters, or substituting numbers for vowels.</p>
              <div className="edu-tip-box">
                <span className="edu-tip-label">SAFETY TAKEAWAY:</span>
                <p className="edu-tip-text">Check the domain name character by character before entering passwords.</p>
              </div>
            </article>

            <article className="edu-card edu-card-light">
              <div className="edu-card-header">
                <span className="edu-tag">HOMOGLYPHS</span>
                <span className="edu-idx">02</span>
              </div>
              <h3 className="edu-title">Some non-Latin characters look identical on screen.</h3>
              <p className="edu-body">Unicode characters from other writing systems (like Cyrillic or Greek) can look identical to Latin letters in modern browsers.</p>
              <div className="edu-tip-box">
                <span className="edu-tip-label">SAFETY TAKEAWAY:</span>
                <p className="edu-tip-text">Inspect the raw Punycode or verify the domain origin in PhishGuard.</p>
              </div>
            </article>

            <article className="edu-card edu-card-light">
              <div className="edu-card-header">
                <span className="edu-tag">URL ENTROPY</span>
                <span className="edu-idx">03</span>
              </div>
              <h3 className="edu-title">Entropy measures the mathematical randomness of text.</h3>
              <p className="edu-body">High entropy in URL parameters often points to session harvesting tokens, base64 payload strings, or obfuscated redirect endpoints.</p>
              <div className="edu-tip-box">
                <span className="edu-tip-label">SAFETY TAKEAWAY:</span>
                <p className="edu-tip-text">Be wary of unusually long, chaotic URL parameter strings in unsolicited messages.</p>
              </div>
            </article>

            <article className="edu-card edu-card-dark">
              <div className="edu-card-header">
                <span className="edu-tag">DOMAIN AGE</span>
                <span className="edu-idx">04</span>
              </div>
              <h3 className="edu-title">Recently registered infrastructure deserves extra scrutiny.</h3>
              <p className="edu-body">Attackers create throwaway domains right before launching phishing blasts. A domain under 30 days old is a notable risk indicator.</p>
              <div className="edu-tip-box">
                <span className="edu-tip-label">SAFETY TAKEAWAY:</span>
                <p className="edu-tip-text">Always verify important notifications directly on the provider's official portal.</p>
              </div>
            </article>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 10: SAFE INSPECTION SANDBOX GUARANTEE
          ------------------------------------------------------------------ */}
      <section className="section safe-guarantee-section">
        <div className="section-container">
          <div className="guarantee-hero-card">
            <div className="guarantee-left-col">
              <span className="editorial-eyebrow">SAFE INSPECTION GUARANTEE</span>
              <h2 className="guarantee-heading">Inspect without opening the destination.</h2>
              <p className="guarantee-desc">
                Traditional link verification tools accidentally trigger drive-by downloads or payload tracking beacons. PhishGuard uses a strict zero-execution model.
              </p>
              <button
                type="button"
                className="btn btn-primary"
                onClick={scrollToScanner}
              >
                <span>Inspect Suspicious Link</span>
                <ArrowUpRight />
              </button>
            </div>

            <div className="guarantee-right-col">
              <div className="guarantee-pill-item">
                <div className="guarantee-pill-icon">🛡️</div>
                <div className="guarantee-pill-text">
                  <strong>Zero Client-Side Execution</strong>
                  <span>Destination HTML, JavaScript, and iframes are never downloaded or executed on your machine.</span>
                </div>
              </div>
              <div className="guarantee-pill-item">
                <div className="guarantee-pill-icon">🔒</div>
                <div className="guarantee-pill-text">
                  <strong>Local Syntactic Parsing</strong>
                  <span>Lexical decomposition and Shannon entropy are calculated securely in-session.</span>
                </div>
              </div>
              <div className="guarantee-pill-item">
                <div className="guarantee-pill-icon">🌐</div>
                <div className="guarantee-pill-text">
                  <strong>Deterministic Threat Output</strong>
                  <span>Verdicts are derived from transparent evidence, not opaque predictive approximations.</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 11: CYBERSECURITY FORENSIC INSIGHTS
          ------------------------------------------------------------------ */}
      <section className="section insights-editorial-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">FORENSIC FIELD NOTES</span>
            <h2 className="section-title">Real-world attack patterns analyzed by PhishGuard.</h2>
            <p className="section-subtitle">
              Case studies on deceptive mechanisms observed across recent spear-phishing and credential harvesting campaigns.
            </p>
          </div>

          <div className="insights-cards-grid">
            <div className="insight-card">
              <div className="insight-top">
                <span className="insight-tag">CASE STUDY 01</span>
                <span className="insight-date font-mono">FINANCIAL SERVICES</span>
              </div>
              <h3 className="insight-title">The Subdomain Brand Illusion</h3>
              <p className="insight-desc">
                Attackers registered <code>paypal.com.account-verify-portal.net</code>. Mobile browsers truncated the address bar to show only "paypal.com", concealing the true malicious root domain.
              </p>
              <div className="insight-footer-badge">
                <span>Signal: Subdomain Brand Trickery</span>
              </div>
            </div>

            <div className="insight-card">
              <div className="insight-top">
                <span className="insight-tag">CASE STUDY 02</span>
                <span className="insight-date font-mono">EXECUTIVE SPOOFING</span>
              </div>
              <h3 className="insight-title">Homoglyphic CEO Impersonation</h3>
              <p className="insight-desc">
                A spear-phishing link used the Cyrillic 'о' (U+043E) in an internal portal URL. The visual difference was 0 pixels in standard sans-serif rendering engines.
              </p>
              <div className="insight-footer-badge">
                <span>Signal: Non-ASCII IDN Detected</span>
              </div>
            </div>

            <div className="insight-card">
              <div className="insight-top">
                <span className="insight-tag">CASE STUDY 03</span>
                <span className="insight-date font-mono">OAUTH INTERCEPTION</span>
              </div>
              <h3 className="insight-title">Entropy-Driven Token Smuggling</h3>
              <p className="insight-desc">
                High-entropy query parameters concealed base64 session identifiers, funneling targets through multi-hop redirect gateways without human detection.
              </p>
              <div className="insight-footer-badge">
                <span>Signal: High Parameter Entropy</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 12: INTERACTIVE FAQ ACCORDION
          ------------------------------------------------------------------ */}
      <section className="section faq-editorial-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">FREQUENTLY ASKED QUESTIONS</span>
            <h2 className="section-title">Everything you need to know about PhishGuard.</h2>
            <p className="section-subtitle">
              Common questions about URL forensics, non-executing sandboxes, homoglyph detection, and threat calculation.
            </p>
          </div>

          <div className="accordion-wrapper">
            {faqItems.map((item, idx) => {
              const isOpen = openFaqIndex === idx
              return (
                <div key={idx} className={`accordion-item ${isOpen ? 'accordion-open' : ''}`}>
                  <button
                    type="button"
                    className="accordion-trigger"
                    onClick={() => setOpenFaqIndex(isOpen ? null : idx)}
                    aria-expanded={isOpen}
                  >
                    <span className="accordion-question">{item.q}</span>
                    <span className="accordion-icon">{isOpen ? '−' : '+'}</span>
                  </button>
                  {isOpen && (
                    <div className="accordion-content">
                      <p>{item.a}</p>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------
          SECTION 13: FINAL CTA BANNER (Automark Style)
          ------------------------------------------------------------------ */}
      <section className="section final-cta-section">
        <div className="section-container">
          <div className="page-bottom-cta-banner automark-final-banner">
            <div className="page-bottom-cta-content">
              <span className="editorial-eyebrow text-accent-gold">START PROTECTING YOURSELF</span>
              <h2 className="page-bottom-cta-title">Before you trust the link, inspect it.</h2>
              <p className="page-bottom-cta-desc">
                Paste any suspicious link, email CTA, SMS shortlink, or lookalike domain to run real-time forensics without executing browser scripts.
              </p>
            </div>
            <div className="final-cta-btn-group">
              <button
                type="button"
                className="btn btn-primary"
                onClick={scrollToScanner}
              >
                <span>Launch URL Inspector</span>
                <ArrowUpRight />
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-inverted"
                onClick={() => onNavigate('blog')}
              >
                <span>Explore Security Blog</span>
              </button>
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
type AssessmentVerdict = NonNullable<BackendAnalysisResponse['final_assessment']>['verdict']

function assessmentLabel(verdict?: AssessmentVerdict): string {
  switch (verdict) {
    case 'confirmed_threat_evidence': return 'Confirmed threat evidence'
    case 'suspicious_indicators': return 'Suspicious indicators'
    case 'no_significant_evidence': return 'No significant evidence'
    default: return 'Inconclusive'
  }
}

function riskTone(score: number): 'safe' | 'suspicious' | 'threat' {
  if (score <= 20) return 'safe'
  if (score <= 60) return 'suspicious'
  return 'threat'
}

function sanitizeForDisplay(value: unknown, key = ''): unknown {
  if (/^(password|passwd|authorization|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret)$/i.test(key)) return value ? '••••••••' : value
  if (Array.isArray(value)) return value.map(item => sanitizeForDisplay(item, key))
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {}
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
      output[childKey] = sanitizeForDisplay(childValue, childKey)
    }
    if ('name' in output && 'value' in output && isLikelySensitiveParam(String(output.name || ''))) {
      output.value = '••••••••'
      if ('values' in output) output.values = ['••••••••']
    }
    return output
  }
  return value
}

function scalarText(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'string') return value || '""'
  return String(value)
}

function JsonTree({ value, depth = 0 }: { value: unknown; depth?: number }): React.ReactElement {
  if (value === null || value === undefined || typeof value !== 'object') {
    return <code className="live-json-leaf">{scalarText(value)}</code>
  }
  if (Array.isArray(value)) {
    return value.length
      ? <div className="live-json-array">{value.map((item, index) => <div className="live-json-array-row" key={`${depth}-${index}`}><span className="live-json-index">{index}</span><JsonTree value={item} depth={depth + 1} /></div>)}</div>
      : <code className="live-json-empty">[]</code>
  }
  const entries = Object.entries(value as Record<string, unknown>)
  return entries.length
    ? <div className="live-json-object">{entries.map(([key, child]) => <div className="live-json-row" key={`${depth}-${key}`}><span className="live-json-key">{humanizeToken(key)}</span><div className="live-json-value"><JsonTree value={child} depth={depth + 1} /></div></div>)}</div>
    : <code className="live-json-empty">{'{}'}</code>
}

function CountLabel({ count, singular, plural }: { count: number; singular: string; plural?: string }): React.ReactElement {
  return <b>{count} {count === 1 ? singular : (plural || `${singular}s`)}</b>
}

function URLPartsReport({ raw }: { raw: BackendAnalysisResponse }): React.ReactElement {
  const u = raw.url
  const queryParameters = u.query_parameters || []
  let query = u.query || ''
  try {
    const masked = new URL(maskUrlForDisplay(u.original, queryParameters, u.has_credentials))
    query = masked.search.replace(/^\?/, '')
  } catch {}
  const pieces: Array<[string, string]> = [
    ['Scheme', `${u.scheme}://`],
    ['Subdomain', u.subdomain ? `${u.subdomain}.` : '—'],
    ['Domain', u.domain || u.registrable_domain || u.hostname],
    ['TLD', u.tld ? `.${u.tld.replace(/^\./, '')}` : '—'],
    ['Port', u.port ? `:${u.port}` : 'default'],
    ['Path', u.path || '/'],
    ['Query', query ? `?${query}` : '—'],
    ['Fragment', u.fragment ? `#${u.fragment}` : '—'],
  ]
  return <div className="live-section-body">
    <div className="live-url-display"><span>Submitted URL</span><code>{maskUrlForDisplay(u.original, queryParameters, u.has_credentials)}</code></div>
    <div className="live-url-ribbon">{pieces.map(([label, value]) => <div className="live-url-piece" key={label}><span>{label}</span><code>{value}</code></div>)}</div>
    <div className="live-fact-grid">{[
      ['Normalized', u.normalized],
      ['Hostname', u.hostname],
      ['Registrable domain', u.registrable_domain || '—'],
      ['Credentials present', u.has_credentials ? 'Yes (redacted)' : 'No'],
      ['Query present', u.has_query ? 'Yes' : 'No'],
      ['Fragment present', u.has_fragment ? 'Yes' : 'No'],
      ['IP hostname', u.is_ip_address ? 'Yes' : 'No'],
      ['Parameter count', String(queryParameters.length)],
    ].map(([key, value]) => <div className="live-fact" key={key}><span>{key}</span><strong>{value}</strong></div>)}</div>
    <div className="live-subtitle-row"><span>Query parameters</span><CountLabel count={queryParameters.length} singular="parameter" /></div>
    {queryParameters.length ? <div className="live-table-wrap"><table className="live-data-table"><thead><tr><th>Name</th><th>Value</th><th>All values</th></tr></thead><tbody>{queryParameters.map((param, index) => <tr key={`${param.name}-${index}`}><td><code>{param.name}</code></td><td><code>{isLikelySensitiveParam(param.name) ? '••••••••' : (param.value || '""')}</code></td><td><code>{(param.values || []).map(value => isLikelySensitiveParam(param.name) ? '••••••••' : (value || '""')).join(', ') || '—'}</code></td></tr>)}</tbody></table></div> : <div className="live-empty-state">No query parameters were returned.</div>}
    <details className="live-json-details"><summary>Complete URL JSON</summary><JsonTree value={sanitizeForDisplay(u)} /></details>
  </div>
}

function DNSReport({ raw }: { raw: BackendAnalysisResponse }): React.ReactElement {
  const dns = raw.dns
  const renderRecords = (title: string, records?: Record<string, { record_type: string; queried_name: string; status: string; records: string[]; error?: string | null }>) => (
    <div className="live-record-group">
      <div className="live-subtitle-row"><span>{title}</span><CountLabel count={Object.keys(records || {}).length} singular="record group" /></div>
      <div className="live-record-grid">{Object.entries(records || {}).map(([type, record]) => <div className="live-record-card" key={`${title}-${type}`}><div className="live-record-top"><strong>{type}</strong><span className={`live-state live-state-${String(record.status).toLowerCase()}`}>{humanizeToken(record.status)}</span></div><small>{record.queried_name}</small><div className="live-record-values">{record.records?.length ? record.records.map((value, index) => <code key={index}>{value}</code>) : <span>{record.error || 'No records returned.'}</span>}</div></div>)}</div>
    </div>
  )
  return <div className="live-section-body">
    <div className="live-fact-grid">{[
      ['Hostname', dns.hostname],
      ['Registrable domain', dns.registrable_domain || '—'],
      ['Overall status', humanizeToken(dns.status)],
      ['Resolved IP count', String(dns.resolved_ips.length)],
      ['Resolved IPs', dns.resolved_ips.join(', ') || 'None returned'],
    ].map(([key, value]) => <div className="live-fact" key={key}><span>{key}</span><strong>{value}</strong></div>)}</div>
    {renderRecords('Hostname records', dns.hostname_records)}
    {renderRecords('Domain records', dns.domain_records)}
    {dns.hostname_txt_records && renderRecords('Hostname TXT', { TXT: dns.hostname_txt_records })}
    <details className="live-json-details"><summary>Complete DNS JSON</summary><JsonTree value={sanitizeForDisplay(dns)} /></details>
  </div>
}

function IPReport({ raw }: { raw: BackendAnalysisResponse }): React.ReactElement {
  const ip = raw.ip_intelligence
  return <div className="live-section-body">
    <div className="live-fact-grid">{[
      ['Lookup status', humanizeToken(ip.status)],
      ['Total IPs', String(ip.total_ips)],
      ['Public IPs', String(ip.public_ips)],
      ['Enriched IPs', String(ip.enriched_ips)],
      ['Lookup limit', String(ip.lookup_limit)],
      ['Limit reached', ip.limit_reached ? 'Yes' : 'No'],
    ].map(([key, value]) => <div className="live-fact" key={key}><span>{key}</span><strong>{value}</strong></div>)}</div>
    <div className="live-subtitle-row"><span>IP intelligence results</span><CountLabel count={ip.results.length} singular="address" /></div>
    {ip.results.length ? ip.results.map(result => <article className="live-ip-card" key={result.ip}>
      <div className="live-ip-header"><div><strong>{result.ip}</strong><span>{result.version === 4 ? 'IPv4' : 'IPv6'} · {humanizeToken(result.classification)}</span></div><span className={`live-state live-state-${String(result.status).toLowerCase()}`}>{humanizeToken(result.status)}</span></div>
      <div className="live-fact-grid compact">{[
        ['Country', result.country_name || result.country_code || 'Not returned'], ['Region', result.region || result.region_code || 'Not returned'], ['City', result.city || 'Not returned'], ['Postal', result.postal || 'Not returned'], ['Latitude', result.latitude == null ? 'Not returned' : String(result.latitude)], ['Longitude', result.longitude == null ? 'Not returned' : String(result.longitude)], ['Timezone', result.timezone || 'Not returned'], ['ASN', result.asn || 'Not returned'], ['Organization', result.organization || 'Not returned'], ['Hostname', result.hostname || 'Not returned'], ['Source', result.source || 'Not returned'],
      ].map(([key, value]) => <div className="live-fact" key={`${result.ip}-${key}`}><span>{key}</span><strong>{value}</strong></div>)}</div>
      {result.error && <div className="live-inline-note">{result.error}</div>}
    </article>) : <div className="live-empty-state">No public IP enrichment results were returned.</div>}
    <details className="live-json-details"><summary>Complete IP / geolocation JSON</summary><JsonTree value={sanitizeForDisplay(ip)} /></details>
  </div>
}

function WhoisReport({ raw }: { raw: BackendAnalysisResponse }): React.ReactElement {
  const w = raw.whois
  if (!w) return <div className="live-section-body"><div className="live-empty-state">WHOIS / RDAP data was not returned.</div></div>
  return <div className="live-section-body">
    <div className="live-fact-grid">{[
      ['Domain', w.domain], ['Status', humanizeToken(w.status)], ['Source', w.source || 'Not returned'], ['RDAP server', w.rdap_server || 'Not returned'], ['Registrar', w.registrar_name || 'Not returned'], ['Registrar ID', w.registrar_id || 'Not returned'], ['Registry', w.registry_name || 'Not returned'], ['Registry ID', w.registry_id || 'Not returned'], ['Registration', formatDate(w.registration_date)], ['Expiration', formatDate(w.expiration_date)], ['Last updated', formatDate(w.last_updated_date)], ['DNSSEC', w.dnssec || 'Not returned'], ['Redacted', w.redacted ? 'Yes' : 'No'],
    ].map(([key, value]) => <div className="live-fact" key={key}><span>{key}</span><strong>{value}</strong></div>)}</div>
    <div className="live-subtitle-row"><span>Domain status</span><CountLabel count={w.domain_status.length} singular="status flag" /></div><div className="live-chip-row">{w.domain_status.length ? w.domain_status.map(status => <span className="live-chip" key={status}>{status}</span>) : <span className="live-muted">No status flags returned.</span>}</div>
    <div className="live-subtitle-row"><span>Nameservers</span><CountLabel count={w.nameservers.length} singular="server" /></div><div className="live-list-grid">{w.nameservers.length ? w.nameservers.map(ns => <div className="live-list-item" key={ns.hostname}><strong>{ns.hostname}</strong><span>IPv4: {ns.ipv4?.join(', ') || '—'} · IPv6: {ns.ipv6?.join(', ') || '—'}</span></div>) : <div className="live-empty-state">No nameservers returned.</div>}</div>
    <div className="live-subtitle-row"><span>RDAP lifecycle events</span><CountLabel count={w.events?.length || 0} singular="event" /></div><div className="live-table-wrap"><table className="live-data-table"><thead><tr><th>Action</th><th>Date</th></tr></thead><tbody>{w.events?.length ? w.events.map((event, index) => <tr key={`${event.action}-${index}`}><td>{event.action}</td><td>{formatDate(event.date)}</td></tr>) : <tr><td colSpan={2}>No lifecycle events returned.</td></tr>}</tbody></table></div>
    {w.error && <div className="live-inline-note">{w.error}</div>}
    <details className="live-json-details"><summary>Complete WHOIS / RDAP JSON</summary><JsonTree value={sanitizeForDisplay(w)} /></details>
  </div>
}

function OSINTReport({ raw }: { raw: BackendAnalysisResponse }): React.ReactElement {
  const o = raw.osint
  if (!o) return <div className="live-section-body"><div className="live-empty-state">OSINT data was not returned.</div></div>
  const usable = o.providers.filter(provider => ['success','no_match'].includes(provider.status)).length
  return <div className="live-section-body">
    <div className="live-fact-grid">{[
      ['Overall status', humanizeToken(o.status)], ['Providers', String(o.providers.length)], ['Total matches', String(o.total_matches)], ['Aggregated matches', String(o.matches.length)], ['Usable providers', String(usable)], ['Unavailable / failed', String(o.providers.length - usable)],
    ].map(([key, value]) => <div className="live-fact" key={key}><span>{key}</span><strong>{value}</strong></div>)}</div>
    <div className="live-subtitle-row"><span>Provider-by-provider intelligence</span><CountLabel count={o.providers.length} singular="provider" /></div>
    <div className="live-provider-list">{o.providers.map(provider => <article className="live-provider-card" key={provider.source}>
      <div className="live-provider-header"><div><strong>{provider.source}</strong><span>Query: {provider.query}</span></div><span className={`live-state live-state-${String(provider.status).toLowerCase()}`}>{humanizeToken(provider.status)}</span></div>
      <div className="live-fact-grid compact"><div className="live-fact"><span>Matched</span><strong>{provider.matched ? 'Yes' : 'No'}</strong></div><div className="live-fact"><span>Match count</span><strong>{provider.match_count}</strong></div></div>
      {provider.matches?.length ? <div className="live-match-list">{provider.matches.map((match,index) => <div className="live-match" key={`${match.source}-${match.indicator}-${index}`}><div><strong>{humanizeToken(match.match_type)}</strong><span>{match.indicator}</span></div>{match.reference && <a href={match.reference} target="_blank" rel="noreferrer">Reference ↗</a>}</div>)}</div> : <div className="live-provider-empty">No direct matches returned by this provider.</div>}
      {provider.error && <div className="live-inline-note">{provider.error}</div>}
      {Object.keys(provider.metadata || {}).length ? <details className="live-json-details"><summary>Provider metadata</summary><JsonTree value={sanitizeForDisplay(provider.metadata)} /></details> : null}
    </article>)}</div>
    <details className="live-json-details"><summary>Complete OSINT JSON</summary><JsonTree value={sanitizeForDisplay(o)} /></details>
  </div>
}

const REPORT_SECTIONS = [
  { kind: 'url', number: '01', eyebrow: 'URL FORENSICS', title: 'URL — All Parts', description: 'Every parser-returned URL component is shown, including authority, path, query parameters and fragment.' },
  { kind: 'dns', number: '02', eyebrow: 'DNS INTELLIGENCE', title: 'DNS Information', description: 'Every hostname and domain record group returned by the resolver is displayed with its actual status.' },
  { kind: 'ip', number: '03', eyebrow: 'NETWORK & GEOLOCATION', title: 'IP Information & Geolocation', description: 'Every IP object returned by the backend is displayed with its network and geolocation fields.' },
  { kind: 'whois', number: '04', eyebrow: 'DOMAIN REGISTRY', title: 'WHOIS / RDAP Information', description: 'Registration lifecycle, registrar data, nameservers, DNSSEC and RDAP metadata.' },
  { kind: 'osint', number: '05', eyebrow: 'OPEN-SOURCE INTELLIGENCE', title: 'OSINT — In Depth', description: 'Provider state, exact matches, references, metadata and errors from the live OSINT response.' },
] as const

function LiveReportCard({ config, raw, index }: { config: typeof REPORT_SECTIONS[number]; raw: BackendAnalysisResponse; index: number }): React.ReactElement {
  const [open, setOpen] = useState(false)
  const body = config.kind === 'url' ? <URLPartsReport raw={raw} /> : config.kind === 'dns' ? <DNSReport raw={raw} /> : config.kind === 'ip' ? <IPReport raw={raw} /> : config.kind === 'whois' ? <WhoisReport raw={raw} /> : <OSINTReport raw={raw} />
  return <article className={`live-report-card ${open ? 'is-open' : ''}`} style={{ '--live-delay': `${index * 70}ms` } as React.CSSProperties}>
    <div className="live-report-card-head"><div className="live-report-number">{config.number}</div><div className="live-report-heading"><span>{config.eyebrow}</span><h3>{config.title}</h3><p>{config.description}</p></div><button type="button" className="live-expand-btn" onClick={() => setOpen(value => !value)} aria-expanded={open}>{open ? 'Collapse' : 'Inspect'} ↗</button></div>
    <div className="live-report-card-content">{body}</div>
  </article>
}

function LiveRiskCircle({ raw }: { raw: BackendAnalysisResponse }): React.ReactElement {
  const target = Math.max(0, Math.min(100, Number(raw.final_assessment?.risk_score ?? 0)))
  const [value, setValue] = useState(0)
  const radius = 112
  const circumference = 2 * Math.PI * radius
  useEffect(() => {
    let frame = 0
    const start = performance.now()
    const duration = 1500
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { setValue(target); return () => undefined }
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - progress, 4)
      setValue(Math.round(target * eased))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target])
  const tone = riskTone(target)
  const offset = circumference - (value / 100) * circumference
  const assessment = raw.final_assessment
  return <div className={`live-risk-card live-risk-${tone}`}>
    <div className="live-risk-heading"><span>LIVE RISK INDEX</span><strong>{assessment?.risk_score_version || 'backend score'}</strong></div>
    <div className="live-risk-orbit"><div className="live-risk-pulse" /><svg viewBox="0 0 260 260" className="live-risk-svg" aria-label={`Risk index ${target} out of 100`}><circle cx="130" cy="130" r={radius} fill="none" className="live-risk-track" strokeWidth="17"/><circle cx="130" cy="130" r={radius} fill="none" className="live-risk-value" strokeWidth="17" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset}/></svg><div className="live-risk-center"><strong>{value}</strong><span>/ 100</span><small>{assessmentLabel(assessment?.verdict)}</small></div></div>
    <div className="live-risk-meta"><div><span>Confidence</span><strong>{assessment?.confidence || 'not returned'}</strong></div><div><span>Source</span><strong>Current API response</strong></div></div>
    <p className="live-risk-note">The circle animates to the exact <code>final_assessment.risk_score</code> returned for this URL. It is an evidence index, not a probability.</p>
  </div>
}

function AssessmentReport({ raw }: { raw: BackendAnalysisResponse }): React.ReactElement {
  const assessment = raw.final_assessment
  const buckets = [raw.security, raw.dns_security, raw.ip_security, raw.whois_security, raw.osint_security, raw.correlation_security]
  const findings = buckets.flatMap(bucket => bucket?.findings || [])
  const osintMatches = Number(raw.osint?.total_matches || 0)
  return <section className="live-assessment-wrap">
    <div className="live-assessment-copy"><div className="live-assessment-top"><span className="live-eyebrow">FINAL EVIDENCE ASSESSMENT</span><span className="live-live-pill"><i /> LIVE API RESULT</span></div>
      <div className="live-verdict-row"><span className={`live-verdict live-verdict-${riskTone(Number(assessment?.risk_score || 0))}`}>{assessmentLabel(assessment?.verdict)}</span><span className="live-confidence">{assessment?.confidence || 'not returned'} confidence</span></div>
      <h2>{raw.url.hostname}</h2><code className="live-assessment-url">{maskUrlForDisplay(raw.url.original, raw.url.query_parameters || [], raw.url.has_credentials)}</code>
      <p className="live-assessment-summary">{assessment?.summary || 'The backend did not return an assessment summary.'}</p>
      <div className="live-metric-row"><div><strong>{findings.length}</strong><span>Total findings</span></div><div><strong>{findings.filter(f => f.severity === 'high').length}</strong><span>High severity</span></div><div><strong>{findings.filter(f => f.severity === 'medium').length}</strong><span>Medium severity</span></div><div><strong>{osintMatches}</strong><span>OSINT matches</span></div></div>
      {assessment?.rationale?.length ? <div className="live-rationale-box"><div className="live-subtitle-row"><span>Why the engine landed here</span><CountLabel count={assessment.rationale.length} singular="rationale item" /></div>{assessment.rationale.map((item,index)=><div className="live-rationale" key={index}><span>{String(index+1).padStart(2,'0')}</span><p>{item}</p></div>)}</div> : null}
      <details className="live-json-details"><summary>Complete final-assessment JSON</summary><JsonTree value={sanitizeForDisplay(assessment)} /></details>
    </div><LiveRiskCircle raw={raw}/>
  </section>
}

function AnalysisPage({ activeUrl, analysisState, analysisResult, analysisError, onStartInspection, onResetScan }: { activeUrl: string | null; analysisState: ScanState; analysisResult: BackendAnalysisResponse | null; analysisError?: string | null; onStartInspection: (url:string)=>void; onResetScan:()=>void }) {
  const [activeStepIndex, setActiveStepIndex] = useState(0)
  const [scanProgress, setScanProgress] = useState(4)
  useEffect(() => {
    if (analysisState !== 'scanning' || !activeUrl) return
    setActiveStepIndex(0); setScanProgress(4)
    let current = 0
    const timer = window.setInterval(() => { current += 1; setActiveStepIndex(Math.min(SCAN_STEPS.length - 1, current)); setScanProgress(Math.min(94, Math.round((current / SCAN_STEPS.length) * 94))); if (current >= SCAN_STEPS.length - 1) window.clearInterval(timer) }, 650)
    return () => window.clearInterval(timer)
  }, [analysisState, activeUrl])
  return <div className="page-view analysis-page-view"><section className="section analysis-hub-section"><div className="section-container live-report-container">
    <div className="section-intro"><span className="editorial-eyebrow">LIVE URL INSPECTION / ANALYSIS DOSSIER</span><h2 className="section-title">Professional evidence report from the URL you submit.</h2><p className="section-subtitle">Every value below is taken from the current FastAPI analysis response. There are no embedded scan results.</p></div>
    <div className="analysis-inspector-wrapper"><UrlInspectorCard initialUrl={activeUrl || ''} onInspect={onStartInspection} isInspecting={analysisState === 'scanning'} /></div>
    {analysisState === 'scanning' && activeUrl ? <div className="analysis-live-scanning-card"><div className="scanning-card-header"><div className="scanning-pulse-box"><SearchPulseIcon /></div><div className="scanning-header-titles"><span className="scanning-status-pill">NON-EXECUTING ANALYSIS IN PROGRESS</span><h3 className="scanning-target-url"><code>{activeUrl}</code></h3></div><div className="scanning-pct-badge">{scanProgress}%</div></div><div className="progress-track-bar"><div className="progress-fill-bar" style={{width:`${scanProgress}%`}}/></div><div className="sequence-steps-grid analysis-scan-grid">{SCAN_STEPS.map((step,index)=>{const done=index<activeStepIndex;const current=index===activeStepIndex;return <div key={step.id} className={`step-item ${done?'step-done':''} ${current?'step-active':''}`}><div className="step-num-badge">{done?'✓':step.id}</div><div className="step-text-wrap"><span className="step-name">{step.name}</span><span className="step-desc">{step.desc}</span></div></div>})}</div></div> : null}
    {analysisState === 'idle' && !analysisResult ? <div className="analysis-empty-compact-card"><div className="empty-compact-content"><div className="empty-compact-badge-row"><span className="empty-status-dot"/><span className="empty-compact-pill">STANDBY MODE</span></div><h3 className="empty-compact-title">No URL inspected yet.</h3><p className="empty-compact-desc">Enter a URL above to generate a complete live report.</p></div></div> : null}
    {analysisState === 'error' ? <div className="analysis-error-card" role="alert"><div className="error-card-icon">!</div><div><span className="analysis-eyebrow">BACKEND SERVICE ERROR</span><h3>Analysis could not be completed.</h3><p>{analysisError || 'The FastAPI service did not return a usable result.'}</p><div className="error-card-actions"><button type="button" className="btn btn-primary btn-sm" onClick={()=>activeUrl&&onStartInspection(activeUrl)}>Retry Analysis <ArrowUpRight /></button><button type="button" className="btn btn-outline btn-sm" onClick={onResetScan}>Scan Another URL</button></div></div></div> : null}
    {analysisState === 'completed' && analysisResult ? <div className="live-report-shell"><div className="live-report-toolbar"><div><span className="live-eyebrow">REPORT READY</span><span className="live-toolbar-url">{analysisResult.url.hostname}</span></div><div className="analysis-toolbar-actions"><button type="button" className="btn btn-secondary btn-sm" onClick={()=>window.print()}>Print / Save PDF</button><button type="button" className="btn btn-outline btn-sm" onClick={onResetScan}>New Scan</button></div></div>
      <AssessmentReport raw={analysisResult}/>
      <div className="live-five-stack">{REPORT_SECTIONS.map((config,index)=><LiveReportCard key={config.kind} config={config} index={index} raw={analysisResult}/>)}</div>
      <section className="live-engine-section"><div className="live-engine-head"><span className="live-eyebrow">ADDITIONAL BACKEND OUTPUT</span><h3>Security and correlation evidence.</h3><p>The five primary sections above cover the intelligence payload. These expandable panels expose the rest of the returned analysis objects so nothing is silently discarded.</p></div><div className="live-engine-grid">{[
        ['URL security', analysisResult.security], ['DNS security', analysisResult.dns_security], ['IP security', analysisResult.ip_security], ['WHOIS security', analysisResult.whois_security], ['OSINT security', analysisResult.osint_security], ['Cross-source correlation', analysisResult.correlation_security],
      ].map(([label,data])=><details className="live-json-details live-engine-detail" key={label as string}><summary>{label as string}</summary><JsonTree value={sanitizeForDisplay(data)}/></details>)}</div></section>
      <div className="analysis-bottom-cta"><div><span className="analysis-eyebrow">NEXT INSPECTION</span><h3>Have another suspicious link?</h3><p>Run another non-executing scan using the same live backend pipeline.</p></div><button type="button" className="btn btn-primary" onClick={onResetScan}>Scan another URL <ArrowUpRight /></button></div>
    </div> : null}
  </div></section></div>
}
// --------------------------------------------------------------------------

// PAGE 3: BLOG (/blog)
// --------------------------------------------------------------------------
interface BlogArticle {
  id: string
  tag: string
  category: 'all' | 'attack_vectors' | 'url_forensics' | 'threat_intel' | 'engine' | 'defense' | 'evasion'
  categoryLabel: string
  title: string
  readTime: string
  badge: string
  summary: string
  sections: Array<{
    heading: string
    content: string
  }>
  keyTakeaways: string[]
}

function BlogPage({ onNavigate }: { onNavigate: (route: PageRoute) => void }) {
  const [activeCategory, setActiveCategory] = useState<string>('all')
  const [selectedArticle, setSelectedArticle] = useState<BlogArticle | null>(null)

  const articles: BlogArticle[] = [
    {
      id: 'how-phishing-attacks-work',
      tag: 'ATTACK VECTORS & LIFECYCLE',
      category: 'attack_vectors',
      categoryLabel: 'Attack Vectors',
      title: 'The Anatomy of a Modern Phishing Campaign: From Deceptive Lures to Credential Harvesting',
      readTime: '5 min read',
      badge: 'Fundamentals',
      summary: 'Understanding how attackers craft deceptive pretexts, deploy lookalike landing pages, bypass multi-factor authentication with Adversary-in-the-Middle (AitM) proxies, and exfiltrate user credentials.',
      sections: [
        {
          heading: '1. Reconnaissance & Target Pretexting',
          content: 'Modern phishing campaigns rarely rely on generic spam. Attackers research organizations via LinkedIn, public DNS records, and vendor relationships to construct believable pretexts. Pretexts frequently mimic urgent notifications: IT password resets, shared document alerts, payroll updates, or critical security incidents that drive victims to act impulsively.'
        },
        {
          heading: '2. Infrastructure Staging & Lookalike Domains',
          content: 'Threat actors register deceptive domain names that imitate known organizations using character substitutions, hyphenation (e.g., login-microsoft-auth.com), or abuse free cloud hosting providers. Infrastructure is often stood up only hours before the campaign begins to evade reputation blocklists.'
        },
        {
          heading: '3. Adversary-in-the-Middle (AitM) Reverse Proxies',
          content: 'Advanced phishing frameworks (such as Evilginx and Modlishka) act as transparent reverse proxies. When the victim enters their username, password, and MFA code, the proxy forwards the credentials to the legitimate identity provider in real time, capturing session tokens and bypassing traditional SMS or OTP multi-factor authentication.'
        },
        {
          heading: '4. Post-Exploitation & Lateral Movement',
          content: 'Once an active session cookie or credential pair is captured, automated scripts immediately probe corporate APIs, set up mailbox forwarding rules, search OneDrive/SharePoint for sensitive credentials, and launch secondary internal spear-phishing attacks against colleagues.'
        }
      ],
      keyTakeaways: [
        'Urgent pretexts are engineered to bypass critical thinking and provoke hasty clicks.',
        'MFA using SMS or push notifications can be intercepted by modern reverse proxy phishing kits.',
        'FIDO2/WebAuthn hardware keys provide cryptographic origin binding that prevents AitM proxy bypasses.'
      ]
    },
    {
      id: 'how-to-identify-suspicious-urls',
      tag: 'URL FORENSICS & ANALYSIS',
      category: 'url_forensics',
      categoryLabel: 'URL Forensics',
      title: 'How to Dissect and Identify Suspicious URLs: A Step-by-Step Security Guide',
      readTime: '6 min read',
      badge: 'Detection Guide',
      summary: 'A hands-on methodology for inspecting hostnames, identifying deceptive subdomains, detecting character substitutions, and spotting obfuscated query strings without executing malware.',
      sections: [
        {
          heading: '1. Isolate the Apex Domain from Subdomains',
          content: 'Attackers routinely create nested subdomains to deceive victims who only glance at the beginning of a URL. For example, in the URL "https://paypal.com.account-verification-service.xyz/login", the apex domain is "account-verification-service.xyz", while "paypal.com" is merely a deceptive subdomain string. Always read the domain hierarchy backwards from the first single forward slash.'
        },
        {
          heading: '2. Check for Internationalized Domain Names (IDN) & Homoglyphs',
          content: 'Internationalized domain names permit Unicode characters in hostnames. Deceptive actors substitute Latin letters with visually indistinguishable Cyrillic or Greek glyphs (e.g. Cyrillic "а" U+0430 for Latin "a" U+0061). In browsers, these are encoded as Punycode starting with "xn--". Any URL displaying unexpected Punycode prefixes should be treated with extreme caution.'
        },
        {
          heading: '3. Analyze Shannon Entropy and Character Randomness',
          content: 'Legitimate web paths typically follow structured, human-readable directory conventions. Malicious URLs frequently feature high mathematical entropy strings (e.g., long pseudo-random alphanumeric hash paths) designed to route victims to transient session endpoints or hide malware signatures from basic regex scrapers.'
        },
        {
          heading: '4. Verify Destination Ports and Protocol Anomalies',
          content: 'Standard web traffic operates over port 443 (HTTPS) or port 80 (HTTP). If a URL contains explicit non-standard ports (such as :8080, :8443, :2083, or :10000), it often indicates an unmanaged staging server, compromised personal device, or hosting control panel being abused for credential harvesting.'
        }
      ],
      keyTakeaways: [
        'The apex domain is determined by reading backwards from the first single path slash.',
        'Punycode hostnames (starting with xn--) often conceal foreign homoglyphs designed to mimic familiar brands.',
        'Inspect URLs syntactically before clicking; never assume the presence of an SSL lock icon guarantees destination safety.'
      ]
    },
    {
      id: 'understanding-domain-and-url-threat-intelligence',
      tag: 'THREAT INTELLIGENCE',
      category: 'threat_intel',
      categoryLabel: 'Threat Intelligence',
      title: 'Understanding Domain & URL Threat Intelligence: RDAP, WHOIS, and Reputation Signals',
      readTime: '7 min read',
      badge: 'Architecture',
      summary: 'How security engines query authoritative registries, compute domain age, analyze autonomous system numbers (ASNs), and evaluate reputation feeds to determine deterministic risk scores.',
      sections: [
        {
          heading: '1. RDAP & WHOIS Registry Timelines',
          content: 'The Registration Data Access Protocol (RDAP) provides structured JSON telemetry regarding a domain registration. One of the highest weighted indicators in URL analysis is domain age: newly registered domains (NRDs created within the last 14 to 30 days) account for a disproportionate percentage of active phishing infrastructure.'
        },
        {
          heading: '2. Autonomous System Numbers (ASN) & Hosting Profiles',
          content: 'Every IP address belongs to an Autonomous System (AS) managed by an internet service provider, cloud host, or colocation center. Threat intelligence systems correlate hosting ASNs with historical abuse rates. High-risk bulletproof hosters and ephemeral cloud proxies score higher risk compared to verified enterprise content networks.'
        },
        {
          heading: '3. DNS Record Validation & Email Authentication',
          content: 'Evaluating DNS record sets (A, AAAA, MX, TXT, NS) reveals the operational maturity of a domain. Missing MX records on a domain claiming to belong to a global corporate entity or name servers hosted on dynamic DNS providers serve as strong heuristic indicators of disposable infrastructure.'
        },
        {
          heading: '4. Synthesizing Multi-Source Signals Deterministically',
          content: 'Rather than relying on opaque black-box outputs, explainable threat intelligence models aggregate individual risk vectors (lexical entropy, domain age, typosquatting edit distance, blocklist telemetry) into an auditable threat score accompanied by transparent evidential findings.'
        }
      ],
      keyTakeaways: [
        'Domain registration age is one of the most reliable single signals in threat detection.',
        'RDAP modernizes WHOIS by providing standardized, machine-readable registry telemetry.',
        'Explainable security requires clear evidence trails rather than unverified categorical labels.'
      ]
    },
    {
      id: 'why-threat-intel-providers-return-no-data',
      tag: 'ENGINE EXPLAINER',
      category: 'engine',
      categoryLabel: 'Engine Explainer',
      title: 'Why Threat Intelligence Feeds Sometimes Return No Detections on Malicious URLs',
      readTime: '4 min read',
      badge: 'Deep Dive',
      summary: 'Explaining telemetry blindspots: zero-hour spear-phishing domains, unindexed private infrastructure, rate limits, and why multi-signal local heuristics remain essential.',
      sections: [
        {
          heading: '1. The Zero-Hour Telemetry Gap',
          content: 'Security blocklists and threat intelligence feeds (such as VirusTotal, URLhaus, and ThreatFox) rely on community submissions, honeypot traps, and web crawler discovery. When an adversary registers a new domain and delivers a targeted spear-phishing email within 15 minutes, no global crawler has yet discovered or indexed that URL. Absence of evidence is not evidence of absence.'
        },
        {
          heading: '2. Geofencing, Bot Filtering & Sandbox Cloaking',
          content: 'Modern phishing kits incorporate sophisticated server-side evasion. When security crawlers or sandbox scanners request the URL, the server checks the visitor IP address, ASN, and user-agent string. If the request originates from a known cloud data center (e.g. AWS, GCP, Microsoft Azure), the server returns a harmless 404 error or redirects to google.com, while serving the phishing kit exclusively to residential IP targets.'
        },
        {
          heading: '3. One-Time Tokenized Links (Burner URLs)',
          content: 'Phishing campaigns increasingly send unique per-victim token parameters. Once the victim loads the page (or if a security gateway crawls it once), the token is permanently invalidated. Subsequent visits by security analysts see an expired page, preventing provider consensus.'
        },
        {
          heading: '4. The Necessity of Multi-Layered Heuristic Analysis',
          content: 'Because external feeds cannot catch zero-hour campaigns instantly, deterministic local checks—such as Shannon entropy, typosquatting Levenshtein distance, Punycode detection, and RDAP registration age—are vital to protect users before community feeds update.'
        }
      ],
      keyTakeaways: [
        'A "0 detections" result on an external threat feed does not guarantee that a URL is safe.',
        'Attackers use server-side bot-cloaking to hide malicious pages from security crawler IP ranges.',
        'Local syntactic and domain-age analysis catches new phishing infrastructure before community lists update.'
      ]
    },
    {
      id: 'safe-browsing-link-verification-playbook',
      tag: 'DEFENSE PLAYBOOK',
      category: 'defense',
      categoryLabel: 'Defensive Guides',
      title: 'The Safe Browsing Playbook: Essential Link Verification Habits for Everyday Security',
      readTime: '5 min read',
      badge: 'Best Practices',
      summary: 'Actionable security hygiene guidelines to protect your credentials and endpoints when encountering unsolicited communications across email, SMS, and messaging platforms.',
      sections: [
        {
          heading: '1. Adopt the "Out-of-Band Navigation" Habit',
          content: 'When receiving an urgent notification (such as a banking security alert, account lock notice, or shipping update), never click the embedded link inside the message. Instead, open a new browser tab and navigate to the provider official website directly through a verified bookmark or clean search.'
        },
        {
          heading: '2. Utilize Non-Executing Inspection Sandboxes',
          content: 'If you must evaluate a link, use a non-executing parser like PhishGuard rather than opening it directly. Sandboxes decompose the hostname, inspect registry data, and verify redirects without executing malicious JavaScript or delivering browser exploit payloads to your workstation.'
        },
        {
          heading: '3. Rely on Password Manager Domain-Bound Autofill',
          content: 'Password managers (such as 1Password, Bitwarden, or browser-native keychains) authenticate against the exact registered domain name in the address bar. If you visit "paypal.login-verify.com", your password manager will refuse to autofill your stored "paypal.com" credentials, providing an immediate automatic warning.'
        },
        {
          heading: '4. Treat Shortened Links and Redirects with Suspicion',
          content: 'URL shorteners (e.g., bit.ly, tinyurl.com) obscure the final destination. Always expand shortened links or inspect the full redirect chain before providing credentials or authorizing OAuth permissions.'
        }
      ],
      keyTakeaways: [
        'Direct navigation via known bookmarks eliminates 95% of phishing link vulnerabilities.',
        'Password managers provide hardware-level domain matching that will not autofill on spoofed domains.',
        'Use dedicated metadata parsers to audit links without downloading remote scripts.'
      ]
    },
    {
      id: 'common-phishing-techniques-and-evasion',
      tag: 'EVASION TACTICS',
      category: 'evasion',
      categoryLabel: 'Evasion Tactics',
      title: 'Modern Phishing Tactics: Reverse Proxies, Cloud Hosting Abuse, and Quishing',
      readTime: '8 min read',
      badge: 'Emerging Threats',
      summary: 'A deep dive into modern attacker evasion methods, including reverse proxy toolkits, QR code lures, and abusing trusted cloud platforms to bypass email security gateways.',
      sections: [
        {
          heading: '1. QR Code Phishing ("Quishing")',
          content: 'By embedding malicious URLs inside QR code images rather than plain text, attackers successfully bypass traditional Secure Email Gateways (SEGs) that inspect plaintext and HTML links. The victim scans the QR code on their mobile device, which often lacks corporate endpoint security agents.'
        },
        {
          heading: '2. Abusing Trusted Cloud Infrastructure (Living off the Cloud)',
          content: 'Adversaries increasingly host phishing forms on legitimate cloud infrastructure such as Microsoft SharePoint, Google Forms, Firebase, Cloudflare Pages, and AWS S3 buckets. Because the root domains (e.g., sharepoint.com) have high global reputation scores, email filters allow them through by default.'
        },
        {
          heading: '3. CAPTCHA Cloaking & Human Verification Shields',
          content: 'Threat actors place Cloudflare Turnstile or Google reCAPTCHA challenges in front of their credential harvesting forms. Automated security scanners cannot solve the CAPTCHA and therefore never see the underlying phishing form, leaving the site unflagged on global blocklists.'
        },
        {
          heading: '4. OAuth Device Code & Illicit Consent Grant Attacks',
          content: 'Rather than stealing passwords, sophisticated attackers prompt users to grant permissions to a malicious OAuth application. Once authorized, the app receives persistent API tokens allowing access to mailboxes and files without triggering password expiration or MFA challenges.'
        }
      ],
      keyTakeaways: [
        'Quishing bypasses text filters by placing deceptive URLs into images scanned on unmanaged mobile devices.',
        'Attackers abuse legitimate cloud hosting domains to inherit high reputation scores.',
        'Always verify third-party OAuth app permission requests before approving corporate access.'
      ]
    }
  ]

  const categories = [
    { id: 'all', label: 'All Articles' },
    { id: 'attack_vectors', label: 'Attack Vectors' },
    { id: 'url_forensics', label: 'URL Forensics' },
    { id: 'threat_intel', label: 'Threat Intelligence' },
    { id: 'engine', label: 'Engine Explainer' },
    { id: 'defense', label: 'Defensive Guides' },
    { id: 'evasion', label: 'Evasion Tactics' },
  ]

  const filteredArticles = activeCategory === 'all'
    ? articles
    : articles.filter(a => a.category === activeCategory)

  return (
    <div className="page-view blog-page-view">
      <section className="section blog-editorial-section">
        <div className="section-container">
          <div className="section-intro">
            <span className="editorial-eyebrow">CYBERSECURITY BLOG</span>
            <h2 className="section-title">Cybersecurity insights, phishing awareness, and practical guidance.</h2>
            <p className="section-subtitle">
              In-depth technical analysis, defensive playbooks, and threat intelligence breakdowns to help you recognize and neutralize deceptive web threats.
            </p>
          </div>

          {/* Category Filter Pills */}
          <div className="blog-filter-bar">
            {categories.map(cat => (
              <button
                key={cat.id}
                type="button"
                className={`blog-filter-btn ${activeCategory === cat.id ? 'blog-filter-active' : ''}`}
                onClick={() => setActiveCategory(cat.id)}
              >
                {cat.label}
              </button>
            ))}
          </div>

          {/* Articles Grid */}
          <div className="blog-articles-grid">
            {filteredArticles.map((article, idx) => (
              <article
                key={article.id}
                className={`blog-card ${idx % 2 === 0 ? 'blog-card-dark' : 'blog-card-light'}`}
              >
                <div className="blog-card-top">
                  <span className="blog-card-tag">{article.tag}</span>
                  <div className="blog-card-meta">
                    <span className="blog-badge">{article.badge}</span>
                    <span className="blog-read-time">{article.readTime}</span>
                  </div>
                </div>

                <h3 className="blog-card-title">{article.title}</h3>
                <p className="blog-card-summary">{article.summary}</p>

                <div className="blog-card-sections-preview">
                  {article.sections.slice(0, 2).map((sec, sIdx) => (
                    <div key={sIdx} className="blog-sec-item">
                      <strong className="blog-sec-heading">{sec.heading}</strong>
                      <p className="blog-sec-text">{sec.content}</p>
                    </div>
                  ))}
                </div>

                <div className="blog-takeaway-box">
                  <span className="blog-takeaway-label">KEY TAKEAWAY:</span>
                  <p className="blog-takeaway-text">{article.keyTakeaways[0]}</p>
                </div>

                <div className="blog-card-actions">
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm blog-read-btn"
                    onClick={() => setSelectedArticle(article)}
                  >
                    <span>Read Full Analysis</span>
                    <ArrowUpRight />
                  </button>
                </div>
              </article>
            ))}
          </div>

          {/* Article Modal Reader */}
          {selectedArticle && (
            <div className="blog-modal-backdrop" onClick={() => setSelectedArticle(null)} role="dialog" aria-modal="true">
              <div className="blog-modal-content" onClick={e => e.stopPropagation()}>
                <div className="blog-modal-header">
                  <div className="blog-modal-tags">
                    <span className="blog-card-tag">{selectedArticle.tag}</span>
                    <span className="blog-badge">{selectedArticle.badge}</span>
                    <span className="blog-read-time">{selectedArticle.readTime}</span>
                  </div>
                  <button
                    type="button"
                    className="blog-modal-close-btn"
                    onClick={() => setSelectedArticle(null)}
                    aria-label="Close article"
                  >
                    ✕
                  </button>
                </div>

                <h2 className="blog-modal-title">{selectedArticle.title}</h2>
                <p className="blog-modal-summary">{selectedArticle.summary}</p>

                <div className="blog-modal-body">
                  {selectedArticle.sections.map((sec, sIdx) => (
                    <div key={sIdx} className="blog-modal-section">
                      <h4 className="blog-modal-section-title">{sec.heading}</h4>
                      <p className="blog-modal-section-p">{sec.content}</p>
                    </div>
                  ))}

                  <div className="blog-modal-takeaways">
                    <h4 className="blog-modal-takeaways-title">Essential Takeaways</h4>
                    <ul className="blog-modal-takeaway-list">
                      {selectedArticle.keyTakeaways.map((item, tIdx) => (
                        <li key={tIdx}>
                          <span className="bullet-check">✓</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="blog-modal-footer">
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setSelectedArticle(null)}
                  >
                    Close Article
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    onClick={() => {
                      setSelectedArticle(null)
                      onNavigate('scanner')
                    }}
                  >
                    <span>Test a Link Now</span>
                    <ArrowUpRight />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Bottom CTA Banner */}
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
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('scanner')}>Home</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('analysis')}>Analysis Dossier</button></li>
              <li><button type="button" className="footer-nav-btn" onClick={() => onNavigate('blog')}>Blog</button></li>
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
  const [analysisResult, setAnalysisResult] = useState<BackendAnalysisResponse | null>(null)
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
      if (hash === 'how-it-works' || hash === 'capabilities') {
        setCurrentRoute('blog')
        window.location.hash = '#/blog'
        return
      }
      const validRoutes: PageRoute[] = ['scanner', 'analysis', 'blog', 'education', 'about', 'support']
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
    const trimmed = url.trim()
    if (!trimmed) return
    setActiveUrl(trimmed)
    setAnalysisState('scanning')
    setAnalysisResult(null)
    setAnalysisError(null)
    void handleCompleteScan(trimmed)
    navigate('analysis', 'forward')
  }

  // Triggered when user clicks "Inspect URL" directly on the Analysis page.
  const handleStartInspectionOnAnalysis = (url: string) => {
    const trimmed = url.trim()
    if (!trimmed) return
    setActiveUrl(trimmed)
    setAnalysisState('scanning')
    setAnalysisResult(null)
    setAnalysisError(null)
    void handleCompleteScan(trimmed)
  }

  // Triggered when the scan completes on the Analysis page
  const handleCompleteScan = async (url: string) => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), ANALYSIS_TIMEOUT_MS)
    try {
      const response = await fetch(BACKEND_ANALYSIS_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ url: normalizeUserUrl(url) }),
        signal: controller.signal,
      })

      if (!response.ok) {
        let errMsg = `Analysis API returned ${response.status}`
        try {
          const errJson = await response.json()
          if (errJson?.detail) {
            errMsg = typeof errJson.detail === 'string'
              ? errJson.detail
              : Array.isArray(errJson.detail)
                ? errJson.detail.map((d: { msg?: string }) => d?.msg).filter(Boolean).join('; ') || JSON.stringify(errJson.detail)
                : JSON.stringify(errJson.detail)
          }
        } catch {
          // Keep the HTTP status fallback.
        }
        const httpError = new Error(errMsg) as Error & { isHttp?: boolean }
        httpError.isHttp = true
        throw httpError
      }

      const raw = (await response.json()) as BackendAnalysisResponse
      if (!raw?.success || !raw?.url || !raw?.final_assessment) {
        throw new Error('The backend returned an incomplete analysis response.')
      }
      setAnalysisResult(raw)
      setAnalysisError(null)
      setAnalysisState('completed')
    } catch (error: unknown) {
      console.error('PhishGuard backend analysis failed:', error)
      let message: string
      if (error instanceof DOMException && error.name === 'AbortError') {
        message = 'The analysis timed out. The domain\'s DNS/WHOIS servers may be slow — please try again.'
      } else if ((error as { isHttp?: boolean })?.isHttp) {
        // Backend responded: show its real reason (e.g. invalid URL), not a "server down" hint.
        message = (error as Error).message
      } else {
        message = 'Could not reach the analysis server. Check that the FastAPI server is running at http://127.0.0.1:8000.'
      }
      setAnalysisError(message)
      setAnalysisResult(null)
      setAnalysisState('error')
    } finally {
      clearTimeout(timer)
    }
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
          <ScannerPage
            onStartInspection={handleStartInspectionFromScanner}
            onNavigate={navigate}
          />
        )}

        {currentRoute === 'analysis' && (
          <AnalysisPage
            activeUrl={activeUrl}
            analysisState={analysisState}
            analysisResult={analysisResult}
            analysisError={analysisError}
            onStartInspection={handleStartInspectionOnAnalysis}
            onResetScan={handleResetScan}
          />
        )}

        {currentRoute === 'blog' && (
          <BlogPage onNavigate={navigate} />
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
