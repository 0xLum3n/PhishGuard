import { useState } from 'react'
import type { AnalysisDetails } from '../App'
import { downloadAnalysisPdf } from '../lib/reportPdf'

function isMissing(v?: string | null) {
  return !v || /^(Unavailable|Not published|Not registered)/i.test(v)
}

function recordEntries(records?: Record<string, { record_type?: string; queried_name?: string; status?: string; records?: string[]; error?: string | null }>) {
  return Object.entries(records || {})
}

function Flag({ on, label }: { on?: boolean; label: string }) {
  return (
    <span className={`report-flag ${on ? 'report-flag-on' : 'report-flag-off'}`}>
      {on ? '●' : '○'} {label}
    </span>
  )
}

function DataRow({ k, v, warn, mono }: { k: string; v: React.ReactNode; warn?: boolean; mono?: boolean }) {
  return (
    <div className="data-row">
      <span className="data-key">{k}</span>
      <span className={`data-val ${warn ? 'text-malicious font-semibold' : ''} ${mono ? 'font-mono text-xs break-all' : ''}`}>{v}</span>
    </div>
  )
}

export function AnalysisReport({
  analysisResult,
  onResetScan,
  ThreatScoreGauge,
}: {
  analysisResult: AnalysisDetails
  onResetScan: () => void
  ThreatScoreGauge: React.ComponentType<{ score: number; verdict: AnalysisDetails['verdict']; comment?: string }>
}) {
  const [pdfBusy, setPdfBusy] = useState(false)
  const [pdfError, setPdfError] = useState<string | null>(null)
  const raw = analysisResult.rawPayload as Record<string, any> | undefined
  const urlParts = raw?.url || {}
  const dns = raw?.dns || {}
  const ipPack = raw?.ip_intelligence || {}
  const whoisRaw = raw?.whois || {}
  const score = analysisResult.riskScore ?? analysisResult.threatScore
  const label = analysisResult.riskLabel
    || (analysisResult.verdict === 'SAFE' ? 'Safe'
      : analysisResult.verdict === 'SUSPICIOUS' ? 'Suspicious'
        : analysisResult.verdict === 'INCONCLUSIVE' || analysisResult.verdict === 'UNREACHABLE' ? 'Cannot be decided'
          : 'Dangerous')
  const verdictClass = analysisResult.verdict.toLowerCase()

  const handlePdf = async () => {
    setPdfBusy(true)
    setPdfError(null)
    try {
      await downloadAnalysisPdf(analysisResult)
    } catch (error) {
      setPdfError(error instanceof Error ? error.message : 'PDF generation failed.')
    } finally {
      setPdfBusy(false)
    }
  }

  return (
    <div className="active-analysis-report-wrapper" id="phishguard-analysis-report">
      <div className="analysis-report-toolbar">
        <button type="button" className="btn btn-primary btn-sm" onClick={onResetScan}>
          <span>← Scan Another URL</span>
        </button>
        <div className="report-toolbar-actions">
          <button type="button" className="btn btn-outline btn-sm" onClick={handlePdf} disabled={pdfBusy}>
            <span>{pdfBusy ? 'Preparing PDF…' : 'Download PDF report'}</span>
          </button>
        </div>
      </div>
      {pdfError && <p className="pdf-error-note" role="alert">{pdfError}</p>}

      <div className={`verdict-hero-card verdict-${verdictClass} reveal-stagger-1`}>
        <div className="verdict-card-left">
          <div className="verdict-badge-row">
            <span className="verdict-tag">{label.toUpperCase()}</span>
            <span className="verdict-score-pill">Risk score: {score}/100</span>
            {typeof analysisResult.confidence === 'number' && (
              <span className="verdict-score-pill">Confidence: {Math.round(analysisResult.confidence * 100)}%</span>
            )}
            {typeof analysisResult.coverageScore === 'number' && (
              <span className="verdict-score-pill">Evidence coverage: {Math.round(analysisResult.coverageScore * 100)}%</span>
            )}
          </div>
          <h3 className="scanned-url-heading">
            <code>{analysisResult.url}</code>
          </h3>
          <p className="verdict-summary-text">{analysisResult.riskComment || analysisResult.summary}</p>
          {analysisResult.domainStatus && (
            <div className={`domain-status-banner dstate-${analysisResult.domainStatus.state}`} role="status">
              <span className="dsb-icon" aria-hidden="true">
                {analysisResult.domainStatus.state === 'live' || analysisResult.domainStatus.state === 'ip_host' ? '✓'
                  : analysisResult.domainStatus.state === 'unknown' ? '?' : '✕'}
              </span>
              <div className="dsb-body">
                <strong>{analysisResult.domainStatus.title}</strong>
                <p>{analysisResult.domainStatus.detail}</p>
                {analysisResult.domainStatus.evidence.length > 0 && (
                  <span className="dsb-evidence">{analysisResult.domainStatus.evidence.join('  ·  ')}</span>
                )}
              </div>
            </div>
          )}
          <div className="url-telemetry-meta">
            <div className="telemetry-item">
              <span className="telemetry-label">Hostname:</span>
              <code className="telemetry-value">{analysisResult.hostname}</code>
            </div>
            <div className="telemetry-item">
              <span className="telemetry-label">Protocol:</span>
              <code className="telemetry-value">{analysisResult.protocol} ({analysisResult.structure.isHttps ? 'Encrypted' : 'Unencrypted'})</code>
            </div>
            <div className="telemetry-item">
              <span className="telemetry-label">Domain Age:</span>
              <span className="telemetry-value">{analysisResult.whois.domainAgeFormatted}</span>
            </div>
          </div>
        </div>
        <div className="verdict-card-right">
          <ThreatScoreGauge
            score={score}
            verdict={analysisResult.verdict}
            comment={analysisResult.riskComment || `Classification: ${label}`}
          />
        </div>
      </div>

      {!!analysisResult.riskComponents?.length && (
        <article className="analysis-card risk-breakdown-card span-3">
          <div className="card-top-bar">
            <span className="card-num">RS</span>
            <span className="card-category">RISK SCORE ENGINE</span>
          </div>
          <h4 className="card-title">Weighted evidence contributions</h4>
          <p className="card-narrative">
            Score {score}/100 is the sum of live lexical, DNS, registration, and network factors. Negative values reduce risk. This is not a static badge.
          </p>
          <div className="risk-component-list">
            {analysisResult.riskComponents.map((component, index) => (
              <div key={`${component.factor}-${index}`} className="risk-component-row">
                <div className="risk-component-meta">
                  <strong>{component.factor}</strong>
                  <span>{component.category}</span>
                </div>
                <p>{component.evidence}</p>
                <span className={`risk-delta ${component.contribution > 0 ? 'delta-up' : component.contribution < 0 ? 'delta-down' : 'delta-zero'}`}>
                  {component.contribution > 0 ? `+${component.contribution}` : component.contribution}
                </span>
              </div>
            ))}
          </div>
        </article>
      )}

      <div className="cards-grid-6">
        <article className="analysis-card stagger-card-1">
          <div className="card-top-bar"><span className="card-num">01</span><span className="card-category">OSINT SNAPSHOT</span></div>
          <h4 className="card-title">Open-source intelligence</h4>
          <div className="card-data-table">
            <DataRow k="Hostname" v={<code>{analysisResult.osint.hostname}</code>} />
            <DataRow k="Domain" v={<code>{analysisResult.osint.domain}</code>} />
            <DataRow k="Subdomain" v={analysisResult.osint.subdomain || 'None'} />
            <DataRow k="TLD" v={analysisResult.osint.tld || '—'} />
            <DataRow k="Protocol" v={analysisResult.osint.scheme.toUpperCase()} />
            <DataRow k="DNS status" v={analysisResult.osint.dnsStatus.replace(/_/g, ' ')} warn={analysisResult.osint.dnsStatus !== 'resolved'} />
            <DataRow k="Resolved IPs" v={analysisResult.osint.resolvedIps.length ? analysisResult.osint.resolvedIps.join(', ') : 'None returned'} mono />
            <DataRow k="IPv6" v={analysisResult.osint.ipv6.length ? analysisResult.osint.ipv6.join(', ') : 'None'} mono />
            <DataRow k="CNAME" v={analysisResult.osint.cname.length ? analysisResult.osint.cname.join(', ') : 'None'} mono />
            <DataRow k="Domain state" v={analysisResult.osint.domainState || 'Unknown'} />
            <DataRow k="Exists" v={String(analysisResult.osint.domainExists ?? 'unknown')} />
            <DataRow k="Query parameters" v={analysisResult.osint.queryParameterCount} />
          </div>
        </article>

        <article className="analysis-card stagger-card-2">
          <div className="card-top-bar"><span className="card-num">02</span><span className="card-category">URL ANATOMY</span></div>
          <h4 className="card-title">Parsed URL components</h4>
          <div className="card-data-table">
            <DataRow k="Original" v={urlParts.original || analysisResult.url} mono />
            <DataRow k="Normalized" v={urlParts.normalized || analysisResult.normalizedUrl} mono />
            <DataRow k="Scheme" v={urlParts.scheme || analysisResult.protocol} />
            <DataRow k="Username" v={urlParts.username || 'None'} warn={Boolean(urlParts.username)} />
            <DataRow k="Hostname" v={urlParts.hostname || analysisResult.hostname} mono />
            <DataRow k="Port" v={urlParts.port ?? 'Default'} />
            <DataRow k="Registrable domain" v={urlParts.registrable_domain || analysisResult.domain} mono />
            <DataRow k="Path" v={urlParts.path || analysisResult.path || '/'} mono />
            <DataRow k="Query" v={urlParts.query || 'None'} mono />
            <DataRow k="Fragment" v={urlParts.fragment || 'None'} mono />
            <DataRow k="Credentials" v={urlParts.has_credentials ? 'Yes' : 'No'} warn={Boolean(urlParts.has_credentials)} />
            <DataRow k="IP address host" v={urlParts.is_ip_address ? 'Yes' : 'No'} warn={Boolean(urlParts.is_ip_address)} />
          </div>
        </article>

        <article className="analysis-card stagger-card-3">
          <div className="card-top-bar"><span className="card-num">03</span><span className="card-category">TYPOSQUATTING</span></div>
          <h4 className="card-title">Lookalike domain detection</h4>
          <div className="card-data-table">
            <DataRow k="Detected" v={analysisResult.typosquatting.detected ? 'Yes' : 'No'} warn={analysisResult.typosquatting.detected} />
            <DataRow
              k="Target brand"
              v={analysisResult.typosquatting.targetBrand
                || (analysisResult.typosquatting.isOfficialDomain ? `${analysisResult.typosquatting.officialBrand} (official)` : 'None identified')}
              warn={analysisResult.typosquatting.detected}
            />
            <DataRow k="Pattern" v={analysisResult.typosquatting.patternType || 'Standard syntax'} />
            <DataRow
              k="Similarity"
              v={analysisResult.typosquatting.similarityScore != null ? `${analysisResult.typosquatting.similarityScore}%` : 'n/a'}
            />
            {analysisResult.typosquatting.officialDomain && (
              <DataRow k="Official domain" v={<code>{analysisResult.typosquatting.officialDomain}</code>} />
            )}
            {analysisResult.typosquatting.confidence && (
              <DataRow k="Confidence" v={analysisResult.typosquatting.confidence} />
            )}
          </div>
          <p className="card-narrative">{analysisResult.typosquatting.explanation}</p>
        </article>

        <article className="analysis-card stagger-card-4">
          <div className="card-top-bar"><span className="card-num">04</span><span className="card-category">HOMOGLYPH AUDIT</span></div>
          <h4 className="card-title">Unicode & character spoofs</h4>
          <div className="card-data-table">
            <DataRow
              k="Status"
              v={analysisResult.homoglyphs.detected ? 'Deceptive characters found' : 'Clean (pure ASCII)'}
              warn={analysisResult.homoglyphs.detected}
            />
            {analysisResult.homoglyphs.characters.map((character, index) => (
              <DataRow
                key={`${character.codePoint}-${index}`}
                k={`Character #${index + 1}`}
                v={<span><code className="char-badge">{character.char}</code> ({character.codePoint}) mimics <code className="char-badge">{character.lookalike}</code> · {character.script}</span>}
              />
            ))}
          </div>
          <p className="card-narrative">{analysisResult.homoglyphs.explanation}</p>
        </article>

        <article className="analysis-card stagger-card-5">
          <div className="card-top-bar"><span className="card-num">05</span><span className="card-category">ENTROPY</span></div>
          <h4 className="card-title">Shannon randomness</h4>
          <div className="card-data-table">
            <DataRow k="Domain entropy" v={`${analysisResult.entropy.domainEntropy} bits/char`} />
            <DataRow k="URL entropy" v={`${analysisResult.entropy.urlEntropy} bits/char`} />
            <DataRow k="Level" v={analysisResult.entropy.level} warn={analysisResult.entropy.level === 'High' || analysisResult.entropy.level === 'Suspiciously High'} />
          </div>
          <p className="card-narrative">{analysisResult.entropy.explanation}</p>
        </article>

        <article className="analysis-card stagger-card-6">
          <div className="card-top-bar"><span className="card-num">06</span><span className="card-category">URL STRUCTURE</span></div>
          <h4 className="card-title">Path & parameter semantics</h4>
          <div className="structure-flag-row">
            <Flag on={analysisResult.structure.hasSuspiciousPath} label="Suspicious path" />
            <Flag on={analysisResult.structure.hasEncodedChars} label="Encoded" />
            <Flag on={analysisResult.structure.doubleEncoded} label="Double encoded" />
            <Flag on={analysisResult.structure.hasObfuscatedQuery} label="Obfuscated query" />
            <Flag on={analysisResult.structure.hasIpHostname} label="IP host" />
            <Flag on={!analysisResult.structure.isHttps} label="No HTTPS" />
            <Flag on={analysisResult.structure.hasUserInfo} label="Userinfo" />
            <Flag on={analysisResult.structure.isUrlShortener} label="Shortener" />
            <Flag on={analysisResult.structure.isTrackingOrRedirectService} label="Tracker" />
            <Flag on={analysisResult.structure.hasRedirectParameter} label="Redirect param" />
            <Flag on={analysisResult.structure.hasOpaquePath} label="Opaque path" />
          </div>
          <div className="card-data-table">
            <DataRow k="Path" v={analysisResult.path || '/'} mono />
            <DataRow
              k="Keywords"
              v={analysisResult.structure.suspiciousKeywords.length
                ? analysisResult.structure.suspiciousKeywords.map((keyword) => <code key={keyword} className="keyword-chip">{keyword}</code>)
                : 'None found'}
              warn={analysisResult.structure.suspiciousKeywords.length > 0}
            />
            <DataRow k="Subdomain depth" v={analysisResult.structure.subdomainDepth ?? 0} warn={(analysisResult.structure.subdomainDepth ?? 0) >= 3} />
            {analysisResult.structure.encodedSegments?.map((segment, index) => (
              <DataRow key={`${segment.raw}-${index}`} k={`Encoded ${index + 1}`} v={`${segment.raw} → ${segment.decoded}`} mono />
            ))}
            {analysisResult.queryParams.map((param) => (
              <DataRow key={param.key} k={`Query ${param.key}${param.isSensitive ? ' ⚠' : ''}`} v={param.value} mono warn={param.isSensitive} />
            ))}
            {analysisResult.structure.redirectTargets?.map((target) => (
              <DataRow key={target.param} k={`Redirect ${target.param}`} v={`${target.host} (${target.crossDomain ? 'cross-domain' : 'same-site'})`} warn={target.crossDomain} mono />
            ))}
          </div>
          <p className="card-narrative">{analysisResult.structure.explanation}</p>
        </article>

        <article className="analysis-card stagger-card-7">
          <div className="card-top-bar"><span className="card-num">07</span><span className="card-category">WHOIS / RDAP</span></div>
          <h4 className="card-title">Registration intelligence</h4>
          <div className="card-data-table">
            <DataRow k="Domain" v={<code>{analysisResult.whois.domain}</code>} />
            <DataRow k="Registrar" v={<span className={isMissing(analysisResult.whois.registrar) ? 'data-val-muted' : ''}>{analysisResult.whois.registrar}</span>} />
            <DataRow k="Registrar ID" v={whoisRaw.registrar_id || 'Not published'} />
            <DataRow k="Registry" v={whoisRaw.registry_name || 'Not published'} />
            <DataRow k="RDAP server" v={whoisRaw.rdap_server || 'Not published'} mono />
            <DataRow k="Registered" v={analysisResult.whois.creationDate} />
            <DataRow k="Domain age" v={analysisResult.whois.domainAgeFormatted} warn={analysisResult.whois.isNewlyRegistered} />
            <DataRow k="Expires" v={analysisResult.whois.expirationDate || 'Not published'} />
            <DataRow k="Updated" v={analysisResult.whois.updatedDate || 'Not published'} />
            <DataRow k="Registry status" v={analysisResult.whois.status} mono />
            <DataRow k="DNSSEC" v={analysisResult.whois.dnssec} />
            <DataRow k="Redacted" v={whoisRaw.redacted ? 'Yes' : 'No'} />
            <DataRow k="Nameservers" v={analysisResult.whois.nameservers?.length ? analysisResult.whois.nameservers.join(', ') : 'Not published'} mono />
            <DataRow k="Source" v={analysisResult.whois.source || 'RDAP'} />
            <DataRow k="Lookup status" v={whoisRaw.status || analysisResult.whois.lookupStatus || 'unknown'} />
          </div>
          {(whoisRaw.events || []).length > 0 && (
            <div className="mini-event-list">
              {whoisRaw.events.map((event: { action?: string; date?: string }, index: number) => (
                <span key={`${event.action}-${index}`} className="mini-event-chip">{event.action}: {event.date || 'n/a'}</span>
              ))}
            </div>
          )}
          {analysisResult.whois.lookupNote && <p className="card-narrative">{analysisResult.whois.lookupNote}</p>}
        </article>

        <article className="analysis-card stagger-card-8 span-2">
          <div className="card-top-bar"><span className="card-num">08</span><span className="card-category">DNS RECORDS</span></div>
          <h4 className="card-title">Resolver evidence</h4>
          <div className="card-data-table">
            <DataRow k="Queried hostname" v={dns.hostname || analysisResult.hostname} mono />
            <DataRow k="Registrable domain" v={dns.registrable_domain || analysisResult.domain} mono />
            <DataRow k="Overall status" v={(dns.status || analysisResult.osint.dnsStatus || 'unknown').replace(/_/g, ' ')} />
            <DataRow k="Resolved IPs" v={(dns.resolved_ips || analysisResult.osint.resolvedIps || []).join(', ') || 'None'} mono />
          </div>
          {[['Hostname records', dns.hostname_records], ['Domain records', dns.domain_records], ['Flat records', dns.records]].map(([title, pack]) => (
            <div key={String(title)} className="dns-record-block">
              <strong>{title as string}</strong>
              {recordEntries(pack as Record<string, any>).length === 0 && <p className="card-narrative">No records returned.</p>}
              {recordEntries(pack as Record<string, any>).map(([type, result]) => (
                <div key={`${title}-${type}`} className="dns-record-row">
                  <code>{result.record_type || type}</code>
                  <span>{(result.status || '').replace(/_/g, ' ')}</span>
                  <span className="font-mono text-xs break-all">{(result.records || []).join(', ') || result.error || 'empty'}</span>
                </div>
              ))}
            </div>
          ))}
        </article>

        <article className="analysis-card stagger-card-9">
          <div className="card-top-bar"><span className="card-num">09</span><span className="card-category">IP INTELLIGENCE</span></div>
          <h4 className="card-title">Network & geolocation</h4>
          <div className="card-data-table">
            <DataRow k="Pack status" v={(ipPack.status || 'unknown').replace(/_/g, ' ')} />
            <DataRow k="Total IPs" v={ipPack.total_ips ?? analysisResult.osint.resolvedIps.length} />
            <DataRow k="Public IPs" v={ipPack.public_ips ?? '—'} />
            <DataRow k="Enriched IPs" v={ipPack.enriched_ips ?? '—'} />
            <DataRow k="Lookup limit" v={ipPack.lookup_limit ?? '—'} />
            <DataRow k="Limit reached" v={String(Boolean(ipPack.limit_reached))} />
          </div>
          {(ipPack.results || []).map((item: Record<string, any>) => (
            <div key={item.ip} className="ip-result-card">
              <strong>{item.ip}</strong>
              <p>IPv{item.version} · {item.classification} · {item.status}</p>
              <p>{[item.city, item.region, item.country_name, item.country_code].filter(Boolean).join(', ') || 'Location unpublished'}</p>
              <p className="font-mono text-xs">{[item.asn, item.organization, item.hostname].filter(Boolean).join(' · ') || 'ASN unpublished'}</p>
              {(item.latitude != null && item.longitude != null) && <p className="font-mono text-xs">{item.latitude}, {item.longitude} {item.timezone ? `· ${item.timezone}` : ''}</p>}
              {item.error && <p className="text-malicious">{item.error}</p>}
            </div>
          ))}
          {!(ipPack.results || []).length && (
            <p className="card-narrative">No enriched IP intelligence was returned for this hostname.</p>
          )}
        </article>

        <article className="analysis-card stagger-card-10">
          <div className="card-top-bar"><span className="card-num">10</span><span className="card-category">PROVIDERS</span></div>
          <h4 className="card-title">Upstream lookups</h4>
          <div className="card-data-table">
            {(analysisResult.providerRows || []).map((row) => (
              <DataRow key={row.name} k={row.name} v={`${row.state.replace(/_/g, ' ')} — ${row.detail}`} warn={row.state === 'error'} />
            ))}
          </div>
        </article>

        <article className="analysis-card stagger-card-11 span-2">
          <div className="card-top-bar"><span className="card-num">11</span><span className="card-category">THREAT REASONING</span></div>
          <h4 className="card-title">Score contributing factors</h4>
          <div className="findings-bullet-list">
            {analysisResult.reasons.map((item, idx) => (
              <div key={`${item.title}-${idx}`} className={`finding-bullet-item severity-${item.severity}`}>
                <span className="finding-bullet-index">{String(idx + 1).padStart(2, '0')}</span>
                <div className="finding-bullet-content">
                  <strong className="finding-bullet-title">{item.title}</strong>
                  <p className="finding-bullet-desc">{item.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </article>

        <article className="analysis-card stagger-card-12 span-3">
          <div className="card-top-bar"><span className="card-num">12</span><span className="card-category">COMPLETE JSON</span></div>
          <h4 className="card-title">Exact backend response</h4>
          <p className="card-narrative">Every field returned by the analysis API is preserved below, including nested DNS, RDAP, and IP objects.</p>
          <pre className="raw-json-panel">{JSON.stringify(analysisResult.rawPayload ?? analysisResult, null, 2)}</pre>
        </article>
      </div>
    </div>
  )
}
