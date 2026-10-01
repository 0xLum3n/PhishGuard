import type { AnalysisDetails } from '../App'

type JsPdfCtor = typeof import('jspdf').jsPDF

function rgb(verdict: string): [number, number, number] {
  if (verdict === 'SAFE') return [34, 197, 94]
  if (verdict === 'SUSPICIOUS') return [245, 158, 11]
  if (verdict === 'INCONCLUSIVE' || verdict === 'UNREACHABLE') return [100, 116, 139]
  return [239, 68, 68]
}

function labelFor(details: AnalysisDetails): string {
  return details.riskLabel
    || (details.verdict === 'SAFE'
      ? 'Safe'
      : details.verdict === 'SUSPICIOUS'
        ? 'Suspicious'
        : details.verdict === 'INCONCLUSIVE' || details.verdict === 'UNREACHABLE'
          ? 'Cannot be decided'
          : 'Dangerous')
}

function flatten(value: unknown, prefix = '', rows: Array<[string, string]> = []): Array<[string, string]> {
  if (value === null || value === undefined) {
    rows.push([prefix || 'value', 'null'])
    return rows
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      rows.push([prefix || 'list', '[]'])
      return rows
    }
    value.forEach((item, index) => {
      flatten(item, prefix ? `${prefix}[${index}]` : `[${index}]`, rows)
    })
    return rows
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
    if (!entries.length) {
      rows.push([prefix || 'object', '{}'])
      return rows
    }
    for (const [key, nested] of entries) {
      flatten(nested, prefix ? `${prefix}.${key}` : key, rows)
    }
    return rows
  }
  rows.push([prefix || 'value', String(value)])
  return rows
}

function wrap(doc: InstanceType<JsPdfCtor>, text: string, width: number): string[] {
  return doc.splitTextToSize(text, width) as string[]
}

function drawGauge(
  doc: InstanceType<JsPdfCtor>,
  cx: number,
  cy: number,
  score: number,
  color: [number, number, number],
) {
  const radius = 18
  doc.setDrawColor(230, 226, 216)
  doc.setLineWidth(3.2)
  doc.circle(cx, cy, radius, 'S')

  const start = -Math.PI / 2
  const end = start + (Math.max(0, Math.min(100, score)) / 100) * Math.PI * 2
  const steps = 48
  doc.setDrawColor(...color)
  doc.setLineWidth(3.4)
  for (let i = 0; i < steps; i++) {
    const a = start + ((end - start) * i) / steps
    const b = start + ((end - start) * (i + 1)) / steps
    doc.line(
      cx + Math.cos(a) * radius,
      cy + Math.sin(a) * radius,
      cx + Math.cos(b) * radius,
      cy + Math.sin(b) * radius,
    )
  }

  doc.setTextColor(18, 18, 17)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(16)
  doc.text(String(score), cx, cy - 1, { align: 'center' })
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  doc.setTextColor(94, 93, 87)
  doc.text('/ 100', cx, cy + 5, { align: 'center' })
}

export async function downloadAnalysisPdf(details: AnalysisDetails): Promise<void> {
  const { jsPDF } = await import('jspdf')
  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const pageWidth = doc.internal.pageSize.getWidth()
  const pageHeight = doc.internal.pageSize.getHeight()
  const margin = 14
  const maxWidth = pageWidth - margin * 2
  let y = 16
  const color = rgb(details.verdict)
  const score = details.riskScore ?? details.threatScore
  const generatedAt = new Date().toISOString()

  const ensureSpace = (needed: number) => {
    if (y + needed > pageHeight - 16) {
      doc.addPage()
      y = 16
    }
  }

  const heading = (title: string) => {
    ensureSpace(12)
    doc.setFillColor(18, 18, 17)
    doc.rect(margin, y, maxWidth, 8, 'F')
    doc.setTextColor(255, 255, 255)
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(10)
    doc.text(title, margin + 3, y + 5.4)
    y += 12
    doc.setTextColor(18, 18, 17)
  }

  const kv = (key: string, value: string) => {
    const lines = wrap(doc, value || '—', maxWidth - 52)
    ensureSpace(5 + (lines.length - 1) * 4)
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.setTextColor(94, 93, 87)
    doc.text(key, margin, y)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(18, 18, 17)
    doc.text(lines, margin + 50, y)
    y += 4.4 + (lines.length - 1) * 4
  }

  doc.setFillColor(18, 18, 17)
  doc.rect(0, 0, pageWidth, 28, 'F')
  doc.setTextColor(243, 186, 47)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(16)
  doc.text('PHISHGUARD', margin, 12)
  doc.setTextColor(255, 255, 255)
  doc.setFontSize(9)
  doc.text('URL Threat Intelligence Report', margin, 18)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8)
  doc.setTextColor(165, 164, 158)
  doc.text(generatedAt, pageWidth - margin, 12, { align: 'right' })
  y = 36

  doc.setDrawColor(...color)
  doc.setFillColor(250, 248, 245)
  doc.setLineWidth(0.6)
  doc.roundedRect(margin, y, maxWidth, 46, 3, 3, 'FD')
  drawGauge(doc, pageWidth - margin - 28, y + 23, score, color)

  doc.setFont('helvetica', 'bold')
  doc.setFontSize(11)
  doc.setTextColor(...color)
  doc.text(labelFor(details).toUpperCase(), margin + 6, y + 8)
  doc.setTextColor(18, 18, 17)
  doc.setFontSize(9)
  const urlLines = wrap(doc, details.url, maxWidth - 70)
  doc.text(urlLines, margin + 6, y + 15)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8)
  doc.setTextColor(94, 93, 87)
  const commentLines = wrap(doc, details.riskComment || details.summary, maxWidth - 70)
  doc.text(commentLines, margin + 6, y + 15 + urlLines.length * 4.2)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(18, 18, 17)
  doc.text(`Risk score ${score}/100`, margin + 6, y + 41)
  doc.setFont('helvetica', 'normal')
  doc.text(`Coverage ${Math.round((details.coverageScore ?? 0) * 100)}%   Confidence ${Math.round((details.confidence ?? 0) * 100)}%`, margin + 52, y + 41)
  y += 54

  heading('Executive summary')
  kv('Normalized URL', details.normalizedUrl)
  kv('Verdict', `${details.verdict} / ${labelFor(details)}`)
  kv('Risk score', `${score} / 100`)
  kv('Comment', details.riskComment || details.summary)
  kv('Summary', details.summary)
  kv('Hostname', details.hostname)
  kv('Protocol', details.protocol)
  kv('Domain age', details.whois.domainAgeFormatted)

  heading('Risk score contributions')
  const components = details.riskComponents?.length
    ? details.riskComponents
    : details.reasons.map((reason) => ({
        factor: reason.title,
        category: reason.severity,
        contribution: 0,
        evidence: reason.detail,
      }))
  for (const component of components) {
    kv(
      `${component.contribution >= 0 ? '+' : ''}${component.contribution}  ${component.factor}`,
      `${component.category}: ${component.evidence}`,
    )
  }

  heading('OSINT')
  kv('Hostname', details.osint.hostname)
  kv('Domain', details.osint.domain)
  kv('Subdomain', details.osint.subdomain || 'None')
  kv('TLD', details.osint.tld || '—')
  kv('DNS status', details.osint.dnsStatus)
  kv('Resolved IPs', details.osint.resolvedIps.join(', ') || 'None')
  kv('IPv6', details.osint.ipv6.join(', ') || 'None')
  kv('CNAME', details.osint.cname.join(', ') || 'None')
  kv('Domain state', details.osint.domainState || 'Unknown')
  kv('Query parameters', String(details.osint.queryParameterCount))

  heading('URL anatomy')
  kv('Path', details.path)
  kv('HTTPS', details.structure.isHttps ? 'Yes' : 'No')
  kv('IP hostname', details.structure.hasIpHostname ? 'Yes' : 'No')
  kv('Keywords', details.structure.suspiciousKeywords.join(', ') || 'None')
  kv('Encoded', details.structure.hasEncodedChars ? 'Yes' : 'No')
  kv('Double encoded', details.structure.doubleEncoded ? 'Yes' : 'No')
  kv('Shortener', details.structure.isUrlShortener ? 'Yes' : 'No')
  kv('Userinfo', details.structure.hasUserInfo ? 'Yes' : 'No')
  kv('Subdomain depth', String(details.structure.subdomainDepth ?? 0))
  for (const param of details.queryParams) {
    kv(`Query ${param.key}`, `${param.value}${param.isSensitive ? ' (sensitive)' : ''}`)
  }

  heading('Lexical analysis')
  kv('Domain entropy', String(details.entropy.domainEntropy))
  kv('URL entropy', String(details.entropy.urlEntropy))
  kv('Entropy level', details.entropy.level)
  kv('Entropy note', details.entropy.explanation)
  kv('Typosquatting', details.typosquatting.detected ? 'Detected' : 'Not detected')
  kv('Typosquat detail', details.typosquatting.explanation)
  kv('Homoglyphs', details.homoglyphs.detected ? 'Detected' : 'Clean ASCII')
  kv('Homoglyph detail', details.homoglyphs.explanation)
  for (const character of details.homoglyphs.characters) {
    kv(`Glyph ${character.char}`, `${character.codePoint} mimics ${character.lookalike} (${character.script})`)
  }

  heading('WHOIS / RDAP')
  kv('Domain', details.whois.domain)
  kv('Registrar', details.whois.registrar)
  kv('Created', details.whois.creationDate)
  kv('Expires', details.whois.expirationDate || 'Not published')
  kv('Updated', details.whois.updatedDate || 'Not published')
  kv('Status', details.whois.status)
  kv('DNSSEC', details.whois.dnssec)
  kv('Nameservers', details.whois.nameservers?.join(', ') || 'Not published')
  kv('Source', details.whois.source || 'RDAP')
  kv('Lookup', details.whois.lookupStatus || 'unknown')

  heading('DNS & IP intelligence')
  kv('Lookup status', details.intelligence?.ipIntelligence?.ip ? 'Enriched' : 'No public IP data')
  kv('Primary IP', details.intelligence?.ipIntelligence?.ip || 'Not available')
  kv('Location', [
    details.intelligence?.ipIntelligence?.geolocation?.city,
    details.intelligence?.ipIntelligence?.geolocation?.region,
    details.intelligence?.ipIntelligence?.geolocation?.country,
  ].filter(Boolean).join(', ') || 'Not available')
  kv('ASN', details.intelligence?.ipIntelligence?.geolocation?.asn || 'Not available')
  kv('Organization', details.intelligence?.ipIntelligence?.geolocation?.org || 'Not available')

  heading('Threat reasons')
  for (const reason of details.reasons) {
    kv(reason.title, `[${reason.severity}] ${reason.detail}`)
  }

  heading('Complete backend JSON')
  const payload = details.rawPayload ?? details
  const rows = flatten(payload)
  doc.setFont('courier', 'normal')
  doc.setFontSize(7)
  for (const [key, value] of rows) {
    const lines = wrap(doc, `${key}: ${value}`, maxWidth)
    ensureSpace(4 * lines.length)
    doc.setTextColor(18, 18, 17)
    doc.text(lines, margin, y)
    y += 3.6 * lines.length
  }

  const pageCount = doc.getNumberOfPages()
  for (let page = 1; page <= pageCount; page++) {
    doc.setPage(page)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    doc.setTextColor(140, 138, 128)
    doc.text(`PhishGuard report · ${labelFor(details)} · ${score}/100`, margin, pageHeight - 8)
    doc.text(`Page ${page} of ${pageCount}`, pageWidth - margin, pageHeight - 8, { align: 'right' })
  }

  const host = details.hostname.replace(/[^a-z0-9.-]/gi, '_')
  doc.save(`phishguard-report-${host}.pdf`)
}
