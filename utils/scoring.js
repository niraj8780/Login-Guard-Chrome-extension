/**
 * LoginGuard - Security Risk Scoring System
 * Calculates a normalized 0-100 risk score and assigns a security verdict.
 */

export const VERDICTS = {
  SAFE: 'SAFE',
  SUSPICIOUS: 'SUSPICIOUS',
  DANGEROUS: 'DANGEROUS'
};

export const THRESHOLDS = {
  SAFE_MAX: 24,
  SUSPICIOUS_MAX: 59,
  DANGEROUS_MIN: 60
};

/**
 * Calculates risk score and assigns verdict based on individual check results.
 * 
 * @param {Object} checks
 * @param {boolean} checks.isHttp - Website uses HTTP instead of HTTPS (+30)
 * @param {boolean} checks.isConfirmedPhishing - Confirmed match in threat database (+70)
 * @param {boolean} checks.isLookalike - Strong lookalike domain match (+35)
 * @param {boolean} checks.isBrandImpersonation - Brand keyword combination (+20)
 * @param {boolean} checks.isRawIP - Login page hosted on raw IP (+25)
 * @param {boolean} checks.isPunycode - Domain uses Punycode IDN (+15)
 * @param {number} checks.rdapScorePenalty - Penalty from RDAP age (+10 or +15)
 * @param {number} checks.structuralScorePenalty - Penalty from excessive hyphens/subdomains/length
 * @param {boolean} checks.isWhitelisted - User marked domain as trusted
 * @param {Array<string>} checks.reasons - Descriptive list of flagged reasons
 */
export function calculateRiskScore(checks = {}) {
  const breakdown = [];
  const reasons = [];
  let rawScore = 0;

  // 1. Phishing Intelligence Check (+70)
  if (checks.isConfirmedPhishing) {
    rawScore += 70;
    breakdown.push({ item: 'Confirmed Phishing Threat', points: 70 });
    reasons.push(checks.phishingNote || 'Website is identified on active phishing/malware threat blocklists.');
  }

  // 2. HTTP Protocol Check (+30)
  if (checks.isHttp) {
    rawScore += 30;
    breakdown.push({ item: 'Unencrypted HTTP Connection', points: 30 });
    reasons.push('Login form transmitted over insecure HTTP. Passwords can be intercepted in transit.');
  }

  // 3. Raw IP Check (+25)
  if (checks.isRawIP) {
    rawScore += 25;
    breakdown.push({ item: 'Direct IP Address Host', points: 25 });
    reasons.push('Login hosted directly on a numeric IP address rather than a verified domain.');
  }

  // 4. Lookalike & Brand Impersonation (+35 or +20)
  if (checks.isLookalike) {
    rawScore += 35;
    breakdown.push({ item: 'Lookalike / Typosquatting Match', points: 35 });
    reasons.push(checks.lookalikeReason || 'Domain name appears to mimic a known brand through typos or homoglyphs.');
  } else if (checks.isBrandImpersonation) {
    rawScore += 20;
    breakdown.push({ item: 'Brand Name In Subdomain/Hyphens', points: 20 });
    reasons.push('Domain incorporates a recognized brand name in an unverified manner.');
  }

  // 5. Punycode (+15)
  if (checks.isPunycode) {
    rawScore += 15;
    breakdown.push({ item: 'Punycode (IDN) Encoding', points: 15 });
    reasons.push('Domain uses Punycode encoding, potentially masking visually misleading characters.');
  }

  // 6. Recently registered domain (+10 to +15)
  if (checks.rdapScorePenalty && checks.rdapScorePenalty > 0) {
    rawScore += checks.rdapScorePenalty;
    breakdown.push({ item: 'Recently Registered Domain', points: checks.rdapScorePenalty });
    reasons.push(checks.rdapWarning || 'Domain was registered very recently, a common trait of temporary phishing sites.');
  }

  // 7. Structural anomalies (hyphens, subdomains, length)
  if (checks.structuralScorePenalty && checks.structuralScorePenalty > 0) {
    const penalty = Math.min(25, checks.structuralScorePenalty);
    rawScore += penalty;
    breakdown.push({ item: 'Suspicious Domain Structure', points: penalty });
    if (checks.structuralIssues && checks.structuralIssues.length > 0) {
      reasons.push(...checks.structuralIssues);
    }
  }

  // Deduplicate reasons
  const uniqueReasons = [...new Set(reasons)];

  // Cap score between 0 and 100
  let normalizedScore = Math.min(100, Math.max(0, rawScore));

  // Determine standard verdict
  let verdict;
  if (checks.isConfirmedPhishing || normalizedScore >= THRESHOLDS.DANGEROUS_MIN) {
    verdict = VERDICTS.DANGEROUS;
    if (normalizedScore < THRESHOLDS.DANGEROUS_MIN) {
      normalizedScore = THRESHOLDS.DANGEROUS_MIN;
    }
  } else if (normalizedScore > THRESHOLDS.SAFE_MAX) {
    verdict = VERDICTS.SUSPICIOUS;
  } else {
    verdict = VERDICTS.SAFE;
  }

  // Whitelist handling
  // Important: Whitelisting suppresses ordinary heuristic warnings ONLY.
  // Never silently override confirmed phishing matches!
  let whitelistSuppressed = false;
  if (checks.isWhitelisted) {
    if (checks.isConfirmedPhishing) {
      verdict = VERDICTS.DANGEROUS;
      uniqueReasons.unshift('CRITICAL: This domain is on your Trusted Whitelist, but has a CONFIRMED PHISHING MATCH in threat intelligence.');
    } else {
      whitelistSuppressed = true;
      verdict = VERDICTS.SAFE;
      normalizedScore = 0;
      uniqueReasons.length = 0;
      uniqueReasons.push('Domain is on your Trusted Whitelist. Heuristic warnings are suppressed.');
    }
  }

  // If score is safe and no reasons found
  if (verdict === VERDICTS.SAFE && uniqueReasons.length === 0) {
    uniqueReasons.push('No known phishing indicators, domain lookalike anomalies, or insecure protocols detected.');
  }

  return {
    score: normalizedScore,
    verdict,
    breakdown,
    reasons: uniqueReasons,
    isWhitelisted: !!checks.isWhitelisted,
    whitelistSuppressed
  };
}
