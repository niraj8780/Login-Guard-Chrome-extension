/**
 * LoginGuard - Domain Checking & Parsing Utility
 * Analyzes URLs, hostnames, public suffixes, IP formats, and structural characteristics.
 */

// Common multi-part public suffixes
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk',
  'com.au', 'net.au', 'edu.au', 'gov.au',
  'ac.in', 'edu.in', 'res.in', 'gov.in', 'co.in', 'net.in',
  'com.br', 'co.jp', 'ne.jp', 'co.za', 'com.sg', 'edu.sg',
  'com.cn', 'edu.cn', 'gov.cn', 'com.mx', 'edu.mx'
]);

/**
 * Checks if a string is a valid IPv4 address.
 */
export function isIPv4(hostname) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(hostname);
}

/**
 * Checks if a string is a valid IPv6 address (with or without brackets).
 */
export function isIPv6(hostname) {
  const clean = hostname.replace(/^\[|\]$/g, '');
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Regex.test(clean);
}

/**
 * Checks if the hostname is a raw IP address (IPv4 or IPv6).
 */
export function isRawIP(hostname) {
  return isIPv4(hostname) || isIPv6(hostname);
}

/**
 * Checks if domain contains Punycode / IDN encoding (starts with xn--).
 */
export function isPunycode(hostname) {
  return hostname.toLowerCase().split('.').some(part => part.startsWith('xn--'));
}

/**
 * Extracts domain components: protocol, hostname, registrableDomain, tld, subdomains.
 */
export function parseDomainInfo(rawUrl) {
  let urlObj;
  try {
    urlObj = new URL(rawUrl);
  } catch (err) {
    return {
      isValid: false,
      error: 'Invalid URL format',
      rawUrl
    };
  }

  const protocol = urlObj.protocol; // 'https:' or 'http:'
  const hostname = urlObj.hostname.toLowerCase();
  const pathname = urlObj.pathname;
  const isIP = isRawIP(hostname);
  const punycode = isPunycode(hostname);

  if (isIP) {
    return {
      isValid: true,
      rawUrl,
      protocol,
      hostname,
      pathname,
      isIP: true,
      isPunycode: false,
      registrableDomain: hostname,
      tld: '',
      subdomains: '',
      subdomainCount: 0,
      hyphenCount: 0,
      domainLength: hostname.length
    };
  }

  const parts = hostname.split('.');
  let tld = '';
  let registrableDomain = hostname;
  let subdomains = '';

  if (parts.length >= 2) {
    const lastTwo = parts.slice(-2).join('.');
    if (parts.length >= 3 && MULTI_PART_SUFFIXES.has(lastTwo)) {
      tld = lastTwo;
      registrableDomain = parts.slice(-3).join('.');
      subdomains = parts.slice(0, -3).join('.');
    } else {
      tld = parts[parts.length - 1];
      registrableDomain = parts.slice(-2).join('.');
      subdomains = parts.slice(0, -2).join('.');
    }
  }

  const subdomainList = subdomains ? subdomains.split('.').filter(Boolean) : [];
  const hyphenCount = (hostname.match(/-/g) || []).length;

  return {
    isValid: true,
    rawUrl,
    protocol,
    hostname,
    pathname,
    isIP: false,
    isPunycode: punycode,
    registrableDomain,
    tld,
    subdomains,
    subdomainList,
    subdomainCount: subdomainList.length,
    hyphenCount,
    domainLength: hostname.length
  };
}

/**
 * List of high-risk keywords often used in phishing domains / subdomains
 */
export const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in',
  'verify', 'verification', 'verif',
  'secure', 'security', 'sec-update',
  'account', 'accounts', 'acct',
  'update', 'billing', 'invoice',
  'banking', 'authenticate', 'auth',
  'wallet', 'recovery', 'support',
  'password', 'credential', 'portal',
  'admin', 'webmail', 'confirm'
];

/**
 * Inspects domain for structural anomalies.
 */
export function analyzeStructuralSuspicion(parsed) {
  const issues = [];
  let suspicionPoints = 0;

  if (!parsed.isValid) {
    return { issues: ['Invalid URL'], scorePenalty: 50 };
  }

  // 1. Raw IP address used in login
  if (parsed.isIP) {
    issues.push('Login page hosted directly on a raw IP address instead of a domain name.');
    suspicionPoints += 25;
  }

  // 2. Punycode / Internationalized Domain Name
  if (parsed.isPunycode) {
    issues.push('Domain uses Punycode (IDN) which can conceal homoglyph character spoofing.');
    suspicionPoints += 15;
  }

  // 3. Excessive hyphens
  if (parsed.hyphenCount >= 3) {
    issues.push(`Domain contains an excessive number of hyphens (${parsed.hyphenCount}).`);
    suspicionPoints += 10;
  } else if (parsed.hyphenCount === 2) {
    issues.push('Domain contains multiple hyphens, often seen in phishing campaigns.');
    suspicionPoints += 5;
  }

  // 4. Excessive subdomains
  if (parsed.subdomainCount >= 4) {
    issues.push(`Excessive subdomain nesting (${parsed.subdomainCount} levels).`);
    suspicionPoints += 10;
  } else if (parsed.subdomainCount === 3) {
    issues.push('Complex subdomain structure detected.');
    suspicionPoints += 5;
  }

  // 5. Extremely long hostname
  if (parsed.domainLength > 45) {
    issues.push(`Extremely long hostname (${parsed.domainLength} characters).`);
    suspicionPoints += 10;
  }

  // 6. Suspicious phishing keywords in unverified domain or subdomains
  const lowerHost = parsed.hostname.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => {
    // Check if keyword appears as token in subdomains or separated by hyphens
    return lowerHost.includes(kw);
  });

  if (matchedKeywords.length >= 2) {
    issues.push(`Multiple security/banking keywords embedded in domain: ${matchedKeywords.slice(0, 3).join(', ')}.`);
    suspicionPoints += 15;
  } else if (matchedKeywords.length === 1 && parsed.subdomainCount >= 1) {
    issues.push(`Sensitive keyword "${matchedKeywords[0]}" found in subdomain/hostname.`);
    suspicionPoints += 5;
  }

  return {
    issues,
    suspicionPoints: Math.min(35, suspicionPoints),
    matchedKeywords
  };
}
