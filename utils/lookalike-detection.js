/**
 * LoginGuard - Lookalike & Brand Impersonation Detection Utility
 * Uses Levenshtein distance, character homoglyphs/leet substitutions, and popular brand lists.
 */

// Curated list of high-value brands frequently targeted by phishing attacks
export const POPULAR_BRANDS = [
  { name: 'Google', domains: ['google.com', 'accounts.google.com', 'gmail.com'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'login.microsoftonline.com'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com', 'appleid.apple.com'] },
  { name: 'PayPal', domains: ['paypal.com'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'] },
  { name: 'Facebook', domains: ['facebook.com', 'fb.com', 'meta.com'] },
  { name: 'Instagram', domains: ['instagram.com'] },
  { name: 'Netflix', domains: ['netflix.com'] },
  { name: 'Chase', domains: ['chase.com'] },
  { name: 'Bank of America', domains: ['bankofamerica.com'] },
  { name: 'Wells Fargo', domains: ['wellsfargo.com'] },
  { name: 'Twitter / X', domains: ['twitter.com', 'x.com'] },
  { name: 'LinkedIn', domains: ['linkedin.com'] },
  { name: 'Dropbox', domains: ['dropbox.com'] },
  { name: 'Adobe', domains: ['adobe.com'] },
  { name: 'GitHub', domains: ['github.com'] },
  { name: 'Binance', domains: ['binance.com'] },
  { name: 'Coinbase', domains: ['coinbase.com'] },
  { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'Yahoo', domains: ['yahoo.com'] }
];

/**
 * Computes standard Levenshtein distance between two strings.
 */
export function levenshteinDistance(a, b) {
  const an = a ? a.length : 0;
  const bn = b ? b.length : 0;
  if (an === 0) return bn;
  if (bn === 0) return an;

  const matrix = Array.from({ length: bn + 1 }, () => new Array(an + 1).fill(0));

  for (let i = 0; i <= an; i++) matrix[0][i] = i;
  for (let j = 0; j <= bn; j++) matrix[j][0] = j;

  for (let j = 1; j <= bn; j++) {
    for (let i = 1; i <= an; i++) {
      if (b[j - 1] === a[i - 1]) {
        matrix[j][i] = matrix[j - 1][i - 1];
      } else {
        matrix[j][i] = Math.min(
          matrix[j - 1][i] + 1,     // deletion
          matrix[j][i - 1] + 1,     // insertion
          matrix[j - 1][i - 1] + 1 // substitution
        );
      }
    }
  }

  return matrix[bn][an];
}

/**
 * Normalizes common homoglyph and leetspeak character substitutions.
 * e.g., 'g00gle' -> 'google', 'paypa1' -> 'paypal', 'micros0ft' -> 'microsoft'
 */
export function normalizeSubstitutions(str) {
  return str
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');
}

/**
 * Extracts base brand name from a registrable domain (e.g., 'google.com' -> 'google').
 */
export function getDomainBase(registrableDomain) {
  if (!registrableDomain) return '';
  const parts = registrableDomain.split('.');
  return parts[0].toLowerCase();
}

/**
 * Analyzes whether the target domain is an illegitimate lookalike of a protected brand.
 * 
 * Returns:
 * {
 *   isLookalike: boolean,
 *   isBrandImpersonation: boolean,
 *   matchedBrand: string | null,
 *   distance: number | null,
 *   reason: string | null,
 *   scorePenalty: number
 * }
 */
export function detectLookalike(registrableDomain, fullHostname = '') {
  if (!registrableDomain) {
    return { isLookalike: false, isBrandImpersonation: false, matchedBrand: null, scorePenalty: 0 };
  }

  const cleanHost = fullHostname.toLowerCase();
  const domainBase = getDomainBase(registrableDomain);
  const normalizedBase = normalizeSubstitutions(domainBase);

  // Check each popular brand
  for (const brand of POPULAR_BRANDS) {
    // 1. If it's an exact authorized domain of this brand, it is legitimate!
    if (brand.domains.includes(registrableDomain.toLowerCase())) {
      return {
        isLegitimateBrand: true,
        isLookalike: false,
        isBrandImpersonation: false,
        matchedBrand: brand.name,
        scorePenalty: 0
      };
    }

    const brandBase = brand.name.toLowerCase().replace(/[^a-z0-9]/g, '');

    // 2. Character substitution check (e.g. g00gle.com, paypa1.com, micros0ft.com)
    if (normalizedBase === brandBase && domainBase !== brandBase) {
      return {
        isLookalike: true,
        isBrandImpersonation: true,
        matchedBrand: brand.name,
        distance: 1,
        reason: `Domain base "${domainBase}" mimics "${brand.name}" using character substitutions.`,
        scorePenalty: 35
      };
    }

    // 3. Levenshtein edit distance check (1 or 2 edits away, e.g. goog1e.com, microsft.com)
    const dist = levenshteinDistance(domainBase, brandBase);
    const normalizedDist = levenshteinDistance(normalizedBase, brandBase);
    const effectiveDist = Math.min(dist, normalizedDist);

    if (effectiveDist > 0 && effectiveDist <= 2 && brandBase.length >= 4) {
      return {
        isLookalike: true,
        isBrandImpersonation: true,
        matchedBrand: brand.name,
        distance: effectiveDist,
        reason: `Domain "${domainBase}" is highly similar to brand "${brand.name}" (${effectiveDist} character edit away).`,
        scorePenalty: 35
      };
    }

    // 4. Misleading brand keyword combination (e.g., goog1e-login.com, paypal-security.com, microsoft-verify.com)
    const brandPattern = new RegExp(`(^|[-._])${brandBase}([-._]|$)`, 'i');
    if (brandPattern.test(domainBase) || brandPattern.test(cleanHost) || brandPattern.test(normalizedBase)) {
      // Check if domain combines brand with security/action keywords
      return {
        isLookalike: true,
        isBrandImpersonation: true,
        matchedBrand: brand.name,
        reason: `Domain contains protected brand name "${brand.name}" combined with unauthorized identifiers.`,
        scorePenalty: 30
      };
    }
  }

  return {
    isLookalike: false,
    isBrandImpersonation: false,
    matchedBrand: null,
    scorePenalty: 0
  };
}
