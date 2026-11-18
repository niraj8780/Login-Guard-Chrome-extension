/**
 * LoginGuard - RDAP (Registration Data Access Protocol) Domain Age Checker
 * Queries public RDAP endpoints to discover domain creation dates and registration age.
 */

const RDAP_SERVERS = [
  'https://rdap.org/domain/',
  'https://rdap.verisign.com/com/v1/domain/'
];

/**
 * Parses events from RDAP payload to locate registration / creation date.
 */
export function extractRegistrationDate(rdapJson) {
  if (!rdapJson || !Array.isArray(rdapJson.events)) {
    return null;
  }

  const creationActionNames = ['registration', 'created', 'transfer'];
  for (const event of rdapJson.events) {
    if (creationActionNames.includes(event.eventAction)) {
      const parsedDate = new Date(event.eventDate);
      if (!isNaN(parsedDate.getTime())) {
        return parsedDate;
      }
    }
  }

  return null;
}

/**
 * Calculates age in days from a creation Date object.
 */
export function calculateDomainAgeInDays(creationDate) {
  if (!creationDate || !(creationDate instanceof Date) || isNaN(creationDate.getTime())) {
    return null;
  }
  const now = new Date();
  const diffMs = now.getTime() - creationDate.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Queries RDAP for a given registrable domain.
 * Falls back gracefully if service is unreachable or domain is not found.
 */
export async function checkDomainAge(registrableDomain, timeoutMs = 4500) {
  if (!registrableDomain || registrableDomain.includes(':') || registrableDomain === 'localhost') {
    return {
      status: 'NOT_APPLICABLE',
      ageInDays: null,
      creationDate: null,
      scorePenalty: 0,
      note: 'RDAP query not applicable for this host'
    };
  }

  // Try fetching from public RDAP resolver
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`;
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/rdap+json, application/json' }
    });

    clearTimeout(timer);

    if (response.status === 404) {
      return {
        status: 'NOT_FOUND',
        ageInDays: null,
        creationDate: null,
        scorePenalty: 0,
        note: 'Domain registration record not found in public RDAP'
      };
    }

    if (!response.ok) {
      return {
        status: 'UNAVAILABLE',
        ageInDays: null,
        creationDate: null,
        scorePenalty: 0,
        note: `RDAP service returned status ${response.status}`
      };
    }

    const data = await response.json();
    const creationDate = extractRegistrationDate(data);
    const ageInDays = calculateDomainAgeInDays(creationDate);

    if (ageInDays === null) {
      return {
        status: 'UNKNOWN_DATE',
        ageInDays: null,
        creationDate: null,
        scorePenalty: 0,
        note: 'Registration event not provided in RDAP record'
      };
    }

    let scorePenalty = 0;
    let warning = null;

    if (ageInDays >= 0 && ageInDays < 30) {
      scorePenalty = 15;
      warning = `Domain is very newly registered (${ageInDays} days old). High risk for phishing campaigns.`;
    } else if (ageInDays >= 30 && ageInDays < 90) {
      scorePenalty = 10;
      warning = `Domain is recently registered (${ageInDays} days old).`;
    }

    return {
      status: 'SUCCESS',
      ageInDays,
      creationDate: creationDate.toISOString(),
      scorePenalty,
      warning,
      note: `Domain age: ${ageInDays} days`
    };
  } catch (err) {
    clearTimeout(timer);
    return {
      status: 'ERROR',
      ageInDays: null,
      creationDate: null,
      scorePenalty: 0,
      note: `RDAP request failed: ${err.name === 'AbortError' ? 'Timeout' : err.message}`
    };
  }
}
