// Rule-based phishing detection engine

export interface AnalysisRule {
  name: string;
  description: string;
  weight: number;
  triggered: boolean;
}

export interface AnalysisResult {
  url: string;
  riskScore: number;
  classification: "Legitimate" | "Suspicious" | "Phishing";
  rules: AnalysisRule[];
  timestamp: Date;
  threatType: ThreatType;
}

export type ThreatType = "url" | "email" | "domain" | "clone" | "sms";

export interface PhishingType {
  id: number;
  name: string;
  icon: string;
  description: string;
  example: string;
  prevention: string;
  threatType: ThreatType;
  placeholder: string;
}

// --- Detection helpers ---

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "update", "secure", "account", "banking",
  "confirm", "password", "suspend", "urgent", "alert", "click",
  "free", "winner", "prize", "gift", "offer", "limited",
  "paypal", "signin", "security", "wallet", "crypto",
];

const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
  ".work", ".buzz", ".cam",
];

const DISPOSABLE_EMAIL_DOMAINS = [
  "tempmail.com", "guerrillamail.com", "throwaway.email", "mailinator.com",
  "yopmail.com", "sharklasers.com", "trashmail.com", "10minutemail.com",
  "fakeinbox.com", "dispostable.com", "getnada.com",
];

const LEGITIMATE_DOMAINS = [
  "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
  "twitter.com", "linkedin.com", "github.com", "netflix.com", "paypal.com",
  "youtube.com", "instagram.com", "whatsapp.com", "wikipedia.org",
];

function hasIPAddress(url: string): boolean {
  return /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(url);
}

function hasSuspiciousLength(url: string): boolean {
  return url.length > 75;
}

function hasNoHTTPS(url: string): boolean {
  const lower = url.toLowerCase();
  if (!lower.startsWith("http://") && !lower.startsWith("https://")) return true;
  return lower.startsWith("http://");
}

function hasSuspiciousKeywords(url: string): boolean {
  const lower = url.toLowerCase();
  return SUSPICIOUS_KEYWORDS.some((kw) => lower.includes(kw));
}

function hasAtSymbol(url: string): boolean {
  return url.includes("@");
}

function hasTooManyDots(url: string): boolean {
  return (url.match(/\./g) || []).length > 4;
}

function hasSuspiciousTLD(url: string): boolean {
  const lower = url.toLowerCase();
  return SUSPICIOUS_TLDS.some((tld) => lower.includes(tld));
}

function hasHyphenBomb(url: string): boolean {
  try {
    const hostname = new URL(url.startsWith("http") ? url : `http://${url}`).hostname;
    return (hostname.match(/-/g) || []).length > 3;
  } catch {
    return false;
  }
}

function hasSubdomainAbuse(url: string): boolean {
  try {
    const hostname = new URL(url.startsWith("http") ? url : `http://${url}`).hostname;
    return hostname.split(".").length > 4;
  } catch {
    return false;
  }
}

function hasEncodedChars(url: string): boolean {
  return /%[0-9a-fA-F]{2}/.test(url) && (url.match(/%/g) || []).length > 2;
}

// --- Input type detection ---

const SMS_KEYWORDS = [
  "urgent", "immediately", "now", "asap", "expires", "limited time", "act fast", "hurry",
  "won", "winner", "prize", "free", "gift", "cash", "money", "bank", "credit", "debit",
  "refund", "payment", "ssn", "social security", "pin", "otp", "code", "verify your",
  "confirm your", "click here", "claim", "congratulations", "selected", "lucky",
  "bit.ly", "tinyurl", "goo.gl", "shorturl", "suspended", "blocked", "unusual activity",
  "text message", "sms", "txt",
];

const CLONE_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "confirm", "account", "password", "auth",
];

export function detectThreatType(input: string): ThreatType {
  const trimmed = input.trim().toLowerCase();

  // Email: contains @ with domain-like structure
  if (/[^\s@]+@[^\s@]+\.[^\s@]+/.test(trimmed)) return "email";

  // SMS: phone patterns, or multi-word messages with urgency/financial keywords
  if (/^(\+?\d[\d\s\-()]{7,})/.test(trimmed)) return "sms";
  const hasSpaces = trimmed.includes(" ");
  const smsKeywordCount = SMS_KEYWORDS.filter(kw => trimmed.includes(kw)).length;
  if (hasSpaces && smsKeywordCount >= 1) return "sms";

  // Clone website: URL-like with login/credential harvesting paths
  const isURLLike = /^https?:\/\//.test(trimmed) || /\//.test(trimmed);
  if (isURLLike) {
    const cloneKeywordCount = CLONE_KEYWORDS.filter(kw => trimmed.includes(kw)).length;
    const hasBrandMimic = LEGITIMATE_DOMAINS.some(ld => {
      const base = ld.split(".")[0];
      return trimmed.includes(base) && !trimmed.includes(ld);
    });
    const hasIP = hasIPAddress(trimmed);
    if ((cloneKeywordCount >= 1 && hasBrandMimic) || (hasIP && cloneKeywordCount >= 1) || (hasBrandMimic && hasIP)) {
      return "clone";
    }
    return "url";
  }

  // Domain: plain domain-like string
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$/.test(trimmed)) return "domain";

  // Multi-word without URL structure → likely SMS
  if (hasSpaces) return "sms";

  return "url";
}

// --- Type-specific analysis ---

function analyzeEmail(email: string): AnalysisRule[] {
  const lower = email.toLowerCase();
  const domain = lower.split("@")[1] || "";
  return [
    { name: "Disposable Email Provider", description: "Email uses a known disposable/temporary email service", weight: 30, triggered: DISPOSABLE_EMAIL_DOMAINS.some(d => domain.includes(d)) },
    { name: "Suspicious Keywords in Address", description: "Email address contains phishing-related keywords", weight: 15, triggered: SUSPICIOUS_KEYWORDS.some(kw => lower.includes(kw)) },
    { name: "Suspicious TLD", description: "Email domain uses a TLD commonly associated with phishing", weight: 15, triggered: SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld)) },
    { name: "Numeric Domain", description: "Email domain contains excessive numbers suggesting auto-generated domain", weight: 20, triggered: /\d{4,}/.test(domain) },
    { name: "Brand Impersonation", description: "Email domain mimics a well-known brand with slight misspelling", weight: 25, triggered: LEGITIMATE_DOMAINS.some(ld => { const base = ld.split(".")[0]; return domain.includes(base) && domain !== ld; }) },
    { name: "Hyphenated Domain", description: "Email domain uses excessive hyphens to appear legitimate", weight: 10, triggered: (domain.match(/-/g) || []).length > 2 },
    { name: "Long Local Part", description: "Local part of email is unusually long suggesting auto-generation", weight: 10, triggered: (lower.split("@")[0] || "").length > 30 },
  ];
}

function analyzeDomain(domain: string): AnalysisRule[] {
  const lower = domain.toLowerCase();
  return [
    { name: "Suspicious TLD", description: "Domain uses a TLD commonly associated with phishing", weight: 20, triggered: SUSPICIOUS_TLDS.some(tld => lower.endsWith(tld)) },
    { name: "Brand Impersonation", description: "Domain mimics a well-known brand name with slight variations", weight: 30, triggered: LEGITIMATE_DOMAINS.some(ld => { const base = ld.split(".")[0]; return lower.includes(base) && lower !== ld; }) },
    { name: "Excessive Hyphens", description: "Domain uses many hyphens to mimic legitimate sites", weight: 15, triggered: (lower.match(/-/g) || []).length > 2 },
    { name: "Excessive Length", description: "Domain is unusually long suggesting obfuscation", weight: 10, triggered: lower.length > 40 },
    { name: "Subdomain Abuse", description: "Domain has too many subdomains to confuse users", weight: 15, triggered: lower.split(".").length > 4 },
    { name: "Numeric Domain", description: "Domain contains many numbers suggesting auto-generation", weight: 15, triggered: /\d{4,}/.test(lower) },
    { name: "Homograph Detection", description: "Domain uses character substitution (e.g., 0 for o, 1 for l)", weight: 20, triggered: /[0-9]/.test(lower.split(".")[0]) && LEGITIMATE_DOMAINS.some(ld => lower.split(".")[0].replace(/0/g, "o").replace(/1/g, "l").includes(ld.split(".")[0])) },
  ];
}

function analyzeCloneWebsite(url: string): AnalysisRule[] {
  const lower = url.toLowerCase();
  return [
    { name: "Brand Impersonation", description: "URL mimics a well-known website with slight variations", weight: 25, triggered: LEGITIMATE_DOMAINS.some(ld => { const base = ld.split(".")[0]; return lower.includes(base) && !lower.includes(ld); }) },
    { name: "No HTTPS", description: "Clone website doesn't use HTTPS encryption", weight: 20, triggered: hasNoHTTPS(url) },
    { name: "IP Address Usage", description: "Website hosted on raw IP instead of domain name", weight: 25, triggered: hasIPAddress(url) },
    { name: "Login/Verify Keywords", description: "URL contains login or verification keywords suggesting credential harvesting", weight: 15, triggered: /\b(login|signin|verify|confirm|account)\b/.test(lower) },
    { name: "Suspicious Path", description: "URL has deep or suspicious path structure mimicking real sites", weight: 10, triggered: (url.match(/\//g) || []).length > 5 },
    { name: "Suspicious TLD", description: "Clone website uses a TLD commonly associated with phishing", weight: 15, triggered: hasSuspiciousTLD(url) },
    { name: "Encoded Characters", description: "URL uses encoding to hide its true destination", weight: 10, triggered: hasEncodedChars(url) },
  ];
}

function analyzeSMS(message: string): AnalysisRule[] {
  const lower = message.toLowerCase();
  return [
    { name: "Urgency Language", description: "Message uses urgent language to pressure immediate action", weight: 20, triggered: /\b(urgent|immediately|now|asap|expires|limited time|act fast|hurry)\b/.test(lower) },
    { name: "Suspicious Link", description: "Message contains a shortened or suspicious URL", weight: 25, triggered: /\b(bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|is\.gd|shorturl)\b/.test(lower) || /https?:\/\/\S+/.test(lower) },
    { name: "Financial Keywords", description: "Message references money, prizes, or financial incentives", weight: 20, triggered: /\b(won|winner|prize|free|gift|cash|money|bank|credit|debit|refund|payment)\b/.test(lower) },
    { name: "Personal Info Request", description: "Message asks for personal or sensitive information", weight: 25, triggered: /\b(ssn|social security|password|pin|otp|code|verify|confirm your)\b/.test(lower) },
    { name: "Brand Impersonation", description: "Message pretends to be from a known brand or service", weight: 15, triggered: LEGITIMATE_DOMAINS.some(ld => lower.includes(ld.split(".")[0])) },
    { name: "Phone Number Presence", description: "Message includes callback phone number for vishing", weight: 10, triggered: /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(message) },
    { name: "Suspicious Sender", description: "Message appears to be from a non-standard number or source", weight: 10, triggered: /^(\+?\d{1,4})/.test(message.trim()) },
  ];
}

function analyzeURLRules(url: string): AnalysisRule[] {
  return [
    { name: "IP Address Detection", description: "URL contains an IP address instead of a domain name", weight: 25, triggered: hasIPAddress(url) },
    { name: "URL Length Check", description: "URL is unusually long (>75 characters)", weight: 15, triggered: hasSuspiciousLength(url) },
    { name: "HTTPS Verification", description: "URL does not use secure HTTPS protocol", weight: 20, triggered: hasNoHTTPS(url) },
    { name: "Suspicious Keywords", description: "URL contains phishing-related keywords", weight: 15, triggered: hasSuspiciousKeywords(url) },
    { name: "@ Symbol Detection", description: "URL contains @ symbol used to obfuscate the real destination", weight: 20, triggered: hasAtSymbol(url) },
    { name: "Excessive Dots", description: "URL has too many dots indicating subdomain manipulation", weight: 10, triggered: hasTooManyDots(url) },
    { name: "Suspicious TLD", description: "URL uses a top-level domain commonly associated with phishing", weight: 15, triggered: hasSuspiciousTLD(url) },
    { name: "Hyphen Abuse", description: "Domain contains excessive hyphens to mimic legitimate sites", weight: 10, triggered: hasHyphenBomb(url) },
    { name: "Subdomain Abuse", description: "URL has excessive subdomains to confuse users", weight: 10, triggered: hasSubdomainAbuse(url) },
    { name: "Encoded Characters", description: "URL contains many encoded characters to hide its true content", weight: 10, triggered: hasEncodedChars(url) },
  ];
}

export function analyzeByType(input: string, threatType: ThreatType): AnalysisResult {
  let rules: AnalysisRule[];
  switch (threatType) {
    case "email": rules = analyzeEmail(input); break;
    case "domain": rules = analyzeDomain(input); break;
    case "clone": rules = analyzeCloneWebsite(input); break;
    case "sms": rules = analyzeSMS(input); break;
    default: rules = analyzeURLRules(input); break;
  }

  const riskScore = Math.min(100, rules.reduce((s, r) => s + (r.triggered ? r.weight : 0), 0));
  let classification: AnalysisResult["classification"];
  if (riskScore <= 20) classification = "Legitimate";
  else if (riskScore <= 50) classification = "Suspicious";
  else classification = "Phishing";

  return { url: input, riskScore, classification, rules, timestamp: new Date(), threatType };
}

export function analyzeURL(input: string): AnalysisResult {
  const threatType = detectThreatType(input);
  return analyzeByType(input, threatType);
}

export const THREAT_TYPE_LABELS: Record<ThreatType, string> = {
  url: "URL Phishing",
  email: "Email Phishing",
  domain: "Domain Spoofing",
  clone: "Clone Website Phishing",
  sms: "SMS Phishing",
};

export const PHISHING_TYPES: PhishingType[] = [
  {
    id: 1,
    name: "URL Phishing",
    icon: "🔗",
    threatType: "url",
    description: "Malicious URLs designed to trick users into visiting fake websites that steal credentials or install malware.",
    example: "http://g00gle-secure.tk/login/verify-account",
    placeholder: "e.g., http://paypa1-secure.tk/login",
    prevention: "Always check the URL carefully before clicking. Look for misspellings and suspicious TLDs.",
  },
  {
    id: 2,
    name: "Email Phishing",
    icon: "📧",
    threatType: "email",
    description: "Fraudulent emails from fake addresses designed to appear as trusted organizations to steal sensitive data.",
    example: "support@paypa1-secure.xyz",
    placeholder: "e.g., admin@g00gle-security.tk",
    prevention: "Verify sender addresses carefully. Never click links in unexpected emails.",
  },
  {
    id: 3,
    name: "Domain Spoofing",
    icon: "🌐",
    threatType: "domain",
    description: "Fake domains that mimic legitimate websites using similar-looking characters or misspellings to deceive users.",
    example: "amaz0n-support.xyz",
    placeholder: "e.g., faceb00k-login.tk",
    prevention: "Always type URLs directly. Check for character substitutions like 0 for o.",
  },
  {
    id: 4,
    name: "Clone Website Phishing",
    icon: "📋",
    threatType: "clone",
    description: "Exact replicas of legitimate websites hosted on different domains to harvest user credentials and data.",
    example: "http://192.168.1.1/netflix/login/verify",
    placeholder: "e.g., http://faceb00k.tk/login/signin",
    prevention: "Check the domain matches the official site. Look for HTTPS and valid certificates.",
  },
  {
    id: 5,
    name: "SMS Phishing (Smishing)",
    icon: "📱",
    threatType: "sms",
    description: "Phishing attacks via SMS text messages containing malicious links, urgency language, or fake prize claims.",
    example: "URGENT: Your bank account is suspended! Verify now at bit.ly/xyz123",
    placeholder: "e.g., You won a $500 gift card! Claim now: bit.ly/free",
    prevention: "Never click links in unexpected texts. Contact the company directly through official channels.",
  },
];
