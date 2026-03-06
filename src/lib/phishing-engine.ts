// Rule-based phishing detection engine

export interface AnalysisRule {
  name: string;
  description: string;
  weight: number;
  triggered: boolean;
}

export type InputType = "url" | "email" | "domain" | "unknown";

export interface AnalysisResult {
  input: string;
  inputType: InputType;
  riskScore: number;
  classification: "Legitimate" | "Suspicious" | "Phishing";
  rules: AnalysisRule[];
  timestamp: Date;
}

export interface PhishingType {
  id: number;
  name: string;
  icon: string;
  description: string;
  example: string;
  prevention: string;
}

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

function hasIPAddress(url: string): boolean {
  const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  return ipPattern.test(url);
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
  const dotCount = (url.match(/\./g) || []).length;
  return dotCount > 4;
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

function detectInputType(input: string): InputType {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (emailPattern.test(input)) return "email";
  if (input.startsWith("http://") || input.startsWith("https://") || input.includes("://")) return "url";
  const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  if (domainPattern.test(input)) return "domain";
  // If it has dots and slashes, treat as URL
  if (input.includes(".") && input.includes("/")) return "url";
  if (input.includes(".")) return "domain";
  return "unknown";
}

// Email-specific checks
const SUSPICIOUS_EMAIL_DOMAINS = [
  "tempmail.com", "throwaway.email", "guerrillamail.com", "mailinator.com",
  "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
];

const LEGITIMATE_EMAIL_PROVIDERS = [
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com",
  "icloud.com", "aol.com", "mail.com", "zoho.com",
];

function emailHasSuspiciousDomain(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase() || "";
  return SUSPICIOUS_EMAIL_DOMAINS.some((d) => domain.includes(d));
}

function emailHasExcessiveDots(email: string): boolean {
  const localPart = email.split("@")[0] || "";
  return (localPart.match(/\./g) || []).length > 3;
}

function emailHasNumbers(email: string): boolean {
  const localPart = email.split("@")[0] || "";
  return (localPart.match(/\d/g) || []).length > 5;
}

function emailHasSuspiciousKeywords(email: string): boolean {
  const lower = email.toLowerCase();
  const keywords = ["admin", "support", "security", "verify", "update", "noreply", "helpdesk", "service", "alert", "urgent"];
  return keywords.some((kw) => lower.includes(kw));
}

function emailIsNotLegitimateProvider(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase() || "";
  return !LEGITIMATE_EMAIL_PROVIDERS.includes(domain);
}

function emailHasMismatchedName(email: string): boolean {
  const localPart = email.split("@")[0]?.toLowerCase() || "";
  // Random-looking local parts (mostly consonants / very short)
  return /^[bcdfghjklmnpqrstvwxyz]{5,}$/.test(localPart) || localPart.length < 3;
}

function domainHasSuspiciousTLD(domain: string): boolean {
  const lower = domain.toLowerCase();
  return SUSPICIOUS_TLDS.some((tld) => lower.endsWith(tld));
}

function domainMimicsLegitimate(domain: string): boolean {
  const lower = domain.toLowerCase();
  const brands = ["google", "facebook", "apple", "microsoft", "amazon", "paypal", "netflix", "instagram", "twitter", "linkedin", "bank"];
  return brands.some((brand) => lower.includes(brand) && !lower.endsWith(brand + ".com"));
}

function analyzeEmail(input: string): AnalysisRule[] {
  return [
    { name: "Disposable Email Domain", description: "Email uses a known temporary/disposable email service", weight: 30, triggered: emailHasSuspiciousDomain(input) },
    { name: "Non-Standard Provider", description: "Email is not from a well-known email provider", weight: 10, triggered: emailIsNotLegitimateProvider(input) },
    { name: "Suspicious Keywords in Email", description: "Email address contains phishing-related keywords like 'admin', 'support', 'verify'", weight: 15, triggered: emailHasSuspiciousKeywords(input) },
    { name: "Excessive Dots in Local Part", description: "Email local part has too many dots, suggesting obfuscation", weight: 10, triggered: emailHasExcessiveDots(input) },
    { name: "Excessive Numbers", description: "Email local part contains many numbers, common in auto-generated phishing addresses", weight: 10, triggered: emailHasNumbers(input) },
    { name: "Suspicious Local Part", description: "Email local part looks random or auto-generated", weight: 15, triggered: emailHasMismatchedName(input) },
    { name: "Suspicious TLD", description: "Email domain uses a TLD commonly associated with phishing", weight: 15, triggered: domainHasSuspiciousTLD(input.split("@")[1] || "") },
    { name: "Brand Impersonation", description: "Email domain appears to mimic a well-known brand", weight: 25, triggered: domainMimicsLegitimate(input.split("@")[1] || "") },
  ];
}

function analyzeDomain(input: string): AnalysisRule[] {
  return [
    { name: "Suspicious TLD", description: "Domain uses a TLD commonly associated with phishing", weight: 20, triggered: domainHasSuspiciousTLD(input) },
    { name: "Brand Impersonation", description: "Domain appears to mimic a well-known brand name", weight: 25, triggered: domainMimicsLegitimate(input) },
    { name: "Excessive Hyphens", description: "Domain contains excessive hyphens to mimic legitimate sites", weight: 15, triggered: hasHyphenBomb("http://" + input) },
    { name: "Subdomain Abuse", description: "Domain has excessive subdomains to confuse users", weight: 15, triggered: hasSubdomainAbuse("http://" + input) },
    { name: "IP Address Detection", description: "Input contains an IP address instead of a domain name", weight: 25, triggered: hasIPAddress(input) },
    { name: "Excessive Dots", description: "Domain has too many dots indicating subdomain manipulation", weight: 10, triggered: hasTooManyDots(input) },
    { name: "Suspicious Keywords", description: "Domain contains phishing-related keywords", weight: 15, triggered: hasSuspiciousKeywords(input) },
  ];
}

function analyzeURLRules(input: string): AnalysisRule[] {
  return [
    { name: "IP Address Detection", description: "URL contains an IP address instead of a domain name", weight: 25, triggered: hasIPAddress(input) },
    { name: "URL Length Check", description: "URL is unusually long (>75 characters)", weight: 15, triggered: hasSuspiciousLength(input) },
    { name: "HTTPS Verification", description: "URL does not use secure HTTPS protocol", weight: 20, triggered: hasNoHTTPS(input) },
    { name: "Suspicious Keywords", description: "URL contains phishing-related keywords", weight: 15, triggered: hasSuspiciousKeywords(input) },
    { name: "@ Symbol Detection", description: "URL contains @ symbol used to obfuscate the real destination", weight: 20, triggered: hasAtSymbol(input) },
    { name: "Excessive Dots", description: "URL has too many dots indicating subdomain manipulation", weight: 10, triggered: hasTooManyDots(input) },
    { name: "Suspicious TLD", description: "URL uses a top-level domain commonly associated with phishing", weight: 15, triggered: hasSuspiciousTLD(input) },
    { name: "Hyphen Abuse", description: "Domain contains excessive hyphens to mimic legitimate sites", weight: 10, triggered: hasHyphenBomb(input) },
    { name: "Subdomain Abuse", description: "URL has excessive subdomains to confuse users", weight: 10, triggered: hasSubdomainAbuse(input) },
    { name: "Encoded Characters", description: "URL contains many encoded characters to hide its true content", weight: 10, triggered: hasEncodedChars(input) },
  ];
}

export function analyzeInput(input: string): AnalysisResult {
  const inputType = detectInputType(input);

  let rules: AnalysisRule[];
  switch (inputType) {
    case "email":
      rules = analyzeEmail(input);
      break;
    case "domain":
      rules = analyzeDomain(input);
      break;
    case "url":
      rules = analyzeURLRules(input);
      break;
    default:
      // For unknown inputs, run URL + domain rules as best effort
      rules = analyzeURLRules(input);
      break;
  }

  const riskScore = Math.min(100, rules.reduce((score, rule) => score + (rule.triggered ? rule.weight : 0), 0));

  let classification: AnalysisResult["classification"];
  if (riskScore <= 20) classification = "Legitimate";
  else if (riskScore <= 50) classification = "Suspicious";
  else classification = "Phishing";

  return { input, inputType, riskScore, classification, rules, timestamp: new Date() };
}

/** @deprecated Use analyzeInput instead */
export function analyzeURL(url: string): AnalysisResult {
  return analyzeInput(url);
}

export const PHISHING_TYPES: PhishingType[] = [
  {
    id: 1,
    name: "Email Phishing",
    icon: "📧",
    description: "Mass emails disguised as trusted organizations, tricking users into clicking malicious links or sharing sensitive data.",
    example: "An email from 'Your Bank' asking you to verify your account by clicking a link.",
    prevention: "Never click links in unexpected emails. Verify sender addresses carefully.",
  },
  {
    id: 2,
    name: "Spear Phishing",
    icon: "🎯",
    description: "Targeted attacks on specific individuals using personal information to appear legitimate and trustworthy.",
    example: "An email mentioning your name and company, pretending to be from your CEO.",
    prevention: "Verify unusual requests through a separate communication channel.",
  },
  {
    id: 3,
    name: "Whaling",
    icon: "🐋",
    description: "Phishing attacks specifically targeting high-profile executives and senior management within organizations.",
    example: "A fake legal subpoena sent to a company's CFO requesting urgent wire transfer.",
    prevention: "Implement multi-person approval for financial transactions.",
  },
  {
    id: 4,
    name: "Smishing (SMS)",
    icon: "📱",
    description: "Phishing attacks delivered through SMS text messages containing malicious links or urgent requests.",
    example: "A text saying 'Your package delivery failed. Click here to reschedule.'",
    prevention: "Never click links in unexpected text messages. Contact the company directly.",
  },
  {
    id: 5,
    name: "Vishing (Voice)",
    icon: "📞",
    description: "Phone-based phishing where attackers impersonate authorities to extract personal or financial information.",
    example: "A call claiming to be from the IRS demanding immediate payment to avoid arrest.",
    prevention: "Hang up and call the organization back using their official number.",
  },
];
