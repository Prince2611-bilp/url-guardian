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

export function analyzeURL(url: string): AnalysisResult {
  const rules: AnalysisRule[] = [
    {
      name: "IP Address Detection",
      description: "URL contains an IP address instead of a domain name",
      weight: 25,
      triggered: hasIPAddress(url),
    },
    {
      name: "URL Length Check",
      description: "URL is unusually long (>75 characters)",
      weight: 15,
      triggered: hasSuspiciousLength(url),
    },
    {
      name: "HTTPS Verification",
      description: "URL does not use secure HTTPS protocol",
      weight: 20,
      triggered: hasNoHTTPS(url),
    },
    {
      name: "Suspicious Keywords",
      description: "URL contains phishing-related keywords",
      weight: 15,
      triggered: hasSuspiciousKeywords(url),
    },
    {
      name: "@ Symbol Detection",
      description: "URL contains @ symbol used to obfuscate the real destination",
      weight: 20,
      triggered: hasAtSymbol(url),
    },
    {
      name: "Excessive Dots",
      description: "URL has too many dots indicating subdomain manipulation",
      weight: 10,
      triggered: hasTooManyDots(url),
    },
    {
      name: "Suspicious TLD",
      description: "URL uses a top-level domain commonly associated with phishing",
      weight: 15,
      triggered: hasSuspiciousTLD(url),
    },
    {
      name: "Hyphen Abuse",
      description: "Domain contains excessive hyphens to mimic legitimate sites",
      weight: 10,
      triggered: hasHyphenBomb(url),
    },
    {
      name: "Subdomain Abuse",
      description: "URL has excessive subdomains to confuse users",
      weight: 10,
      triggered: hasSubdomainAbuse(url),
    },
    {
      name: "Encoded Characters",
      description: "URL contains many encoded characters to hide its true content",
      weight: 10,
      triggered: hasEncodedChars(url),
    },
  ];

  const riskScore = Math.min(
    100,
    rules.reduce((score, rule) => score + (rule.triggered ? rule.weight : 0), 0)
  );

  let classification: AnalysisResult["classification"];
  if (riskScore <= 20) classification = "Legitimate";
  else if (riskScore <= 50) classification = "Suspicious";
  else classification = "Phishing";

  return { url, riskScore, classification, rules, timestamp: new Date() };
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
