import { FileDown } from "lucide-react";

const generateReport = (): string => {
  const now = new Date();
  return `
================================================================================
                        PHISHGUARD — PROJECT REPORT
================================================================================

Generated: ${now.toLocaleDateString()} at ${now.toLocaleTimeString()}

--------------------------------------------------------------------------------
1. PROJECT OVERVIEW
--------------------------------------------------------------------------------

Project Name  : PhishGuard
Version       : 1.0
Type          : Rule-Based Phishing Detection Tool
Category      : Cybersecurity / Student Project
Platform      : Web Application (React + TypeScript)

PhishGuard is a client-side phishing detection tool that analyzes URLs, email
addresses, domains, SMS messages, and clone websites against a comprehensive
set of security rules. It classifies inputs as Legitimate, Suspicious, or
Phishing based on a weighted risk scoring system.

--------------------------------------------------------------------------------
2. TECHNOLOGY STACK
--------------------------------------------------------------------------------

Frontend Framework  : React 18 with TypeScript
Build Tool          : Vite
Styling             : Tailwind CSS with custom design tokens
UI Components       : shadcn/ui (Radix UI primitives)
Icons               : Lucide React
Font                : JetBrains Mono, Space Grotesk

--------------------------------------------------------------------------------
3. THREAT DETECTION CAPABILITIES
--------------------------------------------------------------------------------

PhishGuard detects 5 types of phishing threats:

  3.1 URL Phishing
      - Detects suspicious URLs with IP addresses, excessive subdomains,
        misleading characters, and known malicious TLDs.
      - Rules: IP-based URL, suspicious TLD (.tk, .ml, .xyz, etc.),
        URL length analysis, HTTPS check, homograph detection.

  3.2 Email Phishing
      - Identifies phishing emails by analyzing sender domains,
        display name mismatches, and suspicious patterns.
      - Rules: Free email provider check, domain typosquatting,
        numeric sender patterns, suspicious TLD usage.

  3.3 Domain Spoofing
      - Detects domains that mimic legitimate brands using typosquatting,
        character substitution, and misleading subdomains.
      - Rules: Brand impersonation, homograph attacks, excessive hyphens,
        recently-registered TLD patterns.

  3.4 Clone Websites
      - Identifies cloned/fake versions of legitimate websites.
      - Rules: Login page on suspicious domain, brand keyword + bad TLD,
        IP-hosted login pages, credential harvesting indicators.

  3.5 SMS Phishing (Smishing)
      - Analyzes SMS messages for urgency tactics, suspicious links,
        and social engineering patterns.
      - Rules: URL shortener detection, urgency keywords, financial
        lure patterns, too-good-to-be-true offers.

--------------------------------------------------------------------------------
4. RISK SCORING ALGORITHM
--------------------------------------------------------------------------------

The engine uses a weighted rule-based scoring system:

  - Each rule has a weight (points) assigned based on severity.
  - Triggered rules accumulate points toward a total risk score.
  - The maximum score is capped at 100%.

Classification Thresholds:
  - Legitimate  : Risk Score ≤ 20%
  - Suspicious  : Risk Score 21% – 50%
  - Phishing    : Risk Score > 50%

--------------------------------------------------------------------------------
5. KEY FEATURES
--------------------------------------------------------------------------------

  ✓ Universal input scanner (URL, email, domain, SMS, clone)
  ✓ Auto-detection of input/threat type
  ✓ Real-time live preview while typing
  ✓ Detailed rule-by-rule analysis report
  ✓ Visual risk score bar with color coding
  ✓ Per-category phishing type cards with example inputs
  ✓ Fully client-side — no data sent to any server
  ✓ Dark terminal-style UI theme

--------------------------------------------------------------------------------
6. ARCHITECTURE
--------------------------------------------------------------------------------

  src/
  ├── main.tsx                    # Entry point
  ├── App.tsx                     # Router & providers
  ├── index.css                   # Design tokens & global styles
  ├── pages/
  │   └── Index.tsx               # Main page layout
  ├── components/
  │   ├── URLAnalyzer.tsx         # Search bar & results display
  │   ├── PhishingTypes.tsx       # 5 phishing category cards
  │   └── ProjectReport.tsx       # Report generator (this file)
  └── lib/
      └── phishing-engine.ts      # Detection rules & scoring engine

--------------------------------------------------------------------------------
7. SECURITY RULES SUMMARY
--------------------------------------------------------------------------------

Total Rules per Category:
  - URL Phishing     : 8 rules
  - Email Phishing   : 6 rules
  - Domain Spoofing  : 7 rules
  - Clone Website    : 6 rules
  - SMS Phishing     : 7 rules

Rule examples:
  • IP Address in URL          (weight: 25)
  • Suspicious TLD             (weight: 20)
  • Homograph Characters       (weight: 30)
  • Brand Impersonation        (weight: 35)
  • URL Shortener in SMS       (weight: 20)
  • Urgency Keywords           (weight: 15)

--------------------------------------------------------------------------------
8. LIMITATIONS & FUTURE SCOPE
--------------------------------------------------------------------------------

Current Limitations:
  - Rule-based only (no machine learning)
  - Cannot verify actual website content or certificates
  - No real-time threat intelligence feed
  - Client-side only — no persistent scan history

Future Enhancements:
  - ML-based classification model integration
  - Browser extension for real-time protection
  - API integration with threat intelligence databases
  - Scan history with analytics dashboard
  - PDF report export with visual charts

--------------------------------------------------------------------------------
9. CONCLUSION
--------------------------------------------------------------------------------

PhishGuard demonstrates a practical, rule-based approach to phishing detection
across multiple attack vectors. It provides instant, client-side analysis with
clear visual feedback, making it an effective educational and utility tool for
cybersecurity awareness.

================================================================================
                          END OF REPORT — PhishGuard v1.0
================================================================================
`.trim();
};

const ProjectReport = () => {
  const handleDownload = () => {
    const report = generateReport();
    const blob = new Blob([report], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `PhishGuard_Project_Report_${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="w-full max-w-3xl mx-auto mt-10">
      <div className="bg-card border border-border rounded-lg p-6 flex items-center justify-between">
        <div>
          <h3 className="font-mono text-sm font-bold text-foreground">Project Report</h3>
          <p className="font-mono text-xs text-muted-foreground mt-1">
            Download a complete project report with architecture, rules & analysis details.
          </p>
        </div>
        <button
          onClick={handleDownload}
          className="bg-primary text-primary-foreground px-5 py-2.5 rounded-md font-mono text-sm font-semibold hover:opacity-90 transition-opacity flex items-center gap-2 shrink-0"
        >
          <FileDown className="w-4 h-4" />
          Download Report
        </button>
      </div>
    </div>
  );
};

export default ProjectReport;
