import { Shield, Terminal } from "lucide-react";
import URLAnalyzer from "@/components/URLAnalyzer";
import PhishingTypes from "@/components/PhishingTypes";

const Index = () => {
  return (
    <div className="min-h-screen bg-background scanline">
      <div className="min-h-screen relative">
        {/* Header */}
        <header className="border-b border-border py-6">
          <div className="container max-w-3xl mx-auto px-4 flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="font-mono text-lg font-bold text-foreground tracking-tight">
                PhishGuard
              </h1>
              <p className="font-mono text-xs text-muted-foreground">
                Rule-Based Phishing Detection Tool
              </p>
            </div>
            <div className="ml-auto flex items-center gap-2 text-primary/60">
              <Terminal className="w-4 h-4" />
              <span className="font-mono text-xs">v1.0</span>
            </div>
          </div>
        </header>

        {/* Main content */}
        <main className="container px-4 py-10">
          {/* Hero */}
          <div className="max-w-3xl mx-auto text-center mb-10">
            <p className="font-mono text-xs text-primary mb-2 tracking-widest uppercase">
              Cybersecurity Project
            </p>
            <h2 className="text-2xl sm:text-3xl font-bold text-foreground mb-3 font-mono">
              Detect Phishing Threats Instantly
            </h2>
            <p className="text-sm text-muted-foreground max-w-lg mx-auto">
              Paste any URL, email address, or domain below to analyze it against
              security rules. The tool calculates a risk score and classifies the
              input as Legitimate, Suspicious, or Phishing.
            </p>
          </div>

          <URLAnalyzer />
          <PhishingTypes />

          {/* Footer */}
          <footer className="max-w-3xl mx-auto mt-16 pt-6 border-t border-border text-center">
            <p className="font-mono text-xs text-muted-foreground">
              Built as a student cybersecurity project • Rule-based analysis • No data is sent to any server
            </p>
          </footer>
        </main>
      </div>
    </div>
  );
};

export default Index;
