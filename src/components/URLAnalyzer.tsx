import { useState, useEffect, useRef } from "react";
import { Shield, Search, AlertTriangle, CheckCircle, XCircle, BarChart3 } from "lucide-react";
import { analyzeURL, detectThreatType, THREAT_TYPE_LABELS, type AnalysisResult } from "@/lib/phishing-engine";
import ThreatBarChart from "@/components/ThreatBarChart";

const URLAnalyzer = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [livePreview, setLivePreview] = useState<AnalysisResult | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Live preview as user types
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (!url.trim() || url.trim().length < 3) {
      setLivePreview(null);
      return;
    }
    debounceRef.current = setTimeout(() => {
      setLivePreview(analyzeURL(url.trim()));
    }, 300);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [url]);

  const handleAnalyze = () => {
    if (!url.trim()) return;
    setIsAnalyzing(true);
    setResult(null);
    setLivePreview(null);
    setTimeout(() => {
      setResult(analyzeURL(url.trim()));
      setIsAnalyzing(false);
    }, 1200);
  };

  const getClassColor = (classification: AnalysisResult["classification"]) => {
    switch (classification) {
      case "Legitimate": return "text-safe";
      case "Suspicious": return "text-warning";
      case "Phishing": return "text-danger";
    }
  };

  const getGlowClass = (classification: AnalysisResult["classification"]) => {
    switch (classification) {
      case "Legitimate": return "glow-green border-safe/30";
      case "Suspicious": return "glow-amber border-warning/30";
      case "Phishing": return "glow-red border-danger/30";
    }
  };

  const getRiskBarColor = (score: number) => {
    if (score <= 20) return "bg-safe";
    if (score <= 50) return "bg-warning";
    return "bg-danger";
  };

  const detectedType = url.trim() ? detectThreatType(url.trim()) : null;

  return (
    <section className="w-full max-w-3xl mx-auto">
      {/* Input area */}
      <div className="bg-card border border-border rounded-lg p-6 glow-green">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-primary" />
          <h2 className="font-mono text-sm text-primary tracking-wider uppercase">Universal Threat Scanner</h2>
        </div>
        <div className="flex gap-3">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
            placeholder="Enter URL, email, domain, or SMS message to analyze..."
            className="flex-1 bg-muted border border-border rounded-md px-4 py-3 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
          />
          <button
            onClick={handleAnalyze}
            disabled={!url.trim() || isAnalyzing}
            className="bg-primary text-primary-foreground px-6 py-3 rounded-md font-mono text-sm font-semibold hover:opacity-90 transition-opacity disabled:opacity-40 flex items-center gap-2"
          >
            <Search className="w-4 h-4" />
            {isAnalyzing ? "Scanning..." : "Analyze"}
          </button>
        </div>
        {detectedType && !isAnalyzing && !result && (
          <p className="mt-2 font-mono text-xs text-muted-foreground">
            Auto-detected type: <span className="text-primary font-semibold">{THREAT_TYPE_LABELS[detectedType]}</span>
          </p>
        )}

        {/* Live preview as user types */}
        {livePreview && !isAnalyzing && !result && (
          <div className="mt-3 bg-muted/50 border border-border rounded-md p-3 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {livePreview.classification === "Legitimate" && <CheckCircle className="w-4 h-4 text-safe" />}
                {livePreview.classification === "Suspicious" && <AlertTriangle className="w-4 h-4 text-warning" />}
                {livePreview.classification === "Phishing" && <XCircle className="w-4 h-4 text-danger" />}
                <span className={`font-mono text-sm font-bold ${getClassColor(livePreview.classification)}`}>
                  {livePreview.classification}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  — {THREAT_TYPE_LABELS[livePreview.threatType]}
                </span>
              </div>
              <span className={`font-mono text-sm font-bold ${getClassColor(livePreview.classification)}`}>
                {livePreview.riskScore}%
              </span>
            </div>
            <div className="w-full bg-muted rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full transition-all duration-500 ${getRiskBarColor(livePreview.riskScore)}`}
                style={{ width: `${livePreview.riskScore}%` }}
              />
            </div>
            {livePreview.rules.filter(r => r.triggered).length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {livePreview.rules.filter(r => r.triggered).map((rule, i) => (
                  <span key={i} className="inline-flex items-center gap-1 bg-danger/10 text-danger font-mono text-[10px] px-2 py-0.5 rounded border border-danger/20">
                    <XCircle className="w-2.5 h-2.5" /> {rule.name}
                  </span>
                ))}
              </div>
            )}
            <p className="font-mono text-[10px] text-muted-foreground">Press Enter or click Analyze for full report</p>
          </div>
        )}
      </div>

      {/* Scanning animation */}
      {isAnalyzing && (
        <div className="mt-6 bg-card border border-primary/20 rounded-lg p-8 overflow-hidden relative">
          <div className="absolute inset-0 scanline opacity-50" />
          <div className="absolute inset-0 bg-primary/5 animate-scan" />
          <p className="text-center font-mono text-primary animate-pulse-glow text-sm">
            ⟫ Analyzing against {THREAT_TYPE_LABELS[detectThreatType(url.trim())]} rules...
          </p>
        </div>
      )}

      {/* Results */}
      {result && !isAnalyzing && (
        <div className={`mt-6 bg-card border rounded-lg p-6 ${getGlowClass(result.classification)}`}>
          {/* Threat type badge */}
          <div className="mb-4">
            <span className="inline-block bg-primary/10 text-primary font-mono text-xs px-3 py-1 rounded-full border border-primary/20">
              {THREAT_TYPE_LABELS[result.threatType]}
            </span>
          </div>

          {/* Classification header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              {result.classification === "Legitimate" && <CheckCircle className="w-8 h-8 text-safe" />}
              {result.classification === "Suspicious" && <AlertTriangle className="w-8 h-8 text-warning" />}
              {result.classification === "Phishing" && <XCircle className="w-8 h-8 text-danger" />}
              <div>
                <h3 className={`text-2xl font-bold font-mono ${getClassColor(result.classification)}`}>
                  {result.classification}
                </h3>
                <p className="text-xs text-muted-foreground font-mono">
                  Scanned at {result.timestamp.toLocaleTimeString()}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className={`text-3xl font-bold font-mono ${getClassColor(result.classification)}`}>
                {result.riskScore}%
              </p>
              <p className="text-xs text-muted-foreground font-mono">Risk Score</p>
            </div>
          </div>

          {/* Risk bar */}
          <div className="w-full bg-muted rounded-full h-2 mb-6">
            <div
              className={`h-2 rounded-full transition-all duration-700 ${getRiskBarColor(result.riskScore)}`}
              style={{ width: `${result.riskScore}%` }}
            />
          </div>

          {/* Analyzed input */}
          <div className="bg-muted rounded-md p-3 mb-6">
            <p className="text-xs text-muted-foreground font-mono mb-1">Analyzed Input:</p>
            <p className="font-mono text-sm text-foreground break-all">{result.url}</p>
          </div>

          {/* Rules */}
          <h4 className="font-mono text-xs text-primary uppercase tracking-wider mb-3">
            Security Rules ({result.rules.filter(r => r.triggered).length}/{result.rules.length} triggered)
          </h4>
          <div className="space-y-2">
            {result.rules.map((rule, i) => (
              <div
                key={i}
                className={`flex items-start gap-3 p-3 rounded-md border ${
                  rule.triggered
                    ? "border-danger/20 bg-danger/5"
                    : "border-border bg-muted/30"
                }`}
              >
                <span className="mt-0.5">
                  {rule.triggered ? (
                    <XCircle className="w-4 h-4 text-danger" />
                  ) : (
                    <CheckCircle className="w-4 h-4 text-safe" />
                  )}
                </span>
                <div className="flex-1">
                  <p className={`text-sm font-semibold ${rule.triggered ? "text-danger" : "text-safe"}`}>
                    {rule.name}
                    <span className="ml-2 text-xs text-muted-foreground font-normal">
                      (weight: {rule.weight})
                    </span>
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5">{rule.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
};

export default URLAnalyzer;
