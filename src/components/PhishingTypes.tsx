import { useState } from "react";
import { Search, CheckCircle, AlertTriangle, XCircle, PieChart as PieChartIcon } from "lucide-react";
import { PHISHING_TYPES, analyzeByType, THREAT_TYPE_LABELS, type AnalysisResult } from "@/lib/phishing-engine";
import SubtypePieChart from "@/components/SubtypePieChart";

const PhishingTypes = () => {
  const [inputs, setInputs] = useState<Record<number, string>>({});
  const [results, setResults] = useState<Record<number, AnalysisResult>>({});
  const [analyzing, setAnalyzing] = useState<Record<number, boolean>>({});
  const [showPie, setShowPie] = useState<Record<number, boolean>>({});

  const handleAnalyze = (type: typeof PHISHING_TYPES[0]) => {
    const input = inputs[type.id]?.trim();
    if (!input) return;
    setAnalyzing(prev => ({ ...prev, [type.id]: true }));
    setResults(prev => { const n = { ...prev }; delete n[type.id]; return n; });
    setTimeout(() => {
      setResults(prev => ({ ...prev, [type.id]: analyzeByType(input, type.threatType) }));
      setAnalyzing(prev => ({ ...prev, [type.id]: false }));
    }, 800);
  };

  const getClassColor = (c: AnalysisResult["classification"]) => {
    if (c === "Legitimate") return "text-safe";
    if (c === "Suspicious") return "text-warning";
    return "text-danger";
  };

  const getIcon = (c: AnalysisResult["classification"]) => {
    if (c === "Legitimate") return <CheckCircle className="w-4 h-4 text-safe" />;
    if (c === "Suspicious") return <AlertTriangle className="w-4 h-4 text-warning" />;
    return <XCircle className="w-4 h-4 text-danger" />;
  };

  return (
    <section className="w-full max-w-3xl mx-auto mt-12">
      <div className="flex items-center gap-2 mb-6">
        <span className="text-xl">🛡️</span>
        <h2 className="font-mono text-sm text-primary tracking-wider uppercase">
          5 Types of Phishing Attacks — Test Each One
        </h2>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {PHISHING_TYPES.map((type) => {
          const result = results[type.id];
          const isAnalyzing = analyzing[type.id];
          return (
            <div
              key={type.id}
              className="bg-card border border-border rounded-lg p-5 hover:border-primary/30 transition-colors group flex flex-col"
            >
              <div className="text-3xl mb-3">{type.icon}</div>
              <h3 className="font-mono text-sm font-bold text-foreground mb-2 group-hover:text-primary transition-colors">
                {type.name}
              </h3>
              <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                {type.description}
              </p>
              <div className="bg-muted rounded-md p-2.5 mb-2">
                <p className="text-xs text-muted-foreground">
                  <span className="text-warning font-semibold">Example: </span>
                  {type.example}
                </p>
              </div>
              <p className="text-xs text-safe mb-3">
                <span className="font-semibold">Prevention: </span>
                {type.prevention}
              </p>

              {/* Per-type input */}
              <div className="mt-auto pt-3 border-t border-border">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={inputs[type.id] || ""}
                    onChange={(e) => setInputs(prev => ({ ...prev, [type.id]: e.target.value }))}
                    onKeyDown={(e) => e.key === "Enter" && handleAnalyze(type)}
                    placeholder={type.placeholder}
                    className="flex-1 bg-muted border border-border rounded-md px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50 min-w-0"
                  />
                  <button
                    onClick={() => handleAnalyze(type)}
                    disabled={!inputs[type.id]?.trim() || isAnalyzing}
                    className="bg-primary text-primary-foreground p-2 rounded-md hover:opacity-90 transition-opacity disabled:opacity-40"
                  >
                    <Search className="w-3.5 h-3.5" />
                  </button>
                </div>

                {isAnalyzing && (
                  <p className="font-mono text-xs text-primary animate-pulse mt-2">Scanning...</p>
                )}

                {result && !isAnalyzing && (
                  <div className="mt-2 flex items-center gap-2">
                    {getIcon(result.classification)}
                    <span className={`font-mono text-xs font-bold ${getClassColor(result.classification)}`}>
                      {result.classification}
                    </span>
                    <span className={`font-mono text-xs ${getClassColor(result.classification)}`}>
                      ({result.riskScore}% risk)
                    </span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
};

export default PhishingTypes;
