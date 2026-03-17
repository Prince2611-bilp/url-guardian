import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { YEARLY_THREAT_DATA } from "@/lib/phishing-stats";
import { X } from "lucide-react";

interface ThreatBarChartProps {
  onClose: () => void;
}

const ThreatBarChart = ({ onClose }: ThreatBarChartProps) => {
  return (
    <div className="mt-6 bg-card border border-border rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="font-mono text-sm font-bold text-primary uppercase tracking-wider">
            Phishing Threats Overview (2022–2024)
          </h3>
          <p className="text-xs text-muted-foreground mt-1">
            Reported incidents in thousands — all 5 phishing types compared
          </p>
        </div>
        <button onClick={onClose} className="p-1.5 rounded-md hover:bg-muted transition-colors">
          <X className="w-4 h-4 text-muted-foreground" />
        </button>
      </div>
      <div className="w-full h-[350px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={YEARLY_THREAT_DATA} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis dataKey="year" tick={{ fontSize: 12, fontFamily: "monospace", fill: "hsl(var(--muted-foreground))" }} />
            <YAxis tick={{ fontSize: 11, fontFamily: "monospace", fill: "hsl(var(--muted-foreground))" }} />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontFamily: "monospace",
                fontSize: "12px",
              }}
              labelStyle={{ color: "hsl(var(--foreground))" }}
            />
            <Legend wrapperStyle={{ fontFamily: "monospace", fontSize: "11px" }} />
            <Bar dataKey="urlPhishing" name="URL Phishing" fill="hsl(0, 85%, 55%)" radius={[3, 3, 0, 0]} />
            <Bar dataKey="emailPhishing" name="Email Phishing" fill="hsl(30, 90%, 50%)" radius={[3, 3, 0, 0]} />
            <Bar dataKey="domainSpoofing" name="Domain Spoofing" fill="hsl(45, 85%, 50%)" radius={[3, 3, 0, 0]} />
            <Bar dataKey="cloneWebsite" name="Clone Website" fill="hsl(200, 70%, 45%)" radius={[3, 3, 0, 0]} />
            <Bar dataKey="smsPhishing" name="SMS Phishing" fill="hsl(260, 60%, 50%)" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default ThreatBarChart;
