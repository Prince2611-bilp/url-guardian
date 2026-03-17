import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { PIE_DATA_BY_TYPE, type SubtypePieData } from "@/lib/phishing-stats";
import { X } from "lucide-react";
import type { ThreatType } from "@/lib/phishing-engine";
import { THREAT_TYPE_LABELS } from "@/lib/phishing-engine";

interface SubtypePieChartProps {
  threatType: ThreatType;
  onClose: () => void;
}

const SubtypePieChart = ({ threatType, onClose }: SubtypePieChartProps) => {
  const data: SubtypePieData[] = PIE_DATA_BY_TYPE[threatType] || [];

  return (
    <div className="mt-3 bg-muted/50 border border-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h4 className="font-mono text-xs font-bold text-primary uppercase tracking-wider">
            {THREAT_TYPE_LABELS[threatType]} — Attack Breakdown
          </h4>
          <p className="text-[10px] text-muted-foreground mt-0.5">
            Distribution of sub-attack types (2022–2024 combined)
          </p>
        </div>
        <button onClick={onClose} className="p-1 rounded-md hover:bg-muted transition-colors">
          <X className="w-3.5 h-3.5 text-muted-foreground" />
        </button>
      </div>
      <div className="w-full h-[250px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={45}
              outerRadius={85}
              paddingAngle={3}
              dataKey="value"
              label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              labelLine={{ stroke: "hsl(var(--muted-foreground))" }}
              style={{ fontSize: "10px", fontFamily: "monospace" }}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontFamily: "monospace",
                fontSize: "11px",
              }}
              formatter={(value: number) => [`${value}%`, "Share"]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default SubtypePieChart;
