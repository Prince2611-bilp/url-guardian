import { PHISHING_TYPES } from "@/lib/phishing-engine";

const PhishingTypes = () => {
  return (
    <section className="w-full max-w-3xl mx-auto mt-12">
      <div className="flex items-center gap-2 mb-6">
        <span className="text-xl">🛡️</span>
        <h2 className="font-mono text-sm text-primary tracking-wider uppercase">
          5 Types of Phishing Attacks
        </h2>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {PHISHING_TYPES.map((type) => (
          <div
            key={type.id}
            className="bg-card border border-border rounded-lg p-5 hover:border-primary/30 transition-colors group"
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
            <p className="text-xs text-safe">
              <span className="font-semibold">Prevention: </span>
              {type.prevention}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default PhishingTypes;
