import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import ScanResultCard, { mlConfidencePercent, riskClass } from "./ScanResultCard.jsx";

function urlResult(overrides = {}) {
  return {
    target: "http://paypa1-login.tk/verify",
    type: "URL",
    score: 70,
    level: "HIGH",
    recommendation: "High risk of phishing. Do not click any links.",
    signals: [
      { id: "suspiciousTld", category: "URL", description: "URL uses a TLD commonly abused for phishing", evidence: ".tk" },
      { id: "typosquatting", category: "URL", description: "Domain resembles brand 'paypal'", evidence: "paypa1" },
    ],
    domainAge: { status: "UNKNOWN", domain: "paypa1-login.tk", reason: "WHOIS lookup timed out" },
    ...overrides,
  };
}

describe("riskClass", () => {
  it("maps each level to its color modifier", () => {
    expect(riskClass("LOW")).toBe("risk-low");
    expect(riskClass("MEDIUM")).toBe("risk-medium");
    expect(riskClass("HIGH")).toBe("risk-high");
    expect(riskClass("SOMETHING")).toBe("risk-unknown");
    expect(riskClass(undefined)).toBe("risk-unknown");
  });
});

describe("ScanResultCard", () => {
  it.each([
    ["LOW", "Low risk", "risk-low"],
    ["MEDIUM", "Medium risk", "risk-medium"],
    ["HIGH", "High risk", "risk-high"],
  ])("renders a %s result with its label and color", (level, label, className) => {
    render(<ScanResultCard result={urlResult({ level })} />);

    const card = screen.getByRole("article", { name: "Scan result" });
    expect(card).toHaveClass("result-card", className);
    expect(screen.getByTestId("risk-badge")).toHaveTextContent(label);
  });

  it("shows the score, target, recommendation, and every signal", () => {
    render(<ScanResultCard result={urlResult()} />);

    expect(screen.getByLabelText("Risk score 70 out of 100")).toHaveTextContent("70/100");
    expect(screen.getByText("http://paypa1-login.tk/verify")).toBeInTheDocument();
    expect(screen.getByText(/Do not click any links/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Matched signals (2)" })).toBeInTheDocument();
    expect(screen.getByText("paypa1")).toBeInTheDocument();
  });

  it("explains the domain age, including when it wasn't checked", () => {
    const { rerender } = render(<ScanResultCard result={urlResult()} />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("paypa1-login.tk: WHOIS lookup timed out")).toBeInTheDocument();

    rerender(
      <ScanResultCard
        result={urlResult({
          domainAge: { status: "KNOWN", domain: "github.com", creationDate: "2007-10-09", age: "18 years", ageDays: 6938 },
        })}
      />,
    );
    expect(screen.getByText("18 years")).toBeInTheDocument();

    rerender(<ScanResultCard result={urlResult({ domainAge: { status: "SKIPPED" } })} />);
    expect(screen.getByText("Not checked")).toBeInTheDocument();
  });

  it("says so when no signal matched", () => {
    render(<ScanResultCard result={urlResult({ level: "LOW", score: 0, signals: [] })} />);
    expect(screen.getByText("No phishing indicators matched.")).toBeInTheDocument();
  });

  it("labels threat feed matches", () => {
    const signals = [
      { id: "knownPhishingUrl", category: "URL", description: "Known phishing URL (OpenPhish)", evidence: "" },
      { id: "suspiciousTld", category: "URL", description: "Suspicious TLD", evidence: ".tk" },
    ];
    render(<ScanResultCard result={urlResult({ signals })} />);

    const matches = screen.getByLabelText("Threat feed matches");
    expect(within(matches).getByText("Threat feed: Listed URL")).toBeInTheDocument();
    expect(within(matches).queryByText(/Suspicious TLD/)).not.toBeInTheDocument();
  });

  it("shows ML confidence only when the result carries it", () => {
    const { rerender } = render(<ScanResultCard result={urlResult()} />);
    expect(screen.queryByText("ML confidence")).not.toBeInTheDocument();

    rerender(<ScanResultCard result={urlResult({ ml: { probability: 0.873 } })} />);
    expect(screen.getByText("ML confidence")).toBeInTheDocument();
    expect(screen.getByText("87% phishing")).toBeInTheDocument();
  });

  it("shows the sender, subject, and links of an email result", () => {
    render(
      <ScanResultCard
        result={urlResult({
          type: "EMAIL",
          target: "suspicious.eml",
          domainAge: undefined,
          email: {
            from: "service@paypa1-support.tk",
            displayName: "PayPal",
            replyTo: "collect@evil.tk",
            subject: "Your account is suspended",
            links: ["http://paypa1-support.tk/login"],
          },
        })}
      />,
    );

    expect(screen.getByText("PayPal <service@paypa1-support.tk>")).toBeInTheDocument();
    expect(screen.getByText("collect@evil.tk")).toBeInTheDocument();
    expect(screen.getByText("Your account is suspended")).toBeInTheDocument();
    expect(screen.getByText("http://paypa1-support.tk/login")).toBeInTheDocument();
  });
});

describe("mlConfidencePercent", () => {
  it("reads a probability or a percentage, and nothing else", () => {
    expect(mlConfidencePercent({ ml: { probability: 0.5 } })).toBe(50);
    expect(mlConfidencePercent({ mlProbability: 0.123 })).toBe(12);
    expect(mlConfidencePercent({ ml: { probability: 64 } })).toBe(64);
    expect(mlConfidencePercent({})).toBeNull();
    expect(mlConfidencePercent({ ml: { probability: "high" } })).toBeNull();
  });
});
