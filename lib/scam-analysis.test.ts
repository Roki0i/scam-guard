import { describe, expect, it } from "vitest";
import {
  analyzeScamRisk,
  getUrlFormatError,
  hasAnalysisInput,
} from "./scam-analysis";

describe("analyzeScamRisk", () => {
  it("入力が空なら注意レベル低で、断定しない", () => {
    const result = analyzeScamRisk({ message: "", url: "" });
    expect(result.level).toBe("low");
    expect(result.findings).toHaveLength(0);
    expect(result.summary).not.toMatch(/安全|詐欺ではない/);
  });

  it("急がせる表現と送金要求を検出する", () => {
    const result = analyzeScamRisk({
      message: "至急、本日中に指定口座へ振り込んでください。",
      url: "",
    });
    expect(result.findings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["urgency", "payment"]),
    );
    expect(result.level).toBe("caution");
  });

  it("認証情報・機関名・口止めを検出して高と判定する", () => {
    const result = analyzeScamRisk({
      message: "銀行です。暗証番号と認証コードを今すぐ入力し、誰にも言わないでください。",
      url: "",
    });
    expect(result.level).toBe("high");
    expect(result.findings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["authority", "credentials", "urgency", "secrecy"]),
    );
  });

  it("本文中の短縮HTTP URLを検出する", () => {
    const result = analyzeScamRisk({
      message: "ここから確認 http://bit.ly/example",
      url: "",
    });
    expect(result.findings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["short-url", "insecure-url"]),
    );
  });

  it("IPアドレスや複雑なドメインを不自然なURLとして検出する", () => {
    const ipResult = analyzeScamRisk({ message: "", url: "https://192.0.2.1/login" });
    const longResult = analyzeScamRisk({
      message: "",
      url: "https://official-bank-account-confirmation-example.com",
    });
    expect(ipResult.findings.some((finding) => finding.id === "suspicious-url")).toBe(true);
    expect(longResult.findings.some((finding) => finding.id === "suspicious-url")).toBe(true);
  });

  it("通常のHTTPS URLだけなら危険なURL特徴を検出しない", () => {
    const result = analyzeScamRisk({ message: "", url: "https://example.com/help" });
    expect(result.findings).toHaveLength(0);
    expect(result.level).toBe("low");
  });

  it("再現入力をtrimし、HTTP短縮URLを非暗号化URLとして検出する", () => {
    const input = {
      message: `
        警察です。あなたの口座が犯罪に利用されています。
        本日中に5万円を電子マネーで支払い、認証コードを送ってください。
        この件は誰にも言わないでください。
      `,
      url: "  http://bit.ly/SCAM-TEST-ONLY  ",
    };

    expect(hasAnalysisInput(input)).toBe(true);
    expect(getUrlFormatError(input.url)).toBeNull();

    const result = analyzeScamRisk(input);
    expect(result.input.url).toBe("http://bit.ly/SCAM-TEST-ONLY");
    expect(result.findings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining([
        "authority",
        "urgency",
        "alternative-payment",
        "credentials",
        "secrecy",
        "short-url",
        "insecure-url",
      ]),
    );
    expect(result.level).toBe("high");
  });
});

describe("入力フォームの判定", () => {
  it("文章またはURLのどちらか一方にtrim後の値があれば入力済みと判定する", () => {
    expect(hasAnalysisInput({ message: " 文章 ", url: "   " })).toBe(true);
    expect(hasAnalysisInput({ message: "   ", url: " http://example.com " })).toBe(true);
    expect(hasAnalysisInput({ message: " \n ", url: "\t" })).toBe(false);
  });

  it("不正なURLには理由を返すが、入力済みの判定には影響しない", () => {
    const input = { message: "", url: "  example .com  " };

    expect(hasAnalysisInput(input)).toBe(true);
    expect(getUrlFormatError(input.url)).toBe(
      "URLは http:// または https:// から始めてください。",
    );
  });
});
