export type RiskLevel = "low" | "caution" | "high";

export type FindingId =
  | "urgency"
  | "payment"
  | "alternative-payment"
  | "authority"
  | "credentials"
  | "secrecy"
  | "suspicious-url"
  | "short-url"
  | "insecure-url";

export interface RiskFinding {
  id: FindingId;
  title: string;
  reason: string;
  matches: string[];
  score: number;
}

export interface AnalysisInput {
  message: string;
  url: string;
}

export interface AnalysisResult {
  level: RiskLevel;
  score: number;
  summary: string;
  findings: RiskFinding[];
  recommendations: string[];
  input: AnalysisInput;
}

export function hasAnalysisInput(input: AnalysisInput): boolean {
  return Boolean(input.message.trim() || input.url.trim());
}

export function getUrlFormatError(value: string): string | null {
  const candidate = value.trim();
  if (!candidate) return null;

  if (!/^https?:\/\//i.test(candidate)) {
    return "URLは http:// または https:// から始めてください。";
  }

  try {
    const parsed = new URL(candidate);
    if (!parsed.hostname || /\s/.test(candidate)) {
      return "URLのドメイン名や文字列の形式を確認してください。";
    }
  } catch {
    return "URLのドメイン名や文字列の形式を確認してください。";
  }

  return null;
}

interface Rule {
  id: FindingId;
  title: string;
  reason: string;
  pattern: RegExp;
  score: number;
}

const textRules: Rule[] = [
  {
    id: "urgency",
    title: "判断を急がせる表現",
    reason: "考える時間を与えず、焦りや不安から行動させる手口で使われます。",
    pattern: /今すぐ|至急|緊急|本日中|今日中|ただちに|直ちに|期限(?:が)?迫|早急に/g,
    score: 2,
  },
  {
    id: "payment",
    title: "送金や支払いの要求",
    reason: "不審な相手からの金銭要求に応じると、取り戻すことが難しい場合があります。",
    pattern: /振り?込(?:み|む|んで)|送金|支払(?:い|う|って)|入金|料金を?払|現金/g,
    score: 3,
  },
  {
    id: "alternative-payment",
    title: "追跡しにくい支払い方法の要求",
    reason: "電子マネーやギフトカードなどは、被害後の取り消しが難しい支払い方法です。",
    pattern: /電子マネー|ギフトカード|プリペイドカード|暗号資産|仮想通貨|ビットコイン|カード番号/g,
    score: 4,
  },
  {
    id: "authority",
    title: "公的機関や金融機関を名乗る表現",
    reason: "信頼されやすい組織を名乗り、不安にさせて指示に従わせる手口があります。",
    pattern: /警察|裁判所|検察|銀行|信用金庫|市役所|区役所|役所|税務署|年金機構/g,
    score: 2,
  },
  {
    id: "credentials",
    title: "秘密の認証情報の要求",
    reason: "正規の窓口が、メッセージで暗証番号や認証コードを聞くことは通常ありません。",
    pattern: /パスワード|暗証番号|認証コード|ワンタイムパスワード|秘密の質問|ログイン情報/g,
    score: 4,
  },
  {
    id: "secrecy",
    title: "周囲への相談を止める指示",
    reason: "他の人に相談させず、冷静な判断や被害の発覚を遅らせる狙いがあります。",
    pattern: /誰にも(?:言わ|話さ|相談し)ない|口外(?:しない|禁止)|秘密に(?:して|する)|内密に/g,
    score: 4,
  },
];

const shortenerHosts = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "x.gd", "shorturl.at", "rebrand.ly",
]);

export function analyzeScamRisk(input: AnalysisInput): AnalysisResult {
  const normalizedInput = {
    message: input.message.trim(),
    url: input.url.trim(),
  };
  const findings: RiskFinding[] = [];

  for (const rule of textRules) {
    const matches = uniqueMatches(normalizedInput.message, rule.pattern);
    if (matches.length) findings.push({ ...rule, matches });
  }

  const urls = unique([
    ...extractUrls(normalizedInput.message),
    ...normalizedInput.url.split(/\s+/).filter(Boolean),
  ]);
  const urlFindings = analyzeUrls(urls);
  findings.push(...urlFindings);

  const score = findings.reduce((total, finding) => total + finding.score, 0);
  const level: RiskLevel = score >= 8 ? "high" : score >= 3 ? "caution" : "low";
  const summary = {
    low: "検出された特徴は少なめです。内容と相手を別の方法でも確認してください。",
    caution: "注意が必要な特徴が見つかりました。行動する前に相手や内容を確認してください。",
    high: "複数の危険な特徴が見つかりました。送金や情報入力をいったん止めてください。",
  }[level];

  return {
    level,
    score,
    summary,
    findings,
    recommendations: buildRecommendations(findings),
    input: normalizedInput,
  };
}

function analyzeUrls(values: string[]): RiskFinding[] {
  const insecure: string[] = [];
  const shortened: string[] = [];
  const suspicious: string[] = [];

  for (const value of values) {
    const candidate = value.replace(/[、。，．）」』】>]+$/g, "");
    let parsed: URL;
    try {
      parsed = new URL(/^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`);
    } catch {
      if (candidate.includes(".") || candidate.includes("/")) suspicious.push(candidate);
      continue;
    }

    const host = parsed.hostname.toLowerCase();
    if (parsed.protocol === "http:") insecure.push(candidate);
    if (shortenerHosts.has(host) || [...shortenerHosts].some((item) => host.endsWith(`.${item}`))) {
      shortened.push(candidate);
    }
    if (
      host.startsWith("xn--") ||
      host.includes(".xn--") ||
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ||
      candidate.includes("@") ||
      host.split("-").length >= 4 ||
      host.length > 45
    ) {
      suspicious.push(candidate);
    }
  }

  const findings: RiskFinding[] = [];
  if (suspicious.length) {
    findings.push({
      id: "suspicious-url",
      title: "不自然なURL",
      reason: "見慣れた組織に似せた文字列や複雑なURLで、別のサイトへ誘導する場合があります。",
      matches: unique(suspicious),
      score: 3,
    });
  }
  if (shortened.length) {
    findings.push({
      id: "short-url",
      title: "短縮URL",
      reason: "リンク先のドメインが見えにくく、意図しないサイトへ誘導される可能性があります。",
      matches: unique(shortened),
      score: 3,
    });
  }
  if (insecure.length) {
    findings.push({
      id: "insecure-url",
      title: "暗号化されていないHTTPのURL",
      reason: "通信が暗号化されないため、入力した情報を安全に送れない可能性があります。",
      matches: unique(insecure),
      score: 2,
    });
  }
  return findings;
}

function extractUrls(text: string): string[] {
  return text.match(/https?:\/\/[^\s<>"'「」]+/gi) ?? [];
}

function uniqueMatches(text: string, pattern: RegExp): string[] {
  return unique(text.match(pattern) ?? []).slice(0, 5);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function buildRecommendations(findings: RiskFinding[]): string[] {
  const ids = new Set(findings.map((finding) => finding.id));
  const actions: string[] = [];
  if (ids.has("payment") || ids.has("alternative-payment")) actions.push("送金や支払いを止める");
  if (ids.has("suspicious-url") || ids.has("short-url") || ids.has("insecure-url")) actions.push("URLを開かない");
  if (ids.has("credentials")) actions.push("相手へ個人情報や認証情報を送らない");
  actions.push("家族や信頼できる人へ相談する");
  actions.push("メッセージ内の連絡先ではなく、公式サイトに掲載された連絡先から確認する");
  return actions;
}
