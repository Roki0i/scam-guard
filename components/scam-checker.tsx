"use client";

import { FormEvent, useRef, useState } from "react";
import {
  analyzeScamRisk,
  getUrlFormatError,
  hasAnalysisInput,
  type AnalysisResult,
} from "@/lib/scam-analysis";

const SAMPLE_MESSAGE =
  "【銀行重要通知】あなたの口座が不正利用されています。本日中に確認が必要です。以下のURLから暗証番号と認証コードを入力してください。誰にも言わないでください。";
const SAMPLE_URL = "http://bank-account-check.example.com/login";

const levelLabels = {
  low: "低",
  caution: "注意",
  high: "高",
} as const;

export function ScamChecker() {
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const trimmedInput = { message: message.trim(), url: url.trim() };
  const hasInput = hasAnalysisInput(trimmedInput);
  const urlError = getUrlFormatError(url);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!hasInput) return;
    setResult(analyzeScamRisk(trimmedInput));
    window.setTimeout(
      () => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }),
      0,
    );
  }

  function clearAll() {
    setMessage("");
    setUrl("");
    setResult(null);
  }

  function useSample() {
    setMessage(SAMPLE_MESSAGE);
    setUrl(SAMPLE_URL);
    setResult(null);
  }

  return (
    <>
      <section className="checker-card" aria-labelledby="checker-title">
        <div className="section-heading">
          <span className="step-number" aria-hidden="true">1</span>
          <div>
            <h2 id="checker-title">気になる内容を入力してください</h2>
            <p>メッセージとURLは、どちらか一方だけでも確認できます。</p>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <label htmlFor="message">
            怪しいと感じた文章
            <span className="optional">任意</span>
          </label>
          <textarea
            id="message"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            placeholder="例：本日中に手続きが必要です。以下のリンクから確認してください。"
            rows={7}
          />

          <label htmlFor="url">
            確認したいURL
            <span className="optional">任意</span>
          </label>
          <input
            id="url"
            type="text"
            inputMode="url"
            autoCapitalize="none"
            autoCorrect="off"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="例：https://example.com"
            aria-invalid={urlError ? true : undefined}
            aria-describedby={urlError ? "url-error" : undefined}
          />
          {urlError && (
            <p id="url-error" className="input-error" role="alert">
              {urlError}
            </p>
          )}

          <div className="form-actions">
            <button type="button" className="secondary-button" onClick={useSample}>
              <SparkIcon />
              サンプルを入力
            </button>
            <button
              type="button"
              className="text-button"
              onClick={clearAll}
              disabled={!hasInput}
            >
              <TrashIcon />
              入力内容を削除
            </button>
          </div>

          <button
            className="primary-button"
            type="submit"
            disabled={!hasInput}
          >
            <SearchIcon />
            チェックする
          </button>
        </form>
      </section>

      {result && (
        <ResultPanel
          ref={resultRef}
          result={result}
          onRetry={() => {
            setResult(null);
            window.scrollTo({ top: 0, behavior: "smooth" });
          }}
        />
      )}
    </>
  );
}

function ResultPanel({
  ref,
  result,
  onRetry,
}: {
  ref: React.Ref<HTMLDivElement>;
  result: AnalysisResult;
  onRetry: () => void;
}) {
  return (
    <section ref={ref} className="result-card" aria-labelledby="result-title">
      <div className="section-heading">
        <span className="step-number" aria-hidden="true">2</span>
        <div>
          <h2 id="result-title">チェック結果</h2>
          <p>検出した特徴をもとに、落ち着いて確認しましょう。</p>
        </div>
      </div>

      <div className={`level-banner level-${result.level}`}>
        <div>
          <span className="level-caption">注意レベル</span>
          <strong>{levelLabels[result.level]}</strong>
        </div>
        <p>{result.summary}</p>
      </div>

      <div className="result-section">
        <h3>検出された危険な特徴</h3>
        {result.findings.length ? (
          <ul className="finding-list">
            {result.findings.map((finding) => (
              <li key={finding.id}>
                <span className="alert-dot" aria-hidden="true">!</span>
                <div>
                  <strong>{finding.title}</strong>
                  <p>{finding.reason}</p>
                  {finding.matches.length > 0 && (
                    <p className="matches">
                      検出：{finding.matches.map((item) => `「${item}」`).join("、")}
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="no-findings">
            今回のルールでは、危険な特徴は検出されませんでした。ただし、相手や内容が信頼できることを示すものではありません。
          </p>
        )}
      </div>

      <div className="result-section recommendations">
        <h3>推奨する行動</h3>
        <ul>
          {result.recommendations.map((action) => (
            <li key={action}>
              <CheckIcon />
              <span>{action}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="result-section input-review">
        <h3>入力された内容</h3>
        <dl>
          <div>
            <dt>文章</dt>
            <dd>{result.input.message || "（入力なし）"}</dd>
          </div>
          <div>
            <dt>URL</dt>
            <dd>{result.input.url || "（入力なし）"}</dd>
          </div>
        </dl>
      </div>

      <button className="retry-button" type="button" onClick={onRetry}>
        <RetryIcon />
        入力内容を見直して再チェック
      </button>
    </section>
  );
}

function SearchIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m16 16 5 5" /></svg>;
}
function TrashIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3m3 0-1 14H7L6 7m4 4v6m4-6v6" /></svg>;
}
function SparkIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 2 1.7 5.3L19 9l-5.3 1.7L12 16l-1.7-5.3L5 9l5.3-1.7L12 2Zm7 13 .8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8L19 15Z" /></svg>;
}
function CheckIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6" /></svg>;
}
function RetryIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 7v5h-5M4 17v-5h5M6.1 9a7 7 0 0 1 11.7-2L20 9M4 15l2.2 2a7 7 0 0 0 11.7-2" /></svg>;
}
