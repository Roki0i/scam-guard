import { ScamChecker } from "@/components/scam-checker";

export default function Home() {
  return (
    <main>
      <section className="hero">
        <div className="page-shell hero-inner">
          <div className="brand-mark" aria-hidden="true">
            <ShieldIcon />
          </div>
          <div>
            <p className="eyebrow">詐欺判断支援サービス</p>
            <h1>Scam Guard</h1>
            <p className="hero-copy">
              そのメッセージ、送金する前にチェックしませんか？
            </p>
          </div>
        </div>
      </section>

      <div className="page-shell content">
        <ScamChecker />

        <aside className="notice" aria-labelledby="notice-title">
          <div className="notice-icon" aria-hidden="true">
            i
          </div>
          <div>
            <h2 id="notice-title">大切なお知らせ</h2>
            <p>
              このサービスは詐欺を断定するものではありません。少しでも不審に感じた場合は、送金や個人情報の送信を行わず、公的な相談窓口や信頼できる人へ相談してください。
            </p>
          </div>
        </aside>
      </div>

      <footer>
        <div className="page-shell footer-inner">
          <div className="footer-brand">
            <span className="footer-shield" aria-hidden="true">
              <ShieldIcon />
            </span>
            <strong>Scam Guard</strong>
          </div>
          <p>落ち着いて判断するためのお手伝い</p>
        </div>
      </footer>
    </main>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 48 48" role="img" aria-label="盾">
      <path
        d="M24 4 39 10v11c0 10.2-6.1 18.6-15 23-8.9-4.4-15-12.8-15-23V10L24 4Z"
        fill="currentColor"
      />
      <path
        d="m17.5 24 4.2 4.2 9.5-10"
        fill="none"
        stroke="white"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="3.5"
      />
    </svg>
  );
}
