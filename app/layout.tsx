import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Scam Guard | 詐欺判断支援サービス",
  description: "怪しいメッセージやURLの危険な特徴を確認し、落ち着いた判断を支援します。",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="ja">
      <body>{children}</body>
    </html>
  );
}
