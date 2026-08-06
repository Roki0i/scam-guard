import type { NextConfig } from "next";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants";

export default function nextConfig(phase: string): NextConfig {
  const isDevelopment = phase === PHASE_DEVELOPMENT_SERVER;

  return {
    output: "export",
    basePath: isDevelopment ? "" : "/scam-guard",
    trailingSlash: true,
    images: {
      unoptimized: true,
    },
    turbopack: {
      root: process.cwd(),
    },
  };
}
