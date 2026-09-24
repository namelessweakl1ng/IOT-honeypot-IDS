import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "TRAPSIG — IoT Deception & Intrusion Detection",
  description: "A controlled IoT honeypot and machine-learning IDS laboratory: Raspberry Pi honeypots feed ELK telemetry, scikit-learn classifies attacks, and anomaly detection flags previously unseen behavior.",
  keywords: ["TRAPSIG", "IoT honeypot", "Cowrie", "ELK", "Elasticsearch", "ML IDS", "intrusion detection", "anomaly detection"],
  authors: [{ name: "TRAPSIG Project" }],
  icons: {
    icon: "https://z-cdn.chatglm.cn/z-ai/static/logo.svg",
  },
  openGraph: {
    title: "TRAPSIG",
    description: "IoT Deception & Intrusion Detection Research Platform",
    url: "https://chat.z.ai",
    siteName: "TRAPSIG",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "TRAPSIG",
    description: "IoT Deception & Intrusion Detection Research Platform",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
