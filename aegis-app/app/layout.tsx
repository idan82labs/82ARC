import type { Metadata } from 'next'
import { ClerkProvider } from '@clerk/nextjs'
import './globals.css'

export const metadata: Metadata = {
  title: 'Aegis - AI Agent Security Testing',
  description: 'Stress-test your AI agents before attackers do. Permissioned security assessments that uncover prompt injection, data leakage, and tool misuse.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <ClerkProvider>
      <html lang="en">
        <body className="min-h-screen bg-white font-sans text-slate-900 selection:bg-blue-100 selection:text-blue-900 overflow-x-hidden">
          {children}
        </body>
      </html>
    </ClerkProvider>
  )
}
