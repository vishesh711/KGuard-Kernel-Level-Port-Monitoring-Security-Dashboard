import { ReactNode } from 'react'
import { Sidebar } from './Sidebar'
import { Header } from './Header'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-page">
      <Sidebar />
      <div className="lg:pl-60">
        <Header />
        <main className="py-6">
          <div className="mx-auto max-w-[1400px] px-4 sm:px-6 lg:px-8">{children}</div>
        </main>
      </div>
    </div>
  )
}
