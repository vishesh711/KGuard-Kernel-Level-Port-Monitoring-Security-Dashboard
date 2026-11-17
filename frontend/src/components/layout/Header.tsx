import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRightOnRectangleIcon, Bars3Icon, BellIcon } from '@heroicons/react/24/outline'
import { useAuth } from '../../context/authContext'
import { useLiveStatus } from '../../context/liveStatus'
import { useActiveAlerts, useHealth } from '../../hooks/queries'

const HEALTH_STYLES: Record<string, { dot: string; text: string; label: string }> = {
  healthy: { dot: 'bg-green-500', text: 'text-green-600', label: 'System Healthy' },
  degraded: { dot: 'bg-yellow-500', text: 'text-yellow-600', label: 'System Degraded' },
  unhealthy: { dot: 'bg-red-500', text: 'text-red-600', label: 'System Unhealthy' },
}
const UNKNOWN_HEALTH = { dot: 'bg-gray-400', text: 'text-gray-500', label: 'Backend Unreachable' }

export function Header() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const live = useLiveStatus()
  const { session, logout } = useAuth()
  const health = useHealth()
  const activeAlerts = useActiveAlerts()

  const activeAlertsCount = activeAlerts.data?.total_active ?? 0
  const healthStyle = (health.data && HEALTH_STYLES[health.data.status]) || UNKNOWN_HEALTH

  return (
    <div className="sticky top-0 z-40 flex h-14 shrink-0 items-center gap-x-4 border-b border-gray-200 bg-page/90 px-4 backdrop-blur sm:px-6 lg:px-8">
      {/* Mobile menu button */}
      <button
        type="button"
        className="-m-2.5 p-2.5 text-gray-700 lg:hidden"
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
      >
        <span className="sr-only">Open sidebar</span>
        <Bars3Icon className="h-6 w-6" aria-hidden="true" />
      </button>

      <div className="ml-auto flex items-center gap-x-2 sm:gap-x-3">
        {/* System health */}
        <span className="inline-flex items-center gap-x-2 rounded-full border border-gray-200 bg-surface px-3 py-1">
          <span className={`h-2 w-2 rounded-full ${healthStyle.dot}`} aria-hidden="true" />
          <span className={`text-xs font-medium ${healthStyle.text}`}>{healthStyle.label}</span>
        </span>

        {/* Live updates */}
        <span className="inline-flex items-center gap-x-2 rounded-full border border-gray-200 bg-surface px-3 py-1">
          <span
            className={`h-2 w-2 rounded-full ${live.connected ? 'bg-green-500 animate-pulse-dot' : 'bg-gray-400'}`}
            aria-hidden="true"
          />
          <span className="text-xs font-medium text-gray-600">{live.connected ? 'Live' : 'Offline'}</span>
        </span>

        {/* Open alerts */}
        <Link
          to="/alerts"
          className="relative rounded-full border border-gray-200 bg-surface p-1.5 text-gray-500 hover:text-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500"
        >
          <span className="sr-only">View notifications</span>
          <BellIcon className="h-5 w-5" aria-hidden="true" />
          {activeAlertsCount > 0 && (
            <span className="absolute -right-1.5 -top-1.5 inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-bold text-white">
              {activeAlertsCount > 99 ? '99+' : activeAlertsCount}
            </span>
          )}
        </Link>

        {/* Signed-in user */}
        {session && (
          <div className="ml-1 flex items-center gap-x-2 border-l border-gray-200 pl-3">
            <span className="text-sm text-gray-700">{session.username}</span>
            <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
              {session.role}
            </span>
            <button
              type="button"
              onClick={logout}
              className="rounded p-1 text-gray-400 hover:text-gray-700"
              title="Sign out"
            >
              <span className="sr-only">Sign out</span>
              <ArrowRightOnRectangleIcon className="h-5 w-5" aria-hidden="true" />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
