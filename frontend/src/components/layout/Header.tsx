import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Bars3Icon, BellIcon } from '@heroicons/react/24/outline'
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
  const health = useHealth()
  const activeAlerts = useActiveAlerts()

  const activeAlertsCount = activeAlerts.data?.total_active ?? 0
  const healthStyle = (health.data && HEALTH_STYLES[health.data.status]) || UNKNOWN_HEALTH

  return (
    <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-gray-200 bg-white px-4 shadow-sm sm:gap-x-6 sm:px-6 lg:px-8">
      {/* Mobile menu button */}
      <button
        type="button"
        className="-m-2.5 p-2.5 text-gray-700 lg:hidden"
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
      >
        <span className="sr-only">Open sidebar</span>
        <Bars3Icon className="h-6 w-6" aria-hidden="true" />
      </button>

      {/* Separator */}
      <div className="h-6 w-px bg-gray-200 lg:hidden" aria-hidden="true" />

      <div className="flex flex-1 gap-x-4 self-stretch lg:gap-x-6">
        {/* Page title area */}
        <div className="flex items-center">
          <h1 className="text-lg font-semibold text-gray-900">Network Security Monitor</h1>
        </div>

        {/* Right side */}
        <div className="ml-auto flex items-center gap-x-4 lg:gap-x-6">
          {/* System Health Indicator */}
          <div className="flex items-center space-x-2">
            <div className={`h-3 w-3 rounded-full ${healthStyle.dot}`}></div>
            <span className={`text-sm font-medium ${healthStyle.text}`}>{healthStyle.label}</span>
          </div>

          {/* Alerts notification */}
          <div className="relative">
            <Link
              to="/alerts"
              className="relative block rounded-full bg-white p-1 text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
            >
              <span className="sr-only">View notifications</span>
              <BellIcon className="h-6 w-6" aria-hidden="true" />

              {/* Alert badge */}
              {activeAlertsCount > 0 && (
                <div className="absolute -top-1 -right-1">
                  <span className="inline-flex items-center justify-center h-4 w-4 text-xs font-medium bg-red-600 text-white rounded-full">
                    {activeAlertsCount > 99 ? '99+' : activeAlertsCount}
                  </span>
                </div>
              )}
            </Link>
          </div>

          {/* Separator */}
          <div className="hidden lg:block lg:h-6 lg:w-px lg:bg-gray-200" aria-hidden="true" />

          {/* Real-time status indicator */}
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1">
              <div
                className={`h-2 w-2 rounded-full ${
                  live.connected ? 'bg-green-500 animate-pulse' : 'bg-gray-400'
                }`}
              ></div>
              <span className="text-sm text-gray-600">{live.connected ? 'Live' : 'Offline'}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
