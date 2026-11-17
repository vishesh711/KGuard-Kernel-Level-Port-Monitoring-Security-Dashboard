import { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  ServerIcon,
  ChartBarIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import { StatsCard } from '../components/dashboard/StatsCard'
import { RecentEvents } from '../components/dashboard/RecentEvents'
import { RecentAlerts } from '../components/dashboard/RecentAlerts'
import { TrafficChart } from '../components/charts/TrafficChart'
import { ProtocolChart } from '../components/charts/ProtocolChart'
import { useLiveStatus } from '../context/liveStatus'
import {
  useAlertStats,
  useEventStats,
  useHealth,
  useRecentAlerts,
  useRecentEvents,
  useTrafficSummary,
} from '../hooks/queries'
import { formatUptime } from '../lib/time'

function Panel({
  title,
  icon,
  link,
  className = '',
  children,
}: {
  title: string
  icon: ReactNode
  link?: string
  className?: string
  children: ReactNode
}) {
  return (
    <section className={`card flex flex-col ${className}`}>
      <div className="flex items-center justify-between border-b border-gray-200 px-5 py-3">
        <div className="flex items-center gap-x-2">
          {icon}
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">{title}</h2>
        </div>
        {link && (
          <Link to={link} className="text-xs font-medium text-primary-400 hover:text-primary-300">
            View all →
          </Link>
        )}
      </div>
      <div className="flex-1">{children}</div>
    </section>
  )
}

function StatusDot({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <li className="flex items-center justify-between gap-x-3 py-2.5">
      <span className="text-sm text-gray-700">{label}</span>
      <span
        className={`inline-flex items-center gap-x-1.5 text-xs font-medium ${ok ? 'text-green-600' : 'text-red-600'}`}
      >
        <span
          className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-green-500' : 'bg-red-500'}`}
          aria-hidden="true"
        />
        {detail}
      </span>
    </li>
  )
}

function Loading() {
  return <div className="h-64 animate-pulse rounded bg-gray-100" />
}

export function Dashboard() {
  const live = useLiveStatus()
  const health = useHealth()
  const eventStats = useEventStats(24)
  const alertStats = useAlertStats(24)
  const traffic = useTrafficSummary(24, 1)
  const recentEvents = useRecentEvents(8)
  const recentAlerts = useRecentAlerts(5)

  const backendDown = health.isError && eventStats.isError
  const alertColor = alertStats.data?.critical_alerts
    ? 'danger'
    : alertStats.data?.high_alerts
      ? 'warning'
      : 'success'

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-gray-900">Overview</h1>
          <p className="mt-0.5 text-sm text-gray-500">Last 24 hours on every monitored host</p>
        </div>
      </div>

      {backendDown && (
        <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">
          Can&apos;t reach the KGuard backend. Check that it is running (and, if the dashboard is served apart
          from it, that VITE_API_BASE_URL points to it).
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatsCard
          title="Open alerts"
          value={alertStats.data?.unresolved_alerts ?? 0}
          icon={ShieldCheckIcon}
          loading={alertStats.isLoading}
          subtitle="Need attention"
          color={alertColor}
        />
        <StatsCard
          title="Suspicious events"
          value={eventStats.data?.suspicious_events ?? 0}
          icon={ExclamationTriangleIcon}
          loading={eventStats.isLoading}
          subtitle="Flagged by detection"
          color="warning"
        />
        <StatsCard
          title="Events"
          value={eventStats.data?.total_events ?? 0}
          icon={EyeIcon}
          loading={eventStats.isLoading}
          subtitle="Last 24 hours"
        />
        <StatsCard
          title="Backend uptime"
          value={health.data ? formatUptime(health.data.uptime_seconds) : 'N/A'}
          icon={ServerIcon}
          loading={health.isLoading}
          subtitle={live.connected ? 'Live updates on' : 'Live updates off'}
          color={health.data?.status === 'healthy' ? 'success' : 'warning'}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Latest alerts"
          icon={<ExclamationTriangleIcon className="h-4 w-4 text-red-400" />}
          link="/alerts"
          className="xl:col-span-2"
        >
          <RecentAlerts alerts={recentAlerts.data?.items ?? []} />
        </Panel>
        <div className="flex flex-col gap-4">
          <Panel title="System status" icon={<ServerIcon className="h-4 w-4 text-gray-400" />}>
            <ul className="divide-y divide-gray-200 px-5 py-1">
              <StatusDot
                ok={!!health.data?.database}
                label="Database"
                detail={health.data?.database ? 'Connected' : 'Disconnected'}
              />
              <StatusDot
                ok={!!health.data?.kernel_module}
                label="Kernel module"
                detail={health.data?.kernel_module ? 'Active' : 'Not loaded'}
              />
              <StatusDot
                ok={live.connected}
                label="Live updates"
                detail={live.connected ? 'Connected' : live.reconnecting ? 'Reconnecting…' : 'Disconnected'}
              />
            </ul>
          </Panel>
          <Panel title="Protocols" icon={<ChartBarIcon className="h-4 w-4 text-gray-400" />}>
            <div className="px-5 py-2">
              {eventStats.isLoading ? (
                <Loading />
              ) : (
                <ProtocolChart data={eventStats.data?.protocol_distribution ?? {}} />
              )}
            </div>
          </Panel>
        </div>
      </div>

      <Panel title="Traffic, last 24 hours" icon={<ChartBarIcon className="h-4 w-4 text-gray-400" />}>
        <div className="px-3 py-4">
          {traffic.isLoading ? <Loading /> : <TrafficChart data={traffic.data ?? []} />}
        </div>
      </Panel>

      <Panel title="Recent events" icon={<ClockIcon className="h-4 w-4 text-gray-400" />} link="/events">
        <RecentEvents events={recentEvents.data?.items ?? []} />
      </Panel>
    </div>
  )
}
