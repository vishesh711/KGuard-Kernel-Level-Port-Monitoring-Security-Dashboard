import { Link } from 'react-router-dom'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  ServerIcon,
  ChartBarIcon,
  ClockIcon
} from '@heroicons/react/24/outline'

// Simple StatsCard component
interface StatsCardProps {
  title: string
  value: string | number
  icon: React.ComponentType<{ className?: string }>
  loading?: boolean
  subtitle?: string
  color?: 'primary' | 'success' | 'warning' | 'danger'
}

function StatsCard({ 
  title, 
  value, 
  icon: Icon, 
  loading, 
  subtitle, 
  color = 'primary' 
}: StatsCardProps) {
  const getColorClasses = () => {
    switch (color) {
      case 'success':
        return 'text-green-600 bg-green-50'
      case 'warning':
        return 'text-yellow-600 bg-yellow-50'
      case 'danger':
        return 'text-red-600 bg-red-50'
      default:
        return 'text-blue-600 bg-blue-50'
    }
  }

  return (
    <div className="card">
      <div className="card-content">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <div className={`inline-flex items-center justify-center p-3 rounded-lg ${getColorClasses()}`}>
              <Icon className="h-6 w-6" aria-hidden="true" />
            </div>
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 truncate">
                {title}
              </dt>
              <dd className="flex items-baseline">
                <div className="text-2xl font-semibold text-gray-900">
                  {loading ? (
                    <div className="h-8 w-16 bg-gray-200 rounded animate-pulse"></div>
                  ) : (
                    value
                  )}
                </div>
              </dd>
              {subtitle && (
                <dd className="text-sm text-gray-500">
                  {subtitle}
                </dd>
              )}
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}

export function Dashboard() {
  // Mock data for demonstration - replace with real API calls when backend is ready
  const connectionStatus = { connected: false, reconnecting: false }
  const eventStats = { total_events: 1234, suspicious_events: 23 }
  const alertStats = { unresolved_alerts: 5, critical_alerts: 1, high_alerts: 2 }
  const health = { 
    status: 'healthy', 
    database: true, 
    kernel_module: true, 
    uptime_seconds: 86400 
  }
  const eventsLoading = false
  const alertsLoading = false

  const formatUptime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    return `${hours}h ${minutes}m`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-1 text-sm text-gray-600">
          Real-time network monitoring and threat detection
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Total Events"
          value={eventStats?.total_events || 0}
          icon={EyeIcon}
          loading={eventsLoading}
          subtitle="Last 24 hours"
        />
        
        <StatsCard
          title="Suspicious Events"
          value={eventStats?.suspicious_events || 0}
          icon={ExclamationTriangleIcon}
          loading={eventsLoading}
          subtitle="Flagged as suspicious"
          color="warning"
        />
        
        <StatsCard
          title="Active Alerts"
          value={alertStats?.unresolved_alerts || 0}
          icon={ShieldCheckIcon}
          loading={alertsLoading}
          subtitle="Require attention"
          color={alertStats?.critical_alerts ? 'danger' : alertStats?.high_alerts ? 'warning' : 'success'}
        />
        
        <StatsCard
          title="System Uptime"
          value={health?.uptime_seconds ? formatUptime(health.uptime_seconds) : 'N/A'}
          icon={ServerIcon}
          loading={!health}
          subtitle={connectionStatus.connected ? 'Connected' : 'Disconnected'}
          color={health?.status === 'healthy' ? 'success' : 'warning'}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Traffic Over Time */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center space-x-2">
              <ChartBarIcon className="h-5 w-5 text-gray-400" />
              <h3 className="text-lg font-medium text-gray-900">Traffic Over Time</h3>
            </div>
          </div>
          <div className="card-content">
            <div className="h-64 flex items-center justify-center text-gray-500">
              <p>Traffic chart will appear here</p>
            </div>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center space-x-2">
              <ChartBarIcon className="h-5 w-5 text-gray-400" />
              <h3 className="text-lg font-medium text-gray-900">Protocol Distribution</h3>
            </div>
          </div>
          <div className="card-content">
            <div className="h-64 flex items-center justify-center text-gray-500">
              <p>Protocol chart will appear here</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Events */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ClockIcon className="h-5 w-5 text-gray-400" />
                <h3 className="text-lg font-medium text-gray-900">Recent Events</h3>
              </div>
              <Link
                to="/events"
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                View all
              </Link>
            </div>
          </div>
          <div className="card-content p-0">
            <div className="p-6 text-center text-gray-500">
              <p>Recent events will appear here</p>
            </div>
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ExclamationTriangleIcon className="h-5 w-5 text-gray-400" />
                <h3 className="text-lg font-medium text-gray-900">Recent Alerts</h3>
              </div>
              <Link
                to="/alerts"
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                View all
              </Link>
            </div>
          </div>
          <div className="card-content p-0">
            <div className="p-6 text-center text-gray-500">
              <p>Recent alerts will appear here</p>
            </div>
          </div>
        </div>
      </div>

      {/* System Status */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-medium text-gray-900">System Status</h3>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="flex items-center space-x-3">
              <div className={`h-3 w-3 rounded-full ${
                health?.database ? 'bg-green-500' : 'bg-red-500'
              }`}></div>
              <div>
                <p className="text-sm font-medium text-gray-900">Database</p>
                <p className="text-xs text-gray-500">
                  {health?.database ? 'Connected' : 'Disconnected'}
                </p>
              </div>
            </div>
            
            <div className="flex items-center space-x-3">
              <div className={`h-3 w-3 rounded-full ${
                health?.kernel_module ? 'bg-green-500' : 'bg-red-500'
              }`}></div>
              <div>
                <p className="text-sm font-medium text-gray-900">Kernel Module</p>
                <p className="text-xs text-gray-500">
                  {health?.kernel_module ? 'Active' : 'Inactive'}
                </p>
              </div>
            </div>
            
            <div className="flex items-center space-x-3">
              <div className={`h-3 w-3 rounded-full ${
                connectionStatus.connected ? 'bg-green-500' : 'bg-red-500'
              }`}></div>
              <div>
                <p className="text-sm font-medium text-gray-900">WebSocket</p>
                <p className="text-xs text-gray-500">
                  {connectionStatus.connected ? 'Connected' : 'Disconnected'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}