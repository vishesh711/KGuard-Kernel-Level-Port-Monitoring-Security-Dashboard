import { AlertSeverity } from '../../types'

const STYLES: Record<AlertSeverity, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-blue-100 text-blue-800',
}

export function SeverityPill({ severity }: { severity: AlertSeverity }) {
  return (
    <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-medium ${STYLES[severity]}`}>
      {severity}
    </span>
  )
}
