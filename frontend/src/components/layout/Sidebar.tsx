import { NavLink } from 'react-router-dom'
import {
  Squares2X2Icon,
  BoltIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  Cog6ToothIcon,
  ShieldCheckIcon,
  ServerStackIcon,
  NoSymbolIcon,
  CpuChipIcon,
} from '@heroicons/react/24/outline'
import { ConnectionStatus } from '../ui/ConnectionStatus'

const sections = [
  {
    title: 'Monitor',
    items: [
      { name: 'Overview', href: '/', icon: Squares2X2Icon },
      { name: 'Alerts', href: '/alerts', icon: ExclamationTriangleIcon },
      { name: 'Events', href: '/events', icon: BoltIcon },
      { name: 'Analytics', href: '/analytics', icon: ChartBarIcon },
    ],
  },
  {
    title: 'Infrastructure',
    items: [
      { name: 'Hosts', href: '/hosts', icon: ServerStackIcon },
      { name: 'Processes', href: '/processes', icon: CpuChipIcon },
    ],
  },
  {
    title: 'Response',
    items: [
      { name: 'Blocked', href: '/blocks', icon: NoSymbolIcon },
      { name: 'Settings', href: '/settings', icon: Cog6ToothIcon },
    ],
  },
]

export function Sidebar() {
  return (
    <div className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-60 lg:flex-col">
      <div className="flex grow flex-col overflow-y-auto border-r border-gray-200 bg-sunken px-3 pb-4">
        {/* Logo */}
        <div className="flex h-14 shrink-0 items-center gap-x-2.5 px-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-100 ring-1 ring-primary-300/40">
            <ShieldCheckIcon className="h-5 w-5 text-primary-400" />
          </div>
          <div className="leading-tight">
            <p className="text-base font-bold tracking-tight text-gray-900">KGuard</p>
            <p className="text-[11px] uppercase tracking-wider text-gray-500">Security console</p>
          </div>
        </div>

        <nav className="mt-4 flex flex-1 flex-col gap-y-6">
          {sections.map((section) => (
            <div key={section.title}>
              <p className="px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
                {section.title}
              </p>
              <ul role="list" className="space-y-0.5">
                {section.items.map((item) => (
                  <li key={item.name}>
                    <NavLink
                      to={item.href}
                      end={item.href === '/'}
                      className={({ isActive }) =>
                        `group relative flex items-center gap-x-3 rounded-md px-2 py-1.5 text-sm font-medium transition-colors ${
                          isActive
                            ? 'bg-gray-100 text-gray-900'
                            : 'text-gray-600 hover:bg-gray-100/60 hover:text-gray-900'
                        }`
                      }
                    >
                      {({ isActive }) => (
                        <>
                          {isActive && (
                            <span
                              className="absolute inset-y-1 left-0 w-0.5 rounded-full bg-primary-400"
                              aria-hidden="true"
                            />
                          )}
                          <item.icon
                            className={`h-5 w-5 shrink-0 ${
                              isActive ? 'text-primary-400' : 'text-gray-400 group-hover:text-gray-600'
                            }`}
                            aria-hidden="true"
                          />
                          {item.name}
                        </>
                      )}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}

          <div className="mt-auto px-1">
            <ConnectionStatus />
          </div>
        </nav>
      </div>
    </div>
  )
}
