import { isAxiosError } from 'axios'

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return <p className="px-4 py-8 text-center text-sm text-gray-500">{label}</p>
}

export function ErrorMessage({ error }: { error: unknown }) {
  const detail = isAxiosError(error) ? (error.response?.data?.detail ?? error.message) : String(error)
  return (
    <p role="alert" className="px-4 py-8 text-center text-sm text-red-600">
      Could not load: {typeof detail === 'string' ? detail : JSON.stringify(detail)}
    </p>
  )
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="px-4 py-8 text-center text-sm text-gray-500">{children}</p>
}
