import { FormEvent, useState } from 'react'
import { isAxiosError } from 'axios'
import { ShieldCheckIcon } from '@heroicons/react/24/outline'
import { useAuth } from '../context/auth'

function loginError(error: unknown): string {
  if (isAxiosError(error)) {
    if (error.response?.status === 401) return 'Wrong username or password'
    if (error.response?.status === 429) {
      const wait = error.response.headers['retry-after']
      return `Too many failed attempts; try again in ${wait ?? 60} seconds`
    }
    if (!error.response) return 'Cannot reach the KGuard backend'
  }
  return 'Login failed'
}

export function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username, password)
    } catch (e) {
      setError(loginError(e))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-5 rounded-lg bg-white p-8 shadow"
        aria-label="Sign in"
      >
        <div className="flex items-center space-x-2">
          <ShieldCheckIcon className="h-8 w-8 text-blue-600" aria-hidden="true" />
          <h1 className="text-xl font-semibold text-gray-900">KGuard</h1>
        </div>
        <div>
          <label htmlFor="username" className="block text-sm font-medium text-gray-700">
            Username
          </label>
          <input
            id="username"
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label htmlFor="password" className="block text-sm font-medium text-gray-700">
            Password
          </label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        {error && (
          <p role="alert" className="text-sm text-red-600">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
