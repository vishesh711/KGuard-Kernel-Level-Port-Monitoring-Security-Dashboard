import { Routes, Route } from 'react-router-dom'
import { Layout } from './components/layout/Layout'
import { LiveUpdatesProvider } from './context/LiveUpdates'
import { useAuth } from './context/auth'
import { Dashboard } from './pages/Dashboard'
import { Events } from './pages/Events'
import { Alerts } from './pages/Alerts'
import { Analytics } from './pages/Analytics'
import { Settings } from './pages/Settings'
import { Hosts } from './pages/Hosts'
import { Login } from './pages/Login'
import { AlertDetail } from './pages/AlertDetail'

function App() {
  const { session } = useAuth()
  if (!session) return <Login />

  return (
    <LiveUpdatesProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/events" element={<Events />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </Layout>
    </LiveUpdatesProvider>
  )
}

export default App
