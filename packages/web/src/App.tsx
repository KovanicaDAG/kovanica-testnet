import { Routes, Route, useLocation } from 'react-router-dom'
import { Explorer } from './pages/Explorer'
import { Wallet } from './pages/Wallet'
import { StatusPage } from './pages/StatusPage'
import { Navbar } from './components/Navbar'

const navItems = [
  { path: '/', label: 'Explorer' },
  { path: '/wallet', label: 'Wallet' },
  { path: '/status', label: 'Status' },
] as const

export function App() {
  const location = useLocation()

  return (
    <div className="app">
      <Navbar
        items={navItems.map(item => ({
          path: item.path,
          label: item.label,
          active: location.pathname === item.path,
        }))}
      />
      <main className="page">
        <Routes>
          <Route path="/" element={<Explorer />} />
          <Route path="/wallet" element={<Wallet />} />
          <Route path="/status" element={<StatusPage />} />
        </Routes>
      </main>
    </div>
  )
}