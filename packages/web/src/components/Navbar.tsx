import { Link } from 'react-router-dom'

interface NavItem {
  path: string
  label: string
  active: boolean
}

interface NavbarProps {
  items: NavItem[]
}

export function Navbar({ items }: NavbarProps) {
  return (
    <nav className="navbar" role="navigation" aria-label="Main navigation">
      <Link to="/" className="navbar-brand">
        Kovanica
      </Link>
      <nav className="navbar-nav" aria-label="Main">
        {items.map(item => (
          <Link
            key={item.path}
            to={item.path}
            className={`nav-link ${item.active ? 'active' : ''}`}
            aria-current={item.active ? 'page' : undefined}
          >
            {item.label}
          </Link>
        ))}
      </nav>
    </nav>
  )
}