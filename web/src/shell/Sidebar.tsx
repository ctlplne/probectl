import { NavLink } from 'react-router-dom'
import styles from './Sidebar.module.css'
import { NAV } from '../nav/ia'
import { Icon } from '../components/Icon'

export function Sidebar() {
  return (
    <nav className={styles.sidebar} aria-label="Primary">
      <div className={styles.brand}>
        <span className={styles.mark} aria-hidden="true" />
        <span className={styles.wordmark}>probectl</span>
      </div>
      <ul className={styles.list} role="list">
        {NAV.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              className={({ isActive }) => [styles.link, isActive ? styles.active : ''].join(' ')}
            >
              {({ isActive }) => (
                <>
                  <span className={styles.icon} aria-hidden="true">
                    <Icon name={item.icon} />
                  </span>
                  <span>{item.label}</span>
                  {isActive ? <span className="sr-only"> (current)</span> : null}
                </>
              )}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  )
}
