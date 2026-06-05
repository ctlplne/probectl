import { NavLink } from 'react-router-dom'
import styles from './Sidebar.module.css'
import { NAV } from '../nav/ia'
import { Icon } from '../components/Icon'
import { useBrand } from '../brand/BrandProvider'

export function Sidebar() {
  // White-label (S-T4): the wordmark/logo come from the resolved brand —
  // probectl by default, the MSP's brand when licensed and configured.
  const brand = useBrand()
  return (
    <nav className={styles.sidebar} aria-label="Primary">
      <div className={styles.brand}>
        {brand.logo_data_uri ? (
          <img className={styles.logo} src={brand.logo_data_uri} alt="" aria-hidden="true" />
        ) : (
          <span className={styles.mark} aria-hidden="true" />
        )}
        <span className={styles.wordmark}>{brand.product_name}</span>
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
