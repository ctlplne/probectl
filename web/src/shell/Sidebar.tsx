import { NavLink } from 'react-router-dom'
import styles from './Sidebar.module.css'
import { NAV, NAV_GROUPS } from '../nav/ia'
import { Icon } from '../components/Icon'
import { useBrand } from '../brand/BrandProvider'
import { useI18n } from '../i18n/useI18n'

export function Sidebar() {
  // White-label (S-T4): the wordmark/logo come from the resolved brand -
  // probectl by default, the MSP's brand when licensed and configured.
  const brand = useBrand()
  const { t } = useI18n()
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

      {/* Grouped IA: each group is a labelled list so the 14-item nav reads as
          a structured product rather than one flat column. */}
      {NAV_GROUPS.map((group) => {
        const items = NAV.filter((item) => item.group === group.id)
        if (items.length === 0) return null
        return (
          <div key={group.id} className={styles.group}>
            <p className={styles.groupLabel}>{t(group.labelKey)}</p>
            <ul className={styles.list} role="list">
              {items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    className={({ isActive }) =>
                      [styles.link, isActive ? styles.active : ''].join(' ')
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <span className={styles.icon} aria-hidden="true">
                          <Icon name={item.icon} />
                        </span>
                        <span>{t(item.labelKey)}</span>
                        {isActive ? <span className="sr-only">{t('nav.current')}</span> : null}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        )
      })}
    </nav>
  )
}
