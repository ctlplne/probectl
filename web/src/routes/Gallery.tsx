import { useState } from 'react'
import styles from './Gallery.module.css'
import { Page } from './pages'
import { useTheme } from '../theme/useTheme'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ChartShell,
  EmptyState,
  Field,
  LoadingState,
  Modal,
  Sparkline,
  StatusDot,
  useToast,
} from '../components'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader title={title} />
      <CardBody>
        <div className={styles.row}>{children}</div>
      </CardBody>
    </Card>
  )
}

export function Gallery() {
  const { theme, toggleTheme } = useTheme()
  const { push } = useToast()
  const [modalOpen, setModalOpen] = useState(false)

  return (
    <Page
      title="Design system"
      subtitle="The probectl component library — every value comes from design tokens, so the whole set re-themes when the token set is swapped."
      actions={
        <Button variant="primary" onClick={toggleTheme}>
          Theme: {theme} — swap
        </Button>
      }
    >
      <Section title="Buttons">
        <Button variant="primary">Primary</Button>
        <Button variant="secondary">Secondary</Button>
        <Button variant="ghost">Ghost</Button>
        <Button variant="danger">Danger</Button>
        <Button variant="secondary" size="sm">
          Small
        </Button>
        <Button variant="primary" disabled>
          Disabled
        </Button>
      </Section>

      <Section title="Badges & status">
        <Badge tone="neutral">neutral</Badge>
        <Badge tone="accent">accent</Badge>
        <Badge tone="success">success</Badge>
        <Badge tone="warning">warning</Badge>
        <Badge tone="danger">danger</Badge>
        <Badge tone="info">info</Badge>
        <StatusDot tone="success" label="Online" />
        <StatusDot tone="danger" label="Down" />
      </Section>

      <Section title="Form fields">
        <Field label="Test name" placeholder="edge-dns" hint="A short, unique name." />
        <Field label="Target" placeholder="1.1.1.1" error="Target is required." />
      </Section>

      <Section title="Overlays & feedback">
        <Button onClick={() => setModalOpen(true)}>Open modal</Button>
        <Button onClick={() => push({ tone: 'success', title: 'Saved', message: 'Your test was created.' })}>
          Show toast
        </Button>
        <Modal
          open={modalOpen}
          onClose={() => setModalOpen(false)}
          title="Create test"
          footer={
            <>
              <Button variant="ghost" onClick={() => setModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={() => setModalOpen(false)}>
                Create
              </Button>
            </>
          }
        >
          <Field label="Test name" placeholder="edge-dns" />
        </Modal>
      </Section>

      <Section title="Charts & states">
        <ChartShell title="Latency" height={120}>
          <Sparkline label="Sample latency series" data={[12, 14, 9, 18, 22, 16, 13, 19]} />
        </ChartShell>
        <LoadingState label="Loading…" />
        <EmptyState title="Nothing here yet" description="Empty states guide the next action." />
      </Section>
    </Page>
  )
}
