// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import styles from '../pages.module.css'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Column,
  Field,
  HonestDataState,
  LoadingState,
  Select,
  Table,
  classifySurfaceTruth,
} from '../../components'
import {
  useCreateOrganization,
  useCreateProject,
  useCreateTeam,
  useHierarchy,
} from '../../api/hierarchy'
import { flattenHierarchy, type HierarchyRow } from './hierarchyTree'
import { DateTime } from '../../time/DateTime'

/**
 * HierarchyCard (F24, DPR-254): the native surface for the tenant's
 * org -> team -> project hierarchy. `GET /v1/hierarchy` and
 * `probectl hierarchy show` have always served it, and there was no screen, so
 * a tenant administrator could see and change the structure their RBAC/ABAC
 * scopes are written against only from a terminal.
 *
 * The tree the server returns is what THIS principal may read — ABAC prunes
 * branches per node — so the card says so rather than presenting it as the
 * whole tenant. Creation is a separate permission (`org.write`); when the
 * server refuses, the card surfaces its message instead of hiding the control
 * and pretending the structure is fixed.
 */

const INDENT: Record<HierarchyRow['level'], number> = { organization: 0, team: 1, project: 2 }

export function HierarchyCard() {
  const { data, isPending, isError, error, refetch } = useHierarchy()
  const createOrg = useCreateOrganization()
  const createTeam = useCreateTeam()
  const createProject = useCreateProject()

  const [level, setLevel] = useState<HierarchyRow['level']>('organization')
  const [parentID, setParentID] = useState('')
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [formError, setFormError] = useState('')

  const tree = data ?? { items: [] }
  const rows = flattenHierarchy(tree)
  const orgOptions = tree.items.map((org) => ({ value: org.id, label: org.name }))
  const teamOptions = tree.items.flatMap((org) =>
    org.teams.map((team) => ({ value: team.id, label: `${org.name} / ${team.name}` })),
  )
  const parentOptions = level === 'team' ? orgOptions : level === 'project' ? teamOptions : []
  const pending = createOrg.isPending || createTeam.isPending || createProject.isPending

  const columns: Column<HierarchyRow>[] = [
    {
      key: 'node',
      header: 'Node',
      render: (row) => (
        <span style={{ paddingInlineStart: `calc(var(--space-4) * ${INDENT[row.level]})` }}>
          <strong>{row.name}</strong> <code>{row.slug}</code>
        </span>
      ),
    },
    {
      key: 'level',
      header: 'Level',
      render: (row) => (
        <Badge
          tone={row.level === 'organization' ? 'info' : row.level === 'team' ? 'accent' : 'neutral'}
        >
          {row.level}
        </Badge>
      ),
    },
    { key: 'parent', header: 'Within', render: (row) => row.parent ?? 'the tenant' },
    { key: 'updated', header: 'Updated', render: (row) => <DateTime value={row.updated_at} /> },
  ]

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setFormError('')
    const input = { name: name.trim(), slug: slug.trim() }
    if (!input.name || !input.slug) {
      setFormError('A name and a slug are both required.')
      return
    }
    if (level !== 'organization' && !parentID) {
      setFormError(
        level === 'team'
          ? 'Choose the organization this team belongs to.'
          : 'Choose the team this project belongs to.',
      )
      return
    }
    try {
      if (level === 'organization') {
        await createOrg.mutateAsync(input)
      } else if (level === 'team') {
        await createTeam.mutateAsync({ orgID: parentID, input })
      } else {
        await createProject.mutateAsync({ teamID: parentID, input })
      }
      setName('')
      setSlug('')
    } catch (err) {
      // The server's own refusal — 403 from ABAC, 409 on a duplicate slug, 422
      // on a shape it will not accept — is more useful than anything invented
      // here, so it is shown verbatim.
      setFormError(err instanceof Error ? err.message : 'The server refused the change.')
    }
  }

  const retry = (
    <Button variant="secondary" onClick={() => void refetch()}>
      Reload the hierarchy
    </Button>
  )

  return (
    <Card>
      <CardHeader
        title="Organizations, teams and projects"
        description="The structure this tenant's roles and ABAC rules are written against. You see the branches your own permissions allow; creating one needs org.write."
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Loading the tenant hierarchy…" />
        ) : isError ? (
          <HonestDataState
            state={classifySurfaceTruth({ error })}
            producer="Tenant hierarchy store"
            producerReadiness="The tenant-scoped hierarchy response is unavailable"
            lastSuccessfulIngest={null}
            coverageLimitation="No structure is shown because it could not be read. An empty screen here is not evidence that the tenant has no organizations."
            action={retry}
          />
        ) : (
          <>
            {rows.length === 0 ? (
              <HonestDataState
                state="ready-no-data"
                icon="admin"
                title="No organizations yet"
                producer="Tenant hierarchy store"
                producerReadiness="Ready; the server returned no organizations you may read"
                lastSuccessfulIngest={null}
                coverageLimitation="Either this tenant is flat, or ABAC withholds every branch from you. The tree shows what your permissions allow, never the whole tenant."
                action={retry}
              />
            ) : (
              <Table
                caption="Tenant organization, team and project hierarchy"
                columns={columns}
                rows={rows}
                rowKey={(row) => row.id}
              />
            )}
            <form className={styles.form} onSubmit={(event) => void submit(event)}>
              <Select
                label="Level"
                id="hierarchy-level"
                value={level}
                onChange={(event) => {
                  setLevel(event.target.value as HierarchyRow['level'])
                  setParentID('')
                  setFormError('')
                }}
                options={[
                  { value: 'organization', label: 'Organization' },
                  { value: 'team', label: 'Team' },
                  { value: 'project', label: 'Project' },
                ]}
              />
              {level !== 'organization' && (
                <Select
                  label={level === 'team' ? 'Within organization' : 'Within team'}
                  id="hierarchy-parent"
                  value={parentID}
                  onChange={(event) => setParentID(event.target.value)}
                  options={[{ value: '', label: 'Choose one…' }, ...parentOptions]}
                />
              )}
              <Field
                label="Name"
                id="hierarchy-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Platform Engineering"
              />
              <Field
                label="Slug"
                id="hierarchy-slug"
                hint="Stable identifier used by roles and ABAC rules; it cannot be changed later."
                value={slug}
                onChange={(event) => setSlug(event.target.value)}
                placeholder="platform-eng"
              />
              <Button type="submit" disabled={pending}>
                {pending ? 'Creating…' : `Create ${level}`}
              </Button>
            </form>
            {formError && (
              <p className={styles.subtitle} role="alert">
                {formError}
              </p>
            )}
          </>
        )}
      </CardBody>
    </Card>
  )
}
