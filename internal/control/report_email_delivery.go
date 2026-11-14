// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *DashboardReportSupervisor) deliverTenantReportEmails(ctx context.Context, tenant string, now time.Time) error {
	if s.sourceServer == nil {
		return nil
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	budget := flowstore.ExplorerQueryBudget(s.sourceServer.flowStore)
	if err := budget.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if s.sourceServer.fairnessGate == nil {
		return apierror.Unavailable("report delivery admission unavailable")
	}
	release, err := s.sourceServer.fairnessGate.BeginQuery(ctx, tenant)
	if err != nil {
		return err
	}
	var pending []store.PendingReportEmail
	scanErr := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		pending, err = (store.DashboardReports{}).PendingReportEmails(ctx, sc, now, 20)
		return err
	})
	release()
	if scanErr != nil {
		return scanErr
	}
	var failures error
	for _, item := range pending {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		failures = errors.Join(failures, s.deliverReportEmail(ctx, item, now))
	}
	return failures
}

func (s *DashboardReportSupervisor) deliverReportEmail(ctx context.Context, item store.PendingReportEmail, now time.Time) error {
	server := s.sourceServer
	budget := flowstore.ExplorerQueryBudget(server.flowStore)
	if err := budget.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if server.fairnessGate == nil {
		return apierror.Unavailable("report delivery admission unavailable")
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return tenancy.ErrNoTenant
	}
	release, err := server.fairnessGate.BeginQuery(ctx, tenant.String())
	if err != nil {
		return err
	}
	defer release()
	// A routed read transaction holds only this artifact's advisory delivery lock.
	// SMTP holds no audit stream, row lock or write transaction. Every authority
	// and completion check below uses a new transaction, never this old snapshot.
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(_ context.Context, lease tenancy.Scope) error {
		var acquired bool
		if err := lease.Q.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('report-mail:'||$1::text||':'||$2::text,0))`, lease.Tenant.String(), item.ID).Scan(&acquired); err != nil || !acquired {
			return err
		}
		attempted := false
		err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			delay := time.Minute * time.Duration(1<<min(max(item.Attempts, 0), 6))
			attempted, err = (store.DashboardReports{}).MarkReportEmailAttempt(ctx, sc, item.ID, now, now.Add(min(delay, time.Hour)))
			return err
		})
		if err != nil || !attempted {
			return err
		}
		return s.sendCurrentReportEmail(ctx, item, now)
	})
}

func (s *DashboardReportSupervisor) sendCurrentReportEmail(ctx context.Context, item store.PendingReportEmail, now time.Time) error {
	server := s.sourceServer
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return tenancy.ErrNoTenant
	}
	destination, err := server.reportEmailDestination(tenant.String(), item.DestinationID)
	if err != nil {
		return err
	}
	sender, ok := server.alertChannelDeps.Mail.(alert.AttachmentMailSender)
	if !ok {
		return apierror.Unavailable("report email transport unavailable")
	}
	current, err := loadCurrentUserAuthority(ctx, s.pool, tenant.String(), item.OwnerID)
	if err != nil {
		return err
	}
	ctx, actor, err := current.backgroundContext(ctx, reportBackgroundSourcePermissions())
	if err != nil {
		return err
	}
	if err := server.authorize(ctx, actor, "metrics.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: tenant.String()}); err != nil {
		return err
	}
	var metadata *store.ReportArtifactMetadata
	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		metadata, err = (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, item.ID, item.OwnerID, flowstore.ExplorerQueryBudget(server.flowStore).MemoryBytes/4)
		return err
	}); err != nil {
		return err
	}
	capture, err := server.authorizeStoredReportReader(ctx, actor, metadata)
	if err != nil {
		return err
	}
	verified, stage, err := server.stageStoredReport(ctx, item.ID, item.OwnerID)
	if err != nil {
		return err
	}
	defer func() { _ = stage.Close() }()
	if !sameReportArtifactMetadata(metadata, verified) {
		return apierror.Conflict("report changed during email verification")
	}
	allowed := false
	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant.String()); err != nil {
			return err
		}
		schedule, err := (store.DashboardReports{}).GetSchedule(ctx, sc, item.ScheduleID, item.OwnerID)
		if err != nil {
			return err
		}
		if !schedule.Enabled || schedule.DestinationID != item.DestinationID {
			return (store.DashboardReports{}).CompleteReportEmail(ctx, sc, item.ID, "withdrawn", now)
		}
		latest, err := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, item.ID, item.OwnerID, flowstore.ExplorerQueryBudget(server.flowStore).MemoryBytes/4)
		if err != nil {
			return err
		}
		if !sameReportArtifactMetadata(verified, latest) || latest.EmailDelivery == nil || latest.EmailDelivery.State != "pending" || latest.EmailDelivery.DestinationID != item.DestinationID {
			return apierror.Conflict("report email state changed")
		}
		owner, err := readCurrentUserAuthorityScope(ctx, sc, item.OwnerID)
		if err != nil {
			return err
		}
		fresh, principal, err := owner.backgroundContext(ctx, reportBackgroundSourcePermissions())
		if err != nil {
			return err
		}
		if err := server.authorize(fresh, principal, "metrics.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: tenant.String()}); err != nil {
			return err
		}
		if capture != nil {
			if err := server.revalidateReportFlowCaptureScope(fresh, sc, principal, capture); err != nil {
				return err
			}
		}
		_, err = audit.TenantAppend(ctx, sc, dashboardReportSchedulerActor, "dashboard.report_email_attempt", item.ID, map[string]any{"destination_id": item.DestinationID, "body_sha256": verified.BodySHA256})
		allowed = err == nil
		return err
	}); err != nil || !allowed {
		return err
	}
	if err := server.currentReportTenant(ctx, tenant.String()); err != nil {
		return err
	}
	reader, err := stage.Open(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	messageID := "<probectl-report-" + hex.EncodeToString(crypto.Hash([]byte(tenant.String()+"/"+item.ID))) + "@probectl.invalid>"
	if err := sender.SendAttachment(ctx, destination.Recipients, "[probectl] "+verified.Filename, alert.MailAttachment{Filename: verified.Filename, MediaType: verified.MediaType, MessageID: messageID, Bytes: verified.BodyBytes, Body: reader}); err != nil {
		return err
	}
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant.String()); err != nil {
			return err
		}
		if err := (store.DashboardReports{}).CompleteReportEmail(ctx, sc, item.ID, "sent", time.Now().UTC()); err != nil {
			return err
		}
		_, err := audit.TenantAppend(ctx, sc, dashboardReportSchedulerActor, "dashboard.report_email_sent", item.ID, map[string]any{"destination_id": item.DestinationID, "body_sha256": verified.BodySHA256, "body_bytes": verified.BodyBytes})
		return err
	})
}
