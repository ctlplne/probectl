// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store"
)

func TestHierarchyAPITenantScopedTree(t *testing.T) {
	h, db := setupAPI(t)
	suffix := time.Now().UnixNano()

	orgRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs", "", map[string]any{
		"slug": fmt.Sprintf("eng-%d", suffix), "name": "Engineering",
	})
	if orgRec.Code != http.StatusCreated {
		t.Fatalf("create org = %d body=%s", orgRec.Code, orgRec.Body.String())
	}
	var org store.Organization
	mustJSON(t, orgRec, &org)

	teamRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs/"+org.ID+"/teams", "", map[string]any{
		"slug": "platform", "name": "Platform",
	})
	if teamRec.Code != http.StatusCreated {
		t.Fatalf("create team = %d body=%s", teamRec.Code, teamRec.Body.String())
	}
	var team store.Team
	mustJSON(t, teamRec, &team)

	projectRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/teams/"+team.ID+"/projects", "", map[string]any{
		"slug": "edge", "name": "Edge Observability",
	})
	if projectRec.Code != http.StatusCreated {
		t.Fatalf("create project = %d body=%s", projectRec.Code, projectRec.Body.String())
	}

	list := apiReq(t, h, http.MethodGet, "/v1/hierarchy", "", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list hierarchy = %d body=%s", list.Code, list.Body.String())
	}
	var tree hierarchyResponse
	mustJSON(t, list, &tree)
	if !hierarchyContains(tree, org.ID, team.ID, "edge") {
		t.Fatalf("hierarchy missing created org/team/project: %+v", tree)
	}

	tenantB := freshTenant(t, db, "hier")
	orgBRec := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs", tenantB, map[string]any{
		"slug": fmt.Sprintf("tenant-b-%d", suffix), "name": "Tenant B",
	})
	if orgBRec.Code != http.StatusCreated {
		t.Fatalf("create tenant B org = %d body=%s", orgBRec.Code, orgBRec.Body.String())
	}
	var orgB store.Organization
	mustJSON(t, orgBRec, &orgB)

	cross := apiReq(t, h, http.MethodPost, "/v1/hierarchy/orgs/"+orgB.ID+"/teams", "", map[string]any{
		"slug": "sneaky", "name": "Sneaky",
	})
	if cross.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant parent create = %d body=%s", cross.Code, cross.Body.String())
	}

	defaultList := apiReq(t, h, http.MethodGet, "/v1/hierarchy", "", nil)
	if strings.Contains(defaultList.Body.String(), orgB.ID) || strings.Contains(defaultList.Body.String(), "Tenant B") {
		t.Fatalf("default tenant saw tenant B hierarchy: %s", defaultList.Body.String())
	}
	tenantBList := apiReq(t, h, http.MethodGet, "/v1/hierarchy", tenantB, nil)
	if !strings.Contains(tenantBList.Body.String(), orgB.ID) || strings.Contains(tenantBList.Body.String(), org.ID) {
		t.Fatalf("tenant B hierarchy not isolated: %s", tenantBList.Body.String())
	}
}

func hierarchyContains(tree hierarchyResponse, orgID, teamID, projectSlug string) bool {
	for _, org := range tree.Items {
		if org.ID != orgID {
			continue
		}
		for _, team := range org.Teams {
			if team.ID != teamID {
				continue
			}
			for _, project := range team.Projects {
				if project.Slug == projectSlug {
					return true
				}
			}
		}
	}
	return false
}
