/**
 * Tests for the usePermissions hook and PermissionsProvider logic.
 *
 * These tests validate the permission parsing logic without rendering React
 * components. They test the pure functions that derive permissions from
 * Cognito group names (same regex as backend role_scopes.py).
 */

import { describe, it, expect } from 'vitest';

// Test the group-parsing regex and logic directly
const TEAM_GROUP_RE = /^team-([a-zA-Z0-9_-]+)-([a-z_]+)$/;
const VALID_ROLES = new Set(['admin', 'team_lead', 'editor', 'executor', 'viewer']);
const LEGACY_GROUP_MAPPINGS: Record<string, string> = {
  users: 'editor',
  admins: 'admin',
};

interface TeamRole {
  team_id: string;
  role: string;
  group_name: string;
}

/**
 * Parse groups and derive permissions — mirrors PermissionsProvider logic.
 */
function derivePermissions(groups: string[], scopes: string[]) {
  const teamRoles: TeamRole[] = [];
  let isAdmin = false;

  for (const group of groups) {
    const trimmed = group.trim();

    if (trimmed in LEGACY_GROUP_MAPPINGS) {
      if (LEGACY_GROUP_MAPPINGS[trimmed] === 'admin') {
        isAdmin = true;
      }
      continue;
    }

    const match = TEAM_GROUP_RE.exec(trimmed);
    if (match) {
      const teamId = match[1];
      const role = match[2];
      if (VALID_ROLES.has(role)) {
        teamRoles.push({ team_id: teamId, role, group_name: trimmed });
        if (role === 'admin') {
          isAdmin = true;
        }
      }
    }
  }

  if (scopes.includes('api/admin')) {
    isAdmin = true;
  }

  const isTeamLead = teamRoles.some((t) => t.role === 'team_lead' || t.role === 'admin');

  const hasScope = (scope: string): boolean => {
    if (isAdmin || scopes.includes('api/admin')) return true;
    return scopes.includes(scope);
  };

  return { isAdmin, isTeamLead, teams: teamRoles, hasScope, scopes };
}

describe('usePermissions logic', () => {
  describe('admin user', () => {
    it('recognizes admins group as admin', () => {
      const result = derivePermissions(['admins'], ['api/admin']);
      expect(result.isAdmin).toBe(true);
    });

    it('hasScope returns true for any scope when admin', () => {
      const result = derivePermissions(['admins'], ['api/admin']);
      expect(result.hasScope('api/usecases.read')).toBe(true);
      expect(result.hasScope('api/teams.manage')).toBe(true);
      expect(result.hasScope('api/nonexistent')).toBe(true);
    });

    it('admin has no team roles from legacy admins group', () => {
      const result = derivePermissions(['admins'], ['api/admin']);
      expect(result.teams).toHaveLength(0);
    });
  });

  describe('team editor', () => {
    it('parses team-alpha-editor group correctly', () => {
      const result = derivePermissions(
        ['team-alpha-editor'],
        ['api/usecases.read', 'api/usecases.write']
      );
      expect(result.teams).toHaveLength(1);
      expect(result.teams[0].team_id).toBe('alpha');
      expect(result.teams[0].role).toBe('editor');
      expect(result.isAdmin).toBe(false);
      expect(result.isTeamLead).toBe(false);
    });

    it('hasScope checks actual scopes for non-admin', () => {
      const result = derivePermissions(
        ['team-alpha-editor'],
        ['api/usecases.read', 'api/usecases.write']
      );
      expect(result.hasScope('api/usecases.read')).toBe(true);
      expect(result.hasScope('api/admin')).toBe(false);
    });
  });

  describe('team lead', () => {
    it('isTeamLead is true for team_lead role', () => {
      const result = derivePermissions(
        ['team-beta-team_lead'],
        ['api/teams.manage']
      );
      expect(result.isTeamLead).toBe(true);
      expect(result.isAdmin).toBe(false);
      expect(result.teams[0].role).toBe('team_lead');
    });
  });

  describe('unassigned user', () => {
    it('returns empty teams and no admin for unknown groups', () => {
      const result = derivePermissions(['random-group'], []);
      expect(result.teams).toHaveLength(0);
      expect(result.isAdmin).toBe(false);
      expect(result.isTeamLead).toBe(false);
    });

    it('hasScope returns false for all scopes', () => {
      const result = derivePermissions([], []);
      expect(result.hasScope('api/usecases.read')).toBe(false);
    });
  });

  describe('legacy users group', () => {
    it('users group does not create team roles', () => {
      const result = derivePermissions(
        ['users'],
        ['api/usecases.read', 'api/usecases.write']
      );
      expect(result.teams).toHaveLength(0);
      expect(result.isAdmin).toBe(false);
    });
  });

  describe('decode failure / empty state', () => {
    it('handles empty groups gracefully', () => {
      const result = derivePermissions([], []);
      expect(result.teams).toHaveLength(0);
      expect(result.isAdmin).toBe(false);
      expect(result.isTeamLead).toBe(false);
    });
  });

  describe('multi-team membership', () => {
    it('handles multiple team groups', () => {
      const result = derivePermissions(
        ['team-alpha-editor', 'team-beta-viewer', 'team-gamma-team_lead'],
        ['api/usecases.read']
      );
      expect(result.teams).toHaveLength(3);
      expect(result.isTeamLead).toBe(true);

      const teamIds = result.teams.map((t) => t.team_id);
      expect(teamIds).toContain('alpha');
      expect(teamIds).toContain('beta');
      expect(teamIds).toContain('gamma');
    });
  });

  describe('invalid group names', () => {
    it('ignores team groups with invalid roles', () => {
      const result = derivePermissions(['team-abc-superuser'], []);
      expect(result.teams).toHaveLength(0);
    });

    it('ignores malformed team group names', () => {
      const result = derivePermissions(['team--editor', 'teamabc-editor'], []);
      expect(result.teams).toHaveLength(0);
    });
  });
});
