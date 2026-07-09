import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { PermissionsContext, TeamRole } from './PermissionsContext';

/**
 * Team group naming regex: team-{teamId}-{role}
 * Matches the backend role_scopes.py parse_group pattern.
 */
const TEAM_GROUP_RE = /^team-([a-zA-Z0-9_-]+)-([a-z_]+)$/;

const VALID_ROLES = new Set(['admin', 'team_lead', 'editor', 'executor', 'viewer']);

const LEGACY_GROUP_MAPPINGS: Record<string, string> = {
  users: 'editor',
  admins: 'admin',
};

interface PermissionsProviderProps {
  children: React.ReactNode;
}

export function PermissionsProvider({ children }: PermissionsProviderProps) {
  const [scopes, setScopes] = useState<string[]>([]);
  const [teams, setTeams] = useState<TeamRole[]>([]);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const extractPermissions = async () => {
      try {
        const { fetchAuthSession } = await import('aws-amplify/auth');
        const session = await fetchAuthSession();

        if (session.tokens?.idToken) {
          const idTokenString = session.tokens.idToken.toString();
          const payload = JSON.parse(atob(idTokenString.split('.')[1]));

          // Extract scopes
          const scopeStr = payload.scope || '';
          const parsedScopes = scopeStr.split(' ').filter((s: string) => s.length > 0);
          setScopes(parsedScopes);

          // Extract groups and derive team context
          const groups: string[] = payload['cognito:groups'] || [];
          const teamRoles: TeamRole[] = [];
          let adminDetected = false;

          for (const group of groups) {
            const trimmed = group.trim();

            // Check legacy groups
            if (trimmed in LEGACY_GROUP_MAPPINGS) {
              if (LEGACY_GROUP_MAPPINGS[trimmed] === 'admin') {
                adminDetected = true;
              }
              continue;
            }

            // Check team group pattern
            const match = TEAM_GROUP_RE.exec(trimmed);
            if (match) {
              const teamId = match[1];
              const role = match[2];
              if (VALID_ROLES.has(role)) {
                teamRoles.push({ team_id: teamId, role, group_name: trimmed });
                if (role === 'admin') {
                  adminDetected = true;
                }
              }
            }
          }

          // Also check scopes for admin
          if (parsedScopes.includes('api/admin')) {
            adminDetected = true;
          }

          setTeams(teamRoles);
          setIsAdmin(adminDetected);
        }
      } catch (error) {
        console.error('Failed to extract permissions:', error);
        setScopes([]);
        setTeams([]);
        setIsAdmin(false);
      } finally {
        setIsLoading(false);
      }
    };

    extractPermissions();
  }, []);

  const hasScope = useCallback(
    (scope: string): boolean => {
      if (isAdmin || scopes.includes('api/admin')) {
        return true;
      }
      return scopes.includes(scope);
    },
    [scopes, isAdmin]
  );

  const isTeamLead = useMemo(
    () => teams.some((t) => t.role === 'team_lead' || t.role === 'admin'),
    [teams]
  );

  const value = useMemo(
    () => ({
      hasScope,
      isAdmin,
      isTeamLead,
      teams,
      isLoading,
      scopes,
    }),
    [hasScope, isAdmin, isTeamLead, teams, isLoading, scopes]
  );

  return (
    <PermissionsContext.Provider value={value}>
      {children}
    </PermissionsContext.Provider>
  );
}
