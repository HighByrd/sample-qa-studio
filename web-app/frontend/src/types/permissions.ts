/**
 * Types for team-based permissions and user management.
 */

export type AccessLevel = 'view' | 'execute' | 'full';

export type Role = 'admin' | 'team_lead' | 'editor' | 'executor' | 'viewer';

export interface Team {
  id: string;
  name: string;
  description?: string;
  memberCount: number;
  applicationCount: number;
  created_by?: string;
  created_at?: string;
}

export interface Member {
  userId: string;
  email?: string;
  role: Role;
  joinedAt: string;
}

export interface SharedAccessGrant {
  grantId: string;
  targetTeamId: string;
  targetTeamName: string;
  appId?: string;
  accessLevel: AccessLevel;
  grantedAt: string;
}

export interface UserWithTeams {
  userId: string;
  email: string;
  teams: Array<{ teamId: string; name: string; role: Role }>;
  isAdmin?: boolean;
}
