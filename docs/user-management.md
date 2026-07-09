# User Management Guide

This guide explains how to manage users, teams, and access control in QA Studio.

## Concepts

### Teams

Teams are the primary unit of access control. An application belongs to a team, and only members of that team (plus admins) can see and interact with it.

### Roles

Every team member has one of five roles, from most to least privileged:

| Role | Can do |
|------|--------|
| **Admin** | Everything. Studio-wide access to all teams, apps, users. Can create/delete teams, assign users, reassign apps. |
| **Team Lead** | Manage their team's members (add/remove, change roles up to Team Lead). Create apps within their team. Grant shared access. Cannot delete teams or assign Admin role. |
| **Editor** | Create and edit use cases and test suites within their team's apps. |
| **Executor** | Run (execute) use cases and test suites. Cannot create or modify them. |
| **Viewer** | Read-only access to their team's apps, use cases, and results. |

**Important:** Admin is a studio-wide role. A user with Admin role in any team has full access to the entire system, not just that team.

### Applications, Use Cases, and Test Suites

The access hierarchy is:

```
Team
 └── Application (owned by team via "owner_team_id")
      ├── Use Cases (inherit app's team ownership)
      └── Test Suites (inherit app's team ownership)
```

- **Applications** are the ownership boundary. Each app belongs to one team.
- **Use cases** and **test suites** live inside applications. Access is controlled at the application level — if you can see the app, you can see its contents (subject to your role's permissions).
- Users navigate to their team's apps, then manage use cases and test suites from within.

## Admin Workflows

### Creating a User

1. Go to **Administration > Users**
2. Click **Create User**
3. Enter the user's email address
4. Optionally select a team and role (you can assign later)
5. Click **Create User**

The user receives a temporary password via email. If no team is assigned, the user will see an empty dashboard until they're added to a team.

### Creating a Team

1. Go to **Administration > Teams**
2. Click **Create Team**
3. Enter a team name and optional description
4. Click **Create Team**

This creates the team and provisions 5 Cognito role groups (`team-{id}-admin`, `team-{id}-team_lead`, etc.).

### Adding Members to a Team

1. Go to **Administration > Teams** and click a team name
2. Go to the **Members** tab
3. Click **Add Member**
4. Enter the user's email (they must already exist — created via Create User)
5. Select a role
6. Click **Add Member**

### Assigning an Application to a Team

New applications can be assigned at creation time via the Team dropdown. For existing applications:

1. Go to **Applications** and click the app name
2. Click **Assign to team** (visible to admins only)
3. Select the target team
4. Click **Reassign**

Once assigned, only that team's members (and admins) can see and interact with the application.

### Editing a User's Role

1. Go to **Administration > Users**
2. Click **Edit** next to the user
3. Change the team and/or role
4. Click **Save**

## Team Lead Workflows

Team Leads can manage their own team without needing an Admin.

### Adding Members

1. Go to **My Team** (sidebar)
2. Click **Add Member**
3. Enter the user's email and select a role (cannot assign Admin)

### Creating Applications

1. Go to **Applications** > **Create Application**
2. Your team is pre-selected in the Team dropdown
3. The app will be automatically owned by your team

### Managing Use Cases and Test Suites

Navigate through **Applications** → click your app → manage use cases and test suites from the app's detail page.

## How Access Control Works

### What each role sees in the sidebar

| Role | Sidebar items |
|------|--------------|
| Admin | Dashboard, Applications, Use Cases, Test Suites, Templates, Teams, Users, OAuth Clients |
| Team Lead | Dashboard, Applications, Templates, My Team |
| Editor / Executor / Viewer | Dashboard, Applications, Templates |
| Unassigned (no team) | Empty dashboard with "Forbidden" — contact admin |

### Application visibility

- **Admins** see all applications across all teams
- **Non-admins** see only applications owned by their team
- **Unassigned users** see nothing

### Use case / test suite access

Access is inherited from the parent application:

| Action | Required role |
|--------|--------------|
| View use cases / results | Viewer or above |
| Execute use cases | Executor or above |
| Create / edit use cases | Editor or above |
| Delete use cases | Editor or above (must be creator or Admin) |

### Shared Access

Teams can grant other teams access to their applications:

1. Go to Team Detail > **Shared Access** tab
2. Click **Grant Access**
3. Select the target team and access level (View, Execute, or Full)

The **ceiling rule** applies: a user's effective permission on a shared app = min(their_role_permissions, shared_access_level). For example, a Viewer accessing an app shared with "Full (edit)" access remains view-only.

## Unassigned Users

Users created without a team assignment:
- Can log in (Cognito account exists)
- See an empty/forbidden dashboard
- Cannot access any applications, use cases, or test suites
- Must be added to a team by an Admin or Team Lead before they can do anything

## First-time rollout

There is **no migration step** — v1.3 is backward-compatible by construction and
secure by default:

- **Existing applications** have no owning team, so they are treated as unowned
  and are visible only to admins until explicitly assigned to a team.
- **Existing admins** (users in the `admins` Cognito group) retain full access
  immediately — nothing changes for them.
- **Existing non-admin users** have no team membership, so they see empty lists
  until an admin sets up teams and assigns them + the relevant applications.

This is a deliberate, fail-closed rollout: access is granted intentionally
rather than left open. Expect a short setup window during which non-admin users
have no visible resources — communicate this before upgrading.

**Admin setup after upgrade:**
1. Log in as an admin (the bootstrap admin from the auth stack always qualifies).
2. Create teams (Administration → Teams).
3. Assign users to teams with appropriate roles (Administration → Users).
4. Assign applications to teams (app detail → "Assign to team").

Once an app is assigned to a team, its members gain access per their role. Until
then it remains admin-only.

## FAQ

**Q: Can a user belong to multiple teams?**
A: The data model supports it (multiple membership records), but the current UI assumes one team per user.

**Q: What happens to apps when a team is deleted?**
A: Applications lose their `owner_team_id` and become invisible to non-admins. An admin should reassign them first.

**Q: Can I change the owner of an application?**
A: Yes — admins can click "Assign to team" on any application's detail page.

**Q: Why does a new user see "Forbidden"?**
A: They have no team assignment, so they have no scopes. The dashboard API requires `api/applications.read` which they don't have. Add them to a team to grant access.
