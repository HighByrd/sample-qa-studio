"""
Resource authorization decision engine.

Implements the 9-step authorize_resource algorithm (BL-2) with:
- Admin bypass (FR-1.3)
- Ceiling rule for shared access (FR-3.3)
- Creator-retains-edit override (FR-4.1, bounded by FR-4.3)
- Per-test-case override narrowing (FR-5.1, FR-5.2)
- Deny-by-default on any error

This is the second enforcement layer, called by mutation handlers after require_scopes.
"""

import functools
import logging

from utils import extract_user_identity, create_response
from permissions_repo import (
    get_app_owner,
    list_shared_access,
    list_apps_shared_with_team,
    get_testcase_override,
    list_user_teams,
    get_team,
)
from role_scopes import ROLE_RANK, ACCESS_RANK

logger = logging.getLogger()

# Sentinel distinguishing "owner not supplied" from a legitimate None owner
# (None means an orphaned app → deny). Callers that already hold the resource
# pass owner_team_id explicitly to avoid a redundant get_app_owner() read.
_UNSET = object()

# ---------------------------------------------------------------------------
# Permission Level Mappings
# ---------------------------------------------------------------------------

# Maps a team role to an effective permission level name
_ROLE_TO_LEVEL = {
    'admin': 'full',
    'team_lead': 'full',
    'editor': 'full',
    'executor': 'execute',
    'viewer': 'view',
}

# Action requirements: minimum effective level needed to perform each action
_ACTION_REQUIRES = {
    'view': 'view',
    'execute': 'execute',
    'edit': 'full',
    'delete': 'full',
}


def _level_rank(level: str) -> int:
    """Return numeric rank for a permission level. Higher = more access."""
    return ACCESS_RANK.get(level, 0)


# ---------------------------------------------------------------------------
# Core Helpers
# ---------------------------------------------------------------------------


def effective_permission(caller_role: str, shared_level: str) -> str:
    """
    Compute effective permission using the ceiling rule (BL-3, FR-3.3).

    effective = min(role_to_level(caller_role), access_level(shared_level))

    Args:
        caller_role: The caller's role in their team (e.g. 'editor', 'viewer').
        shared_level: The shared access level granted (e.g. 'full', 'execute', 'view').

    Returns:
        Effective permission level string: 'full', 'execute', or 'view'.
    """
    role_level = _ROLE_TO_LEVEL.get(caller_role, 'view')
    role_rank = _level_rank(role_level)
    shared_rank = _level_rank(shared_level)

    effective_rank = min(role_rank, shared_rank)

    # Map rank back to level name
    for level, rank in sorted(ACCESS_RANK.items(), key=lambda x: x[1]):
        if rank == effective_rank:
            return level

    return 'view'  # Deny-by-default: lowest permission


def can_act(effective_level: str, action: str) -> bool:
    """
    Check if the effective permission level is sufficient for the action (BL-4).

    Args:
        effective_level: Computed effective permission ('full', 'execute', 'view').
        action: Requested action ('view', 'execute', 'edit', 'delete').

    Returns:
        True if action is allowed, False otherwise.
    """
    required_level = _ACTION_REQUIRES.get(action)
    if required_level is None:
        return False  # Unknown action → deny

    return _level_rank(effective_level) >= _level_rank(required_level)


# ---------------------------------------------------------------------------
# Main Authorization Function (BL-2)
# ---------------------------------------------------------------------------


def authorize_resource(event: dict, app_id: str, action: str, created_by: str = None,
                       owner_team_id=_UNSET):
    """
    Second enforcement layer — resource-level authorization.

    Implements the full 9-step algorithm from BL-2:
    1. Extract identity
    2. Admin → ALLOW
    3. Get app owner (None → DENY orphaned)
    4. Direct team membership check
    5. Shared access check (ceiling rule)
    6. No access path → DENY
    7. can_act check
    8. Creator-retains-edit override
    9. ALLOW

    Args:
        event: API Gateway proxy event (with identity from authorizer).
        app_id: The application ID being accessed.
        action: One of 'view', 'execute', 'edit', 'delete'.
        created_by: Optional sub of the resource creator (for creator-retains-edit).
            If None, the creator override is skipped.
        owner_team_id: Optional owning-team id. When supplied (callers that
            already loaded the resource/app), the internal get_app_owner() read
            is skipped — saving a DynamoDB round-trip. Pass None to signal an
            explicitly orphaned resource. Omit to let this function read it.

    Returns:
        Tuple of (identity_dict, error_response_or_None).
        On allow: (identity, None)
        On deny: (identity, error_response_dict)
    """
    identity = None
    try:
        # Step 1: Extract identity
        identity = extract_user_identity(event)

        # Step 2: Admin bypass (FR-1.3)
        if identity.get('is_admin', False):
            logger.info(f"admin_bypass: sub={identity.get('sub')} app={app_id} action={action}")
            return identity, None

        # Step 3: Resolve app owner. Use the caller-supplied value when present
        # (avoids a redundant read); otherwise look it up.
        if owner_team_id is _UNSET:
            owner_team_id = get_app_owner(app_id)
        if owner_team_id is None:
            # Orphaned app — deny for non-admins (BR-4)
            logger.warning(f"orphaned_app_deny: sub={identity.get('sub')} app={app_id}")
            return identity, create_response(403, {
                'error': 'Forbidden',
                'message': 'Application not accessible',
            })

        # Get caller's team membership info
        team_roles = identity.get('team_roles', [])
        caller_team_ids = {tr['team_id'] for tr in team_roles if 'team_id' in tr}

        effective_level = None

        # Step 4: Check direct team membership
        caller_role_in_owner_team = None
        for tr in team_roles:
            if tr.get('team_id') == owner_team_id:
                caller_role_in_owner_team = tr.get('role')
                break

        if caller_role_in_owner_team:
            # Direct member of the owner team
            effective_level = _ROLE_TO_LEVEL.get(caller_role_in_owner_team, 'view')
        else:
            # Step 5: Check shared access (ceiling rule)
            grants = list_shared_access(owner_team_id)
            matched_grant = None
            caller_role_in_target_team = None

            for grant in grants:
                target_team_id = grant.get('target_team_id')
                grant_app_id = grant.get('app_id')

                if grant_app_id == app_id and target_team_id in caller_team_ids:
                    # Found a matching grant — find caller's role in the target team
                    for tr in team_roles:
                        if tr.get('team_id') == target_team_id:
                            matched_grant = grant
                            caller_role_in_target_team = tr.get('role')
                            break
                    if matched_grant:
                        break

            if matched_grant and caller_role_in_target_team:
                shared_level = matched_grant.get('level', 'view')
                effective_level = effective_permission(caller_role_in_target_team, shared_level)
            else:
                # Step 6: No access path found
                logger.info(f"no_access_path: sub={identity.get('sub')} app={app_id}")
                return identity, create_response(403, {
                    'error': 'Forbidden',
                    'message': 'No access to this application',
                })

        # Step 7: Check action against effective permission
        if can_act(effective_level, action):
            # Step 9: ALLOW
            return identity, None

        # Step 8: Creator-retains-edit override (FR-4.1, bounded by FR-4.3)
        if action == 'edit' and created_by and not can_act(effective_level, 'edit'):
            # Creator override only grants 'edit' — NOT 'delete'
            caller_sub = identity.get('sub', '')

            # Condition 1: caller.sub == resource.created_by
            if caller_sub and caller_sub == created_by:
                # Condition 2 (FR-4.3): caller still has team membership
                has_team_membership = (
                    caller_role_in_owner_team is not None
                    or owner_team_id in caller_team_ids
                )

                if has_team_membership:
                    logger.info(
                        f"creator_override_granted: sub={caller_sub} app={app_id}"
                    )
                    return identity, None

        # Action not permitted
        logger.info(
            f"insufficient_permissions: sub={identity.get('sub')} app={app_id} "
            f"action={action} effective={effective_level}"
        )
        return identity, create_response(403, {
            'error': 'Forbidden',
            'message': 'Insufficient permissions for this action',
        })

    except Exception as e:
        # Deny-by-default: any exception results in a 500 deny
        logger.error(f"authorize_resource_error: {e}", exc_info=True)
        if identity is None:
            identity = {'sub': '', 'identity': 'unknown', 'identity_type': 'unknown'}
        return identity, create_response(500, {
            'error': 'Internal Server Error',
            'message': 'Authorization check failed',
        })


# ---------------------------------------------------------------------------
# Handler decorator — centralizes the authorize_resource call site (DRY)
# ---------------------------------------------------------------------------


def require_resource_access(action: str, resolver):
    """
    Decorator that enforces resource-level authorization before a handler runs.

    Removes the repeated import/call/guard boilerplate from every resource
    handler. Apply AFTER the handler has validated scopes (require_scopes),
    typically by calling require_scopes at the top of `resolver`.

    Args:
        action: One of 'view', 'execute', 'edit', 'delete'.
        resolver: Callable(event) -> dict describing the target resource:
            {
              'app_id': <str>,                # required
              'owner_team_id': <str|None>,    # optional — supply to skip a read
              'created_by': <str|None>,       # optional — creator-retains-edit
              'error': <response|None>,       # optional — short-circuit (e.g. 404)
            }
            If 'error' is present and truthy, it is returned immediately (lets
            the resolver surface not-found/validation errors before auth).

    Returns:
        The wrapped handler, or a 403/error response when access is denied.
    """
    def decorator(handler):
        @functools.wraps(handler)
        def wrapper(event, *args, **kwargs):
            resolved = resolver(event)
            if resolved.get('error'):
                return resolved['error']

            owner = resolved['owner_team_id'] if 'owner_team_id' in resolved else _UNSET
            _, auth_err = authorize_resource(
                event,
                resolved['app_id'],
                action,
                created_by=resolved.get('created_by'),
                owner_team_id=owner,
            )
            if auth_err:
                return auth_err
            return handler(event, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# List Filtering (BL-5)
# ---------------------------------------------------------------------------


def annotate_app_source(identity: dict, app: dict, owner_team_id: str) -> dict:
    """
    Annotate an app with source metadata for the current user.

    Adds 'source', 'sharedFrom', and 'effectiveLevel' fields.

    Args:
        identity: Caller identity dict (from extract_user_identity).
        app: Application dict to annotate.
        owner_team_id: The app's owner team ID.

    Returns:
        Annotated app dict (mutated in-place and returned).
    """
    team_roles = identity.get('team_roles', [])
    caller_team_ids = {tr['team_id'] for tr in team_roles if 'team_id' in tr}

    if owner_team_id in caller_team_ids:
        app['source'] = 'owned'
        # Find caller's role in the owner team
        for tr in team_roles:
            if tr.get('team_id') == owner_team_id:
                app['effectiveLevel'] = _ROLE_TO_LEVEL.get(tr.get('role'), 'view')
                break
    else:
        app['source'] = 'shared'
        # Find the grant and compute effective level
        try:
            grants = list_shared_access(owner_team_id)
            app_id = app.get('id') or app.get('app_id', '')
            for grant in grants:
                target_team_id = grant.get('target_team_id')
                if grant.get('app_id') == app_id and target_team_id in caller_team_ids:
                    for tr in team_roles:
                        if tr.get('team_id') == target_team_id:
                            shared_level = grant.get('level', 'view')
                            app['effectiveLevel'] = effective_permission(tr.get('role'), shared_level)
                            break
                    # Try to get the owner team name
                    owner_team = get_team(owner_team_id)
                    app['sharedFrom'] = owner_team.get('name', owner_team_id) if owner_team else owner_team_id
                    break
        except Exception:
            app['sharedFrom'] = owner_team_id
            app['effectiveLevel'] = 'view'

    return app


def filter_visible_apps(identity: dict, apps: list) -> list:
    """
    Filter and annotate applications based on caller's access (BL-5).

    Args:
        identity: Caller identity dict.
        apps: List of application dicts (each must have 'owner_team_id').

    Returns:
        Filtered list of apps the caller can see, annotated with source info.
    """
    # Admin sees everything
    if identity.get('is_admin', False):
        for app in apps:
            app['source'] = 'owned'
            app['effectiveLevel'] = 'full'
        return apps

    team_roles = identity.get('team_roles', [])
    caller_team_ids = {tr['team_id'] for tr in team_roles if 'team_id' in tr}

    if not caller_team_ids:
        return []

    visible = []

    # Build a lookup of incoming shares for all caller's teams
    incoming_grants = {}
    for team_id in caller_team_ids:
        try:
            grants = list_apps_shared_with_team(team_id)
            for grant in grants:
                grant_app_id = grant.get('app_id', '')
                if grant_app_id:
                    incoming_grants.setdefault(grant_app_id, []).append(grant)
        except Exception:
            pass

    for app in apps:
        owner_team_id = app.get('owner_team_id')

        # Skip orphaned apps for non-admins (BR-4)
        if not owner_team_id:
            continue

        # Direct ownership
        if owner_team_id in caller_team_ids:
            annotate_app_source(identity, app, owner_team_id)
            visible.append(app)
            continue

        # Shared access
        app_id = app.get('id') or app.get('app_id', '')
        if app_id in incoming_grants:
            annotate_app_source(identity, app, owner_team_id)
            visible.append(app)
            continue

    return visible


# ---------------------------------------------------------------------------
# Per-Test-Case Override (BR-3)
# ---------------------------------------------------------------------------


def can_view_testcase(identity: dict, testcase_id: str, caller_role: str) -> bool:
    """
    Check if a per-test-case override narrows visibility for this caller (BR-3).

    Overrides can only NARROW access — they cannot grant more than team membership provides.
    Admin bypasses overrides (FR-1.3).

    Args:
        identity: Caller identity dict.
        testcase_id: The test case ID to check.
        caller_role: The caller's role in the relevant team.

    Returns:
        True if the caller can view the test case, False if override denies visibility.
    """
    # Admin bypasses overrides
    if identity.get('is_admin', False):
        return True

    try:
        override = get_testcase_override(testcase_id)
    except Exception:
        # On error, deny (deny-by-default)
        return False

    if override is None:
        # No override exists — allow (standard permissions apply)
        return True

    caller_sub = identity.get('sub', '')

    # Check allowed_subs restriction
    allowed_subs = override.get('allowed_subs', [])
    if allowed_subs and caller_sub not in allowed_subs:
        return False

    # Check allowed_roles restriction
    allowed_roles = override.get('allowed_roles', [])
    if allowed_roles and caller_role not in allowed_roles:
        return False

    return True
