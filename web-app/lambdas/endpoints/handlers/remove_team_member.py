import lambda_init  # noqa: F401 — must be first import
import os
import logging
from typing import Any, Dict
from utils import create_response, require_scopes, extract_user_identity, validate_path_id
import permissions_repo
import cognito_sync
from perm_audit import log_permission_change

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handle(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove a member from a team.

    Requires api/admin scope OR caller must be team-lead/admin of the target team.
    Implements last-admin guard: cannot remove the last admin from the system.

    Path parameters:
        id: Team ID
        userId: User sub (Cognito sub)

    Returns:
        204: Member removed
        403: Insufficient permissions
        404: Membership not found
        409: Cannot remove the last admin
    """
    # Auth: admin or team-lead
    user_identity, error_response = require_scopes(event, ['api/admin'])
    if error_response:
        identity = extract_user_identity(event)
        if identity.get('is_admin'):
            user_identity = identity
        else:
            team_id_raw = (event.get('pathParameters') or {}).get('id', '')
            team_roles = identity.get('team_roles', [])
            is_team_lead = any(
                tr.get('team_id') == team_id_raw and tr.get('role') in ('admin', 'team_lead')
                for tr in team_roles
            )
            if not is_team_lead:
                return create_response(403, {'error': 'Admin or team lead required'})
            user_identity = identity

    team_id, error = validate_path_id(
        (event.get('pathParameters') or {}).get('id'), 'team ID'
    )
    if error:
        return error

    path_params = event.get('pathParameters') or {}
    user_sub = path_params.get('userId', '').strip()
    if not user_sub:
        return create_response(400, {'error': 'userId path parameter is required'})

    # Find the membership to determine role (for Cognito cleanup + last-admin guard)
    members = permissions_repo.list_team_members(team_id)
    target_member = None
    for m in members:
        if m.get('user_sub') == user_sub:
            target_member = m
            break

    if not target_member:
        return create_response(404, {'error': 'Membership not found'})

    member_role = target_member.get('role', '')

    # Last-admin guard: if this user is an admin, check system-wide admin count
    if member_role == 'admin':
        admin_count = permissions_repo.count_admins()
        if admin_count <= 1:
            return create_response(409, {'error': 'Cannot remove the last admin'})

    # Remove membership from DynamoDB
    permissions_repo.remove_membership(user_sub, team_id)

    # Decrement admin counter if removing an admin
    if member_role == 'admin':
        permissions_repo._decrement_admin_count()

    # Remove from Cognito group
    user_pool_id = os.environ.get('USER_POOL_ID', '')
    if user_pool_id and member_role:
        try:
            cognito_sync.remove_user_from_team_role(user_sub, team_id, member_role, user_pool_id)
        except Exception as e:
            # Membership already removed from DynamoDB — log but don't fail
            logger.error(f"Failed to remove {user_sub} from Cognito group for team {team_id}: {e}")

    # Audit log
    actor = {'sub': user_identity.get('sub', ''), 'email': user_identity.get('email', '')}
    log_permission_change(
        actor=actor,
        action='member_remove',
        target={'user_sub': user_sub, 'team_id': team_id},
        details={'role': member_role},
    )

    logger.info(f"Removed member {user_sub} from team {team_id}")
    return {
        'statusCode': 204,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
        'body': '',
    }
