import lambda_init  # noqa: F401 — must be first import
import os
import logging
from typing import Any, Dict
import boto3
from utils import create_response, require_scopes
import permissions_repo
from perm_audit import log_permission_change

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handle(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Delete a user from Cognito and remove all team memberships.

    Requires api/admin scope.

    Path parameters:
        userId: Cognito user sub

    Returns:
        204: User deleted
        400: Missing userId
        403: Insufficient permissions
        409: Cannot delete the last admin
        500: Cognito failure
    """
    user_identity, error_response = require_scopes(event, ['api/admin'])
    if error_response:
        return error_response

    path_params = event.get('pathParameters') or {}
    user_sub = path_params.get('userId', '').strip()
    if not user_sub:
        return create_response(400, {'error': 'userId path parameter is required'})

    # Check if user is an admin — if so, enforce last-admin guard
    user_teams = permissions_repo.list_user_teams(user_sub)
    is_admin_member = any(m.get('role') == 'admin' for m in user_teams)
    if is_admin_member:
        admin_count = permissions_repo.count_admins()
        if admin_count <= 1:
            return create_response(409, {'error': 'Cannot delete the last admin'})

    user_pool_id = os.environ.get('USER_POOL_ID', '')
    if not user_pool_id:
        return create_response(500, {'error': 'USER_POOL_ID not configured'})

    # Remove all team memberships from DynamoDB
    for m in user_teams:
        team_id = m.get('team_id', '')
        role = m.get('role', '')
        try:
            permissions_repo.remove_membership(user_sub, team_id)
            if role == 'admin':
                permissions_repo._decrement_admin_count()
        except Exception as e:
            logger.warning(f"Failed to remove membership for {user_sub} from team {team_id}: {e}")

    # Delete user from Cognito
    client = boto3.client('cognito-idp')
    try:
        client.admin_delete_user(
            UserPoolId=user_pool_id,
            Username=user_sub,
        )
    except client.exceptions.UserNotFoundException:
        logger.info(f"User {user_sub} not found in Cognito (already deleted)")
    except Exception as e:
        logger.error(f"Failed to delete user {user_sub} from Cognito: {e}")
        return create_response(500, {'error': 'Failed to delete user from Cognito'})

    # Audit log
    actor = {'sub': user_identity.get('sub', ''), 'email': user_identity.get('email', '')}
    log_permission_change(
        actor=actor,
        action='user_delete',
        target={'user_sub': user_sub},
        details={'removed_teams': [m.get('team_id', '') for m in user_teams]},
    )

    logger.info(f"Deleted user {user_sub}")
    return {
        'statusCode': 204,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
        'body': '',
    }
