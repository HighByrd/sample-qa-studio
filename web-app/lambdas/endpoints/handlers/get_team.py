import lambda_init  # noqa: F401 — must be first import
import logging
from typing import Any, Dict
from utils import create_response, require_scopes, extract_user_identity, validate_path_id
import permissions_repo

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handle(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get a single team by ID.

    Requires api/admin scope OR caller must be a member of the team.

    Path parameters:
        id: Team ID

    Returns:
        200: Team detail {id, name, created_by, created_at, memberCount, applicationCount}
        403: Insufficient permissions
        404: Team not found
    """
    # Try admin scope first
    user_identity, error_response = require_scopes(event, ['api/admin'])
    if error_response:
        # Not admin — check team membership
        identity = extract_user_identity(event)
        if identity.get('is_admin'):
            user_identity = identity
        else:
            team_id_raw = (event.get('pathParameters') or {}).get('id', '')
            team_roles = identity.get('team_roles', [])
            is_member = any(
                tr.get('team_id') == team_id_raw for tr in team_roles
            )
            if not is_member:
                return create_response(403, {'error': 'Forbidden: admin or team member required'})
            user_identity = identity

    # Validate path parameter
    team_id, error = validate_path_id(
        (event.get('pathParameters') or {}).get('id'), 'team ID'
    )
    if error:
        return error

    team = permissions_repo.get_team(team_id)
    if not team:
        return create_response(404, {'error': 'Team not found'})

    members = permissions_repo.list_team_members(team_id)
    apps = permissions_repo.list_team_apps(team_id)

    response_body = {
        'id': team.get('id', ''),
        'name': team.get('name', ''),
        'created_by': team.get('created_by', ''),
        'created_at': team.get('created_at', ''),
        'memberCount': len(members),
        'applicationCount': len(apps),
    }

    return create_response(200, response_body)
