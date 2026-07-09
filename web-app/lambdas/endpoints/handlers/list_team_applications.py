import lambda_init  # noqa: F401 — must be first import
import logging
from typing import Any, Dict
import boto3
from boto3.dynamodb.conditions import Key
from utils import create_response, get_table_name, require_scopes, extract_user_identity, validate_path_id
import permissions_repo

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handle(event: Dict[str, Any]) -> Dict[str, Any]:
    """List applications owned by a specific team."""
    user_identity, error_response = require_scopes(event, ['api/applications.read'])
    if error_response:
        return error_response

    team_id, error = validate_path_id(
        (event.get('pathParameters') or {}).get('id'), 'team ID'
    )
    if error:
        return error

    # Get apps with owner_team_id matching this team
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(get_table_name())

    # Scan applications and filter by owner_team_id
    index_response = table.query(
        KeyConditionExpression=Key('pk').eq('APPLICATIONS') & Key('sk').begins_with('APPLICATION#')
    )
    app_ids = [item['id'] for item in index_response.get('Items', [])]

    if not app_ids:
        return create_response(200, [])

    keys = [{'pk': f'APPLICATION#{aid}', 'sk': 'METADATA'} for aid in app_ids]
    batch_response = dynamodb.batch_get_item(
        RequestItems={get_table_name(): {'Keys': keys}}
    )
    all_apps = batch_response.get('Responses', {}).get(get_table_name(), [])

    # Filter to apps owned by this team
    team_apps = []
    for app in all_apps:
        if app.get('owner_team_id') == team_id:
            app.pop('pk', None)
            app.pop('sk', None)
            team_apps.append(app)

    return create_response(200, team_apps)
