import json
import logging
from typing import Any, Dict, Optional
import boto3
from utils import create_response, get_table_name, require_scopes, validate_path_id, get_current_timestamp

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handle(event: Dict[str, Any]) -> Dict[str, Any]:
    user_identity, error_response = require_scopes(event, ['api/applications.write'])
    if error_response:
        return error_response

    app_id, error = validate_path_id(event.get('pathParameters', {}).get('id'), 'application ID')
    if error:
        return error

    try:
        body = json.loads(event.get('body', '{}'))
    except json.JSONDecodeError:
        return create_response(400, {'error': 'Invalid JSON in request body'})

    usecase_ids = body.get('usecase_ids', [])
    action = body.get('action', 'add')

    if not usecase_ids or not isinstance(usecase_ids, list):
        return create_response(400, {'error': 'usecase_ids must be a non-empty list'})

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(get_table_name())

    # Load the target application: needed for existence and, more importantly,
    # for resource-level authorization (the app's owning team).
    app_meta = table.get_item(
        Key={'pk': f'APPLICATION#{app_id}', 'sk': 'METADATA'}
    ).get('Item')
    if not app_meta:
        return create_response(404, {'error': 'Application not found'})

    # Resource-level authorization: the caller must have edit access to the app
    # (mirrors create_usecase). Admins bypass; non-members and callers acting on
    # an orphaned/other-team app get 403. Pass the owner we already loaded to
    # avoid a redundant read.
    from resource_auth import authorize_resource
    _, auth_err = authorize_resource(
        event, app_id, 'edit', owner_team_id=app_meta.get('owner_team_id') or None
    )
    if auth_err:
        return auth_err

    if action == 'remove':
        return _remove_usecases(table, app_id, usecase_ids)

    return _add_usecases(
        table, app_id, usecase_ids, body.get('environment', ''),
        app_meta.get('owner_team_id'),
    )


def _add_usecases(table, app_id: str, usecase_ids: list, environment: str,
                  owner_team_id: Optional[str]) -> Dict[str, Any]:
    now = get_current_timestamp()

    # 1. Write the association records (per-app environment lives here).
    with table.batch_writer() as batch:
        for usecase_id in usecase_ids:
            batch.put_item(Item={
                'pk': f'APPLICATION#{app_id}',
                'sk': f'USECASE#{usecase_id}',
                'associated_at': now,
                'environment': environment,
            })

    # 2. Stamp application_id (and the inherited owner_team_id) onto each use
    #    case item. The app-detail list and the "already in application" check
    #    both filter on application_id, and disassociation REMOVEs it — so
    #    without setting it here the association is invisible even though the
    #    request succeeds. Count only *newly* associated use cases so
    #    usecase_count stays accurate when the same use case is added twice.
    newly_added = 0
    for usecase_id in usecase_ids:
        update_expression = 'SET application_id = :app_id'
        expression_values = {':app_id': app_id}
        if owner_team_id:
            update_expression += ', owner_team_id = :owner_team_id'
            expression_values[':owner_team_id'] = owner_team_id
        try:
            resp = table.update_item(
                Key={'pk': 'USECASES', 'sk': f'USECASE#{usecase_id}'},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ConditionExpression='attribute_exists(pk)',
                ReturnValues='UPDATED_OLD',
            )
            old_app_id = (resp.get('Attributes') or {}).get('application_id')
            if old_app_id != app_id:
                newly_added += 1
        except Exception:
            logger.warning(f"Could not set application_id on usecase {usecase_id}")

    if newly_added:
        table.update_item(
            Key={'pk': f'APPLICATION#{app_id}', 'sk': 'METADATA'},
            UpdateExpression='ADD usecase_count :count',
            ExpressionAttributeValues={':count': newly_added},
        )

    logger.info(
        f"Associated {len(usecase_ids)} usecases with application {app_id} "
        f"({newly_added} newly added)"
    )
    return create_response(200, {'status': 'usecases associated', 'count': len(usecase_ids)})


def _remove_usecases(table, app_id: str, usecase_ids: list) -> Dict[str, Any]:
    with table.batch_writer() as batch:
        for usecase_id in usecase_ids:
            batch.delete_item(Key={'pk': f'APPLICATION#{app_id}', 'sk': f'USECASE#{usecase_id}'})

    # Clear application_id, counting only use cases that were actually
    # associated so usecase_count doesn't drift on repeat removes.
    removed = 0
    for usecase_id in usecase_ids:
        try:
            resp = table.update_item(
                Key={'pk': 'USECASES', 'sk': f'USECASE#{usecase_id}'},
                UpdateExpression='REMOVE application_id',
                ConditionExpression='attribute_exists(pk)',
                ReturnValues='UPDATED_OLD',
            )
            if (resp.get('Attributes') or {}).get('application_id') is not None:
                removed += 1
        except Exception:
            logger.warning(f"Could not clear application_id from usecase {usecase_id}")

    if removed:
        table.update_item(
            Key={'pk': f'APPLICATION#{app_id}', 'sk': 'METADATA'},
            UpdateExpression='ADD usecase_count :dec',
            ExpressionAttributeValues={':dec': -removed},
        )

    logger.info(
        f"Removed {len(usecase_ids)} usecases from application {app_id} "
        f"({removed} cleared)"
    )
    return create_response(200, {'status': 'usecases removed', 'count': len(usecase_ids)})
