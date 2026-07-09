"""Tests for user management handlers (list, create, update, delete)."""
import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(__file__))


def _admin_event(body=None, path_params=None):
    """Create admin event."""
    return {
        'httpMethod': 'POST',
        'resource': '/users',
        'body': json.dumps(body) if body else None,
        'pathParameters': path_params or {},
        'requestContext': {
            'authorizer': {
                'sub': 'admin-sub',
                'email': 'admin@example.com',
                'identityType': 'user',
                'scope': 'api/admin',
                'isAdmin': 'true',
                'teamRoles': '[]',
            }
        },
    }


def _non_admin_event(body=None, path_params=None):
    """Create non-admin event."""
    return {
        'httpMethod': 'POST',
        'resource': '/users',
        'body': json.dumps(body) if body else None,
        'pathParameters': path_params or {},
        'requestContext': {
            'authorizer': {
                'sub': 'user-sub',
                'email': 'user@example.com',
                'identityType': 'user',
                'scope': 'api/applications.read',
                'isAdmin': 'false',
                'teamRoles': '[]',
            }
        },
    }


# ======================================================================
# list_users tests
# ======================================================================

class TestListUsers:
    @patch('permissions_repo.get_team')
    @patch('permissions_repo.list_user_teams')
    @patch('boto3.client')
    def test_happy_path(self, mock_boto_client, mock_list_teams, mock_get_team):
        from handlers.list_users import handle

        mock_cognito = MagicMock()
        mock_boto_client.return_value = mock_cognito
        mock_cognito.list_users.return_value = {
            'Users': [
                {
                    'Username': 'user-sub-1',
                    'Attributes': [{'Name': 'email', 'Value': 'u1@example.com'}],
                },
            ],
        }
        mock_list_teams.return_value = [{'team_id': 'team-1', 'role': 'editor'}]
        mock_get_team.return_value = {'id': 'team-1', 'name': 'Alpha'}

        os.environ['USER_POOL_ID'] = 'pool-123'
        event = _admin_event()
        response = handle(event)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert len(body) == 1
        assert body[0]['email'] == 'u1@example.com'
        assert body[0]['teams'][0]['name'] == 'Alpha'

    def test_non_admin_gets_403(self):
        from handlers.list_users import handle

        event = _non_admin_event()
        response = handle(event)

        assert response['statusCode'] == 403


# ======================================================================
# create_user tests
# ======================================================================

class TestCreateUser:
    @patch('perm_audit.log_permission_change')
    @patch('boto3.client')
    def test_happy_path_no_team(self, mock_boto_client, mock_audit):
        from handlers.create_user import handle

        mock_cognito = MagicMock()
        mock_boto_client.return_value = mock_cognito
        mock_cognito.admin_create_user.return_value = {
            'User': {
                'Username': 'new-sub',
                'Attributes': [
                    {'Name': 'sub', 'Value': 'new-sub'},
                    {'Name': 'email', 'Value': 'new@example.com'},
                ],
            },
        }

        os.environ['USER_POOL_ID'] = 'pool-123'
        event = _admin_event(body={'email': 'new@example.com'})
        response = handle(event)

        assert response['statusCode'] == 201
        body = json.loads(response['body'])
        assert body['email'] == 'new@example.com'
        assert body['teams'] == []

    def test_missing_email_returns_400(self):
        from handlers.create_user import handle

        os.environ['USER_POOL_ID'] = 'pool-123'
        event = _admin_event(body={'email': ''})
        response = handle(event)

        assert response['statusCode'] == 400
        assert 'email' in json.loads(response['body'])['error']

    def test_non_admin_gets_403(self):
        from handlers.create_user import handle

        event = _non_admin_event(body={'email': 'x@y.com'})
        response = handle(event)

        assert response['statusCode'] == 403


# ======================================================================
# delete_user tests
# ======================================================================

class TestDeleteUser:
    @patch('perm_audit.log_permission_change')
    @patch('boto3.client')
    @patch('permissions_repo.remove_membership')
    @patch('permissions_repo.count_admins')
    @patch('permissions_repo.list_user_teams')
    def test_happy_path(self, mock_list_teams, mock_count, mock_remove,
                         mock_boto_client, mock_audit):
        from handlers.delete_user import handle

        mock_list_teams.return_value = [{'team_id': 'team-1', 'role': 'editor'}]
        mock_count.return_value = 3
        mock_cognito = MagicMock()
        mock_boto_client.return_value = mock_cognito

        os.environ['USER_POOL_ID'] = 'pool-123'
        event = _admin_event(path_params={'userId': 'user-to-delete'})
        response = handle(event)

        assert response['statusCode'] == 204

    @patch('permissions_repo.count_admins')
    @patch('permissions_repo.list_user_teams')
    def test_last_admin_guard(self, mock_list_teams, mock_count):
        from handlers.delete_user import handle

        mock_list_teams.return_value = [{'team_id': 'team-1', 'role': 'admin'}]
        mock_count.return_value = 1

        event = _admin_event(path_params={'userId': 'last-admin'})
        response = handle(event)

        assert response['statusCode'] == 409

    def test_non_admin_gets_403(self):
        from handlers.delete_user import handle

        event = _non_admin_event(path_params={'userId': 'u1'})
        response = handle(event)

        assert response['statusCode'] == 403
