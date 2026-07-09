"""Tests for member management handlers (add, set_role, remove, list)."""
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
        'resource': '/teams/{id}/members',
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


def _team_lead_event(team_id='team-1', body=None, path_params=None):
    """Create team-lead event."""
    return {
        'httpMethod': 'POST',
        'resource': '/teams/{id}/members',
        'body': json.dumps(body) if body else None,
        'pathParameters': path_params or {},
        'requestContext': {
            'authorizer': {
                'sub': 'lead-sub',
                'email': 'lead@example.com',
                'identityType': 'user',
                'scope': 'api/applications.read',
                'isAdmin': 'false',
                'teamRoles': json.dumps([{'team_id': team_id, 'role': 'team_lead'}]),
            }
        },
    }


def _viewer_event(team_id='team-1', body=None, path_params=None):
    """Create viewer (non-team-lead) event."""
    return {
        'httpMethod': 'POST',
        'resource': '/teams/{id}/members',
        'body': json.dumps(body) if body else None,
        'pathParameters': path_params or {},
        'requestContext': {
            'authorizer': {
                'sub': 'viewer-sub',
                'email': 'viewer@example.com',
                'identityType': 'user',
                'scope': 'api/applications.read',
                'isAdmin': 'false',
                'teamRoles': json.dumps([{'team_id': team_id, 'role': 'viewer'}]),
            }
        },
    }


# ======================================================================
# add_team_member tests
# ======================================================================

class TestAddTeamMember:
    @patch('perm_audit.log_permission_change')
    @patch('permissions_repo._increment_admin_count')
    @patch('permissions_repo.list_team_members')
    @patch('permissions_repo.add_membership')
    @patch('permissions_repo.get_team')
    def test_admin_happy_path(self, mock_get_team, mock_add, mock_list_members,
                               mock_inc, mock_audit):
        from handlers.add_team_member import handle

        mock_get_team.return_value = {'id': 'team-1', 'name': 'Alpha'}
        mock_list_members.return_value = []
        mock_add.return_value = {'team_id': 'team-1', 'user_sub': 'new-user', 'role': 'editor', 'added_at': 'now'}

        event = _admin_event(
            body={'userId': 'new-user', 'role': 'editor'},
            path_params={'id': 'team-1'},
        )
        os.environ['USER_POOL_ID'] = ''  # Skip Cognito sync for test
        response = handle(event)

        assert response['statusCode'] == 201
        body = json.loads(response['body'])
        assert body['user_sub'] == 'new-user'
        assert body['role'] == 'editor'

    @patch('perm_audit.log_permission_change')
    @patch('permissions_repo.list_team_members')
    @patch('permissions_repo.add_membership')
    @patch('permissions_repo.get_team')
    def test_team_lead_can_add_member(self, mock_get_team, mock_add, mock_list_members, mock_audit):
        from handlers.add_team_member import handle

        mock_get_team.return_value = {'id': 'team-1', 'name': 'Alpha'}
        mock_list_members.return_value = []
        mock_add.return_value = {'team_id': 'team-1', 'user_sub': 'new-user', 'role': 'viewer', 'added_at': 'now'}

        event = _team_lead_event(
            team_id='team-1',
            body={'userId': 'new-user', 'role': 'viewer'},
            path_params={'id': 'team-1'},
        )
        os.environ['USER_POOL_ID'] = ''
        response = handle(event)

        assert response['statusCode'] == 201

    def test_viewer_gets_403(self):
        from handlers.add_team_member import handle

        event = _viewer_event(
            team_id='team-1',
            body={'userId': 'new-user', 'role': 'viewer'},
            path_params={'id': 'team-1'},
        )
        response = handle(event)

        assert response['statusCode'] == 403

    @patch('permissions_repo.get_team')
    def test_missing_userId_returns_400(self, mock_get_team):
        from handlers.add_team_member import handle

        mock_get_team.return_value = {'id': 'team-1', 'name': 'Alpha'}
        event = _admin_event(body={'role': 'editor'}, path_params={'id': 'team-1'})
        response = handle(event)

        assert response['statusCode'] == 400
        assert 'userId' in json.loads(response['body'])['error']

    def test_invalid_role_returns_400(self):
        from handlers.add_team_member import handle

        event = _admin_event(body={'userId': 'u1', 'role': 'superadmin'}, path_params={'id': 'team-1'})
        # Mock get_team to succeed
        with patch('permissions_repo.get_team', return_value={'id': 'team-1', 'name': 'T'}):
            response = handle(event)

        assert response['statusCode'] == 400
        assert 'Invalid role' in json.loads(response['body'])['error']

    @patch('permissions_repo.list_team_members')
    @patch('permissions_repo.get_team')
    def test_duplicate_member_returns_400(self, mock_get_team, mock_list_members):
        from handlers.add_team_member import handle

        mock_get_team.return_value = {'id': 'team-1', 'name': 'Alpha'}
        mock_list_members.return_value = [{'user_sub': 'existing-user'}]

        event = _admin_event(
            body={'userId': 'existing-user', 'role': 'editor'},
            path_params={'id': 'team-1'},
        )
        response = handle(event)

        assert response['statusCode'] == 400
        assert 'already a member' in json.loads(response['body'])['error']

    @patch('permissions_repo.remove_membership')
    @patch('permissions_repo.add_membership')
    @patch('permissions_repo.list_team_members')
    @patch('permissions_repo.get_team')
    def test_cognito_failure_triggers_compensation(self, mock_get_team, mock_list_members,
                                                     mock_add, mock_remove):
        from handlers.add_team_member import handle

        mock_get_team.return_value = {'id': 'team-1', 'name': 'Alpha'}
        mock_list_members.return_value = []
        mock_add.return_value = {'team_id': 'team-1', 'user_sub': 'u1', 'role': 'editor', 'added_at': 'now'}

        # Patch the internal Cognito call to fail
        event = _admin_event(
            body={'userId': 'u1', 'role': 'editor'},
            path_params={'id': 'team-1'},
        )
        os.environ['USER_POOL_ID'] = 'pool-123'

        with patch('handlers.add_team_member._add_user_to_team_group', side_effect=Exception('Cognito down')):
            response = handle(event)

        assert response['statusCode'] == 500
        mock_remove.assert_called_once_with('u1', 'team-1')


# ======================================================================
# set_member_role tests
# ======================================================================

class TestSetMemberRole:
    @patch('perm_audit.log_permission_change')
    @patch('permissions_repo.set_member_role')
    def test_happy_path(self, mock_set_role, mock_audit):
        from handlers.set_member_role import handle

        mock_set_role.return_value = {'team_id': 'team-1', 'user_sub': 'u1', 'role': 'editor'}

        event = _admin_event(
            body={'role': 'editor'},
            path_params={'id': 'team-1', 'userId': 'u1'},
        )
        os.environ['USER_POOL_ID'] = ''
        response = handle(event)

        assert response['statusCode'] == 200
        assert json.loads(response['body'])['role'] == 'editor'

    @patch('permissions_repo.set_member_role')
    def test_last_admin_guard_returns_409(self, mock_set_role):
        from handlers.set_member_role import handle

        mock_set_role.side_effect = ValueError("Cannot demote the last admin")

        event = _admin_event(
            body={'role': 'viewer'},
            path_params={'id': 'team-1', 'userId': 'u1'},
        )
        response = handle(event)

        assert response['statusCode'] == 409

    @patch('permissions_repo.set_member_role')
    def test_membership_not_found_returns_404(self, mock_set_role):
        from handlers.set_member_role import handle

        mock_set_role.side_effect = KeyError("Membership not found")

        event = _admin_event(
            body={'role': 'editor'},
            path_params={'id': 'team-1', 'userId': 'u1'},
        )
        response = handle(event)

        assert response['statusCode'] == 404


# ======================================================================
# remove_team_member tests
# ======================================================================

class TestRemoveTeamMember:
    @patch('perm_audit.log_permission_change')
    @patch('cognito_sync.remove_user_from_team_role')
    @patch('permissions_repo._decrement_admin_count')
    @patch('permissions_repo.remove_membership')
    @patch('permissions_repo.count_admins')
    @patch('permissions_repo.list_team_members')
    def test_happy_path(self, mock_list, mock_count, mock_remove, mock_dec,
                         mock_cognito, mock_audit):
        from handlers.remove_team_member import handle

        mock_list.return_value = [{'user_sub': 'u1', 'role': 'editor'}]
        mock_count.return_value = 3

        event = _admin_event(path_params={'id': 'team-1', 'userId': 'u1'})
        os.environ['USER_POOL_ID'] = 'pool-123'
        response = handle(event)

        assert response['statusCode'] == 204
        mock_remove.assert_called_once_with('u1', 'team-1')

    @patch('permissions_repo.count_admins')
    @patch('permissions_repo.list_team_members')
    def test_last_admin_guard(self, mock_list, mock_count):
        from handlers.remove_team_member import handle

        mock_list.return_value = [{'user_sub': 'u1', 'role': 'admin'}]
        mock_count.return_value = 1

        event = _admin_event(path_params={'id': 'team-1', 'userId': 'u1'})
        response = handle(event)

        assert response['statusCode'] == 409

    @patch('permissions_repo.list_team_members')
    def test_member_not_found_returns_404(self, mock_list):
        from handlers.remove_team_member import handle

        mock_list.return_value = []

        event = _admin_event(path_params={'id': 'team-1', 'userId': 'nonexistent'})
        response = handle(event)

        assert response['statusCode'] == 404


# ======================================================================
# list_team_members tests
# ======================================================================

class TestListTeamMembers:
    @patch('permissions_repo.list_team_members')
    @patch('permissions_repo.get_team')
    def test_happy_path(self, mock_get_team, mock_list):
        from handlers.list_team_members import handle

        mock_get_team.return_value = {'id': 'team-1', 'name': 'Alpha'}
        mock_list.return_value = [
            {'user_sub': 'u1', 'role': 'admin', 'added_at': 't1'},
            {'user_sub': 'u2', 'role': 'editor', 'added_at': 't2'},
        ]

        event = _admin_event(path_params={'id': 'team-1'})
        response = handle(event)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert len(body) == 2
        assert body[0]['userId'] == 'u1'

    def test_viewer_gets_403(self):
        from handlers.list_team_members import handle

        event = _viewer_event(team_id='team-1', path_params={'id': 'team-1'})
        response = handle(event)

        assert response['statusCode'] == 403
