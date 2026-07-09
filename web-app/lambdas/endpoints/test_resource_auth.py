"""
Tests for the resource authorization decision engine (resource_auth.py).

Covers:
- Admin bypass
- Owner-team member permissions (all roles)
- Ceiling rule scenarios (US-3.2)
- Creator-retains-edit (FR-4.1, FR-4.3)
- Unassigned user denial
- Orphaned app denial
- Per-test-case override narrowing
- DynamoDB error → deny (deny-by-default)
- filter_visible_apps correctness
"""

import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Ensure the endpoints directory is on the path
sys.path.insert(0, os.path.dirname(__file__))

from resource_auth import (
    authorize_resource,
    effective_permission,
    can_act,
    filter_visible_apps,
    annotate_app_source,
    can_view_testcase,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(sub='user-sub-123', email='user@example.com', team_roles=None,
                is_admin=False, identity_type='user'):
    """Build an API Gateway event with authorizer context."""
    if team_roles is None:
        team_roles = []

    return {
        'requestContext': {
            'authorizer': {
                'sub': sub,
                'email': email,
                'identityType': identity_type,
                'identity_type': identity_type,
                'teamRoles': json.dumps(team_roles),
                'isAdmin': 'true' if is_admin else 'false',
                'scope': 'api/admin' if is_admin else 'api/usecases.read',
            }
        }
    }


# ---------------------------------------------------------------------------
# effective_permission tests
# ---------------------------------------------------------------------------


class TestEffectivePermission:
    """Unit tests for the ceiling rule computation."""

    def test_viewer_plus_full_shared_equals_view(self):
        """US-3.2 scenario 1: Viewer + Full shared → view."""
        assert effective_permission('viewer', 'full') == 'view'

    def test_executor_plus_view_shared_equals_view(self):
        """US-3.2 scenario 2: Executor + View shared → view."""
        assert effective_permission('executor', 'view') == 'view'

    def test_editor_plus_execute_shared_equals_execute(self):
        """US-3.2 scenario 3: Editor + Execute shared → execute."""
        assert effective_permission('editor', 'execute') == 'execute'

    def test_editor_plus_full_shared_equals_full(self):
        """Editor + Full shared → full (no ceiling reduction)."""
        assert effective_permission('editor', 'full') == 'full'

    def test_team_lead_plus_view_shared_equals_view(self):
        """Team lead + View shared → view (ceiling caps)."""
        assert effective_permission('team_lead', 'view') == 'view'

    def test_unknown_role_defaults_to_view(self):
        """Unknown role → treated as view."""
        assert effective_permission('unknown_role', 'full') == 'view'


# ---------------------------------------------------------------------------
# can_act tests
# ---------------------------------------------------------------------------


class TestCanAct:
    """Unit tests for action permission matrix."""

    def test_full_can_do_everything(self):
        assert can_act('full', 'view') is True
        assert can_act('full', 'execute') is True
        assert can_act('full', 'edit') is True
        assert can_act('full', 'delete') is True

    def test_execute_can_view_and_execute(self):
        assert can_act('execute', 'view') is True
        assert can_act('execute', 'execute') is True
        assert can_act('execute', 'edit') is False
        assert can_act('execute', 'delete') is False

    def test_view_can_only_view(self):
        assert can_act('view', 'view') is True
        assert can_act('view', 'execute') is False
        assert can_act('view', 'edit') is False
        assert can_act('view', 'delete') is False

    def test_unknown_action_denied(self):
        assert can_act('full', 'unknown_action') is False


# ---------------------------------------------------------------------------
# authorize_resource tests
# ---------------------------------------------------------------------------


class TestAuthorizeResourceAdminBypass:
    """Admin bypasses all resource authorization."""

    @patch('resource_auth.get_app_owner')
    def test_admin_bypasses_all(self, mock_get_owner):
        """Admin can access any app with any action without checking ownership."""
        event = _make_event(is_admin=True)
        identity, error = authorize_resource(event, 'app-123', 'delete')

        assert error is None
        assert identity['is_admin'] is True
        # Should NOT have called get_app_owner (short-circuited)
        mock_get_owner.assert_not_called()


class TestAuthorizeResourceOwnerTeam:
    """Direct team membership authorization."""

    @patch('resource_auth.get_app_owner')
    def test_editor_can_edit(self, mock_get_owner):
        """Editor in owner team can edit."""
        mock_get_owner.return_value = 'team-alpha'
        event = _make_event(
            team_roles=[{'team_id': 'team-alpha', 'role': 'editor'}]
        )

        identity, error = authorize_resource(event, 'app-123', 'edit')
        assert error is None

    @patch('resource_auth.get_app_owner')
    def test_viewer_cannot_edit(self, mock_get_owner):
        """Viewer in owner team cannot edit."""
        mock_get_owner.return_value = 'team-alpha'
        event = _make_event(
            team_roles=[{'team_id': 'team-alpha', 'role': 'viewer'}]
        )

        identity, error = authorize_resource(event, 'app-123', 'edit')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.get_app_owner')
    def test_executor_can_execute(self, mock_get_owner):
        """Executor in owner team can execute."""
        mock_get_owner.return_value = 'team-alpha'
        event = _make_event(
            team_roles=[{'team_id': 'team-alpha', 'role': 'executor'}]
        )

        identity, error = authorize_resource(event, 'app-123', 'execute')
        assert error is None

    @patch('resource_auth.get_app_owner')
    def test_executor_cannot_edit(self, mock_get_owner):
        """Executor in owner team cannot edit."""
        mock_get_owner.return_value = 'team-alpha'
        event = _make_event(
            team_roles=[{'team_id': 'team-alpha', 'role': 'executor'}]
        )

        identity, error = authorize_resource(event, 'app-123', 'edit')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.get_app_owner')
    def test_viewer_can_view(self, mock_get_owner):
        """Viewer in owner team can view."""
        mock_get_owner.return_value = 'team-alpha'
        event = _make_event(
            team_roles=[{'team_id': 'team-alpha', 'role': 'viewer'}]
        )

        identity, error = authorize_resource(event, 'app-123', 'view')
        assert error is None


class TestAuthorizeResourceOwnerPassThrough:
    """owner_team_id pass-through avoids the internal get_app_owner read."""

    @patch('resource_auth.get_app_owner')
    def test_supplied_owner_skips_read(self, mock_get_owner):
        """When owner_team_id is passed, get_app_owner must NOT be called."""
        event = _make_event(team_roles=[{'team_id': 'team-alpha', 'role': 'editor'}])

        identity, error = authorize_resource(
            event, 'app-123', 'edit', owner_team_id='team-alpha')

        assert error is None
        mock_get_owner.assert_not_called()

    @patch('resource_auth.get_app_owner')
    def test_supplied_owner_still_enforces(self, mock_get_owner):
        """Passing the owner does not bypass the permission check."""
        event = _make_event(team_roles=[{'team_id': 'team-alpha', 'role': 'viewer'}])

        identity, error = authorize_resource(
            event, 'app-123', 'edit', owner_team_id='team-alpha')

        assert error is not None
        assert error['statusCode'] == 403
        mock_get_owner.assert_not_called()

    @patch('resource_auth.get_app_owner')
    def test_supplied_none_owner_denies_as_orphaned(self, mock_get_owner):
        """Explicit owner_team_id=None is treated as orphaned → deny, no read."""
        event = _make_event(team_roles=[{'team_id': 'team-alpha', 'role': 'editor'}])

        identity, error = authorize_resource(
            event, 'app-123', 'view', owner_team_id=None)

        assert error is not None
        assert error['statusCode'] == 403
        mock_get_owner.assert_not_called()

    @patch('resource_auth.get_app_owner')
    def test_omitted_owner_falls_back_to_read(self, mock_get_owner):
        """When owner_team_id is omitted, get_app_owner IS called (fallback)."""
        mock_get_owner.return_value = 'team-alpha'
        event = _make_event(team_roles=[{'team_id': 'team-alpha', 'role': 'editor'}])

        identity, error = authorize_resource(event, 'app-123', 'edit')

        assert error is None
        mock_get_owner.assert_called_once_with('app-123')


class TestAuthorizeResourceCeilingRule:
    """Ceiling rule for shared access (US-3.2 scenarios)."""

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_viewer_plus_full_shared_can_only_view(self, mock_get_owner, mock_list_shared):
        """US-3.2 scenario 1: Viewer + Full shared → view only."""
        mock_get_owner.return_value = 'team-owner'
        mock_list_shared.return_value = [
            {'target_team_id': 'team-beta', 'app_id': 'app-123', 'level': 'full'}
        ]
        event = _make_event(
            team_roles=[{'team_id': 'team-beta', 'role': 'viewer'}]
        )

        # Can view
        identity, error = authorize_resource(event, 'app-123', 'view')
        assert error is None

        # Cannot execute
        identity, error = authorize_resource(event, 'app-123', 'execute')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_executor_plus_view_shared_can_only_view(self, mock_get_owner, mock_list_shared):
        """US-3.2 scenario 2: Executor + View shared → view only."""
        mock_get_owner.return_value = 'team-owner'
        mock_list_shared.return_value = [
            {'target_team_id': 'team-beta', 'app_id': 'app-123', 'level': 'view'}
        ]
        event = _make_event(
            team_roles=[{'team_id': 'team-beta', 'role': 'executor'}]
        )

        # Can view
        identity, error = authorize_resource(event, 'app-123', 'view')
        assert error is None

        # Cannot execute (ceiling caps to view)
        identity, error = authorize_resource(event, 'app-123', 'execute')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_editor_plus_execute_shared_can_execute_not_edit(self, mock_get_owner, mock_list_shared):
        """US-3.2 scenario 3: Editor + Execute shared → execute only."""
        mock_get_owner.return_value = 'team-owner'
        mock_list_shared.return_value = [
            {'target_team_id': 'team-beta', 'app_id': 'app-123', 'level': 'execute'}
        ]
        event = _make_event(
            team_roles=[{'team_id': 'team-beta', 'role': 'editor'}]
        )

        # Can execute
        identity, error = authorize_resource(event, 'app-123', 'execute')
        assert error is None

        # Cannot edit (ceiling caps to execute)
        identity, error = authorize_resource(event, 'app-123', 'edit')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.get_app_owner')
    def test_admin_exempt_from_ceiling(self, mock_get_owner):
        """US-3.2 scenario 4: Admin bypasses ceiling entirely."""
        event = _make_event(is_admin=True)

        identity, error = authorize_resource(event, 'app-123', 'delete')
        assert error is None
        mock_get_owner.assert_not_called()


class TestAuthorizeResourceCreatorOverride:
    """Creator-retains-edit (FR-4.1, bounded by FR-4.3)."""

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_creator_with_viewer_role_gets_edit_override(self, mock_get_owner, mock_list_shared):
        """Creator with viewer role can edit own resource via override."""
        mock_get_owner.return_value = 'team-alpha'
        mock_list_shared.return_value = []

        event = _make_event(
            sub='creator-sub',
            team_roles=[{'team_id': 'team-alpha', 'role': 'viewer'}]
        )

        # Pass created_by matching the caller's sub
        identity, error = authorize_resource(event, 'app-123', 'edit', created_by='creator-sub')
        assert error is None

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_creator_removed_from_team_denied_edit(self, mock_get_owner, mock_list_shared):
        """Creator removed from team loses edit override (FR-4.3)."""
        mock_get_owner.return_value = 'team-alpha'
        mock_list_shared.return_value = []

        # User has NO team membership at all
        event = _make_event(
            sub='creator-sub',
            team_roles=[]
        )

        identity, error = authorize_resource(event, 'app-123', 'edit', created_by='creator-sub')
        # Should be denied (no access path at all — step 6 fires)
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_creator_override_does_not_grant_delete(self, mock_get_owner, mock_list_shared):
        """Creator override only grants edit, NOT delete."""
        mock_get_owner.return_value = 'team-alpha'
        mock_list_shared.return_value = []

        event = _make_event(
            sub='creator-sub',
            team_roles=[{'team_id': 'team-alpha', 'role': 'viewer'}]
        )

        # Even with created_by, delete is not granted
        identity, error = authorize_resource(event, 'app-123', 'delete', created_by='creator-sub')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.get_app_owner')
    def test_non_creator_with_viewer_role_denied_edit(self, mock_get_owner):
        """Non-creator with viewer role cannot edit (no override)."""
        mock_get_owner.return_value = 'team-alpha'

        event = _make_event(
            sub='user-sub-123',
            team_roles=[{'team_id': 'team-alpha', 'role': 'viewer'}]
        )

        # created_by is a different user
        identity, error = authorize_resource(event, 'app-123', 'edit', created_by='other-user')
        assert error is not None
        assert error['statusCode'] == 403


class TestAuthorizeResourceDenyScenarios:
    """Denial scenarios."""

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_unassigned_user_denied(self, mock_get_owner, mock_list_shared):
        """User with no team memberships is denied."""
        mock_get_owner.return_value = 'team-alpha'
        mock_list_shared.return_value = []
        event = _make_event(team_roles=[])

        identity, error = authorize_resource(event, 'app-123', 'view')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.get_app_owner')
    def test_orphaned_app_denied_for_non_admin(self, mock_get_owner):
        """Orphaned app (no owner) is denied for non-admins (BR-4)."""
        mock_get_owner.return_value = None
        event = _make_event(
            team_roles=[{'team_id': 'team-alpha', 'role': 'editor'}]
        )

        identity, error = authorize_resource(event, 'app-orphan', 'view')
        assert error is not None
        assert error['statusCode'] == 403

    @patch('resource_auth.get_app_owner')
    def test_dynamodb_error_denies_access(self, mock_get_owner):
        """DynamoDB error triggers deny-by-default."""
        mock_get_owner.side_effect = Exception("DynamoDB timeout")
        event = _make_event(
            team_roles=[{'team_id': 'team-alpha', 'role': 'editor'}]
        )

        identity, error = authorize_resource(event, 'app-123', 'view')
        assert error is not None
        assert error['statusCode'] == 500
        assert 'Authorization check failed' in json.loads(error['body'])['message']

    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_app_owner')
    def test_user_not_in_shared_target_team_denied(self, mock_get_owner, mock_list_shared):
        """User not in any team that has shared access → deny."""
        mock_get_owner.return_value = 'team-owner'
        mock_list_shared.return_value = [
            {'target_team_id': 'team-other', 'app_id': 'app-123', 'level': 'full'}
        ]
        event = _make_event(
            team_roles=[{'team_id': 'team-unrelated', 'role': 'editor'}]
        )

        identity, error = authorize_resource(event, 'app-123', 'view')
        assert error is not None
        assert error['statusCode'] == 403


# ---------------------------------------------------------------------------
# filter_visible_apps tests
# ---------------------------------------------------------------------------


class TestFilterVisibleApps:
    """Tests for the list filtering function."""

    @patch('resource_auth.list_apps_shared_with_team')
    def test_admin_sees_all_apps(self, mock_shared_with):
        """Admin sees all apps regardless of ownership."""
        identity = {'is_admin': True, 'team_roles': [], 'sub': 'admin-sub'}
        apps = [
            {'id': 'app-1', 'owner_team_id': 'team-a'},
            {'id': 'app-2', 'owner_team_id': 'team-b'},
            {'id': 'app-3', 'owner_team_id': None},  # orphaned
        ]

        result = filter_visible_apps(identity, apps)
        assert len(result) == 3
        assert all(a['source'] == 'owned' for a in result)

    @patch('resource_auth.list_apps_shared_with_team')
    def test_excludes_non_accessible_apps(self, mock_shared_with):
        """Non-admin user cannot see apps from other teams without shared access."""
        mock_shared_with.return_value = []
        identity = {
            'is_admin': False,
            'team_roles': [{'team_id': 'team-a', 'role': 'editor'}],
            'sub': 'user-sub',
        }
        apps = [
            {'id': 'app-1', 'owner_team_id': 'team-a'},
            {'id': 'app-2', 'owner_team_id': 'team-b'},  # not accessible
        ]

        result = filter_visible_apps(identity, apps)
        assert len(result) == 1
        assert result[0]['id'] == 'app-1'
        assert result[0]['source'] == 'owned'

    @patch('resource_auth.list_apps_shared_with_team')
    @patch('resource_auth.list_shared_access')
    @patch('resource_auth.get_team')
    def test_annotates_shared_apps(self, mock_get_team, mock_list_shared, mock_shared_with):
        """Shared apps are annotated with source='shared' and sharedFrom."""
        mock_shared_with.return_value = [
            {'app_id': 'app-2', 'target_team_id': 'team-a', 'owner_team_id': 'team-b', 'level': 'execute'}
        ]
        mock_list_shared.return_value = [
            {'target_team_id': 'team-a', 'app_id': 'app-2', 'level': 'execute'}
        ]
        mock_get_team.return_value = {'name': 'Team B'}

        identity = {
            'is_admin': False,
            'team_roles': [{'team_id': 'team-a', 'role': 'editor'}],
            'sub': 'user-sub',
        }
        apps = [
            {'id': 'app-2', 'owner_team_id': 'team-b'},
        ]

        result = filter_visible_apps(identity, apps)
        assert len(result) == 1
        assert result[0]['source'] == 'shared'
        assert result[0]['sharedFrom'] == 'Team B'

    @patch('resource_auth.list_apps_shared_with_team')
    def test_orphaned_apps_excluded_for_non_admin(self, mock_shared_with):
        """Orphaned apps (null owner) excluded for non-admins."""
        mock_shared_with.return_value = []
        identity = {
            'is_admin': False,
            'team_roles': [{'team_id': 'team-a', 'role': 'editor'}],
            'sub': 'user-sub',
        }
        apps = [
            {'id': 'app-orphan', 'owner_team_id': None},
        ]

        result = filter_visible_apps(identity, apps)
        assert len(result) == 0

    @patch('resource_auth.list_apps_shared_with_team')
    def test_user_with_no_teams_sees_nothing(self, mock_shared_with):
        """User with no team memberships sees zero apps."""
        identity = {
            'is_admin': False,
            'team_roles': [],
            'sub': 'user-sub',
        }
        apps = [
            {'id': 'app-1', 'owner_team_id': 'team-a'},
        ]

        result = filter_visible_apps(identity, apps)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# can_view_testcase tests
# ---------------------------------------------------------------------------


class TestCanViewTestcase:
    """Per-test-case override tests (BR-3)."""

    @patch('resource_auth.get_testcase_override')
    def test_no_override_allows_view(self, mock_override):
        """No override → allow."""
        mock_override.return_value = None
        identity = {'is_admin': False, 'sub': 'user-sub'}

        assert can_view_testcase(identity, 'tc-1', 'editor') is True

    @patch('resource_auth.get_testcase_override')
    def test_admin_bypasses_override(self, mock_override):
        """Admin bypasses per-test-case overrides."""
        mock_override.return_value = {
            'allowed_subs': ['other-sub'],
            'allowed_roles': ['admin'],
        }
        identity = {'is_admin': True, 'sub': 'admin-sub'}

        assert can_view_testcase(identity, 'tc-1', 'viewer') is True
        mock_override.assert_not_called()

    @patch('resource_auth.get_testcase_override')
    def test_sub_not_in_allowed_subs_denied(self, mock_override):
        """Caller not in allowed_subs → denied."""
        mock_override.return_value = {
            'allowed_subs': ['other-sub-1', 'other-sub-2'],
            'allowed_roles': [],
        }
        identity = {'is_admin': False, 'sub': 'user-sub'}

        assert can_view_testcase(identity, 'tc-1', 'editor') is False

    @patch('resource_auth.get_testcase_override')
    def test_role_not_in_allowed_roles_denied(self, mock_override):
        """Caller role not in allowed_roles → denied."""
        mock_override.return_value = {
            'allowed_subs': [],
            'allowed_roles': ['editor', 'team_lead'],
        }
        identity = {'is_admin': False, 'sub': 'user-sub'}

        assert can_view_testcase(identity, 'tc-1', 'viewer') is False

    @patch('resource_auth.get_testcase_override')
    def test_sub_in_allowed_subs_allowed(self, mock_override):
        """Caller in allowed_subs → allowed."""
        mock_override.return_value = {
            'allowed_subs': ['user-sub', 'other-sub'],
            'allowed_roles': [],
        }
        identity = {'is_admin': False, 'sub': 'user-sub'}

        assert can_view_testcase(identity, 'tc-1', 'viewer') is True

    @patch('resource_auth.get_testcase_override')
    def test_dynamodb_error_denies_view(self, mock_override):
        """DynamoDB error on override fetch → deny (deny-by-default)."""
        mock_override.side_effect = Exception("DynamoDB error")
        identity = {'is_admin': False, 'sub': 'user-sub'}

        assert can_view_testcase(identity, 'tc-1', 'editor') is False
