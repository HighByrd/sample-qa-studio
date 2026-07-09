"""
Cognito group synchronization utilities.

Creates, deletes, and manages Cognito user pool groups that correspond to team roles.
For each team, 5 groups are created: team-{teamId}-{role} for each role.

Operations:
- ensure_team_groups: Create all 5 role groups for a team (idempotent)
- delete_team_groups: Delete all 5 role groups for a team (idempotent)
- set_user_role: Change a user's role (add-first-then-remove, no access gap)
- remove_user_from_team_role: Remove a user from a specific team role group
"""

import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Roles that get a Cognito group per team
_TEAM_ROLES = ['admin', 'team_lead', 'editor', 'executor', 'viewer']


def ensure_team_groups(team_id: str, user_pool_id: str) -> list:
    """
    Ensure all 5 role groups exist for a team in the Cognito User Pool.

    Creates groups with the naming convention: team-{teamId}-{role}
    Swallows GroupExistsException if groups already exist (idempotent).

    Args:
        team_id: The team identifier.
        user_pool_id: The Cognito User Pool ID.

    Returns:
        List of group names that were created or already existed.
    """
    client = boto3.client('cognito-idp')
    group_names = []

    for role in _TEAM_ROLES:
        group_name = f'team-{team_id}-{role}'
        try:
            client.create_group(
                GroupName=group_name,
                UserPoolId=user_pool_id,
                Description=f'Team {team_id} - {role} role',
            )
            logger.info(f"Created Cognito group: {group_name}")
        except client.exceptions.GroupExistsException:
            logger.info(f"Cognito group already exists: {group_name}")
        except Exception as e:
            logger.error(f"Failed to create Cognito group {group_name}: {e}")
            raise

        group_names.append(group_name)

    return group_names


def delete_team_groups(team_id: str, user_pool_id: str) -> list:
    """
    Delete all 5 role groups for a team from the Cognito User Pool.

    Idempotent: swallows ResourceNotFoundException if a group doesn't exist.

    Args:
        team_id: The team identifier.
        user_pool_id: The Cognito User Pool ID.

    Returns:
        List of group names that were deleted or already absent.
    """
    client = boto3.client('cognito-idp')
    group_names = []

    for role in _TEAM_ROLES:
        group_name = f'team-{team_id}-{role}'
        try:
            client.delete_group(
                GroupName=group_name,
                UserPoolId=user_pool_id,
            )
            logger.info(f"Deleted Cognito group: {group_name}")
        except client.exceptions.ResourceNotFoundException:
            logger.info(f"Cognito group already absent: {group_name}")
        except Exception as e:
            logger.error(f"Failed to delete Cognito group {group_name}: {e}")
            raise

        group_names.append(group_name)

    return group_names


def remove_user_from_team_role(sub: str, team_id: str, role: str, user_pool_id: str) -> None:
    """
    Remove a user from a specific team role group in Cognito.

    Args:
        sub: The Cognito user sub (username).
        team_id: The team identifier.
        role: The role to remove (e.g. 'editor', 'viewer').
        user_pool_id: The Cognito User Pool ID.

    Raises:
        Exception: If the Cognito API call fails (other than user not in group).
    """
    client = boto3.client('cognito-idp')
    group_name = f'team-{team_id}-{role}'

    try:
        client.admin_remove_user_from_group(
            UserPoolId=user_pool_id,
            Username=sub,
            GroupName=group_name,
        )
        logger.info(f"Removed user {sub} from group {group_name}")
    except Exception as e:
        logger.error(f"Failed to remove user {sub} from group {group_name}: {e}")
        raise


def set_user_role(sub: str, team_id: str, old_role: str, new_role: str, user_pool_id: str) -> None:
    """
    Change a user's role in a team by updating Cognito group membership.

    Implements BL-6: add-first-then-remove ordering to prevent access gaps.
    The user is briefly in BOTH groups (more permissive, never less).

    Args:
        sub: The Cognito user sub (username).
        team_id: The team identifier.
        old_role: Current role to remove (e.g. 'viewer').
        new_role: New role to add (e.g. 'editor').
        user_pool_id: The Cognito User Pool ID.

    Raises:
        Exception: If adding the new group fails.
    """
    client = boto3.client('cognito-idp')
    new_group_name = f'team-{team_id}-{new_role}'
    old_group_name = f'team-{team_id}-{old_role}'

    # Step 1: Add to new group FIRST (no access gap)
    try:
        client.admin_add_user_to_group(
            UserPoolId=user_pool_id,
            Username=sub,
            GroupName=new_group_name,
        )
        logger.info(f"Added user {sub} to group {new_group_name}")
    except Exception as e:
        logger.error(f"Failed to add user {sub} to group {new_group_name}: {e}")
        raise

    # Step 2: Remove from old group (safe — user already has new group)
    try:
        client.admin_remove_user_from_group(
            UserPoolId=user_pool_id,
            Username=sub,
            GroupName=old_group_name,
        )
        logger.info(f"Removed user {sub} from group {old_group_name}")
    except Exception as e:
        # Log warning but don't raise — user has both groups briefly (more permissive, not less)
        logger.warning(
            f"Failed to remove user {sub} from old group {old_group_name}: {e}. "
            f"User may have both roles briefly."
        )
