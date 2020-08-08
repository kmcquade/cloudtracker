import jmespath
import json
import re
from cloudtracker.privileges import Privileges
from cloudtracker.util import make_list


def get_account(accounts, account_name):
    """
    Gets the account struct from the config file, for the account name specified

    accounts: array of accounts from the config file
    account_name: name to search for (or ID)
    """
    for account in accounts:
        if account_name == account['name'] or account_name == str(account['id']):
            # Sanity check all values exist
            if 'name' not in account or 'id' not in account or 'iam' not in account:
                exit("ERROR: Account {} does not specify an id or iam in the config file".format(account_name))

            # Sanity check account ID
            if not re.search("[0-9]{12}", str(account['id'])):
                exit("ERROR: {} is not a 12-digit account id".format(account['id']))

            return account
    exit("ERROR: Account name {} not found in config".format(account_name))
    return None


def get_user_allowed_actions(aws_api_list, user_iam, account_iam):
    """Return the privileges granted to a user by IAM"""
    groups = user_iam['GroupList']
    managed_policies = user_iam['AttachedManagedPolicies']

    privileges = Privileges(aws_api_list)

    # Get permissions from groups
    for group in groups:
        group_iam = jmespath.search('GroupDetailList[] | [?GroupName == `{}`] | [0]'.format(group), account_iam)
        if group_iam is None:
            continue
        # Get privileges from managed policies attached to the group
        for managed_policy in group_iam['AttachedManagedPolicies']:
            policy_filter = 'Policies[?Arn == `{}`].PolicyVersionList[?IsDefaultVersion == true] | [0][0].Document'
            policy = jmespath.search(policy_filter.format(managed_policy['PolicyArn']), account_iam)
            if policy is None:
                continue
            for stmt in make_list(policy['Statement']):
                privileges.add_stmt(stmt)

        # Get privileges from in-line policies attached to the group
        for inline_policy in group_iam['GroupPolicyList']:
            policy = inline_policy['PolicyDocument']
            for stmt in make_list(policy['Statement']):
                privileges.add_stmt(stmt)

    # Get privileges from managed policies attached to the user
    for managed_policy in managed_policies:
        policy_filter = 'Policies[?Arn == `{}`].PolicyVersionList[?IsDefaultVersion == true] | [0][0].Document'
        policy = jmespath.search(policy_filter.format(managed_policy['PolicyArn']), account_iam)
        if policy is None:
            continue
        for stmt in make_list(policy['Statement']):
            privileges.add_stmt(stmt)

    # Get privileges from inline policies attached to the user
    for stmt in jmespath.search('UserPolicyList[].PolicyDocument.Statement', user_iam) or []:
        privileges.add_stmt(stmt)

    return privileges.determine_allowed()


def get_role_allowed_actions(aws_api_list, role_iam, account_iam):
    """Return the privileges granted to a role by IAM"""
    privileges = Privileges(aws_api_list)

    # Get privileges from managed policies
    for managed_policy in role_iam['AttachedManagedPolicies']:
        policy_filter = 'Policies[?Arn == `{}`].PolicyVersionList[?IsDefaultVersion == true] | [0][0].Document'
        policy = jmespath.search(policy_filter.format(managed_policy['PolicyArn']), account_iam)
        if policy is None:
            continue
        for stmt in make_list(policy['Statement']):
            privileges.add_stmt(stmt)

    # Get privileges from attached policies
    for policy in role_iam['RolePolicyList']:
        for stmt in make_list(policy['PolicyDocument']['Statement']):
            privileges.add_stmt(stmt)

    return privileges.determine_allowed()


def get_user_iam(username, account_iam):
    """Given the IAM of an account, and a username, return the IAM data for the user"""
    user_iam = jmespath.search('UserDetailList[] | [?UserName == `{}`] | [0]'.format(username), account_iam)
    if user_iam is None:
        exit("ERROR: Unknown user named {}".format(username))
    return user_iam


def get_role_iam(rolename, account_iam):
    """Given the IAM of an account, and a role name, return the IAM data for the role"""
    role_iam = jmespath.search('RoleDetailList[] | [?RoleName == `{}`] | [0]'.format(rolename), account_iam)
    if role_iam is None:
        raise Exception("Unknown role named {}".format(rolename))
    return role_iam


def get_account_iam(account):
    """Given account data from the config file, open the IAM file for the account"""
    return json.load(open(account['iam']))


def get_allowed_users(account_iam):
    """Return all the users in an IAM file"""
    return jmespath.search('UserDetailList[].UserName', account_iam)


def get_allowed_roles(account_iam):
    """Return all the roles in an IAM file"""
    return jmespath.search('RoleDetailList[].RoleName', account_iam)
