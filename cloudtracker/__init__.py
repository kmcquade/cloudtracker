"""
Copyright 2018 Duo Security

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
---------------------------------------------------------------------------
"""
__version__ = '2.1.5'
import logging
import pkg_resources
from cloudtracker.account_analysis import get_role_allowed_actions, get_user_allowed_actions, get_account_iam, \
    get_allowed_roles, get_allowed_users, get_role_iam, get_user_iam, get_account
from cloudtracker.cloudtrail_analysis import read_aws_api_list
from cloudtracker.constants import SERVICE_RENAMES, NO_IAM, EVENT_RENAMES, normalize_api_call, cloudtrail_supported_actions
from cloudtracker.privileges import Privileges
from cloudtracker.util import make_list, colored_print

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)-8s %(message)s'
)


def print_actor_diff(performed_actors, allowed_actors, use_color):
    """
    Given a list of actors that have performed actions, and a list that exist in the account,
    print the actors and whether they are still active.
    """
    PERFORMED_AND_ALLOWED = 1
    PERFORMED_BUT_NOT_ALLOWED = 2
    ALLOWED_BUT_NOT_PERFORMED = 3

    actors = {}
    for actor in performed_actors:
        if actor in allowed_actors:
            actors[actor] = PERFORMED_AND_ALLOWED
        else:
            actors[actor] = PERFORMED_BUT_NOT_ALLOWED

    for actor in allowed_actors:
        if actor not in actors:
            actors[actor] = ALLOWED_BUT_NOT_PERFORMED

    for actor in sorted(actors.keys()):
        if actors[actor] == PERFORMED_AND_ALLOWED:
            colored_print("  {}".format(actor), use_color, 'white')
        elif actors[actor] == PERFORMED_BUT_NOT_ALLOWED:
            # Don't show users that existed but have since been deleted
            continue
        elif actors[actor] == ALLOWED_BUT_NOT_PERFORMED:
            colored_print("- {}".format(actor), use_color, 'red')
        else:
            raise Exception("Unknown constant")


def is_recorded_by_cloudtrail(action):
    """Given an action, return True if it would be logged by CloudTrail"""
    if action in cloudtrail_supported_actions:
        return True
    return False


def print_diff(performed_actions, allowed_actions, printfilter, use_color):
    """
    For an actor, given the actions they performed, and the privileges they were granted,
    print what they were allowed to do but did not, and other differences.
    """
    PERFORMED_AND_ALLOWED = 1
    PERFORMED_BUT_NOT_ALLOWED = 2
    ALLOWED_BUT_NOT_PERFORMED = 3
    ALLOWED_BUT_NOT_KNOWN_IF_PERFORMED = 4

    actions = {}

    for action in performed_actions:
        # Convert to IAM names
        for iam_name, cloudtrail_name in EVENT_RENAMES.items():
            if action == cloudtrail_name:
                action = iam_name

        # See if this was allowed or not
        if action in allowed_actions:
            actions[action] = PERFORMED_AND_ALLOWED
        else:
            if action in NO_IAM:
                # Ignore actions in cloudtrail such as sts:getcalleridentity that are allowed
                # whether or not they are in IAM
                continue
            actions[action] = PERFORMED_BUT_NOT_ALLOWED

    # Find actions that were allowed, but there is no record of them being used
    for action in allowed_actions:
        if action not in actions:
            if not is_recorded_by_cloudtrail(action):
                actions[action] = ALLOWED_BUT_NOT_KNOWN_IF_PERFORMED
            else:
                actions[action] = ALLOWED_BUT_NOT_PERFORMED

    for action in sorted(actions.keys()):
        # Convert CloudTrail name back to IAM name
        display_name = action

        if not printfilter.get('show_benign', True):
            # Ignore actions that won't exfil or modify resources
            if ":list" in display_name or ":describe" in display_name:
                continue

        if actions[action] == PERFORMED_AND_ALLOWED:
            colored_print("  {}".format(display_name), use_color, 'white')
        elif actions[action] == PERFORMED_BUT_NOT_ALLOWED:
            colored_print("+ {}".format(display_name), use_color, 'green')
        elif actions[action] == ALLOWED_BUT_NOT_PERFORMED:
            if printfilter.get('show_used', True):
                # Ignore this as it wasn't used
                continue
            colored_print("- {}".format(display_name), use_color, 'red')
        elif actions[action] == ALLOWED_BUT_NOT_KNOWN_IF_PERFORMED:
            if printfilter.get('show_used', True):
                # Ignore this as it wasn't used
                continue
            if printfilter.get('show_unknown', True):
                colored_print("? {}".format(display_name), use_color, 'yellow')
        else:
            raise Exception("Unknown constant")


def run(args, config, start, end):
    """Perform the requested command"""
    use_color = args.use_color

    account = get_account(config['accounts'], args.account)

    if 'elasticsearch' in config:
        try:
            from cloudtracker.datasources.es import ElasticSearch
        except ImportError:
            exit(
                "Elasticsearch support not installed. Install with support via "
                "'pip install git+https://github.com/duo-labs/cloudtracker.git#egg=cloudtracker[es1]' for "
                "elasticsearch 1 support, or "
                "'pip install git+https://github.com/duo-labs/cloudtracker.git#egg=cloudtracker[es6]' for "
                "elasticsearch 6 support"
            )
        datasource = ElasticSearch(config['elasticsearch'], start, end)
    else:
        logging.debug("Using Athena")
        from cloudtracker.datasources.athena import Athena
        datasource = Athena(config['athena'], account, start, end, args)

    # Read AWS actions
    aws_api_list = read_aws_api_list()

    # Read cloudtrail_supported_events

    # ct_actions_path = pkg_resources.resource_filename(__name__, "data/{}".format("cloudtrail_supported_actions.txt"))
    # cloudtrail_supported_actions = {}
    # with open(ct_actions_path) as f:
    #     lines = f.readlines()
    # for line in lines:
    #     (service, event) = line.rstrip().split(":")
    #     cloudtrail_supported_actions[normalize_api_call(service, event)] = True

    account_iam = get_account_iam(account)

    if args.list:
        actor_type = args.list

        if actor_type == 'users':
            allowed_actors = get_allowed_users(account_iam)
            performed_actors = datasource.get_performed_users()
        elif actor_type == 'roles':
            allowed_actors = get_allowed_roles(account_iam)
            performed_actors = datasource.get_performed_roles()
        else:
            exit("ERROR: --list argument must be one of 'users' or 'roles'")

        print_actor_diff(performed_actors, allowed_actors, use_color)

    else:
        if args.destaccount:
            destination_account = get_account(config['accounts'], args.destaccount)
        else:
            destination_account = account

        destination_iam = get_account_iam(destination_account)

        search_query = datasource.get_search_query()

        if args.user:
            username = args.user

            user_iam = get_user_iam(username, account_iam)
            print("Getting info on {}, user created {}".format(args.user, user_iam['CreateDate']))

            if args.destrole:
                dest_role_iam = get_role_iam(args.destrole, destination_iam)
                print("Getting info for AssumeRole into {}".format(args.destrole))

                allowed_actions = get_role_allowed_actions(aws_api_list, dest_role_iam, destination_iam)
                performed_actions = datasource.get_performed_event_names_by_user_in_role(
                    search_query, user_iam, dest_role_iam)
            else:
                allowed_actions = get_user_allowed_actions(aws_api_list, user_iam, account_iam)
                performed_actions = datasource.get_performed_event_names_by_user(
                    search_query, user_iam)
        elif args.role:
            rolename = args.role
            role_iam = get_role_iam(rolename, account_iam)
            print("Getting info for role {}".format(rolename))

            if args.destrole:
                dest_role_iam = get_role_iam(args.destrole, destination_iam)
                print("Getting info for AssumeRole into {}".format(args.destrole))

                allowed_actions = get_role_allowed_actions(aws_api_list, dest_role_iam, destination_iam)
                performed_actions = datasource.get_performed_event_names_by_role_in_role(
                    search_query, role_iam, dest_role_iam)
            else:
                allowed_actions = get_role_allowed_actions(aws_api_list, role_iam, account_iam)
                performed_actions = datasource.get_performed_event_names_by_role(
                    search_query, role_iam)
        else:
            exit("ERROR: Must specify a user or a role")

        print_filter = {
            'show_unknown': args.show_unknown,
            'show_benign': args.show_benign,
            'show_used': args.show_used
        }

        print_diff(performed_actions, allowed_actions, print_filter, use_color)
