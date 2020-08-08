import re
from .util import make_list
from .constants import EVENT_RENAMES


class Privileges(object):
    """Keep track of privileges an actor has been granted"""
    stmts = None
    roles = None
    aws_api_list = None

    def __init__(self, aws_api_list):
        self.stmts = []
        self.roles = []
        self.aws_api_list = aws_api_list

    def add_stmt(self, stmt):
        """Adds a statement from an IAM policy"""
        if 'Action' not in stmt:
            # TODO Implement NotAction
            return
        self.stmts.append(stmt)

    def get_actions_from_statement(self, stmt):
        """Figures out what API calls have been granted from a statement"""
        actions = {}

        for action in make_list(stmt['Action']):
            # Normalize it
            action = action.lower()
            # Convert it's globbing to a regex
            action = '^' + action.replace('*', '.*') + '$'

            for possible_action in self.aws_api_list:
                for iam_name, cloudtrail_name in EVENT_RENAMES.items():
                    if possible_action == cloudtrail_name:
                        possible_action = iam_name
                if re.match(action, possible_action):
                    actions[possible_action] = True

        return actions

    def determine_allowed(self):
        """After statements have been added from IAM policiies, find all the allowed API calls"""
        actions = {}

        # Look at alloweds first
        for stmt in self.stmts:
            if stmt['Effect'] == 'Allow':
                stmt_actions = self.get_actions_from_statement(stmt)
                for action in stmt_actions:
                    if action not in actions:
                        actions[action] = [stmt]
                    else:
                        actions[action].append(stmt)

        # Look at denied
        for stmt in self.stmts:
            if (stmt['Effect'] == 'Deny' and
                    '*' in make_list(stmt.get('Resource', None)) and
                    stmt.get('Condition', None) is None):

                stmt_actions = self.get_actions_from_statement(stmt)
                for action in stmt_actions:
                    if action in actions:
                        del actions[action]

        return list(actions)
