import re


# class Config:
#     def __init__(self, config):
#         self.config = config
#         self.accounts = []
#         self._accounts(config)
#
#     def _accounts(self, config):
#         for account in config.get("accounts"):
#             if 'name' not in account or 'id' not in account or 'iam' not in account:
#                 exit("ERROR: Account {} does not specify an id or iam in the config file".format(str(account)))
#             # Sanity check account ID
#             if not re.search("[0-9]{12}", str(account['id'])):
#                 exit("ERROR: {} is not a 12-digit account id".format(account['id']))
#             self.accounts.append(account)
#
#     def get_account(self):
#
# #
# #
#
#
# class Account:
#     """Get the account configuration"""
#     def __init__(self):
#         groups =