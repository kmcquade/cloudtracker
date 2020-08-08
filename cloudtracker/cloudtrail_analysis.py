import pkg_resources
from cloudtracker.constants import SERVICE_RENAMES, normalize_api_call
from policy_sentry.querying.all import get_all_actions


# def read_aws_api_list(aws_api_list_file='aws_api_list.txt'):
#     """Read in the list of all known AWS API calls"""
#     api_list_path = pkg_resources.resource_filename(__name__, "data/{}".format(aws_api_list_file))
#     aws_api_list = {}
#     with open(api_list_path) as f:
#         lines = f.readlines()
#     for line in lines:
#         service, event = line.rstrip().split(":")
#         aws_api_list[normalize_api_call(service, event)] = True
#     return aws_api_list

def read_aws_api_list():
    """Read in the list of all known AWS API calls"""
    aws_api_list = {}
    all_actions = get_all_actions()
    for line in all_actions:
        service, event = line.rstrip().split(":")
        aws_api_list[normalize_api_call(service, event)] = True
    return aws_api_list
