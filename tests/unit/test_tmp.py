import unittest
from cloudtracker.cloudtrail_analysis import read_aws_api_list


class TestTemporary(unittest.TestCase):
    """Test case to understand some of the CloudTracker methods"""

    def test_read_aws_api_list(self):
        """cloudtracker.read_aws_api_list: Printing this out so I understand it"""
        aws_api_list = read_aws_api_list()
        print(aws_api_list)
