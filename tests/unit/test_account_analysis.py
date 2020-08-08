import unittest
from cloudtracker.account_analysis import get_role_iam

# Role IAM policy to be used in different tests
ROLE_IAM = {
    "AssumeRolePolicyDocument": {},
    "RoleId": "AROA00000000000000000",
    "CreateDate": "2017-01-01T00:00:00Z",
    "InstanceProfileList": [],
    "RoleName": "test_role",
    "Path": "/",
    "AttachedManagedPolicies": [],
    "RolePolicyList": [
        {
            "PolicyName": "KmsDecryptSecrets",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "kms:DescribeKey",
                            "kms:Decrypt"
                        ],
                        "Resource": "*",
                        "Effect": "Allow",
                        "Sid": ""
                    }
                ]
            }
        },
        {
            "PolicyName": "S3PutObject",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "s3:PutObject",
                            "s3:PutObjectAcl",
                            "s3:ListBucket"
                        ],
                        "Resource": "*",
                        "Effect": "Allow"
                    }
                ]
            }
        }
    ],
    "Arn": "arn:aws:iam::111111111111:role/test_role"
}


class TestAccountAnalysis(unittest.TestCase):
    def test_get_role_iam(self):
        """Test get_role_iam"""
        account_iam = {
            "RoleDetailList": [ROLE_IAM],
            "UserDetailList": [],
            "GroupDetailList": [],
            "Policies": []
        }
        result = get_role_iam("test_role", account_iam)
        print(result)
