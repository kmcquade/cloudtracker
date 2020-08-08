import pkg_resources

# Translate CloudTrail name -> IAM name
# Pulled from: http://bit.ly/2txbx1L
# but some of the names there seem reversed
SERVICE_RENAMES = {
    'monitoring': 'cloudwatch',
    'email': 'ses',
}

# Translate IAM name -> Cloudtrail name (SOAP API name)
# Pulled from https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudtrail-logging.html
# I think S3 is the only service where IAM names are different than the API calls.
EVENT_RENAMES = {
    's3:listallmybuckets': 's3:listbuckets',
    's3:getbucketaccesscontrolpolicy': 's3:getbucketacl',
    's3:setbucketaccesscontrolpolicy': 's3:putbucketacl',
    's3:getbucketloggingstatus': 's3:getbucketlogging',
    's3:setbucketloggingstatus': 's3:putbucketlogging'
}

# List of actions seen in CloudTrail logs for which no IAM policies exist.
# These are allowed by default.
NO_IAM = {
    'sts:getcalleridentity': True,
    'sts:getsessiontoken': True,
    'signin:consolelogin': True,
    'signin:checkmfa': True,
    "signin:exitrole": True,
    "signin:renewrole": True,
    "signin:switchrole": True
}

cloudtrail_supported_actions = None


def normalize_api_call(service, event_name):
    """Translate API calls to a common representation"""
    service = service.lower()
    event_name = event_name.lower()

    # Remove the dates from event names, such as createdistribution2015_07_27
    event_name = event_name.split("20")[0]

    # Rename the service
    if service in SERVICE_RENAMES:
        service = SERVICE_RENAMES[service]

    return "{}:{}".format(service, event_name)


# Read cloudtrail_supported_events
ct_actions_path = pkg_resources.resource_filename(__name__, "data/{}".format("cloudtrail_supported_actions.txt"))

# global cloudtrail_supported_actions
cloudtrail_supported_actions = {}

with open(ct_actions_path) as f:
    lines = f.readlines()
for line in lines:
    (service, event) = line.rstrip().split(":")
    cloudtrail_supported_actions[normalize_api_call(service, event)] = True
