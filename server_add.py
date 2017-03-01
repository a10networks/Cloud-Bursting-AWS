################################################################################
__copyright__   = "Copyright 2016, A10 Networks, Inc"
################################################################################

import os
import time
import urllib2
import boto3
from base64 import b64encode, b64decode
import json

EncryptedUser    = os.environ['A10User']
EncryptedPass    = os.environ['A10UserPassword']
A10Tenant        = os.environ['A10Tenant']
ServerInstanceID = os.environ['ServerInstanceID']
AwsServerRegion  = os.environ['AwsServerRegion']
CloudServerPort  = os.environ['CloudServerPort']


# Decrypt code should run once and variables stored outside of the function
# handler so that these are decrypted once per container
A10User = boto3.client('kms').decrypt(CiphertextBlob=b64decode(EncryptedUser))['Plaintext']
A10UserPassword = boto3.client('kms').decrypt(CiphertextBlob=b64decode(EncryptedPass))['Plaintext']


# Boto3 service client
Ec2Client = boto3.client(service_name="ec2", region_name=AwsServerRegion)


# Private routines
def _get_public_ip_addr(instance_id):
    response = Ec2Client.describe_instances(
        InstanceIds=[instance_id]
    )
    return response['Reservations'][0]['Instances'][0]['PublicIpAddress']


def _poll_instance_state(instance_id, state='running', poll_time=30):
    """
    Polling method for instance state check.
    
    :return: None
    """
    end_time = time.time() + poll_time
    while time.time() < end_time:
        response = Ec2Client.describe_instances(
            InstanceIds=[instance_id]
        )
        current_state = \
            response['Reservations'][0]['Instances'][0]['State']['Name']
        print("Current instance state is : %s" % current_state)
        if current_state == state.lower(): break
    else:
        raise Exception("Instance state is not %s after : %s secs" % (
            state, poll_time))


def _add_instance_to_server_grp(**kwargs):
    """
    Add the instance to the server group. Before updating server group,
    existing servers we need to know. So, first call ServerGroup get and
    process the response, insert new server and post it to Server Group.
        
    :return: None
    """
    # A10 Lightning APIs
    ServerGrpApi = "applications/{0}/hosts/{1}/services/{2}/servergroups/{3}".format(
        kwargs['applicationId'], kwargs['hostId'],
        kwargs['serviceId'], kwargs['serverGroupId'])
        
    ServerGrpPolicyApi = "applications/{0}/hosts/{1}/services/{2}/servergroups/{3}/policies".format(
        kwargs['applicationId'], kwargs['hostId'],
        kwargs['serviceId'], kwargs['serverGroupId'])
        
    ServerGrpImportApi = "applications/{0}/hosts/{1}/services/{2}/servergroups/_import".format(
        kwargs['applicationId'], kwargs['hostId'], kwargs['serviceId'])
    
    # Build the requests
    request1 = urllib2.Request(
        os.environ["API_BASE_URL"] + ServerGrpApi)
    request2 = urllib2.Request(
        os.environ["API_BASE_URL"] + ServerGrpPolicyApi)
    request3 = urllib2.Request(
        os.environ["API_BASE_URL"] + ServerGrpImportApi)

    cred = A10User + ':' + A10UserPassword
    bas64 = b64encode(bytes(cred))
    auth = "Basic " + bas64.decode("ascii")
    headers = {
        "provider": "root",
        "tenant": A10Tenant,
        "Content-Type": "application/json",
        "Authorization": auth
    }

    for key, value in headers.items():
        request1.add_header(key, value)
        request2.add_header(key, value)
        request3.add_header(key, value)

    response = urllib2.urlopen(request1)
    server_grp_data = json.loads(response.read().decode("utf-8"))
    servers = server_grp_data['servers']
    servers.append(
        {
            "weight": 1,
            "state": "ACTIVE",
            "ipAddress": _get_public_ip_addr(ServerInstanceID),
            "port": CloudServerPort or server_grp_data['defaultPort']
        }
    )
    response = urllib2.urlopen(request2)
    srv_policies = json.loads(response.read().decode("utf-8"))
    server_grp_data['servers'] = servers
    server_grp_data['policies'] = srv_policies
    urllib2.urlopen(request3, json.dumps(server_grp_data).encode("utf-8"))


# Lambda handler: This is the main routine to handle server addition in case
# of Cloud Bursting
def lambda_handler(event, context):
    response = Ec2Client.describe_instances(
        InstanceIds=[ServerInstanceID]
    )
    id_to_state_map = {instance['InstanceId']: instance['State']['Name'] for
                       resv in response['Reservations'] for instance in
                       resv['Instances']}
    
    # If stopped, start the server instance
    if ServerInstanceID in id_to_state_map and id_to_state_map[ServerInstanceID] == 'stopped':
        Ec2Client.start_instances(
            InstanceIds=[ServerInstanceID]
        )

        # Poll till the instance state is running.
        _poll_instance_state(instance_id=ServerInstanceID)

        # Add the instance to server group
        _add_instance_to_server_grp(**event)

        # We are done here, nothing to return
        print("Successfully added server instance %s" %ServerInstanceID)
    else:
        return "Instance is not in stopped state, ignoring the add request"
