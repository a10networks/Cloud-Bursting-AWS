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


def _remove_server_from_sgroup(**kwargs):
    """
    Remove the server instance to the server group. Before updating server group,
    existing servers we need to know. So, first call ServerGroup get and
    process the response, remove the desired server and post it to Server Group.

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

    # Auth header
    cred = A10User + ':' + A10UserPassword
    bas64 = b64encode(bytes(cred))
    auth = "Basic " + bas64.decode("ascii")
    
    # Complete header dict
    headers = {
        "provider": "root",
        "tenant": A10Tenant,
        "Content-Type": "application/json",
        "Authorization": auth
    }

    # Attach all the headers to the requests
    for key, value in headers.items():
        request1.add_header(key, value)
        request2.add_header(key, value)
        request3.add_header(key, value)

    # First retrieve the server group data
    response = urllib2.urlopen(request1)
    server_grp_data = json.loads(response.read().decode("utf-8"))
    servers = server_grp_data['servers']
    
    # Remove the required server
    for serv in servers:
        if serv['ipAddress'] == _get_public_ip_addr(ServerInstanceID):
            servers.remove(serv)

    # Get server group policies
    response = urllib2.urlopen(request2)
    srv_policies = json.loads(response.read().decode("utf-8"))
    
    # Add parsed server data and server group policies and post it
    server_grp_data['servers'] = servers
    server_grp_data['policies'] = srv_policies
    urllib2.urlopen(request3, json.dumps(server_grp_data).encode("utf-8"))


# Lambda handler
def lambda_handler(event, context):
    print("Event is: %s" %event)

    response = Ec2Client.describe_instances()
    id_to_state_map = {instance['InstanceId']: instance['State']['Name'] for
                       resv in response['Reservations'] for instance in
                       resv['Instances']}
    
    # If instance is running, first remove it and send stop command
    if ServerInstanceID in id_to_state_map and id_to_state_map[
       ServerInstanceID] == 'running':

        # Remove the server from server group
        _remove_server_from_sgroup(**event)

        # Stop the server instance
        Ec2Client.stop_instances(
            InstanceIds=[ServerInstanceID]
        )
        time.sleep(5)
    
        # Return current state of the instance
        return "Instance: %s in successfully removed from server group" %ServerInstanceID
    else:
        return "Server is not in running state, ignoring the remove request"
