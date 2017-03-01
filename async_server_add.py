################################################################################
__copyright__   = "Copyright 2016, A10 Networks, Inc"
################################################################################

from __future__ import print_function

import boto3
import json

def lambda_handler(event, context):
    client = boto3.client('lambda')
    response = client.invoke(
        FunctionName='ServerAdd',
        InvocationType='Event',
        Payload=json.dumps(event)
    )
    return "Initiated the process to add cloud server to the Server Group!!"
