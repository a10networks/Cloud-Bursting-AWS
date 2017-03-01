# Cloud-Bursting-AWS
Provides the AWS Lambda Code and workflow to configure cloud bursting (from Data Center to AWS) for an application.

Use Case
========

Please refer ADS-Cloud-Bursting.pdf for details of use case.

Files:
=====
- ADS-Cloud-Bursting.pdf - Presentation explaining the use case, workflow and configuration
- Cloud-bursting.mov - Recorded demo of the use case
- async_server_add.py
- server_add.py - Code of Lambda function for adding a server
- server_delete.py - Code of Lambda function for deleting the server

Lambda Config:
=============

A. Environment Variables

 1. API_BASE_URL
 2. AwsServerRegion
 3. A10Tenant
 4. A10User
 5. CloudServerPort
 6. ServerInstanceID
 7. A10UserPassword

B. ARN permissions
```
 {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:StartInstances",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "lambda:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Stmt1443036478000",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "arn:aws:kms:YOUR-KMS-RESOURCE-KEY-HERE"
            ]
        }
    ]
 }
```

 Note: In IAM-Encryption Keys page, the kms key user section should contain the lambda role listed.
