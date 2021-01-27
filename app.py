#!/usr/bin/env python3

###################################################################
#
# 1. Config Stack
# 
###################################################################

from aws_cdk import core

import boto3
import sys

client = boto3.client('sts')
region=client.meta.region_name

"""
if region != 'us-east-1':
  print("This app may only be run from us-east-1")
  sys.exit()
"""

account_id = client.get_caller_identity()["Account"]

my_env = {'region': region, 'account': account_id}

from stacks.iam_stack import IAMStack
from stacks.lambda_stack import LambdaStack
from stacks.config_stack import ConfigStack

proj_name="config-top-risks"

app = core.App()

iam_stack=IAMStack(app, proj_name+"-iam",env=my_env)
lambda_stack=LambdaStack(app, proj_name+"-lambda",
  config_ebs_enc_lambda_role=iam_stack.config_ebs_enc_lambda_role
)
config_stack=ConfigStack(app,proj_name+"-config",
  s3_cust_kms_function=lambda_stack.s3_cust_kms_function,
  ebs_encrypted_volumes_function=lambda_stack.ebs_encrypted_volumes_function
)

app.synth()
