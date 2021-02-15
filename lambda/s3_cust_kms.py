# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
'''
#####################################
##           Gherkin               ##
#####################################

Rule Name:
  s3-cust-kms-encrypted

Description:
  Check that all S3 Buckets have *Customer* KMS Encryption with IAM user permissions disabled.

Trigger:
  Periodic
  Configuration Change on AWS::S3::Bucket

Reports on:
  AWS::S3::Bucket

Parameters:
  | ----------------------|-----------|-----------------------------------------------|
  | Parameter Name        | Type      | Description                                   |
  | ----------------------|-----------|---------------------------------------------- |
  | prefix_whitelist      | Optional  | List of bucket prefixes that you don't want   |
  |                       |           | to be marked as non-compliant, ex.            |
  |                       |           | CloudFormation, etc.                          |
  | ----------------------|-----------|---------------------------------------------- |

Feature:
    In order to: to protect the data confidentiality
             As: a Security Officer
         I want: To ensure that all S3 Buckets have Customer KMS encryption
            And: that the Customer KMS Key has IAM user access disabled.
        
Scenarios:
    Scenario 1:
      Given: bucket is not in current region
       Then: return NOT_APPLICABLE

    Scenario 2:
      Given: prefix_whitelist is not a list
       Then: return ERROR

    Scenario 3:
      Given: one or more values in the prefix_whitelist list are not strings
       Then: return ERROR

    Scenario 4:
      Given: the bucket is not encrypted at all.
       Then: return NON_COMPLIANT

    Scenario 5:
      Given: the bucket is encrypted but using the S3 default KMS key (SSE-KMS aws/s3).
       Then: return NON_COMPLIANT

    Scenario 6:
      Given: the bucket is encrypted with Amazon's S3 key (SSE-S3)
       Then: return NON_COMPLIANT
    
    Scenario 7:
      Given: the bucket is encrypted with a customer created KMS key (SSE-KMS non-aws/s3)
        And: the customer created KMS key has IAM user permissions enabled
       Then: return NON_COMPLIANT

    Scenario 8:
      Given: the bucket is encrypted with a customer created KMS key (SSE-KMS non-aws/s3)
        And: the customer created KMS key does NOT have IAM user permissions enabled
       Then: return COMPLIANT
'''

import json
import sys
import datetime
import boto3
import botocore

try:
    import liblogging
except ImportError:
    pass

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

# Other parameters (no change needed)
CONFIG_ROLE_TIMEOUT_SECONDS = 900

#############
# Main Code #
#############

DEBUG=0

kms_client = boto3.client('kms')

# Function to check if key has IAM enabled and if its an AWS managed key
# Code from config-kms-iam-cdk project lambda/config_kms_iam_checker.py, with 1 modification
def check_key_policy(_key_id):

  _compliant=0

  # if this errors the key does not have IAM access enabled and IS complaint
  try:
    response = kms_client.get_key_policy(
      KeyId=_key_id,
      PolicyName='default'
    )
    response = kms_client.describe_key(
      KeyId=_key_id,
    )
    
    # check if the key manager is AWS or the customer
    key_manager=response['KeyMetadata']['KeyManager']
    if key_manager=='AWS':
      if DEBUG:
        print(_key_id,"is an AWS Managed Key")
      # Modification from original code; return non-compliant for AWS Managed Keys
      _compliant=0
  except Exception as e:
    if DEBUG:
      print(e)
    _compliant=1
    
  return _compliant

import re

s3_client = boto3.client('s3')

def check_s3_compliance(_bucket_name,_region,_prefix_whitelist):

  # if bucket not in current region, treat it as "whitelisted"
  bucket_region=s3_client.get_bucket_location(Bucket=_bucket_name)['LocationConstraint']
  
  # fix for us-east-1 buckets
  if bucket_region is None:
    bucket_region='us-east-1'
    
  if bucket_region != _region:
    if DEBUG:
      print("Bucket not in region:",_region)
      print("region:",bucket_region)
    return "NOT_APPLICABLE"

  print("Line 161: Prefix whitelist",_prefix_whitelist)

  compliant=0
  whitelisted=0

  for prefix in _prefix_whitelist:
    if DEBUG:
      print("Prefix Check",prefix,_bucket_name)
    pattern="^"+prefix+".*"
    match = re.search(pattern, _bucket_name)
    if match:
      whitelisted=1
      if DEBUG:
        print(_bucket_name,"is whitelisted")
      return "NOT_APPLICABLE"

  if whitelisted==0:
    try:
      response = s3_client.get_bucket_encryption(
        Bucket=_bucket_name,
      )
      key_arn=response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']
      pattern=".*:alias/aws/s3$"
      if re.search(pattern, key_arn):
        compliant=0
      else:
        key_id=key_arn.split("/")[1]
        if DEBUG:
          print(key_id)
        # check if we have a customer key id
        if len(key_id)==36:
          compliant=check_key_policy(key_id)
        if DEBUG:
          print("check_key_policy result:",compliant)
          if complaint==1:
            print("COMPLIANT!! KMS encrypted key with IAM disabled")
          else:
            print("NON_COMPLIANT, key has IAM permissions")
    except Exception as e:
      if DEBUG:
        print("A \"ServerSideEncryptionConfigurationNotFoundError\" error here is fine.")
        print(e)
      pass

    if compliant==1:
      if DEBUG:
        print(_bucket_name,"IS compliant")
      return "COMPLIANT"
    else:
      if DEBUG:
        print(_bucket_name,"is NOT compliant")
      return "NON_COMPLIANT"

def evaluate_compliance(event, configuration_item, valid_rule_parameters, region):

  if DEBUG:
    print("event:",event)
    print("parameters:", json.loads(event['ruleParameters'])['prefix_whitelist'])
    print("valid_rule_parameters:",valid_rule_parameters)

    rule_parameters=json.loads(event['ruleParameters'])

    # check parameters
    # THIS IS RUN AUTOMATICALLY IN THE HANDLER
    #evaluate_parameters(rule_parameters)

  """Form the evaluation(s) to be return to Config Rules

    Return either:
    None -- when no result needs to be displayed
    a string -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    a dictionary -- the evaluation dictionary, usually built by build_evaluation_from_config_item()
    a list of dictionary -- a list of evaluation dictionary , usually built by build_evaluation()

    Keyword arguments:
    event -- the event variable given in the lambda handler
    configuration_item -- the configurationItem dictionary in the invokingEvent
    valid_rule_parameters -- the output of the evaluate_parameters() representing validated parameters of the Config Rule

    Advanced Notes:
    1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status, the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
    2 -- if a None or a list of dictionary is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
    3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
  """

  ###############################
  # Add your custom logic here. #
  ###############################

  # set region in handler and pass it
  #region=context.invoked_function_arn.split(":")[3]

  # check if this is a period run (loop through all keys) or a run based on a change      
  try:
    periodic_test=json.loads(event['invokingEvent'])['configurationItem']
    periodic=0
  except Exception as e:
    if DEBUG:
      print(e)
    periodic=1
    
  print("Loading prefix_whitelist...")
  try:
    prefix_whitelist=json.loads(json.loads(event['ruleParameters'])['prefix_whitelist'])
  except:
    prefix_whitelist=[]
    
  if DEBUG:
    print("Prefix Type:",type(prefix_whitelist))
  
  if periodic==1:
    if DEBUG:
      print("Periodic Run Detected")
        
    # if period run, send results from all keys in evaluations array    
    evaluations=[]

    s3_client = boto3.client('s3')
    response = s3_client.list_buckets()
    

    for bucket in response['Buckets']:
      bucket_name=bucket['Name']
      if DEBUG:
        print(bucket_name)
      compliance=check_s3_compliance(bucket_name,region,prefix_whitelist)
      evaluations.append(build_evaluation(bucket_name, compliance, event, 'AWS::S3::Bucket'))

    if DEBUG:
      print("Evaluations:",evaluations)    
      print("End Lambda Function")
        
    # return array of results    
    return evaluations 

  else:
    # make sure the bucket_name is found
    if DEBUG:
      print("On-demand / Configuration Change Run Detected")
      print("Configuration Item:",json.loads(event['invokingEvent'])['configurationItem'])
    try:    
      bucket_name=json.loads(event['invokingEvent'])['configurationItem']['configuration']['name']
      if DEBUG:
        print(bucket_name)
    except Exception as e:
      if DEBUG:
        print(e)
        print("Line : bucket_name not found")
          
      return None
    
    compliance=check_s3_compliance(bucket_name,region,prefix_whitelist)
    if(DEBUG):
      print(compliance)
    return compliance


def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.

    Return:
    anything suitable for the evaluate_compliance()

    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """
    
    #rule_parameters=json.loads(rule_parameters)
    
    if DEBUG:
      print("eval_param rp:",rule_parameters)
      print("eval_param pw:",rule_parameters['prefix_whitelist'])
      print("eval_param pw json:",json.loads(rule_parameters['prefix_whitelist']))

    if rule_parameters:
      prefix_whitelist=json.loads(rule_parameters['prefix_whitelist'])
      if prefix_whitelist != '':
        if type(prefix_whitelist) is not list:
          raise ValueError('prefix_whitelist needs to be a list.')
        for prefix in prefix_whitelist:
          if type(prefix) is not str:
            raise ValueError('Only strings may be in the prefix_whitelist')

    valid_rule_parameters = rule_parameters
    return valid_rule_parameters

####################
# Helper Functions #
####################

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):
    """Return an error dictionary when the evaluate_parameters() raises a ValueError.

    Keyword arguments:
    ex -- Exception text
    """
    return  build_error_response(internal_error_message="Parameter value is invalid",
                                 internal_error_details="An ValueError was raised during the validation of the Parameter value",
                                 customer_error_code="InvalidParameterValueException",
                                 customer_error_message=str(ex))

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event, region=None):
    """Return the service boto client. It should be used instead of directly calling the client.

    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    region -- the region where the client is called (default: None)
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service, region)
    credentials = get_assume_role_credentials(get_execution_role_arn(event), region)
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=region
                       )

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.

    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None). It will be truncated to 255 if longer.
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = build_annotation(annotation)
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc

def build_evaluation_from_config_item(configuration_item, compliance_type, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on configuration change rules.

    Keyword arguments:
    configuration_item -- the configurationItem dictionary in the invokingEvent
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    annotation -- an annotation to be added to the evaluation (default None). It will be truncated to 255 if longer.
    """
    eval_ci = {}
    if annotation:
        eval_ci['Annotation'] = build_annotation(annotation)
    eval_ci['ComplianceResourceType'] = configuration_item['resourceType']
    eval_ci['ComplianceResourceId'] = configuration_item['resourceId']
    eval_ci['ComplianceType'] = compliance_type
    eval_ci['OrderingTimestamp'] = configuration_item['configurationItemCaptureTime']
    return eval_ci

####################
# Boilerplate Code #
####################

# Get execution role for Lambda function
def get_execution_role_arn(event):
    role_arn = None
    if 'ruleParameters' in event:
        rule_params = json.loads(event['ruleParameters'])
        role_name = rule_params.get("ExecutionRoleName")
        if role_name:
            execution_role_prefix = event["executionRoleArn"].split("/")[0]
            role_arn = "{}/{}".format(execution_role_prefix, role_name)

    if not role_arn:
        role_arn = event['executionRoleArn']

    return role_arn

# Build annotation within Service constraints
def build_annotation(annotation_string):
    if len(annotation_string) > 256:
        return annotation_string[:244] + " [truncated]"
    return annotation_string

# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'ScheduledNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resource_type, resource_id, configuration_capture_time):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1)
    configuration_item = result['configurationItems'][0]
    return convert_api_configuration(configuration_item)

# Convert from the API model to the original invocation model
def convert_api_configuration(configuration_item):
    for k, v in configuration_item.items():
        if isinstance(v, datetime.datetime):
            configuration_item[k] = str(v)
    configuration_item['awsAccountId'] = configuration_item['accountId']
    configuration_item['ARN'] = configuration_item['arn']
    configuration_item['configurationStateMd5Hash'] = configuration_item['configurationItemMD5Hash']
    configuration_item['configurationItemVersion'] = configuration_item['version']
    configuration_item['configuration'] = json.loads(configuration_item['configuration'])
    if 'relationships' in configuration_item:
        for i in range(len(configuration_item['relationships'])):
            configuration_item['relationships'][i]['name'] = configuration_item['relationships'][i]['relationshipName']
    return configuration_item

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invoking_event):
    check_defined(invoking_event, 'invokingEvent')
    if is_oversized_changed_notification(invoking_event['messageType']):
        configuration_item_summary = check_defined(invoking_event['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configuration_item_summary['resourceType'], configuration_item_summary['resourceId'], configuration_item_summary['configurationItemCaptureTime'])
    if is_scheduled_notification(invoking_event['messageType']):
        return None
    return check_defined(invoking_event['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configuration_item, event):
    try:
        check_defined(configuration_item, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configuration_item['configurationItemStatus']
    event_left_scope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")

    return status in ('OK', 'ResourceDiscovered') and not event_left_scope


def get_assume_role_credentials(role_arn, region=None):
    sts_client = boto3.client('sts', region)
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn,
                                                      RoleSessionName="configLambdaExecution",
                                                      DurationSeconds=CONFIG_ROLE_TIMEOUT_SECONDS)
        if 'liblogging' in sys.modules:
            liblogging.logSession(role_arn, assume_role_response)
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        print(str(ex))
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# This removes older evaluation (usually useful for periodic rule not reporting on AWS::::Account).
def clean_up_old_evaluations(latest_evaluations, event):

    cleaned_evaluations = []

    old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=event['configRuleName'],
        ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
        Limit=100)

    old_eval_list = []

    while True:
        for old_result in old_eval['EvaluationResults']:
            old_eval_list.append(old_result)
        if 'NextToken' in old_eval:
            next_token = old_eval['NextToken']
            old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
                ConfigRuleName=event['configRuleName'],
                ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
                Limit=100,
                NextToken=next_token)
        else:
            break

    for old_eval in old_eval_list:
        old_resource_id = old_eval['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        newer_founded = False
        for latest_eval in latest_evaluations:
            if old_resource_id == latest_eval['ComplianceResourceId']:
                newer_founded = True
        if not newer_founded:
            cleaned_evaluations.append(build_evaluation(old_resource_id, "NOT_APPLICABLE", event))

    return cleaned_evaluations + latest_evaluations

def lambda_handler(event, context):
    if 'liblogging' in sys.modules:
        liblogging.logEvent(event)

    global AWS_CONFIG_CLIENT

    region=context.invoked_function_arn.split(":")[3]

    if DEBUG:
      print("handler event:",event)
      print("handler context:",context)
      print("handler region:",region)
    
    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    try:
        valid_rule_parameters = evaluate_parameters(rule_parameters)
    except ValueError as ex:
        return build_parameters_value_error_response(ex)

    try:
        AWS_CONFIG_CLIENT = get_client('config', event)
        if invoking_event['messageType'] in ['ConfigurationItemChangeNotification', 'ScheduledNotification', 'OversizedConfigurationItemChangeNotification']:
            configuration_item = get_configuration_item(invoking_event)
            if is_applicable(configuration_item, event):
                compliance_result = evaluate_compliance(event, configuration_item, valid_rule_parameters, region)
            else:
                compliance_result = "NOT_APPLICABLE"
        else:
            return build_internal_error_response('Unexpected message type', str(invoking_event))
    except botocore.exceptions.ClientError as ex:
        if is_internal_error(ex):
            return build_internal_error_response("Unexpected error while completing API request", str(ex))
        return build_error_response("Customer error while making API request", str(ex), ex.response['Error']['Code'], ex.response['Error']['Message'])
    except ValueError as ex:
        return build_internal_error_response(str(ex), str(ex))

    evaluations = []
    latest_evaluations = []

    if not compliance_result:
        latest_evaluations.append(build_evaluation(event['accountId'], "NOT_APPLICABLE", event, resource_type='AWS::::Account'))
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, str):
        if configuration_item:
            evaluations.append(build_evaluation_from_config_item(configuration_item, compliance_result))
        else:
            evaluations.append(build_evaluation(event['accountId'], compliance_result, event, resource_type=DEFAULT_RESOURCE_TYPE))
    elif isinstance(compliance_result, list):
        for evaluation in compliance_result:
            missing_fields = False
            for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
                if field not in evaluation:
                    print("Missing " + field + " from custom evaluation.")
                    missing_fields = True

            if not missing_fields:
                latest_evaluations.append(evaluation)
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, dict):
        missing_fields = False
        for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
            if field not in compliance_result:
                print("Missing " + field + " from custom evaluation.")
                missing_fields = True
        if not missing_fields:
            evaluations.append(compliance_result)
    else:
        evaluations.append(build_evaluation_from_config_item(configuration_item, 'NOT_APPLICABLE'))

    # Put together the request that reports the evaluation status
    result_token = event['resultToken']
    test_mode = False
    if result_token == 'TESTMODE':
        # Used solely for RDK test to skip actual put_evaluation API call
        test_mode = True

    # Invoke the Config API to report the result of the evaluation
    evaluation_copy = []
    evaluation_copy = evaluations[:]
    while evaluation_copy:
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluation_copy[:100], ResultToken=result_token, TestMode=test_mode)
        del evaluation_copy[:100]

    # Used solely for RDK test to be able to test Lambda function
    return evaluations

def is_internal_error(exception):
    return ((not isinstance(exception, botocore.exceptions.ClientError)) or exception.response['Error']['Code'].startswith('5')
            or 'InternalError' in exception.response['Error']['Code'] or 'ServiceError' in exception.response['Error']['Code'])

def build_internal_error_response(internal_error_message, internal_error_details=None):
    return build_error_response(internal_error_message, internal_error_details, 'InternalError', 'InternalError')

def build_error_response(internal_error_message, internal_error_details=None, customer_error_code=None, customer_error_message=None):
    error_response = {
        'internalErrorMessage': internal_error_message,
        'internalErrorDetails': internal_error_details,
        'customerErrorMessage': customer_error_message,
        'customerErrorCode': customer_error_code
    }
    print(error_response)
    return error_response
