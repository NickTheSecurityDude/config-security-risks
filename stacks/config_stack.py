##############################################################
#
# config_stack.py
#
# Resources:
#   KMS with IAM custom Config rule
#
##############################################################

from aws_cdk import (
  aws_config as config,
  aws_lambda as lambda_,
  core
)

class ConfigStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, s3_cust_kms_function: lambda_.IFunction, ebs_encrypted_volumes_function: lambda_.IFunction, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # Custom Rules (Nick)

    # Checks whether the Amazon Simple Storage Service (Amazon S3) buckets are encrypted with AWS Key Management Service (AWS KMS). 
    # The rule is not NON_COMPLIANT if Amazon S3 bucket is not encrypted with AWS KMS key.
    config.CustomRule(self,"S3 Customer KMS Encryption Config Rule",
      config_rule_name="s3-cust-kms-encrypted",
      lambda_function=s3_cust_kms_function,
      configuration_changes=True,
      periodic=True,
      maximum_execution_frequency=config.MaximumExecutionFrequency.TWENTY_FOUR_HOURS,
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.S3_BUCKET
      ]),
      input_parameters={"prefix_whitelist":"[\"cdktoolkit-stagingbucket-\",\"cf-templates-\",\"aws-codestar-\"]"}
    )

    # Custom Rules (AWS)

    # Check that all EBS Volumes are Encrypted
    # Code from:
    # https://raw.githubusercontent.com/awslabs/aws-config-rules/master/python/EBS_ENCRYPTED_VOLUMES_V2/EBS_ENCRYPTED_VOLUMES_V2.py

    config.CustomRule(self,"EBS ALL Encrypted Config Rule",
      config_rule_name="ebs-all-encrypted",
      lambda_function=ebs_encrypted_volumes_function,
      configuration_changes=True,
      periodic=True,
      maximum_execution_frequency=config.MaximumExecutionFrequency.TWENTY_FOUR_HOURS,
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.EBS_VOLUME
      ])
    )

    # Managed Rules

    # Check that Amazon Elastic Block Store (EBS) encryption is enabled by default. 
    # The rule is NON_COMPLIANT if the encryption is not enabled.

    config.ManagedRule(self,"EBS Default Encryption ",
      config_rule_name="EBS-Default-Encryption",
      identifier="EC2_EBS_ENCRYPTION_BY_DEFAULT",
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.EBS_VOLUME
      ])
    )

