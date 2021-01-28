#           Gherkin               #

**Rule Name:**  
s3-cust-kms-encrypted

Description:
  Check that all S3 Buckets have *Customer* KMS Encryption with IAM user permissions disabled.

Trigger:
  Periodic
  Configuration Change on AWS::S3::Bucket

Reports on:
  AWS::S3::Bucket

Parameters:  
  | Parameter Name        | Type      | Description                                   |
  | ----------------------|-----------|---------------------------------------------- |
  | prefix_whitelist      | Optional  | List of bucket prefixes that you don't want   |
  |                       |           | to be marked as non-compliant, ex.            |
  |                       |           | CloudFormation, etc.                          |

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
