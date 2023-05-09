## 1. AWS Organizations
Obtain list of Member accounts directly from the source

```
aws --profile <profile> organizations list-accounts --query 'Accounts[].Id' --output text | tr '\t' '\n'
```

## 2. AWS CloudTrail
Date search for "Federate" events - adjust range as needed based on start-time value. "Federate" events are when a user logs into through the iDP.

```
aws --profile <profile> cloudtrail --region us-east-1 lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Federate --start-time $(date -d "-1 weeks" +%s) | jq -r ".Events[].CloudTrailEvent | fromjson | [.serviceEventDetails.account_id, .serviceEventDetails.role_name] | @tsv" | sort -u
```

GenerateDataKey is called when CloudTrial logs are configured to use KMS key encryption and include both the management and member account IDs

```
aws --profile <profile> cloudtrail --region us-east-1 lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GenerateDataKey --start-time $(date -d "-1 day" +%s) | jq -r '.Events[].CloudTrailEvent | fromjson | select(.requestParameters.encryptionContext."aws:s3:arn") | .requestParameters.encryptionContext."aws:s3:arn"' | grep -o -E '[0-9]{12}' | sort -u
```

AssumeRole is called whenever a role is assumed by an identity in the management account

```
aws --profile <profile> cloudtrail --region us-east-1 lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --start-time $(date -d "-1 day" +%s) | jq -r '.Events[].CloudTrailEvent | fromjson | .requestParameters.roleArn' | grep -o -E '[0-9]{0,12}' |  sort -u
```

GetGuardrailComplianceStatus used for regular checks in the Member accounts

```
aws --profile <profile> cloudtrail --region us-east-1 lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetGuardrailComplianceStatus --start-time $(date -d "-1 day" +%s) | jq -r '.Events[].CloudTrailEvent | fromjson | .requestParameters | select(.accountId) | .accountId' | sort -u
```

DescribeAccount used by AWS Control Tower to query Member account details

```
aws --profile <profile> cloudtrail --region us-east-1 lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeAccount --start-time $(date -d "-1 day" +%s) | jq -r '.Events[].CloudTrailEvent | fromjson | .requestParameters | select(.accountId) | .accountId' | sort -u
```

AssumeRoleWithSAML
```
TODO
```

## CloudWatch Logs
May have more historic data available than Event History
```
TODO
```

## CloudFormation
Pull member accounts from StackSets
```
TODO
```
