## Table of Contents  
- [Table of Contents](#table-of-contents)
- [SCP Policy Changes](#scp-policy-changes)
  - [Create new SCP](#create-new-scp)
  - [Attach SCP to Member Account](#attach-scp-to-member-account)
  - [Update SCP policy](#update-scp-policy)
  - [Detatch SCP from Member Account](#detatch-scp-from-member-account)
  - [Disable SCP entirely](#disable-scp-entirely)
- [Organizations](#organizations)
  - [Delegate Administration for AWS Organizations](#delegate-administration-for-aws-organizations)
- [Identity Center](#identity-center)
  - [Create Group in Identity Center](#create-group-in-identity-center)
  - [Add User to Group in Identity Center](#add-user-to-group-in-identity-center)
  - [Create Permissions Set in Identity Center](#create-permissions-set-in-identity-center)
  - [Add New Group with Permissions Set to AWS Account in Identity Center](#add-new-group-with-permissions-set-to-aws-account-in-identity-center)
  - [Update Group assigned to AWS Account to new Permissions Set in Identity Center](#update-group-assigned-to-aws-account-to-new-permissions-set-in-identity-center)

<a name="scp_policy_changes"/>
## SCP Policy Changes

<a name="create_new_scp_from_root_account_in_mgmt_account"/>
### Create new SCP

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:09:05Z",
    "eventSource": "organizations.amazonaws.com",
    "eventName": "CreatePolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "name": "Block service access for root user",
        "description": "This policy restricts all access to EC2 actions for the root user account in a member account.",
        "type": "SERVICE_CONTROL_POLICY",
        "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RestrictEC2ForRoot\",\"Effect\":\"Deny\",\"Action\":[\"ec2:*\"],\"Resource\":[\"*\"],\"Condition\":{\"StringLike\":{\"aws:PrincipalArn\":[\"arn:aws:iam::*:root\"]}}}]}"
    },
    "responseElements": {
        "policy": {
            "policySummary": {
                "id": "p-bvdv3rx3",
                "description": "This policy restricts all access to EC2 actions for the root user account in a member account.",
                "type": "SERVICE_CONTROL_POLICY",
                "awsManaged": false,
                "arn": "arn:aws:organizations::<MANAGEMENT_ACCT_ID>:policy/o-pdbiiraurm/service_control_policy/p-bvdv3rx3",
                "name": "Block service access for root user"
            },
            "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RestrictEC2ForRoot\",\"Effect\":\"Deny\",\"Action\":[\"ec2:*\"],\"Resource\":[\"*\"],\"Condition\":{\"StringLike\":{\"aws:PrincipalArn\":[\"arn:aws:iam::*:root\"]}}}]}"
        }
    },
    "requestID": "ac346d2c-cfed-464c-8f9e-31751d62a690",
    "eventID": "cc6e4b52-61ea-47f9-8812-1edcaeb64841",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="attach_scp_to_member_account"/>
### Attach SCP to Member Account

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:33:27Z",
    "eventSource": "organizations.amazonaws.com",
    "eventName": "AttachPolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "targetId": "<MEMBER_ACCT_ID>",
        "policyId": "p-bvdv3rx3"
    },
    "responseElements": null,
    "requestID": "da8fac12-ec99-429e-8489-7325736422ed",
    "eventID": "560c4918-6149-4b78-a0c9-7d62d6ec8f86",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="update_scp_policy"/>
### Update SCP policy

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:40:33Z",
    "eventSource": "organizations.amazonaws.com",
    "eventName": "UpdatePolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RestrictEC2ForRoot\",\"Effect\":\"Deny\",\"Action\":[\"ec2:*\",\"ebs:*\"],\"Resource\":[\"*\"],\"Condition\":{\"StringLike\":{\"aws:PrincipalArn\":[\"arn:aws:iam::*:root\"]}}}]}",
        "policyId": "p-bvdv3rx3",
        "description": "This policy restricts all access to EC2 actions for the root user account in a member account.",
        "name": "Block service access for root user"
    },
    "responseElements": {
        "policy": {
            "policySummary": {
                "id": "p-bvdv3rx3",
                "description": "This policy restricts all access to EC2 actions for the root user account in a member account.",
                "type": "SERVICE_CONTROL_POLICY",
                "awsManaged": false,
                "arn": "arn:aws:organizations::<MANAGEMENT_ACCT_ID>:policy/o-pdbiiraurm/service_control_policy/p-bvdv3rx3",
                "name": "Block service access for root user"
            },
            "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RestrictEC2ForRoot\",\"Effect\":\"Deny\",\"Action\":[\"ec2:*\",\"ebs:*\"],\"Resource\":[\"*\"],\"Condition\":{\"StringLike\":{\"aws:PrincipalArn\":[\"arn:aws:iam::*:root\"]}}}]}"
        }
    },
    "requestID": "42ba0a26-92ee-4a12-bbb4-44387bdf4194",
    "eventID": "f0e2e186-e6aa-4b75-b421-e5058bb92698",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="detach_scp_from_member_account"/>
### Detatch SCP from Member Account

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:39:22Z",
    "eventSource": "organizations.amazonaws.com",
    "eventName": "DetachPolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "targetId": "<MEMBER_ACCT_ID>",
        "policyId": "p-bvdv3rx3"
    },
    "responseElements": null,
    "requestID": "7621816a-a0b3-46bf-a458-056f64243ba9",
    "eventID": "bc589e5f-3859-4acb-9b54-30d7cb08edd6",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="disable_scp_entirely"/>
### Disable SCP entirely

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:20:55Z",
    "eventSource": "organizations.amazonaws.com",
    "eventName": "DisablePolicyType",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "rootId": "r-bmrv",
        "policyType": "SERVICE_CONTROL_POLICY"
    },
    "responseElements": {
        "root": {
            "policyTypes": [
                {
                    "status": "ENABLED",
                    "type": "SERVICE_CONTROL_POLICY"
                }
            ],
            "arn": "arn:aws:organizations::<MANAGEMENT_ACCT_ID>:root/o-pdbiiraurm/r-bmrv",
            "name": "Root",
            "id": "r-bmrv"
        }
    },
    "requestID": "655e3785-6443-40ad-847e-82b381d365b5",
    "eventID": "0906bc30-3853-4ccd-8576-5b4cfa086651",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="organizations"/>
## Organizations

<a name="delegate_admin_for_aws_organizations"/>
### Delegate Administration for AWS Organizations

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T01:02:29Z",
    "eventSource": "organizations.amazonaws.com",
    "eventName": "PutResourcePolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "content": "HIDDEN_DUE_TO_SECURITY_REASONS"
    },
    "responseElements": {
        "resourcePolicy": {
            "resourcePolicySummary": {
                "arn": "arn:aws:organizations::<MANAGEMENT_ACCT_ID>:resourcepolicy/o-pdbiiraurm/rp-vdj3leyl",
                "id": "rp-vdj3leyl"
            },
            "content": "HIDDEN_DUE_TO_SECURITY_REASONS"
        }
    },
    "requestID": "14ab629b-f4c8-4729-bfc9-3bfe339f8ee4",
    "eventID": "dfb4a1ae-ccd6-43e8-8696-6c3154d789b3",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "organizations.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="identity_center"/>
## Identity Center

<a name="create_group_in_identity_center"/>
### Create Group in Identity Center

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:46:02Z",
    "eventSource": "sso-directory.amazonaws.com",
    "eventName": "CreateGroup",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "identityStoreId": "d-906791299c",
        "displayName": "admin-test-group"
    },
    "responseElements": {
        "group": {
            "groupId": "34887428-4081-7042-c3c6-928d413009e7",
            "displayName": "admin-test-group",
            "groupAttributes": {},
            "meta": {
                "createdAt": "Apr 25, 2023 12:46:02 AM",
                "updatedAt": "Apr 25, 2023 12:46:02 AM",
                "createdBy": "<MANAGEMENT_ACCT_ID>",
                "updatedBy": "<MANAGEMENT_ACCT_ID>"
            }
        }
    },
    "requestID": "db281581-3da4-4fa0-958b-bbf936fc546c",
    "eventID": "836af158-a7eb-4c76-8004-dec47393e571",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "up.sso.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="add_user_to_group_in_identity_center"/>
### Add User to Group in Identity Center

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:46:15Z",
    "eventSource": "sso-directory.amazonaws.com",
    "eventName": "AddMemberToGroup",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "requestParameters": {
        "identityStoreId": "d-906791299c",
        "groupId": "34887428-4081-7042-c3c6-928d413009e7",
        "member": {
            "memberId": "94e80458-9021-70ea-08fa-c3a10a1d8a92"
        }
    },
    "responseElements": null,
    "requestID": "33b9dcdf-fb0c-44ba-886f-a46f1487d555",
    "eventID": "28507fe9-d1f8-499f-ac6d-ec78003fa1f0",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "up.sso.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

<a name="create_permissions_set_in_identity_center"/>
### Create Permissions Set in Identity Center

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-24T21:38:47Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T00:48:16Z",
    "eventSource": "sso.amazonaws.com",
    "eventName": "CreatePermissionSet",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "AWS Internal",
    "requestParameters": {
        "name": "AdministratorAccess-test",
        "instanceArn": "arn:aws:sso:::instance/ssoins-72233af8ea2d1f14",
        "sessionDuration": "PT12H",
        "tags": []
    },
    "responseElements": {
        "permissionSet": {
            "name": "AdministratorAccess-test",
            "permissionSetArn": "arn:aws:sso:::permissionSet/ssoins-72233af8ea2d1f14/ps-ae5d1fa1f80b684e",
            "createdDate": "Apr 25, 2023 12:48:16 AM",
            "sessionDuration": "PT12H"
        }
    },
    "requestID": "5d285c93-dc9d-4827-bcef-4ef596931992",
    "eventID": "12d9425b-0114-4550-b2e4-71a7047ab92f",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "sessionCredentialFromConsole": "true"
}
```

<a name="add_group_with_permissions_set_to_aws_account_in_identity_center"/>
### Add New Group with Permissions Set to AWS Account in Identity Center

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-25T19:02:24Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T19:24:49Z",
    "eventSource": "sso.amazonaws.com",
    "eventName": "CreateAccountAssignment",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "AWS Internal",
    "requestParameters": {
        "instanceArn": "arn:aws:sso:::instance/ssoins-72233af8ea2d1f14",
        "targetId": "<MANAGEMENT_ACCT_ID>",
        "targetType": "AWS_ACCOUNT",
        "permissionSetArn": "arn:aws:sso:::permissionSet/ssoins-72233af8ea2d1f14/ps-ae5d1fa1f80b684e",
        "principalType": "GROUP",
        "principalId": "34887428-4081-7042-c3c6-928d413009e7"
    },
    "responseElements": {
        "accountAssignmentCreationStatus": {
            "status": "IN_PROGRESS",
            "requestId": "f8604aff-1de0-48ba-b228-f65559e504c1",
            "targetId": "<MANAGEMENT_ACCT_ID>",
            "targetType": "AWS_ACCOUNT",
            "permissionSetArn": "arn:aws:sso:::permissionSet/ssoins-72233af8ea2d1f14/ps-ae5d1fa1f80b684e",
            "principalType": "GROUP",
            "principalId": "34887428-4081-7042-c3c6-928d413009e7"
        }
    },
    "requestID": "f8604aff-1de0-48ba-b228-f65559e504c1",
    "eventID": "bea150ce-12b4-4417-9983-7be8c28a7a3a",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "sessionCredentialFromConsole": "true"
}
```

<a name="update_group_assigned_to_aws_account_to_new_permissions_set_in_identity_center"/>
### Update Group assigned to AWS Account to new Permissions Set in Identity Center

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-25T19:02:24Z",
                "mfaAuthenticated": "true"
            }
        },
        "invokedBy": "sso.amazonaws.com"
    },
    "eventTime": "2023-04-25T19:24:50Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateRole",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "sso.amazonaws.com",
    "userAgent": "AWS Internal",
    "requestParameters": {
        "path": "/aws-reserved/sso.amazonaws.com/",
        "roleName": "AWSReservedSSO_AdministratorAccess-test_c194f596bcea55cc",
        "assumeRolePolicyDocument": "{  \"Version\": \"2012-10-17\",  \"Statement\": {    \"Effect\": \"Allow\",    \"Action\": [      \"sts:AssumeRoleWithSAML\",      \"sts:TagSession\"    ],    \"Principal\": {\"Federated\": \"arn:aws:iam::<MANAGEMENT_ACCT_ID>:saml-provider/AWSSSO_DO_NOT_DELETE\"},    \"Condition\": {\"StringEquals\": {\"SAML:aud\": \"https://signin.aws.amazon.com/saml\"}}  }}",
        "maxSessionDuration": 43200
    },
    "responseElements": {
        "role": {
            "path": "/aws-reserved/sso.amazonaws.com/",
            "roleName": "AWSReservedSSO_AdministratorAccess-test_c194f596bcea55cc",
            "roleId": "AROAZ73XJMJGC5KJSHBHM",
            "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess-test_c194f596bcea55cc",
            "createDate": "Apr 25, 2023 7:24:50 PM",
            "assumeRolePolicyDocument": "%7B%20%20%22Version%22%3A%20%222012-10-17%22%2C%20%20%22Statement%22%3A%20%7B%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%20%20%20%20%22Action%22%3A%20%5B%20%20%20%20%20%20%22sts%3AAssumeRoleWithSAML%22%2C%20%20%20%20%20%20%22sts%3ATagSession%22%20%20%20%20%5D%2C%20%20%20%20%22Principal%22%3A%20%7B%22Federated%22%3A%20%22arn%3Aaws%3Aiam%3A%3A<MANAGEMENT_ACCT_ID>%3Asaml-provider%2FAWSSSO_DO_NOT_DELETE%22%7D%2C%20%20%20%20%22Condition%22%3A%20%7B%22StringEquals%22%3A%20%7B%22SAML%3Aaud%22%3A%20%22https%3A%2F%2Fsignin.aws.amazon.com%2Fsaml%22%7D%7D%20%20%7D%7D"
        }
    },
    "requestID": "77326b67-192b-4c87-b7fc-8ba10ea702ef",
    "eventID": "fb43cde3-485e-4128-afdd-04bec12211a7",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "sessionCredentialFromConsole": "true"
}
```
```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-25T19:02:24Z",
                "mfaAuthenticated": "true"
            }
        },
        "invokedBy": "sso.amazonaws.com"
    },
    "eventTime": "2023-04-25T19:24:50Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "AttachRolePolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "sso.amazonaws.com",
    "userAgent": "AWS Internal",
    "requestParameters": {
        "roleName": "AWSReservedSSO_AdministratorAccess-test_c194f596bcea55cc",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    },
    "responseElements": null,
    "requestID": "1cf98dda-6a80-4986-8d73-1016a36f2490",
    "eventID": "d42a8333-0688-4782-b01a-4885dae831ee",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "sessionCredentialFromConsole": "true"
}
```
```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-25T19:02:24Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T19:25:55Z",
    "eventSource": "sso.amazonaws.com",
    "eventName": "CreateAccountAssignment",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "AWS Internal",
    "requestParameters": {
        "instanceArn": "arn:aws:sso:::instance/ssoins-72233af8ea2d1f14",
        "targetId": "<MANAGEMENT_ACCT_ID>",
        "targetType": "AWS_ACCOUNT",
        "permissionSetArn": "arn:aws:sso:::permissionSet/ssoins-72233af8ea2d1f14/ps-a1b9e6bd2d4fb336",
        "principalType": "GROUP",
        "principalId": "34887428-4081-7042-c3c6-928d413009e7"
    },
    "responseElements": {
        "accountAssignmentCreationStatus": {
            "status": "IN_PROGRESS",
            "requestId": "fcb3a718-f979-45e9-b912-0081559afaaf",
            "targetId": "<MANAGEMENT_ACCT_ID>",
            "targetType": "AWS_ACCOUNT",
            "permissionSetArn": "arn:aws:sso:::permissionSet/ssoins-72233af8ea2d1f14/ps-a1b9e6bd2d4fb336",
            "principalType": "GROUP",
            "principalId": "34887428-4081-7042-c3c6-928d413009e7"
        }
    },
    "requestID": "fcb3a718-f979-45e9-b912-0081559afaaf",
    "eventID": "7dbd28aa-25a8-404c-a45b-af7184ba9129",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "sessionCredentialFromConsole": "true"
}
```
```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "<MANAGEMENT_ACCT_ID>",
        "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:root",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-25T19:02:24Z",
                "mfaAuthenticated": "true"
            }
        }
    },
    "eventTime": "2023-04-25T19:25:56Z",
    "eventSource": "sso.amazonaws.com",
    "eventName": "DeleteAccountAssignment",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "<REDACTED>",
    "userAgent": "AWS Internal",
    "requestParameters": {
        "instanceArn": "arn:aws:sso:::instance/ssoins-72233af8ea2d1f14",
        "targetId": "<MANAGEMENT_ACCT_ID>",
        "targetType": "AWS_ACCOUNT",
        "permissionSetArn": "arn:aws:sso:::permissionSet/ssoins-72233af8ea2d1f14/ps-ae5d1fa1f80b684e",
        "principalType": "GROUP",
        "principalId": "34887428-4081-7042-c3c6-928d413009e7"
    },
    "responseElements": {
        "accountAssignmentDeletionStatus": {
            "status": "IN_PROGRESS",
            "requestId": "1634804f-7389-4b8a-b6b4-dbf38284a6ce",
            "targetId": "<MANAGEMENT_ACCT_ID>",
            "targetType": "AWS_ACCOUNT",
            "permissionSetArn": "arn:aws:sso:::permissionSet/ssoins-72233af8ea2d1f14/ps-ae5d1fa1f80b684e",
            "principalType": "GROUP",
            "principalId": "34887428-4081-7042-c3c6-928d413009e7"
        }
    },
    "requestID": "1634804f-7389-4b8a-b6b4-dbf38284a6ce",
    "eventID": "0d4fb26b-af27-420b-9f83-007d21080745",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management",
    "sessionCredentialFromConsole": "true"
}
```
```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAZ73XJMJGC7W4XYY5E:AWS-SSO",
        "arn": "arn:aws:sts::<MANAGEMENT_ACCT_ID>:assumed-role/AWSServiceRoleForSSO/AWS-SSO",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": "AROAZ73XJMJGC7W4XYY5E",
                "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO",
                "accountId": "<MANAGEMENT_ACCT_ID>",
                "userName": "AWSServiceRoleForSSO"
            },
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-25T19:26:04Z",
                "mfaAuthenticated": "false"
            }
        },
        "invokedBy": "sso.amazonaws.com"
    },
    "eventTime": "2023-04-25T19:26:10Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "DetachRolePolicy",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "sso.amazonaws.com",
    "userAgent": "sso.amazonaws.com",
    "requestParameters": {
        "roleName": "AWSReservedSSO_AdministratorAccess-test_c194f596bcea55cc",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    },
    "responseElements": null,
    "requestID": "3bbcf76e-df5a-4dbc-9afb-820f09d62934",
    "eventID": "d4be97d6-7eb7-48d6-af90-bf93f81e0608",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management"
}
```
```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAZ73XJMJGC7W4XYY5E:AWS-SSO",
        "arn": "arn:aws:sts::<MANAGEMENT_ACCT_ID>:assumed-role/AWSServiceRoleForSSO/AWS-SSO",
        "accountId": "<MANAGEMENT_ACCT_ID>",
        "accessKeyId": "<REDACTED>",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": "AROAZ73XJMJGC7W4XYY5E",
                "arn": "arn:aws:iam::<MANAGEMENT_ACCT_ID>:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO",
                "accountId": "<MANAGEMENT_ACCT_ID>",
                "userName": "AWSServiceRoleForSSO"
            },
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2023-04-25T19:26:04Z",
                "mfaAuthenticated": "false"
            }
        },
        "invokedBy": "sso.amazonaws.com"
    },
    "eventTime": "2023-04-25T19:26:10Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "DeleteRole",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "sso.amazonaws.com",
    "userAgent": "sso.amazonaws.com",
    "requestParameters": {
        "roleName": "AWSReservedSSO_AdministratorAccess-test_c194f596bcea55cc"
    },
    "responseElements": null,
    "requestID": "f4d5df23-a995-4bee-bf2d-73be9b6ff367",
    "eventID": "a44c8c21-9a8f-491f-bbdb-d33260a92f05",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "<MANAGEMENT_ACCT_ID>",
    "eventCategory": "Management"
}
```

