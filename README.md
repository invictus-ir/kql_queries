# kql_queries
KQL queries for Incident Response


# KQL query to detect cross-synchronization attacks
```
AuditLogs
| where OperationName == "Add a partner to cross-tenant access setting" 
| where parse_json(tostring(TargetResources[0].modifiedProperties))[0].displayName == "tenantId"
| extend initiating_user=parse_json(tostring(InitiatedBy.user)).userPrincipalName
| extend source_ip=parse_json(tostring(InitiatedBy.user)).ipAddress
| extend target_tenant=parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue
| project TimeGenerated, OperationName,initiating_user,source_ip, AADTenantId,target_tenant
| project-rename source_tenant= AADTenantId
```
# KQL query to identify generation and listing of SAS Keys
```
AzureActivity 
| where OperationNameValue == "http://MICROSOFT.STORAGE/STORAGEACCOUNTEACCOUNTS/LISTKEYS/ACTION"
| extend storage_account = tostring(parse_json(Properties).resource)
| extend appid_responsible_for_activity = tostring(parse_json(Claims).appid)
| project TimeGenerated,CallerIpAddress, OperationNameValue, storage_account,appid_responsible_for_activity
```
# GraphRunner - Detect Activity related to Get-GraphTokens
```
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where ResourceDisplayName == "Microsoft Graph"
```

# GraphRunner - Detect Activity related to Get-AzureAppTokens
```
AADServicePrincipalSignInLogs 
| where ServicePrincipalName == "sp-name-that-is-abused" or AppId == "ID-of-abused-app"
```

# GraphRunner - Detect Graph Activity related to Invoke-GraphRunner and Invoke-GraphRecon module
```
let InvokeGraphRunnerCalls = dynamic(["https://graph.microsoft.com/v1.0/search/query", "https://graph.microsoft.com/v1.0/servicePrincipals/", "https://graph.microsoft.com/v1.0/users/", "https://graph.microsoft.com/v1.0/organization", "https://graph.microsoft.com/v1.0/applications", "https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken="]);
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri in~ (InvokeGraphRunnerCalls) or RequestUri has_all("https://graph.microsoft.com/v1.0/servicePrincipals(appId=", "appRoleAssignedTo")
| extend RequestedAppId = extract(@"appId='(.*?)'", 1, RequestUri)
| sort by TimeGenerated asc
| extend timeDiffInSeconds = datetime_diff('second', prev(TimeGenerated, 1), TimeGenerated)
| where timeDiffInSeconds == 0
```

# GraphRunner - Detect Graph Activity related to Invoke-GraphOpenInboxFinder module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri has_all("https://graph.microsoft.com/v1.0/users/","/mailFolders/Inbox/messages")
| extend RequestedUPN = tostring(extract(@"users/(.*?)/mailFolders", 1, RequestUri))
| project-reorder TimeGenerated, RequestUri, ResponseStatusCode, RequestedUPN
```
# GraphRunner - Detect Graph Activity related to Invoke-GraphOpenInboxFinder module and summarizes by accessed mailbox
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri has_all("https://graph.microsoft.com/v1.0/users/","/mailFolders/Inbox/messages")
| extend RequestedUPN = tostring(extract(@"users/(.*?)/mailFolders", 1, RequestUri))
| where ResponseStatusCode == 200
| summarize OpenMailboxes = make_set(RequestedUPN)
```

# GraphRunner - Detect Graph Activity related to Get-SharePointSiteURLs module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri == "https://graph.microsoft.com/v1.0/search/query"
```

# GraphRunner - Detect Graph Activity related to Get-DynamicGroups module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri == "https://graph.microsoft.com/v1.0/groups"
```

# GraphRunner - Detect Graph Activity related to Get-UpdatableGroups module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri == "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess" or RequestUri == "https://graph.microsoft.com/v1.0/groups"
| project-reorder TimeGenerated, RequestUri
```

# GraphRunner - Detect Graph Activity related to Invoke-DumpApps module
```
let InvokeDumpAppsCalls = dynamic(["https://graph.microsoft.com/v1.0/users/", "https://graph.microsoft.com/v1.0/organization" ,"https://graph.microsoft.com/v1.0/applications","https://graph.microsoft.com/v1.0/servicePrincipals/",'https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken="']);
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri in~ (InvokeDumpAppsCalls) or RequestUri has_all("https://graph.microsoft.com/v1.0/servicePrincipals(appId=", "appRoleAssignedTo")
| extend RequestedAppId = extract(@"appId='(.*?)'", 1, RequestUri)
```

# GraphRunner - Detect Graph Activity related to Get-SecurityGroups module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where (RequestUri == "https://graph.microsoft.com/v1.0/groups?=securityEnabled%20eq%20true" or RequestUri has_all("https://graph.microsoft.com/v1.0/groups/","members"))
| extend GroupObjectId = tostring(extract(@"groups/(.*?)/members", 1, RequestUri))
```

# GraphRunner - Detect Graph Activity related to Get-AzureADUsers module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri == "https://graph.microsoft.com/v1.0/users"
```

# GraphRunner - Detect app registration
```
let ApplicationOperations = dynamic(["Add application", "Update application - Certificates and secrets management", "Update application"]);
AuditLogs
| where AdditionalDetails[0].value contains "PowerShell"
| where OperationName in (ApplicationOperations)
```

# GraphRunner - Detect Graph Activity related to Invoke-InjectOAuthApp module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where (RequestUri has_all("https://graph.microsoft.com/v1.0/applications/", "addPassword") or
RequestUri == "https://graph.microsoft.com/v1.0/applications" or
RequestUri == "https://graph.microsoft.com/v1.0/servicePrincipals")
| extend ApplicationId = tostring(extract(@"applications/(.*?)/addPassword", 1, RequestUri))
```

# GraphRunner - Detect creation of group
```
AuditLogs
| where AdditionalDetails[0].value contains "PowerShell"
| where (OperationName == "Add member to group" or OperationName == "Add group")
```

# GraphRunner - Detect Graph Activity realted to Invoke-SecurityGroupCloner module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri has_all("https://graph.microsoft.com/v1.0/groups/", "/members/$ref")
 or RequestUri has_all("https://graph.microsoft.com/v1.0/groups", "/members")
 or RequestUri == "https://graph.microsoft.com/v1.0/groups?=securityEnabled%20eq%20true"
 or RequestUri == "https://graph.microsoft.com/v1.0/me"
| extend GroupObjectId = tostring(extract(@"groups/(.*?)/members", 1, RequestUri))
```

# GraphRunner - Detect invitation and adding of user 
```
AuditLogs
| where (OperationName == "Invite external user" or (OperationName == "Add user" and AdditionalDetails[0].value == "Microsoft Azure Graph Client Library 1.0"))
| extend UserUPN = TargetResources[0].userPrincipalName
```
# GraphRunner - Detect Microsoft Graph activity related to Invoke-InviteGuest module
```
MicrosoftGraphActivityLogs
| search "*PowerShell*"
| where (RequestUri == "https://graph.microsoft.com/v1.0/invitations" or RequestUri == "https://graph.microsoft.com/v1.0/organization")
```

# GraphRunner - Detect Entra ID activity where user is added to group
```
AuditLogs
| where AdditionalDetails[0].value contains "PowerShell"
| where OperationName == "Add member to group"
| extend UserUPN = TargetResources[0].userPrincipalName, GroupID = TargetResources[1].id
```
# GraphRunner - Detect UAL activity where user is added to group
```
OfficeActivity
| where Operation == "Add member to group."
```
# GraphRunner - Detect Microsoft Graph activity related to Invoke-AddGroupMember module
```
MicrosoftGraphActivityLogs
| where UserAgent contains "PowerShell"
| where RequestUri has_all("https://graph.microsoft.com/v1.0/groups/","/members/$ref")
| extend GroupObjectId = tostring(extract(@"groups/(.*?)/members", 1, RequestUri))
```
