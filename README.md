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
