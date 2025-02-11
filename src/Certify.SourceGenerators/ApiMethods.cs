﻿using System;
using System.Collections.Generic;
using System.Linq;
using SourceGenerator;

namespace Certify.SourceGenerators
{
    public class ApiMethods
    {
        public static string HttpGet = "HttpGet";
        public static string HttpPost = "HttpPost";
        public static string HttpDelete = "HttpDelete";

        public static string GetFormattedTypeName(Type type)
        {
            if (type.IsGenericType)
            {
                var genericArguments = type.GetGenericArguments()
                                    .Select(x => x.FullName)
                                    .Aggregate((x1, x2) => $"{x1}, {x2}");
                return $"{type.FullName.Substring(0, type.FullName.IndexOf("`"))}"
                     + $"<{genericArguments}>";
            }

            return type.FullName;
        }
        public static List<GeneratedAPI> GetApiDefinitions()
        {
            // declaring an API definition here is then used by the source generators to:
            // - create the public API endpoint
            // - map the call from the public API to the background service API in the service API Client (interface and implementation)
            // - to then generate the public API clients, run nswag when the public API is running.

            return new List<GeneratedAPI> {

                  new() {
                        OperationName = "CheckSecurityPrincipleHasAccess",
                        OperationMethod = HttpPost,
                        Comment = "Check a given security principle has permissions to perform a specific action for a specific resource action",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciple/allowedaction",
                        ServiceAPIRoute = "access/securityprinciple/allowedaction",
                        ReturnType = "bool",
                        Params =new Dictionary<string, string>{{"check","Certify.Models.Hub.AccessCheck"} }
                    },
                    new() {
                        OperationName = "GetSecurityPrincipleAssignedRoles",
                        OperationMethod = HttpGet,
                        Comment = "Get list of Assigned Roles for a given security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciple/{id}/assignedroles",
                        ServiceAPIRoute = "access/securityprinciple/{id}/assignedroles",
                        ReturnType = "ICollection<AssignedRole>",
                        Params =new Dictionary<string, string>{{"id","string"}}
                    },
                    new() {
                        OperationName = "GetSecurityPrincipleRoleStatus",
                        OperationMethod = HttpGet,
                        Comment = "Get list of Assigned Roles etc for a given security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciple/{id}/rolestatus",
                        ServiceAPIRoute = "access/securityprinciple/{id}/rolestatus",
                        ReturnType = "RoleStatus",
                        Params =new Dictionary<string, string>{{"id","string"}}
                    },
                    new() {
                        OperationName = "GetAccessRoles",
                        OperationMethod = HttpGet,
                        Comment = "Get list of available security Roles",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "roles",
                        ServiceAPIRoute = "access/roles",
                        ReturnType = "ICollection<Role>"
                    },
                    new() {
                         OperationName = "GetAssignedAccessTokens",
                         OperationMethod = HttpGet,
                         Comment = "Get list of API assigned access tokens",
                         PublicAPIController = "Access",
                         PublicAPIRoute = "assignedtoken",
                         ServiceAPIRoute = "access/assignedtoken/list",
                         ReturnType = "ICollection<Certify.Models.Hub.AssignedAccessToken>"
                     },
                    new() {
                           OperationName = "AddAssignedAccessToken",
                           OperationMethod = HttpPost,
                           Comment = "Add new assigned access token",
                           PublicAPIController = "Access",
                           PublicAPIRoute = "assignedtoken",
                           ServiceAPIRoute = "access/assignedtoken",
                           ReturnType = "Models.Config.ActionResult",
                           Params = new Dictionary<string, string>{{"token", "Certify.Models.Hub.AssignedAccessToken" } }
                    },
                    new() {

                        OperationName = "GetSecurityPrinciples",
                        OperationMethod = HttpGet,
                        Comment = "Get list of available security principles",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciples",
                        ServiceAPIRoute = "access/securityprinciples",
                        ReturnType = "ICollection<SecurityPrinciple>"
                    },
                    new() {
                        OperationName = "ValidateSecurityPrinciplePassword",
                        OperationMethod = HttpPost,
                        Comment = "Check password valid for security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "validate",
                        ServiceAPIRoute = "access/validate",
                        ReturnType = "Certify.Models.Hub.SecurityPrincipleCheckResponse",
                        Params = new Dictionary<string, string>{{"passwordCheck", "Certify.Models.Hub.SecurityPrinciplePasswordCheck" } }
                    },
                    new() {

                        OperationName = "UpdateSecurityPrinciplePassword",
                        OperationMethod = HttpPost,
                        Comment = "Update password for security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "updatepassword",
                        ServiceAPIRoute = "access/updatepassword",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{{"passwordUpdate", "Certify.Models.Hub.SecurityPrinciplePasswordUpdate" } }
                    },
                    new() {

                        OperationName = "AddSecurityPrinciple",
                        OperationMethod = HttpPost,
                        Comment = "Add new security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciple",
                        ServiceAPIRoute = "access/securityprinciple",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{{"principle", "Certify.Models.Hub.SecurityPrinciple" } }
                    },
                    new() {

                        OperationName = "UpdateSecurityPrinciple",
                        OperationMethod = HttpPost,
                        Comment = "Update existing security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciple/update",
                        ServiceAPIRoute = "access/securityprinciple/update",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{
                            { "principle", "Certify.Models.Hub.SecurityPrinciple" }
                        }
                    },
                      new() {
                        OperationName = "UpdateSecurityPrincipleAssignedRoles",
                        OperationMethod = HttpPost,
                        Comment = "Update assigned roles for a security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciple/roles/update",
                        ServiceAPIRoute = "access/securityprinciple/roles/update",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{
                            { "update", "Certify.Models.Hub.SecurityPrincipleAssignedRoleUpdate" }
                        }
                    },
                    new() {
                        OperationName = "RemoveSecurityPrinciple",
                        OperationMethod = HttpDelete,
                        Comment = "Remove security principle",
                        PublicAPIController = "Access",
                        PublicAPIRoute = "securityprinciple",
                        ServiceAPIRoute = "access/securityprinciple/{id}",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{{"id","string"}}
                    },
                    new() {
                        OperationName = "GetManagedChallenges",
                        OperationMethod = HttpGet,
                        Comment = "Get list of available managed challenges (DNS challenge delegation etc)",
                        PublicAPIController = "ManagedChallenge",
                        PublicAPIRoute = "list",
                        ServiceAPIRoute = "managedchallenge",
                        ReturnType = "ICollection<ManagedChallenge>",
                        RequiredPermissions = [new ("managedchallenge", "managedchallenge_list")]
                    },
                    new() {
                        OperationName = "UpdateManagedChallenge",
                        OperationMethod = HttpPost,
                        Comment = "Add/update a managed challenge (DNS challenge delegation etc)",
                        PublicAPIController = "ManagedChallenge",
                        PublicAPIRoute = "update",
                        ServiceAPIRoute = "managedchallenge",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{
                            { "update", "Certify.Models.Hub.ManagedChallenge" }
                        },
                        RequiredPermissions = [new ("managedchallenge", "managedchallenge_update")]
                    },
                    new() {
                        OperationName = "RemoveManagedChallenge",
                        OperationMethod = HttpDelete,
                        Comment = "Delete a managed challenge (DNS challenge delegation etc)",
                        PublicAPIController = "ManagedChallenge",
                        PublicAPIRoute = "remove",
                        ServiceAPIRoute = "managedchallenge/{id}",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{
                            { "id", "string" }
                        },
                        RequiredPermissions = [new ("managedchallenge", "managedchallenge_delete")]
                    },
                    new() {
                        OperationName = "PerformManagedChallenge",
                        OperationMethod = HttpPost,
                        Comment = "Perform a managed challenge (DNS challenge delegation etc)",
                        PublicAPIController = null, // skip public controller implementation
                        ServiceAPIRoute = "managedchallenge/request",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{
                            { "request", "Certify.Models.Hub.ManagedChallengeRequest" }
                        },
                        RequiredPermissions = [new ("managedchallenge", "managedchallenge_request")]
                    },
                    new() {
                        OperationName = "CleanupManagedChallenge",
                        OperationMethod = HttpPost,
                        Comment = "Perform cleanup for a previously managed challenge (DNS challenge delegation etc)",
                        PublicAPIController = null, // skip public controller implementation
                        ServiceAPIRoute = "managedchallenge/cleanup",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string>{
                            { "request", "Certify.Models.Hub.ManagedChallengeRequest" }
                        }
                    },
                    /* per instance API, via management hub */
                    new() {
                        OperationName = "GetAcmeAccounts",
                        OperationMethod = HttpGet,
                        Comment = "Get All Acme Accounts",
                        UseManagementAPI = true,
                        PublicAPIController = "CertificateAuthority",
                        PublicAPIRoute = "{instanceId}/accounts/",
                        ReturnType = "ICollection<Models.AccountDetails>",
                        Params = new Dictionary<string, string> { { "instanceId", "string" } }
                    },
                    new() {
                        OperationName = "AddAcmeAccount",
                        OperationMethod = HttpPost,
                        Comment = "Add New Acme Account",
                        UseManagementAPI = true,
                        PublicAPIController = "CertificateAuthority",
                        PublicAPIRoute = "{instanceId}/account/",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string> { { "instanceId", "string" }, { "registration", "Certify.Models.ContactRegistration" } }
                    },
                    new() {
                        OperationName = "GetCertificateAuthorities",
                        OperationMethod = HttpGet,
                        Comment = "Get list of defined Certificate Authorities",
                        UseManagementAPI = true,
                        PublicAPIController = "CertificateAuthority",
                        PublicAPIRoute = "{instanceId}/authority",
                        ReturnType = "ICollection<Models.CertificateAuthority>",
                        Params = new Dictionary<string, string> { { "instanceId", "string" } }
                    },
                    new() {
                        OperationName = "UpdateCertificateAuthority",
                        OperationMethod = HttpPost,
                        Comment = "Add/Update Certificate Authority",
                        UseManagementAPI = true,
                        PublicAPIController = "CertificateAuthority",
                        PublicAPIRoute = "{instanceId}/authority",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string> { { "instanceId", "string" }, { "ca", "Certify.Models.CertificateAuthority" } }
                    },
                    new() {
                        OperationName = "RemoveCertificateAuthority",
                        OperationMethod = HttpDelete,
                        Comment = "Remove Certificate Authority",
                        UseManagementAPI = true,
                        PublicAPIController = "CertificateAuthority",
                        PublicAPIRoute = "{instanceId}/authority/{id}",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string> { { "instanceId", "string" }, { "id", "string" } }
                    },
                    new() {
                        OperationName = "RemoveAcmeAccount",
                        OperationMethod = HttpDelete,
                        Comment = "Remove ACME Account",
                        UseManagementAPI = true,
                        PublicAPIController = "CertificateAuthority",
                        PublicAPIRoute = "{instanceId}/accounts/{storageKey}/{deactivate}",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string> { { "instanceId", "string" }, { "storageKey", "string" }, { "deactivate", "bool" } }
                    },
                     new() {
                         OperationName = "GetStoredCredentials",
                         OperationMethod = HttpGet,
                         Comment = "Get List of Stored Credentials",
                         UseManagementAPI = true,
                         PublicAPIController = "StoredCredential",
                         PublicAPIRoute = "{instanceId}",
                         ReturnType = "ICollection<Models.Config.StoredCredential>",
                         Params = new Dictionary<string, string> { { "instanceId", "string" } }
                     },
                    new() {
                        OperationName = "UpdateStoredCredential",
                        OperationMethod = HttpPost,
                        Comment = "Add/Update Stored Credential",
                        PublicAPIController = "StoredCredential",
                        PublicAPIRoute = "{instanceId}",
                        ReturnType = "Models.Config.ActionResult",
                        UseManagementAPI = true,
                        Params = new Dictionary<string, string> { { "instanceId", "string" }, { "item", "Models.Config.StoredCredential" } }
                    },
                    new() {
                        OperationName = "RemoveStoredCredential",
                        OperationMethod = HttpDelete,
                        Comment = "Remove Stored Credential",
                        UseManagementAPI = true,
                        PublicAPIController = "StoredCredential",
                        PublicAPIRoute = "{instanceId}/{storageKey}",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string> { { "instanceId", "string" }, { "storageKey", "string" } }
                    },
                    new() {
                        OperationName = "GetDeploymentProviders",
                        OperationMethod = HttpGet,
                        Comment = "Get Deployment Task Providers",
                        UseManagementAPI = true,
                        PublicAPIController = "DeploymentTask",
                        PublicAPIRoute = "{instanceId}",
                        ReturnType = "ICollection<Certify.Models.Config.DeploymentProviderDefinition>",
                        Params = new Dictionary<string, string>{
                            { "instanceId", "string" }
                        }
                    },
                    new() {
                        OperationName = "GetTargetServiceTypes",
                        OperationMethod = HttpGet,
                        Comment = "Get Service Types present on instance (IIS, nginx etc)",
                        UseManagementAPI = true,
                        ManagementHubCommandType = Models.Hub.ManagementHubCommands.GetTargetServiceTypes,
                        PublicAPIController = "Target",
                        PublicAPIRoute = "{instanceId}/types",
                        ReturnType = "ICollection<string>",
                        Params = new Dictionary<string, string>{
                            { "instanceId", "string" }
                        }
                    },
                    new() {
                        OperationName = "GetTargetServiceItems",
                        OperationMethod = HttpGet,
                        Comment = "Get Service items (sites) present on instance (IIS, nginx etc).",
                        UseManagementAPI = true,
                        ManagementHubCommandType = Models.Hub.ManagementHubCommands.GetTargetServiceItems,
                        PublicAPIController = "Target",
                        PublicAPIRoute = "{instanceId}/{serviceType}/items",
                        ReturnType = "ICollection<SiteInfo>",
                        Params = new Dictionary<string, string>{
                            { "instanceId", "string" },
                            { "serviceType", "string" }
                        }
                    },
                    new() {
                        OperationName = "GetTargetServiceItemIdentifiers",
                        OperationMethod = HttpGet,
                        Comment = "Get Service item identifiers (domains on a website etc) present on instance (IIS, nginx etc)",
                        UseManagementAPI = true,
                        ManagementHubCommandType = Models.Hub.ManagementHubCommands.GetTargetServiceItemIdentifiers,
                        PublicAPIController = "Target",
                        PublicAPIRoute = "{instanceId}/{serviceType}/item/{itemId}/identifiers",
                        ReturnType = "ICollection<DomainOption>",
                        Params = new Dictionary<string, string>{
                            { "instanceId", "string" },
                            { "serviceType", "string" },
                            { "itemId", "string" }
                        }
                    },
                    new() {
                        OperationName = "GetChallengeProviders",
                        OperationMethod = HttpGet,
                        Comment = "Get Dns Challenge Providers",
                        UseManagementAPI = true,
                        PublicAPIController = "ChallengeProvider",
                        PublicAPIRoute = "{instanceId}",
                        ReturnType = "ICollection<Certify.Models.Config.ChallengeProviderDefinition>",
                        Params = new Dictionary<string, string>{
                            { "instanceId", "string" }
                        }
                    },
                      new() {
                          OperationName = "GetDnsZones",
                          OperationMethod = HttpGet,
                          Comment = "Get List of Zones with the current DNS provider and credential",
                          UseManagementAPI = true,
                          PublicAPIController = "ChallengeProvider",
                          PublicAPIRoute = "{instanceId}/dnszones/{providerTypeId}/{credentialId}",
                          ReturnType = "ICollection<Certify.Models.Providers.DnsZone>",
                          Params = new Dictionary<string, string>{
                            { "instanceId", "string" } ,
                            { "providerTypeId", "string" },
                            { "credentialId", "string" }
                        }
                      },
                    new() {
                        OperationName = "ExecuteDeploymentTask",
                        OperationMethod = HttpGet,
                        Comment = "Execute Deployment Task",
                        UseManagementAPI = true,
                        PublicAPIController = "DeploymentTask",
                        PublicAPIRoute = "{instanceId}/execute/{managedCertificateId}/{taskId}",
                        ReturnType = "ICollection<ActionStep>",
                        Params = new Dictionary<string, string>{
                            { "instanceId", "string" },
                            { "managedCertificateId", "string" },
                            { "taskId", "string" }
                        }
                    },
                    new() {
                        OperationName = "RemoveManagedCertificate",
                        OperationMethod = HttpDelete,
                        Comment = "Remove Managed Certificate",
                        UseManagementAPI = true,
                        PublicAPIController = "Certificate",
                        PublicAPIRoute = "{instanceId}/settings/{managedCertId}",
                        ReturnType = "Models.Config.ActionResult",
                        Params = new Dictionary<string, string> { { "instanceId", "string" }, { "managedCertId", "string" } }
                    },
                    // TODO
                    new() {
                        OperationName = "PerformExport",
                        OperationMethod = HttpPost,
                        Comment = "Perform an export of all settings",
                        PublicAPIController = "System",
                        PublicAPIRoute = "system/migration/export",
                        ServiceAPIRoute = "system/migration/export",
                        ReturnType = "Models.Config.Migration.ImportExportPackage",
                        Params = new Dictionary<string, string> { { "exportRequest", "Certify.Models.Config.Migration.ExportRequest" } }
                    },
                     new() {
                         OperationName = "PerformImport",
                         OperationMethod = HttpPost,
                         Comment = "Perform an import of all settings",
                         PublicAPIController = "System",
                         PublicAPIRoute = "system/migration/import",
                         ServiceAPIRoute = "system/migration/import",
                         ReturnType = "ICollection<ActionStep>",
                         Params = new Dictionary<string, string> { { "importRequest", "Certify.Models.Config.Migration.ImportRequest" } }
                     },
                };
        }
    }
}
