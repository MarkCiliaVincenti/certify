using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certify.Core.Management.Access;
using Certify.Models;
using Certify.Models.Hub;
using Certify.Providers;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace Certify.Core.Tests.Unit
{
    public class MemoryObjectStore : IConfigurationStore
    {
        private ConcurrentDictionary<string, ConfigurationStoreItem> _store = new ConcurrentDictionary<string, ConfigurationStoreItem>();

        public Task Add<T>(string itemType, ConfigurationStoreItem item)
        {
            item.ItemType = itemType;

            // clone the item to avoid reference issue mutating the same object, as we are using an in-memory store
            var clonedItem = JsonConvert.DeserializeObject<T>(JsonConvert.SerializeObject(item)) as ConfigurationStoreItem;
            return Task.FromResult(_store.TryAdd(clonedItem.Id, clonedItem));
        }

        public Task<bool> Delete<T>(string itemType, string id)
        {
            return Task.FromResult((_store.TryRemove(id, out _)));
        }

        public Task<List<T>> GetItems<T>(string itemType)
        {
            var items = _store.Values
                    .Where((s => s.ItemType == itemType))
                    .Select(s => (T)Convert.ChangeType(s, typeof(T)));

            return Task.FromResult((items.ToList()));
        }

        public Task<T> Get<T>(string itemType, string id)
        {
            _store.TryGetValue(id, out var value);
            return Task.FromResult((T)Convert.ChangeType(value, typeof(T)));
        }

        public Task Add<T>(string itemType, T item)
        {
            var o = item as ConfigurationStoreItem;
            o.ItemType = itemType;

            var clonedItem = JsonConvert.DeserializeObject<T>(JsonConvert.SerializeObject(o)) as ConfigurationStoreItem;
            return Task.FromResult(_store.TryAdd(clonedItem.Id, clonedItem));
        }

        public Task Update<T>(string itemType, T item)
        {
            var o = JsonConvert.DeserializeObject<T>(JsonConvert.SerializeObject(item)) as ConfigurationStoreItem;

            _store.TryGetValue(o.Id, out var value);
            var c = Task.FromResult((T)Convert.ChangeType(value, typeof(T))).Result as ConfigurationStoreItem;
            var r = Task.FromResult(_store.TryUpdate(o.Id, o, c));
            if (r.Result == false)
            {
                throw new Exception("Could not store item type");
            }

            return r;
        }
    }

    public class TestAssignedRoles
    {
        public static AssignedRole TestAdmin { get; } = new AssignedRole
        {
            // test administrator
            RoleId = StandardRoles.Administrator.Id,
            SecurityPrincipleId = TestSecurityPrinciples.TestAdmin.Id
        };
        public static AssignedRole Admin { get; } = new AssignedRole
        {
            // administrator
            RoleId = StandardRoles.Administrator.Id,
            SecurityPrincipleId = TestSecurityPrinciples.Admin.Id
        };
        public static AssignedRole DevopsUserDomainConsumer { get; } = new AssignedRole
        {
            // devops user in consumer role for a specific domain
            RoleId = StandardRoles.CertificateConsumer.Id,
            SecurityPrincipleId = TestSecurityPrinciples.DevopsAppDomainConsumer.Id,
            IncludedResources = new List<Resource>{
                new Resource{ ResourceType=ResourceTypes.Domain, Identifier="www.example.com" },
            }
        };
        public static AssignedRole DevopsUserWildcardDomainConsumer { get; } = new AssignedRole
        {
            // devops user in consumer role for a wildcard domain
            RoleId = StandardRoles.CertificateConsumer.Id,
            SecurityPrincipleId = TestSecurityPrinciples.DevopsUser.Id,
            IncludedResources = new List<Resource>{
                new Resource{ ResourceType=ResourceTypes.Domain, Identifier="*.microsoft.com" },
            }
        };
    }

    public class TestSecurityPrinciples
    {
        public static SecurityPrinciple TestAdmin => new SecurityPrinciple
        {
            Id = "[test]",
            Username = "test administrator",
            Description = "Example test administrator used as context user during test",
            Email = "test_admin@test.com",
            Password = "ABCDEFG",
            PrincipleType = SecurityPrincipleType.User
        };
        public static SecurityPrinciple Admin => new SecurityPrinciple
        {
            Id = "admin_01",
            Username = "admin",
            Description = "Administrator account",
            Email = "info@test.com",
            Password = "ABCDEFG",
            PrincipleType = SecurityPrincipleType.User,
        };
        public static SecurityPrinciple DomainOwner => new SecurityPrinciple
        {
            Id = "domain_owner_01",
            Username = "demo_owner",
            Description = "Example domain owner",
            Email = "domains@test.com",
            Password = "ABCDEFG",
            PrincipleType = SecurityPrincipleType.User,
        };
        public static SecurityPrinciple DevopsUser => new SecurityPrinciple
        {
            Id = "devops_user_01",
            Username = "devops_01",
            Description = "Example devops user",
            Email = "devops01@test.com",
            Password = "ABCDEFG",
            PrincipleType = SecurityPrincipleType.User,
        };
        public static SecurityPrinciple DevopsAppDomainConsumer => new SecurityPrinciple
        {
            Id = "devops_app_01",
            Username = "devapp_01",
            Description = "Example devops app domain consumer",
            Email = "dev_app01@test.com",
            Password = "ABCDEFG",
            PrincipleType = SecurityPrincipleType.User,
        };
    }

    [TestClass]
    public class AccessControlTests
    {
        private Loggy loggy;
        private AccessControl access;
        private const string contextUserId = "[test]";

        [TestInitialize]
        public async Task TestInitialize()
        {
            this.loggy = new Loggy(LoggerFactory.Create(builder => builder.AddDebug()).CreateLogger<AccessControlTests>());

            this.access = new AccessControl(loggy, new MemoryObjectStore());
        }

        [TestMethod]
        public async Task TestAddGetSecurityPrinciples()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Get stored security principles
            var storedSecurityPrinciples = await access.GetSecurityPrinciples(contextUserId);

            // Validate SecurityPrinciple list returned by AccessControl.GetSecurityPrinciples()
            Assert.IsNotNull(storedSecurityPrinciples, "Expected list returned by AccessControl.GetSecurityPrinciples() to not be null");
            Assert.AreEqual(2, storedSecurityPrinciples.Count, "Expected list returned by AccessControl.GetSecurityPrinciples() to have 2 SecurityPrinciple objects");
            foreach (var passedPrinciple in adminSecurityPrinciples)
            {
                Assert.IsNotNull(storedSecurityPrinciples.Find(x => x.Id == passedPrinciple.Id), $"Expected a SecurityPrinciple returned by GetSecurityPrinciples() to match Id '{passedPrinciple.Id}' of SecurityPrinciple passed into AddSecurityPrinciple()");
            }
        }

        [TestMethod]
        public async Task TestGetSecurityPrinciplesNoRoles()
        {
            // Add test security principles
            var securityPrincipleAdded = await access.AddSecurityPrinciple(contextUserId, TestSecurityPrinciples.TestAdmin);

            // Get stored security principles
            Assert.IsFalse(securityPrincipleAdded, $"Expected AddSecurityPrinciple() to be unsuccessful without roles defined for {contextUserId}");
        }

        [TestMethod]
        public async Task TestAddGetSecurityPrinciple()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            foreach (var securityPrinciple in adminSecurityPrinciples)
            {
                // Get stored security principle
                var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, securityPrinciple.Id);

                // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple()
                Assert.IsNotNull(storedSecurityPrinciple, "Expected object returned by AccessControl.GetSecurityPrinciple() to not be null");
                Assert.AreEqual(storedSecurityPrinciple.Id, securityPrinciple.Id, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Id '{securityPrinciple.Id}' of SecurityPrinciple passed into AddSecurityPrinciple()");
            }
        }

        [TestMethod]
        public async Task TestAddGetAssignedRoles()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            var addPolicy = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            Assert.IsTrue(addPolicy, "Expected to add role");

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            var addedRole = await access.AddRole(contextUserId, role, bypassIntegrityCheck: true);

            Assert.IsTrue(addedRole, "Expected to add role");

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r, bypassIntegrityCheck: true));

            // Validate AssignedRole list returned by AccessControl.GetAssignedRoles()
            foreach (var assignedRole in assignedRoles)
            {
                var adminAssignedRoles = await access.GetAssignedRoles(contextUserId, assignedRole.SecurityPrincipleId);
                Assert.IsNotNull(adminAssignedRoles, "Expected list returned by AccessControl.GetAssignedRoles() to not be null");
                Assert.AreEqual(1, adminAssignedRoles.Count, "Expected list returned by AccessControl.GetAssignedRoles() to have 1 AssignedRole object");
                Assert.AreEqual(assignedRole.SecurityPrincipleId, adminAssignedRoles[0].SecurityPrincipleId, "Expected AssignedRole returned by GetAssignedRoles() to match SecurityPrincipleId of AssignedRole passed into AddAssignedRole()");
            }
        }

        [TestMethod]
        public async Task TestGetAssignedRolesNoRoles()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // assigned admin role to TestAdmin (also the contextUserId) so they can check roles for the other admin user
            await access.AddAssignedRole(TestSecurityPrinciples.TestAdmin.Id, TestAssignedRoles.TestAdmin, bypassIntegrityCheck: true);

            // Validate AssignedRole list returned by AccessControl.GetAssignedRoles()
            var adminAssignedRoles = await access.GetAssignedRoles(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.IsNotNull(adminAssignedRoles, "Expected list returned by AccessControl.GetAssignedRoles() to not be null");
            Assert.AreEqual(0, adminAssignedRoles.Count, "Expected list returned by AccessControl.GetAssignedRoles() to have no AssignedRole objects");
        }

        [TestMethod]
        public async Task TestAddResourcePolicyNoRoles()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            var addedResourcePolicy = await access.AddResourcePolicy(contextUserId, policy);

            // Validate that AddResourcePolicy() failed when no roles are defined
            Assert.IsFalse(addedResourcePolicy, $"Unable to add a resource policy using {contextUserId} when roles are undefined");
        }

        [TestMethod]
        public async Task TestUpdateSecurityPrinciple()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };

            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r, bypassIntegrityCheck: true));

            // Validate email of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before update
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.AreEqual(storedSecurityPrinciple.Email, adminSecurityPrinciples[0].Email, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Email '{adminSecurityPrinciples[0].Email}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Update security principle in AccessControl with a new principle object of the same Id, but different email
            var updateSecurityPrinciple = new SecurityPrinciple
            {
                Id = TestSecurityPrinciples.Admin.Id,
                Username = TestSecurityPrinciples.Admin.Username,
                Description = TestSecurityPrinciples.Admin.Description,
                Email = "new_test_email@test.com"
            };

            var securityPrincipleUpdated = await access.UpdateSecurityPrinciple(contextUserId, updateSecurityPrinciple);
            Assert.IsTrue(securityPrincipleUpdated, $"Expected security principle update for {updateSecurityPrinciple.Id} to succeed");

            // Validate email of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after update
            storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, updateSecurityPrinciple.Id);
            Assert.AreNotEqual(storedSecurityPrinciple.Email, adminSecurityPrinciples[0].Email, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to not match previous Email '{adminSecurityPrinciples[0].Email}' of SecurityPrinciple passed into AddSecurityPrinciple()");
            Assert.AreEqual(storedSecurityPrinciple.Email, updateSecurityPrinciple.Email, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match updated Email '{updateSecurityPrinciple.Email}' of SecurityPrinciple passed into AddSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestUpdateSecurityPrincipleNoRoles()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Validate email of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before update
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.AreEqual(storedSecurityPrinciple.Email, adminSecurityPrinciples[0].Email, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Email '{adminSecurityPrinciples[0].Email}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Update security principle in AccessControl with a new principle object of the same Id, but different email, with roles undefined
            var newSecurityPrinciple = TestSecurityPrinciples.Admin;
            newSecurityPrinciple.Email = "new_test_email@test.com";

            var securityPrincipleUpdated = await access.UpdateSecurityPrinciple(contextUserId, newSecurityPrinciple);
            Assert.IsFalse(securityPrincipleUpdated, $"Expected security principle update for {newSecurityPrinciple.Id} to be unsuccessful without roles defined");
        }

        [TestMethod]
        public async Task TestUpdateSecurityPrincipleBadUpdate()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role, bypassIntegrityCheck: true);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r, bypassIntegrityCheck: true));

            // Validate email of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before update
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.AreEqual(storedSecurityPrinciple.Email, adminSecurityPrinciples[0].Email, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Email '{adminSecurityPrinciples[0].Email}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Update security principle in AccessControl with a new principle object with a bad Id name and different email
            var newSecurityPrinciple = TestSecurityPrinciples.Admin;
            newSecurityPrinciple.Email = "new_test_email@test.com";
            newSecurityPrinciple.Id = "missing_username";
            var securityPrincipleUpdated = await access.UpdateSecurityPrinciple(contextUserId, newSecurityPrinciple);

            Assert.IsFalse(securityPrincipleUpdated, $"Expected security principle update for {newSecurityPrinciple.Id} to be unsuccessful with bad update data (Id does not already exist in store)");
        }

        [TestMethod]
        public async Task TestUpdateSecurityPrinciplePassword()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            var firstPassword = adminSecurityPrinciples[0].Password;
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role, bypassIntegrityCheck: true);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r, bypassIntegrityCheck: true));

            // Validate password of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before update
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            var firstPasswordHashed = access.HashPassword(firstPassword, storedSecurityPrinciple.Password.Split('.')[1]);
            Assert.AreEqual(storedSecurityPrinciple.Password, firstPasswordHashed, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Password '{firstPasswordHashed}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Update security principle in AccessControl with a new password
            var newPassword = "GFEDCBA";
            var securityPrincipleUpdated = await access.UpdateSecurityPrinciplePassword(contextUserId, new Models.Hub.SecurityPrinciplePasswordUpdate(adminSecurityPrinciples[0].Id, firstPassword, newPassword));
            Assert.IsTrue(securityPrincipleUpdated, $"Expected security principle password update for {adminSecurityPrinciples[0].Id} to succeed");

            // Validate password of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after update
            storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            var newPasswordHashed = access.HashPassword(newPassword, storedSecurityPrinciple.Password.Split('.')[1]);

            Assert.AreNotEqual(storedSecurityPrinciple.Password, firstPasswordHashed, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to not match previous Password '{firstPasswordHashed}' of SecurityPrinciple passed into AddSecurityPrinciple()");
            Assert.AreEqual(storedSecurityPrinciple.Password, newPasswordHashed, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match updated Password '{newPasswordHashed}' of SecurityPrinciple passed into AddSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestUpdateSecurityPrinciplePasswordNoRoles()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            var firstPassword = adminSecurityPrinciples[0].Password;
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Update security principle in AccessControl with a new password
            var newPassword = "GFEDCBA";
            var securityPrincipleUpdated = await access.UpdateSecurityPrinciplePassword(contextUserId, new Models.Hub.SecurityPrinciplePasswordUpdate(adminSecurityPrinciples[0].Id, firstPassword, newPassword));
            Assert.IsFalse(securityPrincipleUpdated, $"Expected security principle password update for {adminSecurityPrinciples[0].Id} to fail without roles");

            // Validate password of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after failed update
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            var firstPasswordHashed = access.HashPassword(firstPassword, storedSecurityPrinciple.Password.Split('.')[1]);

            Assert.AreEqual(storedSecurityPrinciple.Password, firstPasswordHashed, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Password '{firstPasswordHashed}' of SecurityPrinciple passed into AddSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestUpdateSecurityPrinciplePasswordBadPassword()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            var firstPassword = adminSecurityPrinciples[0].Password;
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r));

            // Update security principle in AccessControl with a new password, but wrong original password
            var newPassword = "GFEDCBA";
            var securityPrincipleUpdated = await access.UpdateSecurityPrinciplePassword(contextUserId, new Models.Hub.SecurityPrinciplePasswordUpdate(adminSecurityPrinciples[0].Id, firstPassword.ToLower(), newPassword));
            Assert.IsFalse(securityPrincipleUpdated, $"Expected security principle password update for {adminSecurityPrinciples[0].Id} to fail with wrong password");

            // Validate password of SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after failed update
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            var firstPasswordHashed = access.HashPassword(firstPassword, storedSecurityPrinciple.Password.Split('.')[1]);
            Assert.AreEqual(storedSecurityPrinciple.Password, firstPasswordHashed, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Password '{firstPasswordHashed}' of SecurityPrinciple passed into AddSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestDeleteSecurityPrinciple()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role, bypassIntegrityCheck: true);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r, bypassIntegrityCheck: true));

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before delete is not null
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.IsNotNull(storedSecurityPrinciple, "Expected object returned by AccessControl.GetSecurityPrinciple() to not be null");
            Assert.AreEqual(storedSecurityPrinciple.Id, adminSecurityPrinciples[0].Id, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Id '{adminSecurityPrinciples[0].Id}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Delete first security principle in adminSecurityPrinciples list from AccessControl store
            var securityPrincipleDeleted = await access.DeleteSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.IsTrue(securityPrincipleDeleted, $"Expected security principle deletion for {adminSecurityPrinciples[0].Id} to succeed");

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after delete is null
            storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.IsNull(storedSecurityPrinciple, $"Expected SecurityPrinciple for '{adminSecurityPrinciples[0].Id}' to be null from GetSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestDeleteSecurityPrincipleNoRoles()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before delete is not null
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.IsNotNull(storedSecurityPrinciple, "Expected object returned by AccessControl.GetSecurityPrinciple() to not be null");
            Assert.AreEqual(storedSecurityPrinciple.Id, adminSecurityPrinciples[0].Id, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Id '{adminSecurityPrinciples[0].Id}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Try to delete first security principle in adminSecurityPrinciples list from AccessControl store
            var securityPrincipleDeleted = await access.DeleteSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.IsFalse(securityPrincipleDeleted, $"Expected security principle deletion for {adminSecurityPrinciples[0].Id} to fail without roles defined");

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after delete is not null
            storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[0].Id);
            Assert.IsNotNull(storedSecurityPrinciple, $"Expected SecurityPrinciple for '{adminSecurityPrinciples[0].Id}' to not be null from GetSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestDeleteSecurityPrincipleSelfDeletion()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r));

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before delete is not null
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[1].Id);
            Assert.IsNotNull(storedSecurityPrinciple, "Expected object returned by AccessControl.GetSecurityPrinciple() to not be null");
            Assert.AreEqual(storedSecurityPrinciple.Id, adminSecurityPrinciples[1].Id, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Id '{adminSecurityPrinciples[1].Id}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Try to delete second security principle in adminSecurityPrinciples list from AccessControl store
            var securityPrincipleDeleted = await access.DeleteSecurityPrinciple(contextUserId, contextUserId);
            Assert.IsFalse(securityPrincipleDeleted, $"Expected security principle self deletion for {contextUserId} to fail");

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after delete is not null
            storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[1].Id);
            Assert.IsNotNull(storedSecurityPrinciple, $"Expected SecurityPrinciple for '{adminSecurityPrinciples[1].Id}' to not be null from GetSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestDeleteSecurityPrincipleBadId()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r));

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() before delete is not null
            var storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[1].Id);
            Assert.IsNotNull(storedSecurityPrinciple, "Expected object returned by AccessControl.GetSecurityPrinciple() to not be null");
            Assert.AreEqual(storedSecurityPrinciple.Id, adminSecurityPrinciples[1].Id, $"Expected SecurityPrinciple returned by GetSecurityPrinciple() to match Id '{adminSecurityPrinciples[1].Id}' of SecurityPrinciple passed into AddSecurityPrinciple()");

            // Try to delete second security principle in adminSecurityPrinciples list from AccessControl store
            var securityPrincipleDeleted = await access.DeleteSecurityPrinciple(contextUserId, contextUserId.ToUpper());
            Assert.IsFalse(securityPrincipleDeleted, $"Expected security principle deletion for {contextUserId.ToUpper()} to fail");

            // Validate SecurityPrinciple object returned by AccessControl.GetSecurityPrinciple() after delete is not null
            storedSecurityPrinciple = await access.GetSecurityPrinciple(contextUserId, adminSecurityPrinciples[1].Id);
            Assert.IsNotNull(storedSecurityPrinciple, $"Expected SecurityPrinciple for '{adminSecurityPrinciples[1].Id}' to not be null from GetSecurityPrinciple()");
        }

        [TestMethod]
        public async Task TestIsPrincipleInRole()
        {
            // Add test security principles
            var adminSecurityPrinciples = new List<SecurityPrinciple> { TestSecurityPrinciples.Admin, TestSecurityPrinciples.TestAdmin };
            adminSecurityPrinciples.ForEach(async p => await access.AddSecurityPrinciple(contextUserId, p, bypassIntegrityCheck: true));

            // Setup security principle actions
            var actions = Policies.GetStandardResourceActions().FindAll(a => a.ResourceType == ResourceTypes.System);
            actions.ForEach(async a => await access.AddResourceAction(contextUserId, a, bypassIntegrityCheck: true));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.AccessAdmin);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.Administrator.Id);
            await access.AddRole(contextUserId, role, bypassIntegrityCheck: true);

            // Assign security principles to roles and add roles and policy assignments to store
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.Admin, TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r, bypassIntegrityCheck: true));

            // Validate specified admin user is a principle role
            bool hasAccess;
            foreach (var assignedRole in assignedRoles)
            {
                hasAccess = await access.IsPrincipleInRole(contextUserId, assignedRole.SecurityPrincipleId, StandardRoles.Administrator.Id);
                Assert.IsTrue(hasAccess, $"User '{assignedRole.SecurityPrincipleId}' should be in role");
            }

            // Validate fake admin user is not a principle role
            hasAccess = await access.IsPrincipleInRole(contextUserId, "admin_02", StandardRoles.Administrator.Id);
            Assert.IsFalse(hasAccess, "User should not be in role");
        }

        [TestMethod]
        public async Task TestDomainAuth()
        {
            // Add test devops user security principle
            _ = await access.AddSecurityPrinciple(contextUserId, TestSecurityPrinciples.DevopsUser, bypassIntegrityCheck: true);

            // Setup security principle actions
            await access.AddResourceAction(contextUserId, Policies.GetStandardResourceActions().Find(r => r.Id == StandardResourceActions.CertificateDownload));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.CertificateConsumer);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.CertificateConsumer.Id);
            await access.AddRole(contextUserId, role, bypassIntegrityCheck: true);

            // Assign security principles to roles and add roles and policy assignments to store
            await access.AddAssignedRole(contextUserId, TestAssignedRoles.DevopsUserDomainConsumer, true); // devops user in consumer role for a specific domain

            // Validate user can consume a cert for a given domain 
            var isAuthorised = await access.IsSecurityPrincipleAuthorised(contextUserId, new AccessCheck(TestSecurityPrinciples.DevopsAppDomainConsumer.Id, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "www.example.com"));
            Assert.IsTrue(isAuthorised, "User should be a cert consumer for this domain");

            // Validate user can't consume a cert for a subdomain they haven't been granted
            isAuthorised = await access.IsSecurityPrincipleAuthorised(contextUserId, new AccessCheck(TestSecurityPrinciples.DevopsAppDomainConsumer.Id, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "secure.example.com"));
            Assert.IsFalse(isAuthorised, "User should not be a cert consumer for this domain");
        }

        [TestMethod]
        public async Task TestWildcardDomainAuth()
        {
            // Add test devops user security principle
            _ = await access.AddSecurityPrinciple(contextUserId, TestSecurityPrinciples.DevopsUser, bypassIntegrityCheck: true);

            // Setup security principle actions
            await access.AddResourceAction(contextUserId, Policies.GetStandardResourceActions().Find(r => r.Id == StandardResourceActions.CertificateDownload));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.CertificateConsumer);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.CertificateConsumer.Id);
            await access.AddRole(contextUserId, role, bypassIntegrityCheck: true);

            // Assign security principles to roles and add roles and policy assignments to store
            await access.AddAssignedRole(contextUserId, TestAssignedRoles.DevopsUserWildcardDomainConsumer, bypassIntegrityCheck: true); // devops user in consumer role for a wildcard domain

            // Validate user can consume any subdomain via a granted wildcard
            var isAuthorised = await access.IsSecurityPrincipleAuthorised(contextUserId, new AccessCheck(TestSecurityPrinciples.DevopsUser.Id, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "random.microsoft.com"));
            Assert.IsTrue(isAuthorised, "User should be a cert consumer for this subdomain via wildcard");

            // Validate user can't consume a random wildcard
            isAuthorised = await access.IsSecurityPrincipleAuthorised(contextUserId, new AccessCheck(TestSecurityPrinciples.DevopsUser.Id, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "*  lkjhasdf98862364"));
            Assert.IsFalse(isAuthorised, "User should not be a cert consumer for random wildcard");

            // Validate user can't consume a random wildcard
            isAuthorised = await access.IsSecurityPrincipleAuthorised(contextUserId, new AccessCheck(TestSecurityPrinciples.DevopsUser.Id, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "lkjhasdf98862364.*.microsoft.com"));
            Assert.IsFalse(isAuthorised, "User should not be a cert consumer for random wildcard");
        }

        [TestMethod]
        public async Task TestRandomUserAuth()
        {
            // Add test devops user security principle
            _ = await access.AddSecurityPrinciple(contextUserId, TestSecurityPrinciples.DevopsUser, bypassIntegrityCheck: true);

            // Setup security principle actions
            await access.AddResourceAction(contextUserId, Policies.GetStandardResourceActions().Find(r => r.Id == StandardResourceActions.CertificateDownload));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.CertificateConsumer);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.CertificateConsumer.Id);
            await access.AddRole(contextUserId, role);

            // Assign security principles to roles and add roles and policy assignments to store
            await access.AddAssignedRole(contextUserId, TestAssignedRoles.DevopsUserWildcardDomainConsumer); // devops user in consumer role for a wildcard domain

            // Validate that random user should not be authorised
            var isAuthorised = await access.IsSecurityPrincipleAuthorised(contextUserId, new AccessCheck("randomuser", ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "random.microsoft.com"));
            Assert.IsFalse(isAuthorised, "Unknown user should not be a cert consumer for this subdomain via wildcard");
        }

        [TestMethod]
        public async Task TestSecurityPrinciplePwdValid()
        {
            // Add test devops user security principle
            _ = await access.AddSecurityPrinciple(contextUserId, TestSecurityPrinciples.DevopsUser, bypassIntegrityCheck: true);
            var check = await access.CheckSecurityPrinciplePassword(contextUserId, new Models.Hub.SecurityPrinciplePasswordCheck(TestSecurityPrinciples.DevopsUser.Id, TestSecurityPrinciples.DevopsUser.Password));

            Assert.IsTrue(check.IsSuccess, "Password should be valid");
        }

        [TestMethod]
        public async Task TestSecurityPrinciplePwdInvalid()
        {
            // Add test devops user security principle
            _ = await access.AddSecurityPrinciple(contextUserId, TestSecurityPrinciples.DevopsUser, bypassIntegrityCheck: true);
            var check = await access.CheckSecurityPrinciplePassword(contextUserId, new Models.Hub.SecurityPrinciplePasswordCheck(TestSecurityPrinciples.DevopsUser.Id, "INVALID_PWD"));

            Assert.IsFalse(check.IsSuccess, "Password should not be valid");
        }

        [TestMethod]
        public async Task TestUserAPIToken()
        {
            // setup a test security principle, add them to the certificate consumer role, assign an API token then test if they are authorized based on the API token

            // allow test admin to perform access checks
            var assignedRoles = new List<AssignedRole> { TestAssignedRoles.TestAdmin };
            assignedRoles.ForEach(async r => await access.AddAssignedRole(contextUserId, r, bypassIntegrityCheck: true));

            // Add test devops user security principle
            _ = await access.AddSecurityPrinciple(contextUserId, TestSecurityPrinciples.DevopsUser, bypassIntegrityCheck: true);

            // Setup security principle actions
            await access.AddResourceAction(contextUserId, Policies.GetStandardResourceActions().Find(r => r.Id == StandardResourceActions.CertificateDownload));

            // Setup policy with actions and add policy to store
            var policy = Policies.GetStandardPolicies().Find(p => p.Id == StandardPolicies.CertificateConsumer);
            _ = await access.AddResourcePolicy(contextUserId, policy, bypassIntegrityCheck: true);

            // Setup and add roles and policy assignments to store
            var role = Policies.GetStandardRoles().Find(r => r.Id == StandardRoles.CertificateConsumer.Id);
            await access.AddRole(contextUserId, role);

            // Assign security principles to roles and add roles and policy assignments to store
            await access.AddAssignedRole(contextUserId, TestAssignedRoles.DevopsUserWildcardDomainConsumer); // devops user in consumer role for a wildcard domain

            var assignedRolesForDevopsUser = await access.GetAssignedRoles(contextUserId, TestSecurityPrinciples.DevopsUser.Id);

            // create and assign a new API token
            var apiToken = new AccessToken { ClientId = TestSecurityPrinciples.DevopsUser.Id, Secret = Guid.NewGuid().ToString(), TokenType = AccessTokenTypes.Simple, Description = "An example API token" };
            var apiExpiredToken = new AccessToken { ClientId = TestSecurityPrinciples.DevopsUser.Id, Secret = Guid.NewGuid().ToString(), TokenType = AccessTokenTypes.Simple, Description = "An example expired API token", DateExpiry = DateTimeOffset.UtcNow.AddDays(-1) };
            var apiRevokedToken = new AccessToken { ClientId = TestSecurityPrinciples.DevopsUser.Id, Secret = Guid.NewGuid().ToString(), TokenType = AccessTokenTypes.Simple, Description = "An example revoked API token", DateRevoked = DateTimeOffset.UtcNow.AddDays(-1) };
            var apiTokenBad = new AccessToken { ClientId = TestSecurityPrinciples.DomainOwner.Id, Secret = Guid.NewGuid().ToString(), TokenType = AccessTokenTypes.Simple, Description = "An example bad API token (invalid client id)" };
            var assignedToken = new AssignedAccessToken
            {
                AccessTokens = [apiToken, apiExpiredToken, apiRevokedToken],
                SecurityPrincipleId = TestSecurityPrinciples.DevopsUser.Id,
                Title = "test token",
                ScopedAssignedRoles = [assignedRolesForDevopsUser.First(r => r.RoleId == StandardRoles.CertificateConsumer.Id).Id]
            };

            await access.AddAssignedAccessToken(contextUserId, assignedToken);

            var isAuthorized = await access.IsAccessTokenAuthorised(contextUserId, apiToken, new AccessCheck(null, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "random.microsoft.com"));
            Assert.IsTrue(isAuthorized.IsSuccess, "Token should have access");

            isAuthorized = await access.IsAccessTokenAuthorised(contextUserId, apiToken, new AccessCheck(null, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "random.test.com"));
            Assert.IsFalse(isAuthorized.IsSuccess, "Token should not have access (wrong domain identifier resource)");

            isAuthorized = await access.IsAccessTokenAuthorised(contextUserId, apiTokenBad, new AccessCheck(null, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "random.microsoft.com"));
            Assert.IsFalse(isAuthorized.IsSuccess, "Token should not have access (bad token)");

            isAuthorized = await access.IsAccessTokenAuthorised(contextUserId, apiExpiredToken, new AccessCheck(null, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "random.microsoft.com"));
            Assert.IsFalse(isAuthorized.IsSuccess, "Token should not have access (expired)");

            isAuthorized = await access.IsAccessTokenAuthorised(contextUserId, apiRevokedToken, new AccessCheck(null, ResourceTypes.Domain, StandardResourceActions.CertificateDownload, identifier: "random.microsoft.com"));
            Assert.IsFalse(isAuthorized.IsSuccess, "Token should not have access (revoked)");

        }
    }
}
