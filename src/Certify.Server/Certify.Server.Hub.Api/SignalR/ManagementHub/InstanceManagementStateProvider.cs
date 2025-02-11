﻿using System.Collections.Concurrent;
using Certify.Models;
using Certify.Models.Hub;
using Certify.Models.Reporting;

namespace Certify.Server.Hub.Api.SignalR.ManagementHub
{
    public interface IInstanceManagementStateProvider
    {
        public void Clear();
        public void SetManagementHubInstanceId(string instanceId);
        public string GetManagementHubInstanceId();
        public void UpdateInstanceConnectionInfo(string connectionId, ManagedInstanceInfo instanceInfo);
        public void UpdateInstanceStatusSummary(string instanceId, StatusSummary summary);
        public string GetConnectionIdForInstance(string instanceId);
        public string GetInstanceIdForConnection(string connectionId);
        public List<ManagedInstanceInfo> GetConnectedInstances();
        public void AddAwaitedCommandRequest(InstanceCommandRequest command);
        public void RemoveAwaitedCommandRequest(Guid commandId);
        public InstanceCommandRequest? GetAwaitedCommandRequest(Guid commandId);
        public void AddAwaitedCommandResult(InstanceCommandResult result);
        public Task<InstanceCommandResult?> ConsumeAwaitedCommandResult(Guid commandId);
        public void UpdateInstanceItemInfo(string instanceId, List<ManagedCertificate> items);
        public ConcurrentDictionary<string, ManagedInstanceItems> GetManagedInstanceItems(string instanceId = null);
        public void UpdateCachedManagedInstanceItem(string instanceId, ManagedCertificate managedCertificate);
        public void DeleteCachedManagedInstanceItem(string instanceId, string managedCertificateId);
        public bool HasItemsForManagedInstance(string instanceId);

        public bool HasStatusSummaryForManagedInstance(string instanceId);
        public ConcurrentDictionary<string, StatusSummary> GetManagedInstanceStatusSummaries();
    }

    /// <summary>
    /// Track state across pool of instance connections to the management hub
    /// </summary>
    public class InstanceManagementStateProvider : IInstanceManagementStateProvider
    {
        private ConcurrentDictionary<string, ManagedInstanceInfo> _instanceConnections = [];
        private ConcurrentDictionary<Guid, InstanceCommandRequest> _awaitedCommandRequests = [];
        private ConcurrentDictionary<Guid, InstanceCommandResult> _awaitedCommandResults = [];

        private ConcurrentDictionary<string, ManagedInstanceItems> _managedInstanceItems = [];
        private ConcurrentDictionary<string, StatusSummary> _managedInstanceStatusSummary = [];
        private ILogger<InstanceManagementStateProvider> _logger;
        private string _mgmtHubInstanceId = string.Empty;

        public InstanceManagementStateProvider(ILogger<InstanceManagementStateProvider> logger)
        {
            _logger = logger;
        }

        public void Clear()
        {
            _logger.LogWarning("Flushing management hub state, clients will need to reconnect.");
            _instanceConnections.Clear();
            _managedInstanceItems.Clear();
            _awaitedCommandRequests.Clear();
            _awaitedCommandResults.Clear();
            _managedInstanceStatusSummary.Clear();

        }

        public void SetManagementHubInstanceId(string instanceId)
        {
            _mgmtHubInstanceId = instanceId;
        }

        public string GetManagementHubInstanceId()
        {
            return _mgmtHubInstanceId;
        }

        public List<ManagedInstanceInfo> GetConnectedInstances()
        {
            return _instanceConnections.Values.ToList();
        }
        /// <summary>
        /// Track the instance info associated with a hub connection
        /// </summary>
        /// <param name="connectionId"></param>
        /// <param name="instanceInfo"></param>
        public void UpdateInstanceConnectionInfo(string connectionId, ManagedInstanceInfo instanceInfo)
        {
            var existingOther = _instanceConnections.FirstOrDefault(a => a.Value.InstanceId == instanceInfo.InstanceId && a.Key != connectionId);

            if (existingOther.Value != null)
            {
                _logger.LogWarning("[InstanceManagementStateProvider] Connection ID for instance {instance} changed to {connection}", instanceInfo.Title, connectionId);
                _instanceConnections.Remove(existingOther.Key, out _);
            }

            _instanceConnections.AddOrUpdate(connectionId, instanceInfo, (i, oldValue) => { return instanceInfo; });
        }

        public void UpdateInstanceStatusSummary(string instanceId, StatusSummary summary)
        {
            _managedInstanceStatusSummary.AddOrUpdate(instanceId, summary, (i, oldValue) => summary);
        }

        /// <summary>
        /// Get the current connection ID we haev associated with the given instance id
        /// </summary>
        /// <param name="instanceId"></param>
        /// <returns></returns>
        public string GetConnectionIdForInstance(string instanceId)
        {
            // TODO: of instances use the same instanceid accidentally they will clobber each other
            var info = _instanceConnections.FirstOrDefault(k => k.Value.InstanceId == instanceId);

            return info.Key;
        }

        public string? GetInstanceIdForConnection(string connectionId)
        {
            _instanceConnections.TryGetValue(connectionId, out var managedInstanceInfo);

            if (managedInstanceInfo != null)
            {
                return managedInstanceInfo.InstanceId;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Track command requests we are waiting on responses for.
        /// </summary>
        /// <param name="command"></param>
        public void AddAwaitedCommandRequest(InstanceCommandRequest command)
        {
            _awaitedCommandRequests.AddOrUpdate(command.CommandId, command, (i, oldValue) => { return command; });
        }

        /// <summary>
        /// Get command request we are waiting on a response for
        /// </summary>
        /// <param name="commandId"></param>
        /// <returns></returns>
        public InstanceCommandRequest? GetAwaitedCommandRequest(Guid commandId)
        {
            _awaitedCommandRequests.TryGetValue(commandId, out var cmd);
            return cmd;
        }

        public void AddAwaitedCommandResult(InstanceCommandResult result)
        {
            _awaitedCommandResults.AddOrUpdate(result.CommandId, result, (i, oldValue) => result);
        }

        public async Task<InstanceCommandResult?> ConsumeAwaitedCommandResult(Guid commandId)
        {
            _logger.LogInformation("Waiting for command result {commandId}..", commandId);
            var attempts = 50;

            while (attempts > 0 && !_awaitedCommandResults.TryGetValue(commandId, out _))
            {
                attempts--;
                await Task.Delay(100);
                _logger.LogInformation("Still waiting for command result {commandId}..", commandId);
            }

            _awaitedCommandResults.Remove(commandId, out var cmd);

            if (cmd == null)
            {
                _logger.LogError("Gave up waiting for command result {commandId}..", commandId);
            }
            else
            {
                _logger.LogInformation("Got command result {commandId}..", commandId);
            }

            return cmd;
        }

        /// <summary>
        /// Remove a command request we have received a response for
        /// </summary>
        /// <param name="commandId"></param>
        public void RemoveAwaitedCommandRequest(Guid commandId)
        {
            _awaitedCommandRequests.Remove(commandId, out _);
        }

        public void UpdateInstanceItemInfo(string instanceId, List<ManagedCertificate> items)
        {
            var info = new ManagedInstanceItems { InstanceId = instanceId, Items = items };
            _managedInstanceItems.AddOrUpdate(instanceId, info, (k, old) => info);
        }

        public ConcurrentDictionary<string, ManagedInstanceItems> GetManagedInstanceItems(string instanceId = null)
        {
            return _managedInstanceItems;
        }

        public ConcurrentDictionary<string, StatusSummary> GetManagedInstanceStatusSummaries()
        {
            return _managedInstanceStatusSummary;
        }

        public void UpdateCachedManagedInstanceItem(string instanceId, ManagedCertificate managedCertificate)
        {
            _managedInstanceItems.TryGetValue(instanceId, out var instance);
            if (instance?.Items != null)
            {
                instance.Items.RemoveAll(r => r.Id == managedCertificate.Id);
                instance.Items.Add(managedCertificate);
            }
        }

        public bool HasItemsForManagedInstance(string instanceId)
        {
            return _managedInstanceItems.ContainsKey(instanceId);
        }

        public bool HasStatusSummaryForManagedInstance(string instanceId)
        {
            return _managedInstanceStatusSummary.ContainsKey(instanceId);
        }

        public void DeleteCachedManagedInstanceItem(string instanceId, string managedCertificateId)
        {
            _managedInstanceItems.TryGetValue(instanceId, out var instance);

            if (instance?.Items != null)
            {
                instance.Items.RemoveAll(r => r.Id == managedCertificateId);
            }
        }
    }
}
