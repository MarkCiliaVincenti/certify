﻿using System;
using System.Collections.Generic;

namespace Certify.Models.Hub
{
    public class ManagedInstanceInfo
    {
        public string InstanceId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string OS { get; set; } = string.Empty;
        public string OSVersion { get; set; } = string.Empty;
        public string ClientName { get; set; } = string.Empty;
        public string ClientVersion { get; set; } = string.Empty;

        public List<string> Tags { get; set; } = new List<string>();
        public DateTimeOffset LastReported { get; set; }
    }

    public class ManagedInstanceItems
    {
        public string InstanceId { get; set; } = string.Empty;
        public List<ManagedCertificate> Items { get; set; } = new List<ManagedCertificate>();
    }
}
