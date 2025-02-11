﻿using Certify.Client;
using Certify.Server.Hub.Api.Services;
using Microsoft.AspNetCore.Mvc;

namespace Certify.Server.Hub.Api.Controllers
{
    /// <summary>
    /// Internal API for extended certificate management. Not intended for general use.
    /// </summary>
    [ApiController]
    [Route("internal/v1/[controller]")]
    public partial class CertificateAuthorityController : ApiControllerBase
    {

        private readonly ILogger<CertificateAuthorityController> _logger;

        private readonly ICertifyInternalApiClient _client;
        private readonly ManagementAPI _mgmtAPI;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="client"></param>
        public CertificateAuthorityController(ILogger<CertificateAuthorityController> logger, ICertifyInternalApiClient client, ManagementAPI mgmtApi)
        {
            _logger = logger;
            _client = client;
            _mgmtAPI = mgmtApi;
        }
    }
}
