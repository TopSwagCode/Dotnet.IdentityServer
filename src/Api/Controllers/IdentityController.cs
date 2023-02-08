﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Api.Controllers
{
    // Comment
    [Route("identity")]
    [Authorize]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        }

        [HttpGet("admin")]
        [Authorize(Roles = "admin")]
        public IActionResult Admin()
        {
            // Add comment to start build
            return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
        }
    }
}
