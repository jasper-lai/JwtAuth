﻿using Microsoft.AspNetCore.Authorization;

namespace JwtAuthDemo.Controllers
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using System.Security.Claims;
    using System.Xml.Linq;

    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class JwtController : ControllerBase
    {

        /// <summary>
        /// 取得 JWT Token 中的所有 Claims
        /// </summary>
        /// <returns></returns>
        //[HttpGet(Name = nameof(GetClaims))]
        [HttpGet("claims")]
        public IActionResult GetAllClaims()
        {
            return Ok(User.Claims.Select(p => new { p.Type, p.Value }));
        }

        /// <summary>
        /// 取得 JWT Token 中的使用者名稱
        /// </summary>
        /// <returns></returns>
        [HttpGet("username")]
        public IActionResult GetUserName()
        {
            return Ok(User.Identity?.Name); 
        }

        /// <summary>
        /// 取得使用者是否擁有特定角色
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        [HttpGet("isInRole")]
        public IActionResult IsInRole(string name)
        {
            return Ok(User.IsInRole(name));
        }


        /// <summary>
        /// 取得 JWT Token 中的 JWT ID
        /// </summary>
        /// <returns></returns>
        [HttpGet("jwtid")]
        public IActionResult GetJwtId()
        {
            return Ok(User.Claims.FirstOrDefault(p => p.Type == "jti")?.Value);
        }


    }
}
