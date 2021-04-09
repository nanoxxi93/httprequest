using HttpRequest.Entities;
using HttpRequest.Models;
using HttpRequest.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace HttpRequest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private IUserService _userService;
        IConfiguration configuration;

        public UserController(IUserService userService, IConfiguration configuration)
        {
            _userService = userService;
            this.configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody]User userParam)
        {
            var user = await _userService.Authenticate(userParam.Username, userParam.Password);

            if (user == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            return Ok(user);
        }

        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [HttpGet]
        public async Task<ActionResult> GetAll()
        {
            var users = await _userService.GetAll();
            return Ok(users);
        }

        [AllowAnonymous]
        [HttpPost("bearerpost")]
        public async Task<IActionResult> Bearer([FromBody]User userParam)
        {
            var user = await _userService.Authenticate(userParam.Username, userParam.Password);

            if (user == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            return BuildToken(user);
        }

        private IActionResult BuildToken(User userParam)
        {
            try
            {

                Claim[] claims = new[] {
                new Claim(JwtRegisteredClaimNames.UniqueName, userParam.FirstName + " " + userParam.LastName),
                new Claim(JwtRegisteredClaimNames.NameId, userParam.Id.ToString())
                };

                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token");
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["SymmetricKey"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expiring = DateTime.UtcNow.AddMinutes(1);

                JwtSecurityToken token = new JwtSecurityToken(
                    claims: claimsIdentity.Claims,
                    signingCredentials: creds
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = expiring,
                    result = userParam
                });
            }
            catch (Exception ex)
            {
                return Json(ex);
            }
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("bearerget")]
        public async Task<ActionResult> GetAllBearer()
        {
            var users = await _userService.GetAll();
            return Ok(users);
        }
    }
}
