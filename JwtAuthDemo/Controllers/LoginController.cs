namespace JwtAuthDemo.Controllers
{
    using JwtAuthDemo.Helpers;
    using JwtAuthDemo.ViewModels;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;

    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private JwtHelpers _jwt;

        public LoginController(JwtHelpers jwt)
        {   
            _jwt = jwt;
        }

        private bool ValidateUser(LoginViewModel login)
        {
            return true;
        }

        /// <summary>
        /// 登入並取得 JWT Token
        /// </summary>
        /// <param name="login"></param>
        /// <param name="jwt"></param>
        /// <returns></returns>
        //[HttpPost(Name = nameof(SignIn))]
        [HttpPost("signin")]
        public IActionResult SignIn(LoginViewModel login)
        {
            if (ValidateUser(login))
            {
                var token = _jwt.GenerateToken(login.UserName);
                return Ok(new { token });
            }
            else
            {
                return BadRequest();
            }
        }
    }
}
