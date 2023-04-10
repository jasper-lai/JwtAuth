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
        [HttpPost(Name = "signin")]
        public IActionResult SignIn(LoginViewModel login, JwtHelpers jwt)
        {
            if (ValidateUser(login))
            {
                var token = jwt.GenerateToken(login.UserName);
                return Ok(new { token });
            }
            else
            {
                return BadRequest();
            }
        }
    }
}
