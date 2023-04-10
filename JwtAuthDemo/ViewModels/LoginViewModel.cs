namespace JwtAuthDemo.ViewModels
{
    public record LoginViewModel
    {
        public string UserName { get; init; }
        public string Password { get; init; }

        public LoginViewModel(string username, string password) => 
            (UserName, Password) = (username, password);
    }
}
