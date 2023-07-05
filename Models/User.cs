namespace box13_Cs_basics_.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;

        public byte[] PasswordHash { get; set; }

        public byte[] PasswordSalt { get; set; }
    }
}