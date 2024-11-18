namespace TgMiniAppAuth;

/// <summary>
/// Contains constants used in the Telegram Mini App authentication.
/// </summary>
public static class TgMiniAppAuthConstants
{
    /// <summary>
    /// The authentication scheme for the Telegram Mini App.
    /// </summary>
    public const string AuthenticationScheme = "TMiniApp";

    /// <summary>
    /// Contains claim types used in the Telegram Mini App authentication.
    /// </summary>
    public static class Claims
    {
        private const string Prefix = "TMiniApp";

        /// <summary>
        /// The raw authentication data claim type.
        /// </summary>
        public const string RawAuthData = $"{Prefix}:RawAuthData";

        /// <summary>
        /// The user ID claim type.
        /// </summary>
        public const string Id = $"{Prefix}:Id";

        /// <summary>
        /// The first name claim type.
        /// </summary>
        public const string FirstName = $"{Prefix}:FirstName";

        /// <summary>
        /// The last name claim type.
        /// </summary>
        public const string LastName = $"{Prefix}:LastName";

        /// <summary>
        /// The username claim type.
        /// </summary>
        public const string Username = $"{Prefix}:Username";

        /// <summary>
        /// The language code claim type.
        /// </summary>
        public const string LanguageCode = $"{Prefix}:LanguageCode";

        /// <summary>
        /// The premium status claim type.
        /// </summary>
        public const string IsPremium = $"{Prefix}:IsPremium";

        /// <summary>
        /// The allow write to private message claim type.
        /// </summary>
        public const string AllowWriteToPm = $"{Prefix}:AllowWriteToPm";

        /// <summary>
        /// Photo url claim type.
        /// </summary>
        public const string PhotoUrl = $"{Prefix}:PhotoUrl";
    }
}