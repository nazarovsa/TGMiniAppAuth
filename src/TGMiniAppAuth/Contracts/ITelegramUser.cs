namespace TGMiniAppAuth.Contracts;

public interface ITelegramUser
{
    public long Id { get; }

    public string FirstName { get; }

    public string LastName { get; }

    public string? Username { get; }

    public string? LanguageCode { get; }

    public bool IsPremium { get; }

    public bool AllowWriteToPm { get; }
}