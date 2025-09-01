using System;

namespace TgMiniAppAuth.Authorization
{
    /// <summary>
    /// Interface for validating Telegram mini app authorization contexts
    /// </summary>
    public interface ITelegramAuthorizationContextValidator
    {
        /// <summary>
        /// Check that hash value valid sign of all pairs except 'hash=*' of WebAppData with the token of the telegram bot. 
        /// </summary>
        /// <param name="urlEncodedString">Signed data from telegram mini app</param>
        /// <param name="token">Token of the telegram bot</param>
        /// <param name="issuedAt">Date of signed data issued</param>
        /// <param name="stackAllocationThreshold">Stack allocation threshold</param>
        /// <returns>Returns true if sign is valid</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        bool IsValidTelegramMiniAppContext(
            string urlEncodedString,
            string token,
            out DateTimeOffset issuedAt,
            int? stackAllocationThreshold = null);
    }
}