using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace TgMiniAppAuth.AuthContext;

/// <summary>
/// Telegram mini app auth context
/// </summary>
internal class TelegramAuthorizationContextValidator : ITelegramAuthorizationContextValidator
{
    /// <summary>
    /// Static value used as a key for bot token sign
    /// </summary>
    private static readonly byte[] WebAppDataBytes = "WebAppData"u8.ToArray();

    private const int StackAllocationThreshold = 1024;

    /// <inheritdoc />
    /// <summary>
    /// Check that hash value valid sign of all pairs except 'hash=*' of <see cref="WebAppDataBytes"/> with the token of the telegram bot. 
    /// </summary>
    /// <param name="urlEncodedString">Signed data from telegram mini app</param>
    /// <param name="token">Token of the telegram bot</param>
    /// <param name="issuedAt">Date of signed data issued</param>
    /// <param name="stackAllocationThreshold"></param>
    /// <returns>Returns true if sign is valid</returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public bool IsValidTelegramMiniAppContext(string urlEncodedString,
        string token,
        out DateTimeOffset issuedAt,
        int? stackAllocationThreshold = null)
    {
        var threshold = stackAllocationThreshold ?? StackAllocationThreshold;

        Span<char> hashPair = stackalloc char[69];
        Span<char> authDatePair = stackalloc char[64];
        Span<char> decodedBuffer = urlEncodedString.Length <= threshold
            ? stackalloc char[threshold]
            : new char[urlEncodedString.Length];
        // Decode in stack if in threshold
        UrlDecode(urlEncodedString, Encoding.UTF8, decodedBuffer, out var decodedBytesLength, out var decodedCharsLength, threshold);
        decodedBuffer = decodedBuffer.Slice(0, decodedCharsLength);
        var blocksCount = decodedBuffer.Count('&') + 1;

        // Pairs start indexes + length, except hash
        Span<int> pairsBorders = stackalloc int[(blocksCount - 1) * 2];

        var pairIndex = 0;
        var startPairIndex = 0;
        var endPairIndex = decodedBuffer.IndexOf('&');
        var pairLength = endPairIndex;
        var seekPair = decodedBuffer.Slice(startPairIndex, pairLength);

        // Find pairs start indexes and length. Put them into pairsBorders.
        // Index of pair start = 2 * pairIndex, Index of length = 2 * pairIndex + 1
        while (startPairIndex < decodedBuffer.Length)
        {
            seekPair = decodedBuffer.Slice(startPairIndex, pairLength);
            if (seekPair.Length == 0)
                break;

            if (seekPair.StartsWith("hash"))
            {
                seekPair.CopyTo(hashPair);
            }
            else
            {
                if (seekPair.StartsWith("auth_date"))
                {
                    seekPair.CopyTo(authDatePair);
                    authDatePair = authDatePair.Slice(0, seekPair.Length);
                }

                pairsBorders[2 * pairIndex] = startPairIndex;
                pairsBorders[2 * pairIndex + 1] = endPairIndex - startPairIndex;

                pairIndex++;
            }

            startPairIndex = startPairIndex + pairLength + 1;
            if (startPairIndex > decodedBuffer.Length - 1)
                break;

            var newSlice = decodedBuffer.Slice(startPairIndex);
            var nextAmpIndex = newSlice.IndexOf('&');
            if (nextAmpIndex == -1)
            {
                endPairIndex = decodedBuffer.Length;
                pairLength = endPairIndex - startPairIndex;
                continue;
            }

            endPairIndex = startPairIndex + newSlice.IndexOf('&');
            pairLength = endPairIndex - startPairIndex;
        }

        // All pairs except hash and &, so: decodedCharsLength - hashPair.Length - 1
        Span<char> orderedCheckData = stackalloc char[decodedCharsLength - hashPair.Length - 1];
        Span<int> newPairBorders = stackalloc int[pairsBorders.Length];
        // Build check string: use alphabetically sorted pairs except 'hash=*' joined with '\n'
        CopyOrderedBuffer(decodedBuffer, pairsBorders, orderedCheckData, newPairBorders, threshold);

        if (hashPair.IsEmpty)
        {
            throw new ArgumentException("Key 'hash' not found");
        }

        if (authDatePair.IsEmpty)
        {
            throw new ArgumentException("Key 'auth_date' not found");
        }

        if (!long.TryParse(GetPairValue(authDatePair), out var unixAuthDate))
        {
            throw new InvalidOperationException("Failed to parse 'auth_date'");
        }

        issuedAt = DateTimeOffset.FromUnixTimeSeconds(unixAuthDate);

        var checkDataBytesLength = decodedBytesLength - hashPair.Length - 1;
        Span<byte> checkDataBytes = checkDataBytesLength <= threshold
            ? stackalloc byte[checkDataBytesLength]
            : new byte[checkDataBytesLength];
        Encoding.UTF8.GetBytes(orderedCheckData, checkDataBytes);

        Span<byte> tokenSignedBytes = stackalloc byte[32];
        Span<byte> targetHashBytes = stackalloc byte[32];
        var tokenBytesLength = Encoding.UTF8.GetByteCount(token);
        Span<byte> tokenBytes = stackalloc byte[tokenBytesLength];

        Encoding.UTF8.GetBytes(token, tokenBytes);

        // Hash of the token with the key "WebAppData"
        HMACSHA256.HashData(WebAppDataBytes, tokenBytes, tokenSignedBytes);
        HMACSHA256.HashData(tokenSignedBytes, checkDataBytes, targetHashBytes);

        var hash = GetPairValue(hashPair);
        Span<byte> hashHexBytes = stackalloc byte[32];
        HexStringToByteSpan(hash, hashHexBytes);

        return hashHexBytes.SequenceEqual(targetHashBytes);
    }

    /// <summary>
    /// Order pairs from input, copy them into output, fill newIndexArray with sorted start indexes and lengths of pairs 
    /// </summary>
    /// <param name="input">Input string</param>
    /// <param name="indexArray">Start indexes and lengths of pairs</param>
    /// <param name="output">Sorted input string</param>
    /// <param name="newIndexArray">New index array for sorted output</param>
    /// <param name="stackAllocationThreshold">Threshold of stack allocation.</param>
    private void CopyOrderedBuffer(Span<char> input, Span<int> indexArray, Span<char> output,
        Span<int> newIndexArray, int? stackAllocationThreshold = null)
    {
        var pairsCount = newIndexArray.Length / 2;
        indexArray.CopyTo(newIndexArray);

        // Sort
        for (int i = 1; i < pairsCount; i++)
        {
            var (currentStart, currentLength) = GetPairPointer(newIndexArray, i);
            int j = i - 1;

            var (prevStartIndex, prevLength) = GetPairPointer(newIndexArray, j);
            while (j >= 0 && CompareParameterKeys(input, prevStartIndex, prevLength, currentStart, currentLength) > 0)
            {
                SetPairPointer(newIndexArray, j + 1, prevStartIndex, prevLength);
                j--;
                if (j >= 0)
                {
                    (prevStartIndex, prevLength) = GetPairPointer(newIndexArray, j);
                }
            }

            SetPairPointer(newIndexArray, j + 1, currentStart, currentLength);
        }

        Span<char> result = input.Length <= stackAllocationThreshold
            ? stackalloc char[output.Length]
            : new char[output.Length];
        int pos = 0;

        for (int i = 0; i < pairsCount; i++)
        {
            if (i > 0)
            {
                result[pos++] = '\n';
            }

            var (pairStart, pairLength) = GetPairPointer(newIndexArray, i);
            var pair = input.Slice(pairStart, pairLength);
            var dest = result.Slice(pos);
            pair.CopyTo(dest);
            pos += pair.Length;
        }

        result.CopyTo(output);
    }

    private (int start, int length) GetPairPointer(ReadOnlySpan<int> indexArray, int index)
    {
        var startIndex = 2 * index;
        var lengthIndex = 2 * index + 1;

        var sourceStartIndex = indexArray[startIndex];
        var sourceLengthIndex = indexArray[lengthIndex];
        return (sourceStartIndex, sourceLengthIndex);
    }

    private void SetPairPointer(Span<int> array, int index, int start, int length)
    {
        var startIndex = 2 * index;
        var lengthIndex = 2 * index + 1;

        array[startIndex] = start;
        array[lengthIndex] = length;
    }

    private int CompareParameterKeys(ReadOnlySpan<char> chars, int leftStart, int leftLength,
        int rightStart, int rightLength)
    {
        var span1 = chars.Slice(leftStart, leftLength);
        var span2 = chars.Slice(rightStart, rightLength);

        return span1.CompareTo(span2, StringComparison.Ordinal);
    }

    private ReadOnlySpan<char> GetPairValue(ReadOnlySpan<char> source)
    {
        var indexOfEquals = source.IndexOf("=");
        return source[(indexOfEquals + 1)..];
    }

    #region Hex

    /// <summary>
    /// https://gist.github.com/crozone/06c4aa41e13be89def1352ba0d378b0f
    /// </summary>
    /// <param name="inputChars"></param>
    /// <param name="decodedBytesBuffer"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    private void HexStringToByteSpan(ReadOnlySpan<char> inputChars, Span<byte> decodedBytesBuffer)
    {
        if (inputChars.Length % 2 != 0)
        {
            throw new InvalidOperationException($"{nameof(inputChars)} length must be even");
        }

        int bufferLength = inputChars.Length / 2;
        if (decodedBytesBuffer.Length < bufferLength)
        {
            throw new InvalidOperationException(
                $"{nameof(decodedBytesBuffer)} must be at least half the length of {nameof(inputChars)}");
        }

        for (int bx = 0, sx = 0; bx < bufferLength; ++bx, ++sx)
        {
            // Convert first half of byte
            char c = inputChars[sx];
            decodedBytesBuffer[bx] = (byte)((c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0')) << 4);

            // Convert second half of byte
            c = inputChars[++sx];
            decodedBytesBuffer[bx] |= (byte)(c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0'));
        }
    }

    #endregion

    #region UrlDecode

    // Internal code from https://learn.microsoft.com/en-us/dotnet/api/system.web.httputility.urldecode?view=net-9.
    public void UrlDecode(ReadOnlySpan<char> input, Encoding encoding, Span<char> decoded, out int lengthBytes, out int lengthChars,
        int? stackAllocationThreshold = null)
    {
        var allocationThreshold = stackAllocationThreshold ?? StackAllocationThreshold;
        if (input.IsEmpty)
        {
            lengthBytes = 0;
            lengthChars = 0;
            return;
        }

        int count = input.Length;
        UrlDecoder helper = count <= allocationThreshold
            ? new UrlDecoder(stackalloc char[allocationThreshold], stackalloc byte[allocationThreshold], encoding)
            : new UrlDecoder(new char[count], new byte[count], encoding);

        // go through the string's chars collapsing %XX and %uXXXX and
        // appending each char as char, with exception of %XX constructs
        // that are appended as bytes

        for (int pos = 0; pos < count; pos++)
        {
            char ch = input[pos];

            if (ch == '+')
            {
                ch = ' ';
            }
            else if (ch == '%' && pos < count - 2)
            {
                if (input[pos + 1] == 'u' && pos < count - 5)
                {
                    int h1 = FromChar(input[pos + 2]);
                    int h2 = FromChar(input[pos + 3]);
                    int h3 = FromChar(input[pos + 4]);
                    int h4 = FromChar(input[pos + 5]);

                    if ((h1 | h2 | h3 | h4) != 0xFF)
                    {
                        // valid 4 hex chars
                        ch = (char)((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
                        pos += 5;

                        // only add as char
                        helper.AddChar(ch);
                        continue;
                    }
                }
                else
                {
                    int h1 = FromChar(input[pos + 1]);
                    int h2 = FromChar(input[pos + 2]);

                    if ((h1 | h2) != 0xFF)
                    {
                        // valid 2 hex chars
                        byte b = (byte)((h1 << 4) | h2);
                        pos += 2;

                        // don't add as char
                        helper.AddByte(b);
                        continue;
                    }
                }
            }

            if ((ch & 0xFF80) == 0)
            {
                helper.AddByte((byte)ch); // 7 bit have to go as bytes because of Unicode
            }
            else
            {
                helper.AddChar(ch);
            }
        }

        lengthBytes = helper.BytesLength;
        helper.WriteString(decoded);
        lengthChars = helper.CharsLength;
    }


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FromChar(int c)
    {
        return (c >= CharToHexLookup.Length) ? 0xFF : CharToHexLookup[c];
    }

    /// <summary>Map from an ASCII char to its hex value, e.g. arr['b'] == 11. 0xFF means it's not a hex digit.</summary>
    public static ReadOnlySpan<byte> CharToHexLookup =>
    [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 15
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 31
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 47
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 63
        0xFF, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 79
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 95
        0xFF, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 111
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 127
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 143
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 159
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 175
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 191
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 207
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 223
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 239
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // 255
    ];

    // Microsoft: System.Web.HttpUtility.UrlEncoder
    // Internal class to facilitate URL decoding -- keeps char buffer and byte buffer, allows appending of either chars or bytes
    private ref struct UrlDecoder
    {
        // Accumulate characters in a special array
        private int _numChars;
        private readonly Span<char> _charBuffer;

        // Accumulate bytes for decoding into characters in a special array
        private int _numBytes;
        private readonly Span<byte> _byteBuffer;

        public int BytesLength => _numBytes;
        public int CharsLength => _numChars;

        // Encoding to convert chars to bytes
        private readonly Encoding _encoding;

        private void FlushBytes()
        {
            if (_numBytes > 0)
            {
                _numChars += _encoding.GetChars(_byteBuffer.Slice(0, _numBytes), _charBuffer.Slice(_numChars));
                _numBytes = 0;
            }
        }

        internal UrlDecoder(Span<char> charBuffer, Span<byte> byteBuffer, Encoding encoding)
        {
            _charBuffer = charBuffer;
            _byteBuffer = byteBuffer;
            _encoding = encoding;
        }

        internal void AddChar(char ch)
        {
            if (_numBytes > 0)
            {
                FlushBytes();
            }

            _charBuffer[_numChars++] = ch;
        }

        internal void AddByte(byte b)
        {
            // if there are no pending bytes treat 7 bit bytes as characters
            // this optimization is temp disable as it doesn't work for some encodings
            /*
                            if (_numBytes == 0 && ((b & 0x80) == 0)) {
                                AddChar((char)b);
                            }
                            else
            */
            {
                _byteBuffer[_numBytes++] = b;
            }
        }

        internal void WriteString(Span<char> output)
        {
            if (_numBytes > 0)
            {
                FlushBytes();
            }

            Span<char> chars = _charBuffer.Slice(0, _numChars);

            const char HIGH_SURROGATE_START = '\ud800';
            const char LOW_SURROGATE_END = '\udfff';

            // Replace any invalid surrogate chars.
            int idxOfFirstSurrogate = chars.IndexOfAnyInRange(HIGH_SURROGATE_START, LOW_SURROGATE_END);
            for (int i = idxOfFirstSurrogate; (uint)i < (uint)chars.Length; i++)
            {
                if (char.IsHighSurrogate(chars[i]))
                {
                    if ((uint)(i + 1) >= (uint)chars.Length || !char.IsLowSurrogate(chars[i + 1]))
                    {
                        // High surrogate not followed by a low surrogate.
                        chars[i] = (char)Rune.ReplacementChar.Value;
                    }
                    else
                    {
                        i++;
                    }
                }
                else if (char.IsLowSurrogate(chars[i]))
                {
                    // Low surrogate not preceded by a high surrogate.
                    chars[i] = (char)Rune.ReplacementChar.Value;
                }
            }

            for (var i = 0; i < chars.Length; i++)
            {
                output[i] = chars[i];
            }
        }
    }

    #endregion
}