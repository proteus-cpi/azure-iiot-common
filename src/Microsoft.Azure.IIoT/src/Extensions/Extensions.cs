﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System {
    using Newtonsoft.Json.Linq;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    public static class Extensions {

        /// <summary>
        /// Using type converter, convert type
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value"></param>
        /// <returns></returns>
        public static T As<T>(this object value) {
            var converter = TypeDescriptor.GetConverter(typeof(T));
            return (T)converter.ConvertFrom(value);
        }

        /// <summary>
        /// Using type converter, convert type
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="value"></param>
        /// <returns></returns>
        public static object As(this object value, Type type) {
            var converter = TypeDescriptor.GetConverter(type);
            return converter.ConvertFrom(value);
        }

        /// <summary>
        /// Convert to base 16
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string ToBase16String(this byte[] value) {
            if (value == null) {
                return null;
            }
            const string hexAlphabet = @"0123456789abcdef";
            var chars = new char[checked(value.Length * 2)];
            unchecked {
                for (var i = 0; i < value.Length; i++) {
                    chars[i * 2] = hexAlphabet[value[i] >> 4];
                    chars[i * 2 + 1] = hexAlphabet[value[i] & 0xF];
                }
            }
            return new string(chars);
        }

        /// <summary>
        /// Convert to base 64
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string ToBase64String(this byte[] value) {
            if (value == null) {
                return null;
            }
            return Convert.ToBase64String(value);
        }

        /// <summary>
        /// Check whether this is base 64
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static bool IsBase64(this string str) {
            try {
                Convert.FromBase64String(str);
                return true;
            }
            catch {
                return false;
            }
        }

        /// <summary>
        /// Convert from base 64
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static byte[] DecodeAsBase64(this string str) {
            if (str == null) {
                return null;
            }
            return Convert.FromBase64String(str);
        }

        /// <summary>
        /// Hashes the string
        /// </summary>
        /// <param name="bytestr">string to hash</param>
        /// <returns></returns>
        public static string ToSha1Hash(this byte[] bytestr) {
            if (bytestr == null) {
                return null;
            }
            using (var sha1 = new SHA1Managed()) {
                var hash = sha1.ComputeHash(bytestr);
                return hash.ToBase16String();
            }
        }

        /// <summary>
        /// Hashes the string
        /// </summary>
        /// <param name="str">string to hash</param>
        /// <returns></returns>
        public static string ToSha1Hash(this string str) =>
            Encoding.UTF8.GetBytes(str).ToSha1Hash();

        /// <summary>
        /// hashes a json object
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static string ToSha1Hash(this JToken token) =>
            token.ToStringMinified().ToSha1Hash();

        /// <summary>
        /// Append byte array to string builder
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="size"></param>
        public static string ToString(this byte[] bytes, int size) {
            var truncate = bytes.Length > size;
            var length = truncate ? size : bytes.Length;
            var ascii = IsAscii(bytes, length);
            var content = ascii ? Encoding.ASCII.GetString(bytes, 0, length) :
                BitConverter.ToString(bytes, 0, length);
            length = content.IndexOf('\n');
            if (length > 0) {
                return content.Substring(0, length);
            }
            return content;
        }

        /// <summary>
        /// Check whether bytes are ascii
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static bool IsAscii(this byte[] bytes, int length) =>
            bytes.Take(length).All(x => x > 32 || x <= 127);

        /// <summary>
        /// Trims only matching chars from front and back
        /// </summary>
        /// <param name="input"></param>
        /// <param name="match"></param>
        /// <returns></returns>
        public static string TrimMatching(this string input, char match) {
            if (input.Length >= 2 && input[0] == match &&
                input[input.Length - 1] == match) {
                return input.Substring(1, input.Length - 2);
            }
            return input;
        }

        /// <summary>
        /// Trims quotes
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string TrimQuotes(this string input) {
            var value = input.TrimMatching('"');
            if (value == input) {
                return input.TrimMatching('\'');
            }
            return value;
        }

        /// <summary>
        /// Replace whitespace
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string SanitizePropertyName(this string value) {
            var chars = new char[checked(value.Length)];
            unchecked {
                for (var i = 0; i < value.Length; i++) {
                    chars[i] = !char.IsLetterOrDigit(value[i]) ? '_' : value[i];
                }
            }
            return new string(chars);
        }

        /// <summary>
        /// Extract data between start and end
        /// </summary>
        /// <param name="str"></param>
        /// <param name="findStart"></param>
        /// <param name="findEnd"></param>
        /// <returns></returns>
        public static string Extract(this string str, string findStart, string findEnd) {
            var start = str.IndexOf(findStart, 0, StringComparison.Ordinal);
            if (start == -1) {
                return string.Empty;
            }
            start += findStart.Length;
            var end = str.IndexOf(findEnd, start, StringComparison.Ordinal);
            if (end == -1) {
                return string.Empty;
            }
            return str.Substring(start, end - start);
        }

        /// <summary>
        /// Split using predicate
        /// </summary>
        /// <param name="str"></param>
        /// <param name="predicate"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static IEnumerable<string> Split(this string str, Func<char, bool> predicate,
            StringSplitOptions options = StringSplitOptions.None) {
            var next = 0;
            for (var c = 0; c < str.Length; c++) {
                if (predicate(str[c])) {
                    var v = str.Substring(next, c - next);
                    if (options != StringSplitOptions.RemoveEmptyEntries ||
                        !string.IsNullOrEmpty(v)) {
                        yield return v;
                    }
                    next = c + 1;
                }
            }
            if (options == StringSplitOptions.RemoveEmptyEntries && next == str.Length) {
                yield break;
            }
            yield return str.Substring(next);
        }

        /// <summary>
        /// Split command line based on https://stackoverflow.com/questions/298830
        /// </summary>
        /// <param name="commandLine"></param>
        /// <returns></returns>
        public static string[] ParseAsCommandLine(this string commandLine) {
            char? quote = null;
            var isEscaping = false;
            return commandLine
                .Split(c => {
                    if (c == '\\' && !isEscaping) {
                        isEscaping = true;
                        return false;
                    }
                    if ((c == '"' || c == '\'') && !isEscaping) {
                        quote = c;
                    }
                    isEscaping = false;
                    return quote == null && char.IsWhiteSpace(c);
                }, StringSplitOptions.RemoveEmptyEntries)
                .Select(arg => arg.Trim().TrimMatching(quote ?? ' ').Replace("\\\"", "\""))
                .Where(arg => !string.IsNullOrEmpty(arg))
                .ToArray();
        }

        /// <summary>
        /// Combine messages
        /// </summary>
        /// <param name="ae"></param>
        /// <returns></returns>
        public static string GetCombinedExceptionMessage(this AggregateException ae) {
            var sb = new StringBuilder();
            foreach (var e in ae.InnerExceptions) {
                sb.AppendLine(string.Concat("E: ", e.Message));
            }
            return sb.ToString();
        }

        /// <summary>
        /// Combine stack trace
        /// </summary>
        /// <param name="ae"></param>
        /// <returns></returns>
        public static string GetCombinedExceptionStackTrace(this AggregateException ae) {
            var sb = new StringBuilder();
            foreach (var e in ae.InnerExceptions) {
                sb.AppendLine(string.Concat("StackTrace: ", e.StackTrace));
            }
            return sb.ToString();
        }

        /// <summary>
        /// Returns first exception of specified type in exception
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="ex"></param>
        /// <returns></returns>
        public static T GetFirstOf<T>(this Exception ex) where T : Exception {
            if (ex is T) {
                return (T)ex;
            }
            if (ex is AggregateException ae) {
                ae = ae.Flatten();
                foreach (var e in ae.InnerExceptions) {
                    var found = GetFirstOf<T>(e);
                    if (found != null) {
                        return found;
                    }
                }
            }
            return null;
        }
    }
}