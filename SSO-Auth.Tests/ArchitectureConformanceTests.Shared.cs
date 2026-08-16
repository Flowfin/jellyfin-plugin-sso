// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the helpers more than one surface reads with: the type and source-file sequences, the code-line reader that drops prose, and the balanced-call parser.
/// </content>
public partial class ArchitectureConformanceTests
{
    // Parse a flat JS string-array const (const <name> = [ "a", "b" ];) from config.js into a set.
    private static HashSet<string> ParseJsStringArrayConst(string js, string constName)
    {
        var start = js.IndexOf("const " + constName + " = [", StringComparison.Ordinal);
        Assert.True(start >= 0, $"{constName} was not found in config.js.");
        var end = js.IndexOf("];", start, StringComparison.Ordinal);
        Assert.True(end > start, $"{constName} has no closing ];.");
        var region = js[start..end];

        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in Regex.Matches(region, "\"(\\w+)\""))
        {
            set.Add(m.Groups[1].Value);
        }

        return set;
    }

    // A configuration type for the facade rule: the plugin configuration itself or any provider config
    // (OidConfig/SamlConfig derive from ProviderConfigBase), including one buried in a generic
    // (e.g. Func<PluginConfiguration, T>) or array signature.
    private static bool MentionsConfiguration(Type t) =>
        typeof(BasePluginConfiguration).IsAssignableFrom(t)
        || typeof(ProviderConfigBase).IsAssignableFrom(t)
        || (t.HasElementType && MentionsConfiguration(t.GetElementType()!))
        || (t.IsGenericType && t.GetGenericArguments().Any(MentionsConfiguration));

    // Catches concrete dictionaries (they implement non-generic IDictionary) AND fields declared as the
    // generic IDictionary<,> interface, which does not inherit the non-generic one - otherwise an
    // interface-typed field would slip past the mutable-keyed-state rule.
    private static bool IsDictionaryLike(Type t) =>
        typeof(System.Collections.IDictionary).IsAssignableFrom(t)
        || (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(IDictionary<,>))
        || t.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IDictionary<,>));

    // The reflection Name of a generic type carries a `1 arity suffix (e.g. "Cache`1"); strip it so suffix
    // matching sees the source name.
    private static string SimpleName(Type t)
    {
        var name = t.Name;
        var tick = name.IndexOf('`', StringComparison.Ordinal);
        return tick < 0 ? name : name[..tick];
    }

    private static bool IsCompilerGenerated(Type t) =>
        t.Name.Contains('<', StringComparison.Ordinal)
        || t.GetCustomAttribute<CompilerGeneratedAttribute>() is not null;

    // Every source file that declares a controller type, discovered from reflection so the controller
    // source scans follow the planned #318 controller split automatically (#388): reflection names the
    // controller TYPES (deriving from ControllerBase); the files are those declaring them - a partial-class
    // split declares one type across several files, a multi-controller split adds more types, and both are
    // found. Matching the declaration in the file body, not the file name, also survives a controller file
    // rename. The set must be non-empty: a scan reading no file would pass every controller rule vacuously,
    // so a controller reflection can no longer find (removed base type, moved out of the source tree) fails
    // loudly here rather than turning the rules into silent no-ops.
    private static IReadOnlyList<string> ControllerSourceFiles()
    {
        var controllerTypes = PluginClasses.Where(t => typeof(ControllerBase).IsAssignableFrom(t));
        var files = SourceFilesDeclaring(controllerTypes);

        Assert.True(
            files.Count > 0,
            "No controller source file was found to scan; a controller was renamed, moved out of SSO-Auth, or lost its ControllerBase base, so the controller source scans would pass vacuously - update ControllerSourceFiles (#388).");
        return files;
    }

    // The C# keywords a type declaration's name can immediately follow. "struct" alone also matches a
    // "record struct" declaration (the name follows "struct", not "record", in that form); "record" alone
    // matches a positional/reference record ("record Foo(...)"), since "record class Foo" is already
    // covered by "class".
    private static readonly string[] TypeDeclarationKeywords = { "class", "struct", "record" };

    // Every source file that declares any of the given types, matched by class/struct/record declaration
    // in the file body (not the file name), so a file rename still resolves via the type's own name.
    // Shared by ControllerSourceFiles above and the raw socket/DNS liveness check (#444) - both need
    // "which files declare these types", just for a different type set (#542).
    private static IReadOnlyList<string> SourceFilesDeclaring(IEnumerable<Type> types)
    {
        var declarations = types
            .SelectMany(t => TypeDeclarationKeywords.Select(keyword =>
                new Regex($@"\b{keyword}\s+{Regex.Escape(SimpleName(t))}\b")))
            .ToList();

        return Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => declarations.Any(d => d.IsMatch(File.ReadAllText(path))))
            .ToList();
    }

    // Whether trimmed text opens a comment: a line comment, a block-comment opener, or the continuation line
    // of a block or XML-doc comment. THE ONLY COPY of the form list - a fourth form added to one of two
    // copies is how a rule silently stops covering the spelling it was written for, and the two consumers
    // below had already drifted apart on the block-comment opener (#1214).
    //
    // It reads the FIRST characters of what it is given and nothing else, so a comment opened part-way along
    // a line ("Load(x); // moved") is not a comment to either consumer, and a block comment is only seen on
    // the lines that begin one. That limit is shared by both, which is the property the fixture pins.
    private static bool OpensAComment(string trimmedText) =>
        trimmedText.StartsWith("//", StringComparison.Ordinal)
        || trimmedText.StartsWith("/*", StringComparison.Ordinal)
        || trimmedText.StartsWith("*", StringComparison.Ordinal);

    // A source text's numbered CODE lines: comment and XML-doc lines are excluded, because prose can name a
    // banned type or quote a piece of markup without any call site reaching for it. On CRLF input the
    // trailing \r survives the split and is removed by the Trim, so a line's text does not depend on the
    // checkout's line endings.
    private static IEnumerable<(int Number, string Text)> CodeLinesOf(string source) =>
        source.Split('\n')
            .Select((line, index) => (Number: index + 1, Text: line.Trim()))
            .Where(l => !OpensAComment(l.Text));

    // A file's numbered CODE lines, by the rule above and no second opinion. A file that ends in a newline
    // yields one extra entry past its last line, whose text is empty; every predicate above searches for a
    // non-empty token, so nothing matches it.
    private static IEnumerable<(int Number, string Text)> CodeLines(string path) =>
        CodeLinesOf(File.ReadAllText(path));

    // Whether a source text CALLS something, as opposed to merely mentioning it. Comment lines are excluded,
    // because the likeliest edit that breaks a call-site rule is removing the call and documenting the
    // removal in a comment that names it - which reads as diligence and would turn a whole-file text search
    // green (#1122). Takes source rather than a path so a fixture can feed it synthetic lines.
    private static bool SourceCallsInCode(string source, string invocation) =>
        CodeLinesOf(source).Any(l => l.Text.Contains(invocation, StringComparison.Ordinal));

    // The double-quoted string literals on a line, escapes honoured so a \" cannot end one early. Verbatim
    // (@"...") literals are not modelled: the SAML module uses none, and a markup literal spelled that way
    // would still have to be consumed by one of the scanned string operations to matter.
    private static IEnumerable<string> StringLiterals(string line) =>
        Regex.Matches(line, "\"(?:[^\"\\\\]|\\\\.)*\"").Select(m => m.Value);

    // Every invocation of the named methods in a source file, with its receiver and balanced argument text.
    // Matching the balanced parentheses (rather than the line) is what lets the namespace-aware rule judge a
    // call that wraps across lines or nests another call in its arguments, and what lets the hardened-reader
    // ban see the whole argument instead of the text up to the first comma or parenthesis.
    private static IEnumerable<(int Line, string Receiver, string Method, string Arguments)> CallsTo(string source, params string[] methodNames)
    {
        foreach (var method in methodNames)
        {
            var token = method + "(";
            for (var index = source.IndexOf(token, StringComparison.Ordinal); index >= 0; index = source.IndexOf(token, index + 1, StringComparison.Ordinal))
            {
                // Not a call to this method if the token is only the tail of a longer identifier.
                if (index > 0 && (char.IsLetterOrDigit(source[index - 1]) || source[index - 1] == '_'))
                {
                    continue;
                }

                var line = source.Take(index).Count(c => c == '\n') + 1;
                var arguments = BalancedArguments(source, index + method.Length);
                if (arguments is not null && !IsOnACommentLine(source, index))
                {
                    yield return (line, ReceiverBefore(source, index), method, arguments);
                }
            }
        }
    }

    // The identifier a call is made on: the word immediately before the dot preceding the method name, or the
    // empty string for an unqualified call. Only the last segment is returned (a.b.C() yields "b"), which is
    // all the receiver-identity checks need.
    private static string ReceiverBefore(string source, int methodIndex)
    {
        if (methodIndex == 0 || source[methodIndex - 1] != '.')
        {
            return string.Empty;
        }

        var end = methodIndex - 1;
        var start = end;
        while (start > 0 && (char.IsLetterOrDigit(source[start - 1]) || source[start - 1] == '_'))
        {
            start--;
        }

        return source[start..end];
    }

    // The text between the parenthesis at openIndex and its match, string and char literals skipped so a
    // parenthesis inside one cannot close the call early. Null when the parentheses are unbalanced.
    private static string? BalancedArguments(string source, int openIndex)
    {
        var depth = 0;
        for (var i = openIndex; i < source.Length; i++)
        {
            var c = source[i];
            if (c is '"' or '\'')
            {
                i = SkipLiteral(source, i);
                continue;
            }

            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
                if (depth == 0)
                {
                    return source[(openIndex + 1)..i];
                }
            }
        }

        return null;
    }

    // Whether an argument list holds more than one argument - a comma outside any nested call, collection or
    // literal. This is what "the lookup carries its namespace argument" reduces to.
    private static bool HasTopLevelComma(string arguments)
    {
        var depth = 0;
        for (var i = 0; i < arguments.Length; i++)
        {
            var c = arguments[i];
            if (c is '"' or '\'')
            {
                i = SkipLiteral(arguments, i);
            }
            else if (c is '(' or '[' or '{')
            {
                depth++;
            }
            else if (c is ')' or ']' or '}')
            {
                // Angle brackets are deliberately not counted: '<' and '>' are ambiguous between generic
                // arguments and comparison/lambda operators, and mis-tracking them would corrupt the depth.
                depth--;
            }
            else if (c == ',' && depth == 0)
            {
                return true;
            }
        }

        return false;
    }

    // The index of the closing quote of the literal starting at start, escapes honoured.
    private static int SkipLiteral(string text, int start)
    {
        var quote = text[start];
        for (var i = start + 1; i < text.Length; i++)
        {
            if (text[i] == '\\')
            {
                i++;
            }
            else if (text[i] == quote)
            {
                return i;
            }
        }

        return text.Length - 1;
    }

    // Whether the call at index sits on a line whose code has already been commented out - the argument-level
    // scan reads the whole file, so it needs the same comment exclusion CodeLines applies. The two cannot be
    // the same function: this one judges the text AHEAD OF a call index, which is what lets it decide about a
    // call sitting part-way along a line, where CodeLinesOf judges a whole trimmed line. They share the form
    // list instead, so the parity this comment claims is a call and not a coincidence.
    private static bool IsOnACommentLine(string source, int index)
    {
        var lineStart = source.LastIndexOf('\n', Math.Min(index, source.Length - 1)) + 1;
        return OpensAComment(source[lineStart..index].TrimStart());
    }
}
