// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Newtonsoft.Json;

namespace Jellyfin.Plugin.SSO_Auth.Fuzz;

/// <summary>
/// Differential driver for the repeated-member walk (#1188). It generates discovery-shaped documents and
/// asks two independently written readers the same question - does any object scope name a member twice -
/// then reports every case where they answer differently.
///
/// Why a second reader rather than a table of expected verdicts. A fixture table only ever covers the
/// documents somebody thought of, and the walk's whole job is to hold on documents nobody thought of. The
/// reference here is Newtonsoft's <see cref="JsonTextReader"/>: a different parser family from the
/// <c>Utf8JsonReader</c> the walk is built on, already in this project's dependency graph, and the reader
/// whose measured behaviour - it drops one occurrence at parse time - is half of why the walk exists. Two
/// tokenizers written by different people agreeing about a document is evidence about the document;
/// one tokenizer agreeing with a list of expectations is evidence about the list.
///
/// It is NOT coverage-guided and does not need libFuzzer, so it runs anywhere the harness builds - which is
/// what makes it re-runnable on my Windows box rather than only in the Linux weekly job.
///
/// Triage rule, inherited from the harness README and not softened here: a divergence is a FINDING. It is
/// reported, with the document that produced it, and it is filed - never patched away inside this driver.
/// </summary>
internal static class DiscoveryDifferential
{
    // Deliberately tiny, so a four-member object collides often. A large name pool would make the generator
    // spend fifty thousand cases proving that documents with no repeats have no repeats, which measures the
    // generator rather than the walk.
    //
    // The last two entries spell "a" and "issuer" with a \u escape. They are the same NAMES as the plain
    // spellings above them, so a walk that compared raw bytes instead of unescaped names would call the pair
    // clean while the reference reader calls it a repeat - the divergence this pool exists to reach.
    private static readonly string[] MemberNames =
    {
        "a",
        "b",
        "issuer",
        "jwks_uri",
        string.Empty,
        "\\u0061",
        "iss\\u0075er",
    };

    // A member name carrying an unpaired surrogate escape: thirteen bytes both parser families read without
    // complaint, and the input that makes System.Text.Json's GetString throw where Newtonsoft hands back the
    // lone surrogate. Generated at a low rate rather than never, so the run keeps meeting the arm the corpus
    // seed pins, and rather than often, so it does not crowd out the comparable cases.
    private const string LoneSurrogateName = "a\\ud800";

    /// <summary>
    /// Runs the differential and reports the counts.
    /// </summary>
    /// <param name="args">Optional single argument: the corpus directory replayed ahead of the generated cases.</param>
    /// <returns>0 when the readers never disagreed and the run was non-vacuous; 1 on a divergence; 3 on a vacuous run.</returns>
    internal static int Run(string[] args)
    {
        var cases = ReadCount("SSO_FUZZ_CASES", 50_000);
        var seed = ReadCount("SSO_FUZZ_SEED", 1188);
        var corpus = args.Length > 0
            ? args[0]
            : Environment.GetEnvironmentVariable("SSO_FUZZ_CORPUS") ?? Path.Combine("corpus", "discovery");

        var tally = new Tally();
        var samples = new List<string>();

        // The committed corpus runs FIRST and is part of the case count. #1188 asks for the run to be seeded
        // with the thirteen-byte lone-surrogate document specifically; reading the directory rather than
        // naming that file keeps every seed a later issue adds in the run by the fact of being committed.
        var seeds = 0;
        if (Directory.Exists(corpus))
        {
            foreach (var file in Directory.EnumerateFiles(corpus))
            {
                Compare(File.ReadAllText(file), tally, samples);
                seeds++;
            }
        }
        else
        {
            Console.Error.WriteLine($"Corpus directory not found: {corpus}");
            return 2;
        }

        var random = new Random(seed);
        for (var i = 0; i < cases; i++)
        {
            Compare(Generate(random), tally, samples);
        }

        Console.WriteLine(Line($"Differential over {seeds} committed seed(s) + {cases} generated case(s), seed={seed}."));
        Console.WriteLine(Line($"  agreed, no repeat      : {tally.AgreedClean}"));
        Console.WriteLine(Line($"  agreed, repeat         : {tally.AgreedRepeated}"));
        Console.WriteLine(Line($"  walk refused, ref read : {tally.RefusedWhileReferenceRead}"));
        Console.WriteLine(Line($"  not comparable         : {tally.NotComparable}"));
        Console.WriteLine(Line($"  DIVERGENCES            : {tally.Divergences} (first {samples.Count} shown)"));

        foreach (var sample in samples)
        {
            Console.Error.WriteLine($"::divergence:: {sample}");
        }

        if (tally.Divergences > 0)
        {
            Console.Error.WriteLine(
                "A divergence is a finding: file it with the document above, do not patch this driver.");
            return 1;
        }

        // Sentinel against a vacuous pass. A walk that answered Unreadable to every document, or a generator
        // that stopped producing repeats, would report zero divergences and look identical to a clean run.
        // Both directions of agreement have to have been reached for the zero to mean anything.
        if (tally.AgreedClean == 0 || tally.AgreedRepeated == 0)
        {
            Console.Error.WriteLine(
                "Vacuous run: the two readers never agreed in both directions, so zero divergences establishes nothing.");
            return 3;
        }

        Console.WriteLine("No divergence between the walk and the reference reader.");
        return 0;
    }

    // The two answers, and the three ways they can fail to be a straight comparison.
    private sealed class Tally
    {
        internal int AgreedClean { get; set; }

        internal int AgreedRepeated { get; set; }

        // The walk established nothing about a document the reference read to the end. It refuses, so this is
        // never an accept defect - but it is counted rather than folded into agreement, because a walk that
        // drifted into refusing everything would otherwise read as perfect agreement.
        internal int RefusedWhileReferenceRead { get; set; }

        // The reference could not read the document, so it has no duplicate-key outcome to compare against.
        internal int NotComparable { get; set; }

        // Every disagreement, not just the ones that fitted in the printed sample. Counted separately
        // because the sample list is capped: an earlier version printed the list's length as the total and
        // reported twenty against a weakened walk that had actually diverged on thousands of documents.
        internal int Divergences { get; set; }
    }

    private static void Compare(string json, Tally tally, List<string> samples)
    {
        var verdict = StrictJson.Inspect(json, out _);
        var reference = ReferenceSeesRepeat(json);

        if (reference is null)
        {
            tally.NotComparable++;
            return;
        }

        if (verdict == StrictJson.Verdict.Unreadable)
        {
            tally.RefusedWhileReferenceRead++;
            return;
        }

        var walkSawRepeat = verdict == StrictJson.Verdict.Repeated;
        if (walkSawRepeat == reference.Value)
        {
            if (walkSawRepeat)
            {
                tally.AgreedRepeated++;
            }
            else
            {
                tally.AgreedClean++;
            }

            return;
        }

        tally.Divergences++;

        // The printed sample is bounded, so one systematically divergent shape cannot turn the report into a
        // data dump nobody reads. The COUNT above is unbounded and is the number to quote.
        if (samples.Count < 20)
        {
            samples.Add(
                Line($"walk={verdict} reference={(reference.Value ? "repeat" : "no repeat")} document={Escape(json)}"));
        }
    }

    private static string Line(FormattableString text) => FormattableString.Invariant(text);

    // The reference answer: does any object scope name a member twice, as a second parser family sees it.
    // Null means the reference could not read the document to the end, so it has no answer to compare.
    private static bool? ReferenceSeesRepeat(string json)
    {
        try
        {
            using var reader = new JsonTextReader(new StringReader(json))
            {
                // Values are irrelevant here and date coercion is one more way the two readers could differ
                // for a reason that has nothing to do with member names.
                DateParseHandling = DateParseHandling.None,
            };

            var scopes = new Stack<HashSet<string>>();
            var repeated = false;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonToken.StartObject:
                        scopes.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;

                    case JsonToken.EndObject:
                        scopes.Pop();
                        break;

                    case JsonToken.PropertyName:
                        if (!scopes.Peek().Add(reader.Value as string ?? string.Empty))
                        {
                            repeated = true;
                        }

                        break;

                    default:
                        break;
                }
            }

            return repeated;
        }
        catch (JsonReaderException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            // An unbalanced scope on a document the reader accepted far enough to hand out an EndObject it
            // has no StartObject for. Nothing was established, same as a read failure.
            return null;
        }
    }

    // Builds one document. Discovery-shaped rather than arbitrary bytes: the walk is only ever handed a body
    // a provider served as its well-known document or its key set, and the interesting structure there is
    // nesting - a repeat two scopes down is the case an indexed-members walk missed and this one must not.
    private static string Generate(Random random)
    {
        var text = new StringBuilder();

        // The root is an object nine times in ten, because that is what a well-known document and a key set
        // are. Rooting at an arbitrary value instead measured the wrong thing: a well-formed array of
        // scalars carries no object scope, so the walk correctly establishes nothing about it, and a first
        // version of this generator spent two thirds of the run on documents that could not disagree. The
        // remaining tenth keeps the other root shapes in the run rather than assuming they never arrive.
        if (random.Next(10) == 0)
        {
            WriteValue(random, text, depth: 0);
        }
        else
        {
            WriteObject(random, text, depth: 0);
        }

        var document = text.ToString();

        // A share of the run is deliberately malformed. Truncation is what a provider serving a body over a
        // dropped connection produces, and it exercises the arm where neither reader establishes anything.
        var mangle = random.Next(100);
        if (mangle < 5 && document.Length > 2)
        {
            return document.Substring(0, random.Next(1, document.Length));
        }

        if (mangle < 8)
        {
            var at = random.Next(document.Length + 1);
            return string.Concat(document.AsSpan(0, at), "\"", document.AsSpan(at));
        }

        return document;
    }

    private static void WriteValue(Random random, StringBuilder text, int depth)
    {
        // Four levels is past the two the real documents use and past the depth an indexed-members walk could
        // see, while staying well clear of the reader's depth cap - which is a different property, pinned
        // elsewhere, and not what this run is measuring.
        var choice = depth >= 4 ? random.Next(3, 7) : random.Next(7);
        switch (choice)
        {
            case 0:
                WriteObject(random, text, depth);
                break;

            case 1:
                WriteArray(random, text, depth);
                break;

            case 2:
                WriteObject(random, text, depth);
                break;

            case 3:
                text.Append(CultureInfo.InvariantCulture, $"{random.Next(-1000, 1000)}");
                break;

            case 4:
                text.Append("\"https://idp.example.com/").Append(random.Next(10)).Append('"');
                break;

            case 5:
                text.Append(random.Next(2) == 0 ? "true" : "false");
                break;

            default:
                text.Append("null");
                break;
        }
    }

    private static void WriteObject(Random random, StringBuilder text, int depth)
    {
        var members = random.Next(5);
        text.Append('{');
        for (var i = 0; i < members; i++)
        {
            if (i > 0)
            {
                text.Append(',');
            }

            // Two per hundred members carry the unpaired surrogate escape, which is the name System.Text.Json
            // refuses to decode and Newtonsoft hands back intact.
            var name = random.Next(100) < 2 ? LoneSurrogateName : MemberNames[random.Next(MemberNames.Length)];
            text.Append('"').Append(name).Append("\":");
            WriteValue(random, text, depth + 1);
        }

        text.Append('}');
    }

    private static void WriteArray(Random random, StringBuilder text, int depth)
    {
        var elements = random.Next(4);
        text.Append('[');
        for (var i = 0; i < elements; i++)
        {
            if (i > 0)
            {
                text.Append(',');
            }

            WriteValue(random, text, depth + 1);
        }

        text.Append(']');
    }

    private static int ReadCount(string variable, int fallback)
    {
        var raw = Environment.GetEnvironmentVariable(variable);
        return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value > 0
            ? value
            : fallback;
    }

    // A divergent document is printed, so it is bounded and its line endings are stripped here at the write
    // rather than in a helper - the same rule the plugin's own log calls follow.
    private static string Escape(string json)
    {
        var trimmed = json.Length > 400 ? json.Substring(0, 400) + "[truncated]" : json;
        return trimmed.ReplaceLineEndings(string.Empty);
    }
}
