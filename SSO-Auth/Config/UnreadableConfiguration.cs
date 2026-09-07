// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What one read of the stored file said (#1543): whether it came back at all, and whether what came
/// back is a configuration somebody put there rather than the empty default the host writes.
/// </summary>
/// <param name="Readable">Whether the file yielded a configuration.</param>
/// <param name="HoldsAProvider">Whether that configuration holds at least one provider, which is what makes it somebody's rather than a default.</param>
/// <param name="Judged">
/// Whether the read happened at all. False is the third answer, and it is a THIRD VALUE rather than a
/// shading of the other two: an undecidable read was once written as the same pair as "read back, holds
/// nothing", which is the host's own empty default - so on the one boot where a marker was already there,
/// the answer that was supposed to decide nothing decided the refusal.
/// </param>
internal readonly record struct Restored(bool Readable, bool HoldsAProvider, bool Judged)
{
    /// <summary>
    /// Gets the answer for a file that is not there: nothing to preserve, and a first start rather than
    /// damage. It is not "nothing to refuse", and the difference is a marker: a file that is GONE while an
    /// unrepaired incident is recorded is still a server about to serve defaults, so the carried-over arm
    /// judges it like any other file that holds no provider. An operator who followed the break-glass
    /// instruction moves the file aside AND deletes the marker; doing half of it leaves the state standing,
    /// which is the honest answer rather than a hole.
    /// </summary>
    internal static Restored Nothing => new(true, false, true);

    /// <summary>Gets the answer for a read that could not be made at all, which decides nothing.</summary>
    internal static Restored Unknown => new(false, false, false);

    /// <summary>Gets the answer for a file that is there and does not come back.</summary>
    internal static Restored Damaged => new(false, false, true);
}

/// <summary>
/// Whether the stored configuration could be read at start, and where the damaged file was kept (#1543).
/// </summary>
/// <remarks>
/// The default value is the healthy one: a configuration that read back, and a first start with no file at
/// all, are both <c>IsUnreadable = false</c>. So a caller that forgets to assign this serves logins, which
/// is the right direction for a flag whose true value takes SSO offline.
/// </remarks>
/// <param name="IsUnreadable">Whether the stored configuration failed to deserialize, so the host is about to serve defaults over it.</param>
/// <param name="PreservedCopyPath">
/// Where the damaged file was copied, or <see langword="null"/> - when the copy could not be written, when
/// the marker records none, or when the one it records is no longer there. Null does NOT weaken
/// <paramref name="IsUnreadable"/>: what is uncertain is the evidence, not the refusal. Read by the log
/// lines and by the tests; the plugin itself acts on <paramref name="IsUnreadable"/> alone.
/// </param>
internal readonly record struct UnreadableConfigurationState(bool IsUnreadable, string? PreservedCopyPath);

/// <summary>
/// Keeps the evidence when <c>SSO-Auth.xml</c> cannot be read, and says so (#1543).
/// </summary>
/// <remarks>
/// <para>
/// WHAT THE HOST DOES, MEASURED RATHER THAN REASONED. <c>BasePlugin&lt;T&gt;.LoadConfiguration</c> catches
/// every exception, builds a default configuration and WRITES IT BACK over the file. So a damaged
/// <c>SSO-Auth.xml</c> - a write truncated by a full disk, a filesystem corruption, an interrupted restore,
/// a hand edit - is replaced by defaults on the next start, and the only artefact a repair could have
/// worked on is overwritten in the same act. Every provider, every canonical link and every at-rest secret
/// envelope goes with it.
/// </para>
/// <para>
/// WHY A WINDOW EXISTS AT ALL. The host's load is LAZY: after the plugin's constructor returns, the
/// serializer has been asked for nothing and the damaged file is byte-for-byte intact - the destruction
/// happens on the FIRST read of <c>Configuration</c>. That window belongs to this plugin, and this is what
/// it is spent on. The check is the plugin's own and touches no base-class member: it reads the file
/// itself, so nothing here can trigger the load it exists to get ahead of.
/// </para>
/// <para>
/// A write-side rename would not reach this. That repair publishes a complete file or none, which stops
/// the truncation - and leaves the load side exactly as it is for every other cause of an unreadable file
/// (#1532). The destructive act is the host's, on load, and no write-side change touches it.
/// </para>
/// </remarks>
internal static class UnreadableConfiguration
{
    /// <summary>The suffix a preserved copy is named with, before its UTC timestamp.</summary>
    internal const string CopySuffix = ".unreadable-";

    /// <summary>
    /// The suffix of the marker that keeps the state across a restart. Its own file rather than a flag in
    /// the configuration, because the configuration is the thing that was lost.
    /// </summary>
    internal const string MarkerSuffix = ".unreadable";

    // The two records the marker carries under its sentence, so the next boot can tell a restart of THIS
    // incident from a new one and can name the copy this incident actually produced.
    private const string IncidentPrefix = "Damaged-file: ";
    private const string CopyPrefix = "Kept-copy: ";

    // How many taken copy names one boot walks past before it gives up and lets File.Copy refuse. It is a
    // bound rather than a capacity: a boot needs a free name at most once, and reaching this many means a
    // clock that does not advance, which is a fault of its own rather than a directory to fill.
    private const int CopyNameLimit = 100;

    /// <summary>
    /// Screens the stored configuration before anything reads it, keeps the evidence when it cannot be
    /// read, and answers whether this server is about to serve defaults.
    /// </summary>
    /// <remarks>
    /// THREE ANSWERS, NOT TWO, and the third is the one a fail-closed reading gets wrong. A file that
    /// deserializes is healthy. A file that fails to deserialize for a reason about its CONTENT is damage.
    /// A file that could not be READ AT ALL - locked by a virus scanner, a backup agent or a sync client at
    /// exactly the moment plugins load, an IO error on the volume - is neither: this check could not run,
    /// and the host's own read a moment later may well succeed. Latching the refusal on that would take SSO
    /// offline permanently on a server whose configuration is perfectly good and is live in memory, with a
    /// log line that is false in both halves, until somebody notices and presses Save. The refusal is
    /// worth having against real damage and is not worth that, so an IO failure says so and changes
    /// nothing - which leaves the behaviour exactly where it stood before this check existed.
    /// </remarks>
    /// <remarks>
    /// IT SURVIVES A RESTART, and it has to. By the next boot the host has already replaced the damaged
    /// file with a readable default, so the screen alone would report healthy - no banner, no line, no
    /// refusal - and every SSO sign-in would go back to answering that the provider is unknown, which is
    /// the confusion this exists to end. Restarting is also the first thing an operator does when told SSO
    /// is down. So a marker file is written beside the copy and outlives the process; only an administrator
    /// supplying a configuration removes it, and it is a marker rather than the copy, so the evidence is
    /// never what gets deleted.
    /// </remarks>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="serializer">The host's XML serializer, asked the same question the host will ask it.</param>
    /// <param name="logger">The logger the refusal is announced on.</param>
    /// <param name="nowUtc">The instant a copy is named after.</param>
    /// <returns>The screened state: unreadable or not, and where the damaged file was kept.</returns>
    internal static UnreadableConfigurationState Preserve(string? configurationFilePath, IXmlSerializer serializer, ILogger logger, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(serializer);

        if (string.IsNullOrWhiteSpace(configurationFilePath))
        {
            return default;
        }

        // No file at all is a first start: nothing to preserve and nothing to refuse. Treating it as damage
        // would take every new installation offline before it was ever configured.
        var stored = File.Exists(configurationFilePath) ? ReadsBack(configurationFilePath, serializer, logger) : Restored.Nothing;

        // A READ THAT DID NOT HAPPEN DECIDES NOTHING, AND THAT HAS TO INCLUDE THE MARKER ARM. Returning
        // here rather than falling into the carried-over branch is the whole of it: that branch asks
        // whether the file holds a provider, an undecidable read holds no answer to that question, and
        // answering "no" for it turns the marker of a PAST incident into a refusal on the present boot.
        // The boot that costs is the one this feature's own recovery story ends on - restore the file,
        // restart - where the marker is by construction still there and the agents most likely to have
        // the file open for a moment are the backup and scanning ones a restore just woke up. So a
        // momentary lock would take every SSO sign-in on a fully repaired server offline for the life of
        // the process. The marker and the copies are left exactly as they are, so the next boot judges
        // the same file again with nothing lost.
        if (!stored.Judged)
        {
            return default;
        }

        if (stored.Readable)
        {
            return CarriedOver(configurationFilePath, stored.HoldsAProvider, logger);
        }

        // One copy per INCIDENT, and the marker has to say WHICH incident rather than merely that one
        // happened. Keying the dedup on the marker's existence alone reads a stale marker - one whose
        // delete failed after a repair - as this incident, so a second, unrelated damage months later is
        // never copied at all while the log names the first incident's file as "the only surviving copy
        // of your providers, links and secrets". Both halves of that sentence are then wrong, and the
        // bytes the whole screen exists to keep are gone.
        //
        // What separates the two is the damaged file itself: a boot loop re-reads the SAME bytes, and a
        // new incident is a different file. So the marker carries the file's length and last-write
        // instant, and a copy is reused only when the file it was taken from is the file being looked at
        // now. An identity that cannot be read decides "new incident", which costs one extra copy and
        // never costs the evidence.
        var incident = IncidentOf(configurationFilePath);
        var carried = ReadMarker(configurationFilePath);

        // Read once for the whole boot: the record's check below and the directory walk beneath Copy ask
        // the same question of the same bytes, and reading them twice is also two chances to disagree
        // about a file something else is rewriting.
        var damagedBytes = ReadAllBytesOrNull(configurationFilePath);

        var sameIncident = incident is not null
            && carried?.Incident is { } previous
            && string.Equals(previous, incident, StringComparison.Ordinal);
        // THE RECORD BELONGS TO ITS OWN INCIDENT AND INHERITS NOTHING. Carrying a previous incident's copy
        // name into this incident's marker looks tidy and does two harmful things at once: it names a
        // months-old file holding different providers as this incident's kept copy, and - because a copy
        // that is already "kept" is never taken again - it suppresses the retry on the next boot, so a new
        // incident whose first copy attempt failed is NEVER preserved. That is the evidence this whole
        // screen exists for, lost to a bookkeeping convenience.
        //
        // THE RECORD MAY NOT OUTRANK THE BYTES, and until the twelfth review of this branch it did. `Kept`
        // proves the recorded copy still EXISTS and nothing else, and existence is the wrong question: a
        // copy an operator opened and saved over - the repair loop the log itself invites - still exists
        // and no longer holds the damage, and a copy emptied by the same volume that produced the damage
        // still exists too. On that boot the copy was reused, no second one was taken, and the line an
        // operator reads said the bytes had been kept. So the record's answer is verified against the
        // bytes here, which is the test AlreadyCopied makes one call deeper - and it is asked HERE rather
        // than left to that scan because reading one named file needs no directory listing, so the bound
        // survives a directory this plugin may write but may not enumerate.
        //
        // AND A COMPARISON THAT COULD NOT BE MADE DECIDES NOTHING, which is the rule Restored.Judged
        // already states one level up and which the first form of this gate did not apply. Collapsing
        // "the recorded copy does not hold the damage" and "the damage could not be read at all" into one
        // false answer took the bound off entirely for a file no managed array can hold - past two
        // gigabytes, or merely past the largest block a small host can allocate - because File.Copy
        // streams where File.ReadAllBytes does not: three boots wrote three full copies where one had
        // been written before, onto the volume whose exhaustion is this feature's own premise. Worse, the
        // marker was then rewritten with an empty copy line, so the next boot told the operator that
        // nothing had been kept while the copies sat beside the configuration. An unreadable file falls
        // back to the record, which is what the parent did for every file.
        var preserved = sameIncident && carried?.Kept is { } kept
                && (damagedBytes is null || HoldsTheSameBytes(damagedBytes, kept))
            ? kept
            : Copy(configurationFilePath, damagedBytes, nowUtc, logger);
        Mark(configurationFilePath, incident, preserved, logger);
        Announce(() => SsoAudit.UnreadableConfigurationFound(logger, configurationFilePath, preserved));
        return new UnreadableConfigurationState(true, preserved);
    }

    /// <summary>
    /// Removes the marker, so a server that has been given a configuration stops serving defaults across
    /// restarts too (#1543). The preserved copies are deliberately left where they are: they are the
    /// evidence, and an operator may not have looked at them yet.
    /// </summary>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="logger">The logger a failure to remove it is reported on.</param>
    internal static void ClearMarker(string? configurationFilePath, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(configurationFilePath))
        {
            return;
        }

        try
        {
            File.Delete(configurationFilePath + MarkerSuffix);
        }
#pragma warning disable CA1031 // a marker that cannot be removed must not turn a successful save into a failure
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Announce(() => SsoAudit.UnreadableConfigurationMarkerNotCleared(logger, configurationFilePath + MarkerSuffix, ex));
        }
    }

    // The state a previous boot left behind, judged against what the file now holds.
    //
    // A file that reads back is not yet a repair: the host replaces a damaged one with a DEFAULT, which
    // parses perfectly and holds nothing, so the marker has to be believed over the mere fact that it
    // parses. A file that reads back AND holds a provider is a different thing entirely - somebody put the
    // configuration back, and the two ways they will actually do it are restoring the backup over the file
    // and copying it in from elsewhere, neither of which is a write this plugin ever sees. Refusing on
    // through those would leave a server whose providers, links and secrets are all correct and live
    // answering 503 to every sign-in for good, with the log telling the operator that no configuration had
    // been supplied - and on a server whose administrators all arrived through SSO, nobody to fix it.
    private static UnreadableConfigurationState CarriedOver(string configurationFilePath, bool holdsAProvider, ILogger logger)
    {
        if (!MarkerExists(configurationFilePath))
        {
            return default;
        }

        if (holdsAProvider)
        {
            ClearMarker(configurationFilePath, logger);
            Announce(() => SsoAudit.UnreadableConfigurationRepairedOnDisk(logger, configurationFilePath));
            return default;
        }

        // THE MARKER'S OWN RECORD AND NOTHING ELSE. A copy that could not be written - the full disk this
        // area is about, one step further along - leaves a marker naming no copy, and the answer to that
        // is null. Searching the directory instead finds whatever is lying there, which after an earlier,
        // repaired incident is a months-old file holding different providers, different links and
        // different secret envelopes; naming it as the copy kept for THIS damage is the both-halves-false
        // sentence this record exists to remove. Null here means one of two things - the marker records no
        // copy, or the one it records is no longer beside the configuration because somebody moved it to
        // look at it, which the log invites - and the line says exactly that rather than picking one of
        // them, because nothing here can tell them apart.
        var preserved = ReadMarker(configurationFilePath)?.Kept;
        Announce(() => SsoAudit.UnreadableConfigurationStillUnrepaired(logger, configurationFilePath, preserved));
        return new UnreadableConfigurationState(true, preserved);
    }

    // Copies the damaged file aside, never over an existing name. A copy that cannot be written is reported
    // and does not soften the refusal: the state is unreadable either way, and losing the evidence is the
    // worse outcome rather than a reason to serve logins as though nothing had happened.
    //
    // THE BOUND IS THE BYTES, NOT A DECISION. The marker's record deduplicates a boot loop, and it is
    // itself a file that can be locked or refused - and the causes that stop it being read are the causes
    // that stop it being deleted, so a stale marker and an unreadable one are one fault rather than two
    // coincidences. Declining to copy when the marker cannot be read bounds the loop by throwing away the
    // evidence of whatever incident is actually happening, which inverts this module's whole priority. So
    // the bound is asked of the copies themselves instead: a copy already beside the configuration holding
    // exactly these bytes IS this incident's copy, whoever wrote it and whatever any record says, and a
    // second one would be the same file under another name. That answer needs no marker, cannot be wrong
    // about a NEW incident - different bytes, different answer - and costs one read of a file that is
    // small enough for the plugin to deserialize.
    private static string? Copy(string configurationFilePath, byte[]? damagedBytes, DateTime nowUtc, ILogger logger)
    {
        if (AlreadyCopied(configurationFilePath, damagedBytes) is { } existing)
        {
            return existing;
        }

        var copy = FreeCopyName(configurationFilePath, nowUtc);
        try
        {
            File.Copy(configurationFilePath, copy, overwrite: false);
            return copy;
        }
#pragma warning disable CA1031 // the state is unreadable whether or not the copy succeeded, and saying so is what matters
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Announce(() => SsoAudit.UnreadableConfigurationNotPreserved(logger, copy, ex));
            return null;
        }
    }

    // The first copy name beside the configuration that nothing occupies.
    //
    // AN OCCUPIED NAME IS A DIFFERENT INCIDENT'S FILE, AND ABANDONING THE COPY FOR IT LOST THE EVIDENCE.
    // AlreadyCopied has already said that nothing beside the configuration holds these bytes, so a name
    // this second happens to collide with belongs to another fault - a host that repeats a wall-clock
    // second across boots because it has no persisted clock, a snapshot restored again and again, a second
    // instance on the same volume. The old code composed one name, met `overwrite: false`, and returned
    // null: the host then wrote defaults over the configuration and no later boot reached this arm again,
    // because by then the file reads back. So the name is disambiguated rather than the copy dropped, and
    // nothing existing is ever overwritten, which is the rule that made the collision possible.
    //
    // The walk is bounded, and the bound fails towards the rule rather than around it: after CopyNameLimit
    // taken names the stamped name is handed back as it stands, File.Copy refuses it, and the failure is
    // reported as a copy that could not be written.
    private static string FreeCopyName(string configurationFilePath, DateTime nowUtc)
    {
        var stem = configurationFilePath + CopySuffix + nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z";
        var name = stem;
        for (var attempt = 1; attempt <= CopyNameLimit && File.Exists(name); attempt++)
        {
            name = string.Create(CultureInfo.InvariantCulture, $"{stem}.{attempt}");
        }

        return name;
    }

    // Whether the file at candidate holds exactly the damaged configuration's bytes. One name, asked by
    // both the marker's recorded copy and the directory walk, so "already kept" means one thing here.
    //
    // Not being able to answer - the candidate locked, gone, or larger than an array - is answered as
    // "no", which costs a copy and never the evidence. A LINK IS NOT A COPY: FileInfo.Length and
    // File.ReadAllBytes both follow one, so a link left beside the configuration and pointing back at it
    // would compare equal to the damage, suppress the copy, and then resolve to the defaults the host
    // writes a moment later.
    private static bool HoldsTheSameBytes(byte[] damaged, string candidate)
    {
        try
        {
            var kept = new FileInfo(candidate);
            return kept.LinkTarget is null
                && kept.Length == damaged.LongLength
                && File.ReadAllBytes(candidate).AsSpan().SequenceEqual(damaged);
        }
#pragma warning disable CA1031 // a comparison that cannot be made is answered as "not the same", which costs a copy
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }

    private static byte[]? ReadAllBytesOrNull(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
#pragma warning disable CA1031 // bytes that cannot be read decide nothing here; the caller answers "not the same"
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    // Says a thing, and never at the cost of the decision that produced it.
    //
    // EVERY AUDIT CALL IN THIS FILE RUNS IN A PLUGIN CONSTRUCTOR, after the screen has already decided,
    // copied and marked. The one failure that reaches one is a logger that throws, which is the same full
    // disk that damaged the configuration taking the file sink down with it - the trigger the constructor's
    // own comment names. Letting it escape hands that constructor's catch a screen that DID run, and its
    // answer there is "not unreadable": a decided, already-marked refusal becomes a server that accepts
    // every SSO sign-in and answers "no matching provider" for the life of the process, while the marker
    // on disk says the opposite and the next boot refuses again. That is a fail-OPEN on a control whose
    // whole posture is fail-closed, so the announcement is contained where it is made.
    private static void Announce(Action say)
    {
        try
        {
            say();
        }
#pragma warning disable CA1031, RCS1075 // an announcement that cannot be made costs the line and never the decision
        catch (Exception)
#pragma warning restore CA1031, RCS1075
        {
        }
    }

    // The damaged file's identity, as the two facts a boot can read without opening it: how long it is and
    // when it was last written. A boot loop meets the same pair; a new incident does not. Null when the
    // file cannot be stat'ed at all, which is read as a new incident.
    private static string? IncidentOf(string configurationFilePath)
    {
        try
        {
            var file = new FileInfo(configurationFilePath);
            return string.Create(CultureInfo.InvariantCulture, $"{file.Length}:{file.LastWriteTimeUtc.Ticks}");
        }
#pragma warning disable CA1031 // an identity that cannot be read is answered as a new incident, which costs a copy and never the evidence
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    private static Marker? ReadMarker(string configurationFilePath)
    {
        try
        {
            if (!File.Exists(configurationFilePath + MarkerSuffix))
            {
                return null;
            }

            string? incident = null;
            string? copy = null;
            foreach (var line in File.ReadAllLines(configurationFilePath + MarkerSuffix))
            {
                if (line.StartsWith(IncidentPrefix, StringComparison.Ordinal))
                {
                    incident = line[IncidentPrefix.Length..];
                }
                else if (line.StartsWith(CopyPrefix, StringComparison.Ordinal) && line.Length > CopyPrefix.Length)
                {
                    copy = line[CopyPrefix.Length..];
                }
            }

            return new Marker(incident, copy);
        }
#pragma warning disable CA1031 // a marker that cannot be read is the same answer as one that records nothing
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    // A copy already beside the configuration whose bytes are exactly the damaged file's, or null. Length
    // first, because it settles almost every pair without a read, and the read that follows is of a file
    // this plugin was about to hand to an XML deserializer. Not being able to look is answered as "no
    // copy", which costs one more copy and never the evidence.
    private static string? AlreadyCopied(string configurationFilePath, byte[]? damagedBytes)
    {
        if (damagedBytes is null)
        {
            return null;
        }

        string[] candidates;
        try
        {
            var directory = Path.GetDirectoryName(configurationFilePath);
            if (string.IsNullOrEmpty(directory))
            {
                return null;
            }

            candidates = Directory.GetFiles(directory, Path.GetFileName(configurationFilePath) + CopySuffix + "*");
        }
#pragma warning disable CA1031 // not being able to look at all is the same answer as there being no copy, which costs one copy
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }

        foreach (var candidate in candidates)
        {
            // PER CANDIDATE, AND THAT IS THE WHOLE OF THE BOUND. One try around the entire walk abandoned
            // every candidate after the first that could not be read, and the candidate guaranteed to
            // reach the read is this incident's OWN copy, because a genuine copy has the damaged file's
            // length by construction. So a single further fault - an ACL a restore left behind, a bad
            // block on the disk that caused the damage, an agent holding the file open - answered "no
            // copy" for the whole directory, and every later boot wrote another full copy of the
            // configuration into the folder the whole server needs writable. That is the unbounded loop
            // this method was added to stop, reachable again through one extra fault.
            if (HoldsTheSameBytes(damagedBytes, candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    // Writes the marker that outlives the process. A marker that cannot be written costs the state its
    // survival across a restart and nothing else, so it is reported rather than thrown - this runs in a
    // plugin constructor, and a server that cannot start is a worse answer than one that forgets.
    // The sentence stays first, because an operator who opens this file is reading it rather than parsing
    // it; the two records below it are for the next boot.
    private static void Mark(string configurationFilePath, string? incident, string? preservedCopyPath, ILogger logger)
    {
        try
        {
            var text = "This server could not read its SSO configuration and is serving defaults. Save or import a configuration holding at least one provider to clear this. To clear it by hand instead, move the unreadable configuration file out of the way AND delete this file, then restart - deleting this file alone re-arms the refusal on the next start if the configuration file is still unreadable. The timestamped files beside it are the copies that were kept."
                + Environment.NewLine + IncidentPrefix + (incident ?? string.Empty)
                + Environment.NewLine + CopyPrefix + (preservedCopyPath ?? string.Empty);
            File.WriteAllText(configurationFilePath + MarkerSuffix, text);
        }
#pragma warning disable CA1031 // a marker that cannot be written costs only its survival across a restart
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Announce(() => SsoAudit.UnreadableConfigurationMarkerNotWritten(logger, configurationFilePath + MarkerSuffix, ex));
        }
    }

    private static bool MarkerExists(string configurationFilePath)
    {
        try
        {
            return File.Exists(configurationFilePath + MarkerSuffix);
        }
#pragma warning disable CA1031 // not being able to look is the same answer as there being no marker
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }

    // Whether the host serializer can turn the stored bytes back into this plugin configuration type. A
    // failure ABOUT THE CONTENT is the condition being detected: the host catches it, hands out defaults and
    // persists them over the file, whatever its type. A deserialize that RETURNS null is judged the same
    // way here and is not the same host outcome - the host would hand out a null configuration and write
    // nothing - so this arm is a deliberate widening rather than an equivalence, taken because a plugin
    // asked for a configuration and given null is a server that cannot answer either way. An IO failure is not that: it means this check could not read the bytes
    // at all, the host's own read may still succeed, and latching a permanent refusal on a file somebody
    // else had open for a moment is a worse failure than the one being guarded. It says so and reports
    // readable, which leaves the server exactly where it stood before this check existed.
    private static Restored ReadsBack(string configurationFilePath, IXmlSerializer serializer, ILogger logger)
    {
        try
        {
            // NULL-TOLERANT ON BOTH MAPS, and it is not politeness. These two reads are inside the try
            // whose catch means "the file's CONTENT is damaged", so a null map here would be reported as a
            // damaged configuration on a file the host reads back perfectly - and because the host never
            // touches these members it never rewrites the file, so every boot repeats it and the 503
            // stands until an administrator who can still sign in intervenes.
            //
            // WHAT THIS DOES NOT CLAIM is that the rest of the plugin survives a null map. Plenty of
            // readers of these two dereference them without a guard, so a configuration that really
            // carried one would fail somewhere else. That is not this screen's question: it is asked
            // whether the stored file could be READ, a file that deserializes could be, and answering
            // "unreadable" because of how this method reads a member of the result would be this check
            // reporting its own fault as the file's.
            return serializer.DeserializeFromFile(typeof(PluginConfiguration), configurationFilePath) is PluginConfiguration configuration
                ? new Restored(true, configuration.OidConfigs?.Count > 0 || configuration.SamlConfigs?.Count > 0, true)
                : Restored.Damaged;
        }
#pragma warning disable CA1031 // the shape of the failure is the whole question, and it is asked below
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // WRAPPED OR NOT, an IO failure is an IO failure. The serializer turns anything the stream
            // threw into an InvalidOperationException with the real cause inside, so matching only the
            // top-level type catches a file that would not OPEN and misses one that failed halfway
            // through - a network mount hiccupping, a device read error - and calls it damage. Nothing
            // genuine is lost by looking inside: an XmlException is a SystemException and is never an
            // IOException, so real corruption still lands on the damage arm.
            //
            // WHAT THIS DOES NOT REACH, stated rather than implied: a restore rewriting the file UNDER
            // the read hands back bytes that are readable and not well-formed, so it arrives as an
            // XmlException and is judged damage. Nothing in the bytes separates a torn read from real
            // corruption, and inventing a distinction would weaken the arm that matters. What that costs
            // is one boot of refusal on a server that was being repaired at that moment; the next start
            // reads the finished file, sees a provider, and clears the marker itself.
            for (var cause = ex; cause is not null; cause = cause.InnerException)
            {
                if (cause is IOException or UnauthorizedAccessException)
                {
                    Announce(() => SsoAudit.UnreadableConfigurationCheckSkipped(logger, configurationFilePath, ex));
                    return Restored.Unknown;
                }
            }

            return Restored.Damaged;
        }
    }

    // What a marker left behind says: which damaged file it was written for, and where that file was kept.
    // Both may be absent - a marker from before this record existed, or one whose copy could not be
    // written - and absent is answered as "not this incident" and "no copy", which are the readings that
    // cost a copy rather than the evidence.
    private readonly record struct Marker(string? Incident, string? CopyPath)
    {
        // The recorded copy, and only if it is still there. A recorded name that no longer resolves - a
        // directory remounted elsewhere, a copy an operator moved - is answered as none rather than
        // printed at somebody, because a path that does not exist helps nobody and a scan for a
        // replacement finds files this incident never wrote.
        internal string? Kept => CopyPath is { } path && File.Exists(path) ? path : null;
    }
}
