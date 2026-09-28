// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>Renders the intermediate auth page the browser posts the login token from.</summary>
/// <remarks>See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Login-Flow#the-shape-both-flows-share"/>.</remarks>
internal static class WebResponse
{
    /// <summary>The shared HTML between all of the responses.</summary>
    internal static readonly string Base = @"<!DOCTYPE html>
<html lang='{{LANG}}'><head>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<style nonce=""{{NONCE}}"">
  body {
    background: #101010;
    color: #d1cfce;
    font-family: Noto Sans, Noto Sans HK, Noto Sans JP, Noto Sans KR, Noto Sans SC, Noto Sans TC, sans-serif;
  }
  a {
    color: #00a4dc;
  }
  #iframe-main {
    position: absolute;
    width: 0;
    height: 0;
    border: 0;
  }
</style>
</head><body>
<p role='status' aria-live='polite'>{{LOGGING_IN}}</p>
<noscript>{{ENABLE_JS}}</noscript>
<script nonce=""{{NONCE}}"">

function isTv() {
    // This is going to be really difficult to get right
    const userAgent = navigator.userAgent.toLowerCase();

    // The OculusBrowsers userAgent also has the samsungbrowser defined but is not a tv.
    if (userAgent.indexOf('oculusbrowser') !== -1) {
        return false;
    }

    if (userAgent.indexOf('tv') !== -1) {
        return true;
    }

    if (userAgent.indexOf('samsungbrowser') !== -1) {
        return true;
    }

    if (userAgent.indexOf('viera') !== -1) {
        return true;
    }

    return isWeb0s();
}

function isWeb0s() {
    const userAgent = navigator.userAgent.toLowerCase();

    return userAgent.indexOf('netcast') !== -1
        || userAgent.indexOf('web0s') !== -1;
}

// Browser detection trimmed from jellyfin-web's browser.js to what getDeviceName reads; re-sync from upstream rather than editing (#364).
const uaMatch = function (ua) {
    ua = ua.toLowerCase();

    const match = /(chrome)[ /]([\w.]+)/.exec(ua)
        || /(edg)[ /]([\w.]+)/.exec(ua)
        || /(edga)[ /]([\w.]+)/.exec(ua)
        || /(edgios)[ /]([\w.]+)/.exec(ua)
        || /(edge)[ /]([\w.]+)/.exec(ua)
        || /(opera)[ /]([\w.]+)/.exec(ua)
        || /(opr)[ /]([\w.]+)/.exec(ua)
        || /(safari)[ /]([\w.]+)/.exec(ua)
        || /(firefox)[ /]([\w.]+)/.exec(ua)
        || ua.indexOf('compatible') < 0 && /(mozilla)(?:.*? rv:([\w.]+)|)/.exec(ua)
        || [];

    const versionMatch = /(version)[ /]([\w.]+)/.exec(ua);

    let platform_match = /(ipad)/.exec(ua)
        || /(iphone)/.exec(ua)
        || /(windows)/.exec(ua)
        || /(android)/.exec(ua)
        || [];

    let browser = match[1] || '';

    if (browser === 'edge') {
        platform_match = [''];
    }

    if (browser === 'opr') {
        browser = 'opera';
    }

    let version;
    if (versionMatch && versionMatch.length > 2) {
        version = versionMatch[2];
    }

    version = version || match[2] || '0';

    let versionMajor = parseInt(version.split('.')[0], 10);

    if (isNaN(versionMajor)) {
        versionMajor = 0;
    }

    return {
        browser: browser,
        version: version,
        platform: platform_match[0] || '',
        versionMajor: versionMajor
    };
};

const userAgent = navigator.userAgent;

const matched = uaMatch(userAgent);
const browser = {};

if (matched.browser) {
    browser[matched.browser] = true;
}

if (matched.platform) {
    browser[matched.platform] = true;
}

browser.edgeChromium = browser.edg || browser.edga || browser.edgios;

if (!browser.chrome && !browser.edgeChromium && !browser.edge && !browser.opera && userAgent.toLowerCase().indexOf('webkit') !== -1) {
    browser.safari = true;
}

browser.osx = userAgent.toLowerCase().indexOf('mac os x') !== -1;

// This is a workaround to detect iPads on iOS 13+ that report as desktop Safari
// This may break in the future if Apple releases a touchscreen Mac
// https://forums.developer.apple.com/thread/119186
if (browser.osx && !browser.iphone && !browser.ipod && !browser.ipad && navigator.maxTouchPoints > 1) {
    browser.ipad = true;
}

if (userAgent.toLowerCase().indexOf('playstation 4') !== -1) {
    browser.ps4 = true;
    browser.tv = true;
}

if (userAgent.toLowerCase().indexOf('xbox') !== -1) {
    browser.xboxOne = true;
    browser.tv = true;
}
browser.tizen = userAgent.toLowerCase().indexOf('tizen') !== -1 || window.tizen != null;
browser.web0s = isWeb0s();
browser.edgeUwp = browser.edge && (userAgent.toLowerCase().indexOf('msapphost') !== -1 || userAgent.toLowerCase().indexOf('webview') !== -1);

if (browser.tizen) {
    // A Tizen UserAgent contains 'Safari' and 'safari' is set by the matched browser, but we only
    // want 'tizen' to be true so getDeviceName reports the Samsung TV, not Safari.
    delete browser.safari;
}

if (browser.edgeUwp) {
    browser.edge = true;
}

browser.tv = isTv();
browser.operaTv = browser.tv && userAgent.toLowerCase().indexOf('opr/') !== -1;

function getDeviceName() {
	var deviceName = '';
    if (!deviceName) {
        if (browser.tizen) {
            deviceName = 'Samsung Smart TV';
        } else if (browser.web0s) {
            deviceName = 'LG Smart TV';
        } else if (browser.operaTv) {
            deviceName = 'Opera TV';
        } else if (browser.xboxOne) {
            deviceName = 'Xbox One';
        } else if (browser.ps4) {
            deviceName = 'Sony PS4';
        } else if (browser.chrome) {
            deviceName = 'Chrome';
        } else if (browser.edgeChromium) {
            deviceName = 'Edge Chromium';
        } else if (browser.edge) {
            deviceName = 'Edge';
        } else if (browser.firefox) {
            deviceName = 'Firefox';
        } else if (browser.opera) {
            deviceName = 'Opera';
        } else if (browser.safari) {
            deviceName = 'Safari';
        } else {
            deviceName = 'Web Browser';
        }

        if (browser.ipad) {
            deviceName += ' iPad';
        } else if (browser.iphone) {
            deviceName += ' iPhone';
        } else if (browser.android) {
            deviceName += ' Android';
        }
    }

    return deviceName;
}

const sleep = (milliseconds) => {
    return new Promise(resolve => setTimeout(resolve, milliseconds))
}

// The server id the web client stored for this origin, or null while it has not, so the wait keeps polling.
function storedServerId() {
    try {
        var credentials = JSON.parse(localStorage.getItem('jellyfin_credentials'));
        var server = credentials && credentials.Servers ? credentials.Servers[0] : null;
        return server && server.Id != null ? server.Id : null;
    } catch (e) {
        return null;
    }
}

// A terminal failure offers a way back, built through DOM APIs and never innerHTML (#667).
function showReturnLink() {
    if (document.getElementById('sso-return-link')) return;
    const link = document.createElement('a');
    link.id = 'sso-return-link';
    link.textContent = {{RETURN_LINK_JS}};
    link.href = ssoBaseUrl + '/web/index.html';
    document.querySelector('p').insertAdjacentElement('afterend', link);
}

";

    // The page's script, with the per-request values as placeholders; the localized texts are the catalogue keys.
    private const string Script = @"
const ssoBaseUrl = {{BASE_URL}};
const ssoProvider = {{PROVIDER}};
const ssoMode = {{MODE}};
async function link(jfCredentials, request) {
    if (jfCredentials == null) return;

    const jfUser = jfCredentials['Servers'][0]['UserId'];
    const jfToken = jfCredentials['Servers'][0]['AccessToken'];

    if (jfUser == null) return;
    if (jfToken == null) return;

    const url = ssoBaseUrl + '/sso/' + ssoMode + '/Link/' + encodeURIComponent(ssoProvider) + '/' + jfUser;

    return new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');

       xhr.setRequestHeader(
           'Authorization',
           `MediaBrowser Client=""${request.appName}"",Device=""${request.deviceName}"",DeviceId=""${request.deviceId}"",Version=""${request.appVersion}"",Token=""${jfToken}""`)

       xhr.onload = function(e) {
         resolve(xhr.status);
       };
       xhr.onerror = function (e) {
         console.log(e);
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
}

async function main() {
    // The link leg needs the current tab's session, captured before the login leg's credential wipe below.
    var preLinkCredentials = null;
    if ({{IS_LINKING}}) {
        var preLinkCredentialsString = localStorage.getItem(""jellyfin_credentials"");
        if (preLinkCredentialsString != null) {
            preLinkCredentials = JSON.parse(preLinkCredentialsString);
        }
    }

    var data = {{DATA}};

    if (preLinkCredentials != null && preLinkCredentials['Servers']?.[0]?.['UserId'] != null) {
        // A live session is in hand, so the wipe-and-reload the login leg needs is skipped.
        while (localStorage.getItem(""_deviceId2"") == null) {
            await sleep(100);
        }
        var linkDeviceId = localStorage.getItem(""_deviceId2"");
        var linkAppName = ""Jellyfin Web"";
        var linkAppVersion = ""10.8.0"";
        var linkDeviceName = getDeviceName();
        var linkRequest = {deviceId: linkDeviceId, appName: linkAppName, appVersion: linkAppVersion, deviceName: linkDeviceName, data};

        // A definitive link outcome is terminal, because the Auth leg could never redeem the consumed token; only a network error falls through (#614).
        var linkStatus = await link(preLinkCredentials, linkRequest);
        if (linkStatus !== undefined) {
            const linked = linkStatus >= 200 && linkStatus < 300;
            document.querySelector('p').textContent =
                linked
                    ? {{page.account_linked}}
                    : linkStatus === 429
                        ? {{error.rate_limited}}
                        : {{page.link_failed}};
            if (!linked) {
                showReturnLink();
            }
            return;
        }
    }

    // The iframe shares localStorage only at the same origin, so a mismatched origin is terminal rather than an endless wait.
    var pageOrigin = location.origin;
    var serverUrl = null;
    try { serverUrl = new URL(ssoBaseUrl); } catch (e) { serverUrl = null; }
    if (serverUrl === null || serverUrl.origin !== pageOrigin) {
        // The page's origin carries the server's path base, so the suggested override keeps its prefix.
        var pageBase = pageOrigin + (serverUrl === null ? '' : serverUrl.pathname.replace(/\/+$/, ''));
        document.querySelector('p').textContent = {{page.address_mismatch}}
            .split('{page}').join(pageBase).split('{server}').join(ssoBaseUrl);
        showReturnLink();
        return;
    }

    localStorage.removeItem('jellyfin_credentials');
    document.getElementById('iframe-main').src = ssoBaseUrl + '/web/index.html';

    // After twenty seconds the status line says what is being waited for and offers the way back, without leaving the loop.
    var waitingSince = Date.now();
    var waitNoticeShown = false;
    while (localStorage.getItem(""_deviceId2"") == null || storedServerId() == null) {
        if (!waitNoticeShown && Date.now() - waitingSince > 20000) {
            waitNoticeShown = true;
            document.querySelector('p').textContent = {{page.still_waiting}}
                .split('{server}').join(ssoBaseUrl);
            showReturnLink();
        }
        // If localStorage isn't initialized yet, try again.
        await sleep(100);
    }
    var deviceId = localStorage.getItem(""_deviceId2"");
    var appName = ""Jellyfin Web"";
    var appVersion = ""10.8.0"";
    var deviceName = getDeviceName();

    var request = {deviceId, appName, appVersion, deviceName, data};

    var url = ssoBaseUrl + '/sso/' + ssoMode + '/Auth/' + encodeURIComponent(ssoProvider);

    let response = await new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');
       xhr.onload = function(e) {
         resolve({status: xhr.status, body: xhr.response});
       };
       xhr.onerror = function () {
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
    var responseJson;
    try {
        responseJson = response && response.status === 200 ? JSON.parse(response.body) : undefined;
    } catch (e) {
        responseJson = undefined;
    }
    if (!responseJson) {
        // A throttled or failed authentication surfaces as text rather than an endless wait.
        document.querySelector('p').textContent =
            response && response.status === 429
                ? {{error.login_rate_limited}}
                : {{page.login_failed}};
        showReturnLink();
        return;
    }
    var userId = 'user-' + responseJson['User']['Id'] + '-' + responseJson['User']['ServerId'];
    responseJson['User']['EnableAutoLogin'] = true;
    localStorage.setItem(userId, JSON.stringify(responseJson['User']));
    var jfCreds = JSON.parse(localStorage.getItem('jellyfin_credentials'));
    jfCreds['Servers'][0]['AccessToken'] = responseJson['AccessToken'];
    jfCreds['Servers'][0]['UserId'] = responseJson['User']['Id'];
    localStorage.setItem('jellyfin_credentials', JSON.stringify(jfCreds));
    localStorage.setItem('enableAutoLogin', 'true');
    window.location.replace(ssoBaseUrl + '/web/index.html');
}

document.addEventListener('DOMContentLoaded', function () {
    main();
});

// https://stackoverflow.com/a/25435165
</script><iframe id='iframe-main' sandbox='allow-same-origin allow-forms allow-scripts' src=''></iframe></body></html>";

    private static readonly string[] ScriptTexts = { "page.account_linked", "error.rate_limited", "page.link_failed", "page.address_mismatch", "page.still_waiting", "error.login_rate_limited", "page.login_failed" };

    /// <summary>Renders the auth page with the server-derived values encoded as JSON constants.</summary>
    /// <param name="data">The opaque value the page posts back to the mint leg: a one-time token, or a base64 assertion on the SAML linking path.</param>
    /// <param name="provider">The name of the provider to callback to.</param>
    /// <param name="baseUrl">The base URL of the Jellyfin installation.</param>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="nonce">The per-response CSP nonce emitted on the inline script and style tags.</param>
    /// <param name="isLinking">Whether this request is to link accounts rather than authenticate.</param>
    /// <param name="culture">The culture the page's own text is rendered in, or null for English (#913).</param>
    /// <returns>A string with the HTML to serve to the client.</returns>
    public static string Generator(string data, string provider, string baseUrl, string mode, string nonce, bool isLinking = false, string? culture = null)
    {
        System.ArgumentNullException.ThrowIfNull(baseUrl);

        // The domain is converted to Punycode; a base URL with no scheme separator fails closed rather than mis-splitting.
        var idnMapping = new IdnMapping();
        var protocolSeparatorIndex = baseUrl.IndexOf("//", System.StringComparison.Ordinal);

        if (protocolSeparatorIndex < 0)
        {
            throw new System.ArgumentException("baseUrl must contain a protocol separator ('//').", nameof(baseUrl));
        }

        var protocol = baseUrl.Substring(0, protocolSeparatorIndex + 2);
        var domain = baseUrl.Substring(protocolSeparatorIndex + 2);
        var punycodeDomain = idnMapping.GetAscii(domain);
        var punycodeBaseUrl = protocol + punycodeDomain;

        // HTML-context strings are HTML-encoded and script-context strings JSON-encoded, so no value can end the script element (#913).
        string Localize(string key) => SsoLocalizer.GetString(key, culture);
        var head = Base
            .Replace("{{NONCE}}", nonce, System.StringComparison.Ordinal)
            .Replace("{{LANG}}", HtmlEncoder.Default.Encode(culture ?? SsoLocalizer.FallbackCulture), System.StringComparison.Ordinal)
            .Replace("{{LOGGING_IN}}", HtmlEncoder.Default.Encode(Localize("page.logging_in")), System.StringComparison.Ordinal)
            .Replace("{{ENABLE_JS}}", HtmlEncoder.Default.Encode(Localize("page.enable_javascript")), System.StringComparison.Ordinal)
            .Replace("{{RETURN_LINK_JS}}", JsonSerializer.Serialize(Localize("error.return_to_login")), System.StringComparison.Ordinal);

        // The base URL and the provider derive from the request, so both are treated as untrusted.
        var values = new Dictionary<string, string>(System.StringComparer.Ordinal)
        {
            ["BASE_URL"] = JsonSerializer.Serialize(punycodeBaseUrl),
            ["PROVIDER"] = JsonSerializer.Serialize(provider),
            ["MODE"] = JsonSerializer.Serialize(mode),
            ["IS_LINKING"] = isLinking ? "true" : "false",
            ["DATA"] = JsonSerializer.Serialize(data),
        };
        foreach (var key in ScriptTexts)
        {
            values[key] = JsonSerializer.Serialize(Localize(key));
        }

        return head + FillScript(values);
    }

    // One pass over the template, so a substituted value is never read as a placeholder.
    private static string FillScript(Dictionary<string, string> values)
    {
        var page = new StringBuilder(Script.Length + 1024);
        var at = 0;
        while (true)
        {
            var open = Script.IndexOf("{{", at, System.StringComparison.Ordinal);
            if (open < 0)
            {
                return page.Append(Script, at, Script.Length - at).ToString();
            }

            var close = Script.IndexOf("}}", open, System.StringComparison.Ordinal);
            page.Append(Script, at, open - at).Append(values[Script[(open + 2)..close]]);
            at = close + 2;
        }
    }
}
