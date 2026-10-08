@echo off
setlocal
chcp 65001 >nul 2>&1
title DoPing
set "SELF=%~f0"
set "ARG1=%~1"
set "ARG2=%~2"
where powershell >nul 2>&1 || (echo PowerShell bulunamadi. Windows 7 SP1 veya uzeri gerekli. & pause & exit /b 1)
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create(([IO.File]::ReadAllText($env:SELF,[Text.Encoding]::UTF8) -split '(?m)^#PSBEGIN#\r?\n',2)[1]))"
set "RC=%errorlevel%"
if defined ARG2 exit /b %RC%
echo.
pause
exit /b %RC%
#PSBEGIN#
# ============================================================================
#  DoPing v2.0  -  Alan adi kesif, gecikme (ping/TCP/TLS/HTTP) ve saglik analizi
#  Yalnizca herkese acik DNS/sertifika kayitlari ve standart baglanti testleri
#  kullanir. Sadece sahibi oldugunuz veya test izniniz olan alan adlarinda kullanin.
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$script:Ver      = '2.0'
$script:SelfTest = ($env:DOPING_SELFTEST -eq '1')
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
try { [Net.ServicePointManager]::DefaultConnectionLimit = 200 } catch {}
try {
    $ui = $Host.UI.RawUI
    $bs = $ui.BufferSize; $ws = $ui.WindowSize
    $bs.Width  = [math]::Max($bs.Width, 150)
    $bs.Height = [math]::Max($bs.Height, 5000)
    $ui.BufferSize = $bs
    $ws.Width = 150
    $ui.WindowSize = $ws
} catch {}
$script:ConW = 120
try { $script:ConW = $Host.UI.RawUI.WindowSize.Width } catch {}
if ($script:ConW -lt 100) { $script:ConW = 100 }
try { $Host.UI.RawUI.WindowTitle = 'DoPing v2.0' } catch {}

if ($env:SELF) { $script:SelfDir = Split-Path -Parent $env:SELF } else { $script:SelfDir = (Get-Location).Path }
$script:OutDir   = Join-Path $script:SelfDir 'Sonuclar'
$script:HasRDN   = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
$script:Cand     = @{}
$script:Findings = New-Object System.Collections.ArrayList
$script:Log      = New-Object System.Collections.ArrayList
$script:LastHtml = $null
$script:Inv      = [Globalization.CultureInfo]::InvariantCulture
$script:TrCult   = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')

# ----------------------------------------------------------- C# ag motoru
$csCode = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class DpProbe
{
    public string Host; public string Ip; public int Port; public bool Tls;
    public bool TcpOk; public double TcpMs;
    public bool TlsOk; public double TlsMs; public string TlsProto; public string Cipher;
    public string CertSubject; public string CertIssuer; public string CertSans;
    public string CertNotAfter; public int CertDays; public bool CertNameMatch; public bool CertChainOk;
    public string CertKey; public string CertSig; public int SanCount;
    public bool HttpOk; public double TtfbMs; public double TotalMs; public int Status;
    public string StatusLine; public string Server; public string Location; public string ContentType;
    public string PoweredBy; public string CdnHint;
    public bool Hsts; public bool Csp; public bool Xfo; public bool Xcto; public bool RefPol;
    public string Error;
}

public static class DpNet
{
    static double Ms(long a, long b) { return (b - a) * 1000.0 / Stopwatch.Frequency; }
    static bool TrustAll(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }

    public static double TcpConnect(string ip, int port, int timeoutMs)
    {
        Socket s = null;
        try
        {
            IPAddress a = IPAddress.Parse(ip);
            s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            s.NoDelay = true;
            long t0 = Stopwatch.GetTimestamp();
            IAsyncResult ar = s.BeginConnect(new IPEndPoint(a, port), null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs, false)) return -1;
            s.EndConnect(ar);
            return Ms(t0, Stopwatch.GetTimestamp());
        }
        catch { return -1; }
        finally { if (s != null) { try { s.Close(); } catch { } } }
    }

    static int ReadLen(byte[] d, ref int p)
    {
        if (p >= d.Length) return -1;
        int b = d[p++];
        if (b < 0x80) return b;
        int n = b & 0x7F; int v = 0;
        for (int i = 0; i < n; i++) { if (p >= d.Length) return -1; v = (v << 8) | d[p++]; }
        return v;
    }

    static List<string> ParseSans(X509Certificate2 c)
    {
        List<string> res = new List<string>();
        try
        {
            foreach (X509Extension ext in c.Extensions)
            {
                if (ext.Oid != null && ext.Oid.Value == "2.5.29.17")
                {
                    byte[] d = ext.RawData; int p = 1;
                    if (d.Length < 2 || d[0] != 0x30) break;
                    int len = ReadLen(d, ref p); int end = p + len; if (end > d.Length) end = d.Length;
                    while (p < end)
                    {
                        byte tag = d[p++]; int l = ReadLen(d, ref p);
                        if (l < 0 || p + l > d.Length) break;
                        if (tag == 0x82) res.Add(Encoding.ASCII.GetString(d, p, l).ToLowerInvariant());
                        p += l;
                    }
                }
            }
        }
        catch { }
        return res;
    }

    static bool NameMatches(string host, List<string> sans, string cn)
    {
        host = host.ToLowerInvariant();
        List<string> all = new List<string>(sans);
        if (all.Count == 0 && !string.IsNullOrEmpty(cn)) all.Add(cn.ToLowerInvariant());
        foreach (string s in all)
        {
            if (s == host) return true;
            if (s.StartsWith("*."))
            {
                string suf = s.Substring(1);
                int dot = host.IndexOf('.');
                if (dot > 0 && host.Substring(dot) == suf) return true;
            }
        }
        return false;
    }

    static string Cdn(Dictionary<string, string> h)
    {
        string v;
        if (h.ContainsKey("cf-ray")) return "Cloudflare";
        if (h.TryGetValue("server", out v) && v.ToLowerInvariant().Contains("cloudflare")) return "Cloudflare";
        if (h.ContainsKey("x-amz-cf-id")) return "CloudFront";
        if (h.TryGetValue("via", out v) && v.ToLowerInvariant().Contains("cloudfront")) return "CloudFront";
        if (h.ContainsKey("x-azure-ref")) return "Azure FrontDoor";
        if (h.ContainsKey("x-vercel-id")) return "Vercel";
        if (h.ContainsKey("x-nf-request-id")) return "Netlify";
        if (h.ContainsKey("x-github-request-id")) return "GitHub Pages";
        if (h.ContainsKey("x-sucuri-id")) return "Sucuri";
        if (h.ContainsKey("x-iinfo") || h.ContainsKey("x-cdn")) return "Imperva";
        if (h.TryGetValue("server", out v))
        {
            string l = v.ToLowerInvariant();
            if (l.Contains("akamai")) return "Akamai";
            if (l.Contains("fastly")) return "Fastly";
            if (l == "gws" || l.Contains("esf") || l.Contains("gse")) return "Google";
            if (l.Contains("amazons3")) return "AWS S3";
            if (l.Contains("bunny")) return "BunnyCDN";
        }
        if (h.TryGetValue("x-served-by", out v) && v.ToLowerInvariant().Contains("cache-")) return "Fastly";
        if (h.ContainsKey("x-akamai-transformed") || h.ContainsKey("akamai-grn")) return "Akamai";
        return "";
    }

    public static DpProbe Probe(string host, string ip, int port, bool tls, int timeoutMs)
    {
        DpProbe r = new DpProbe(); r.Host = host; r.Ip = ip; r.Port = port; r.Tls = tls;
        Socket s = null; Stream st = null;
        try
        {
            IPAddress a = IPAddress.Parse(ip);
            s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            s.NoDelay = true;
            long t0 = Stopwatch.GetTimestamp();
            IAsyncResult ar = s.BeginConnect(new IPEndPoint(a, port), null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs, false)) { r.Error = "TCP zaman asimi"; return r; }
            s.EndConnect(ar);
            r.TcpMs = Ms(t0, Stopwatch.GetTimestamp()); r.TcpOk = true;
            s.ReceiveTimeout = timeoutMs; s.SendTimeout = timeoutMs;
            st = new NetworkStream(s, false);

            if (tls)
            {
                SslStream ssl = new SslStream(st, false, new RemoteCertificateValidationCallback(TrustAll));
                st = ssl;
                long t2 = Stopwatch.GetTimestamp();
                try
                {
                    try { ssl.AuthenticateAsClient(host, null, (SslProtocols)(3072 | 12288), false); }
                    catch (ArgumentException) { ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false); }
                    catch (NotSupportedException) { ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false); }
                    r.TlsMs = Ms(t2, Stopwatch.GetTimestamp()); r.TlsOk = true;
                }
                catch (Exception ex) { r.Error = "TLS: " + ex.Message; return r; }

                int pv = (int)ssl.SslProtocol;
                r.TlsProto = (pv == 12288) ? "TLS1.3" : (pv == 3072 ? "TLS1.2" : (pv == 768 ? "TLS1.1" : (pv == 192 ? "TLS1.0" : ssl.SslProtocol.ToString())));
                try { r.Cipher = ssl.CipherAlgorithm.ToString() + "-" + ssl.CipherStrength.ToString(); } catch { }
                try
                {
                    X509Certificate rc = ssl.RemoteCertificate;
                    if (rc != null)
                    {
                        X509Certificate2 c2 = new X509Certificate2(rc);
                        r.CertSubject = c2.GetNameInfo(X509NameType.SimpleName, false);
                        r.CertIssuer = c2.GetNameInfo(X509NameType.SimpleName, true);
                        DateTime na = c2.NotAfter.ToUniversalTime();
                        r.CertNotAfter = na.ToString("yyyy-MM-dd");
                        r.CertDays = (int)Math.Floor((na - DateTime.UtcNow).TotalDays);
                        List<string> sans = ParseSans(c2);
                        r.SanCount = sans.Count;
                        r.CertSans = string.Join(" ", sans.ToArray());
                        r.CertNameMatch = NameMatches(host, sans, r.CertSubject);
                        try { r.CertSig = c2.SignatureAlgorithm.FriendlyName; } catch { }
                        try
                        {
                            r.CertKey = c2.PublicKey.Oid.FriendlyName;
                            try
                            {
                                object k = typeof(PublicKey).GetProperty("Key").GetValue(c2.PublicKey, null);
                                object ks = k.GetType().GetProperty("KeySize").GetValue(k, null);
                                r.CertKey += " " + ks.ToString();
                            }
                            catch { }
                        }
                        catch { }
                        try
                        {
                            X509Chain ch = new X509Chain();
                            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            r.CertChainOk = ch.Build(c2);
                        }
                        catch { }
                    }
                }
                catch { }
            }

            try
            {
                string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: DoPing/2.0 (latency-probe)\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
                byte[] rb = Encoding.ASCII.GetBytes(req);
                long t3 = Stopwatch.GetTimestamp();
                st.Write(rb, 0, rb.Length); st.Flush();
                byte[] buf = new byte[16384]; int tot = 0; bool first = true;
                while (tot < buf.Length)
                {
                    int n = st.Read(buf, tot, buf.Length - tot);
                    if (n <= 0) break;
                    if (first) { r.TtfbMs = Ms(t3, Stopwatch.GetTimestamp()); first = false; }
                    tot += n;
                    string tmp = Encoding.ASCII.GetString(buf, 0, tot);
                    if (tmp.IndexOf("\r\n\r\n", StringComparison.Ordinal) >= 0) break;
                }
                r.TotalMs = Ms(t3, Stopwatch.GetTimestamp());
                string text = Encoding.ASCII.GetString(buf, 0, tot);
                int he = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                string head = he >= 0 ? text.Substring(0, he) : text;
                string[] lines = head.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                if (lines.Length > 0 && lines[0].StartsWith("HTTP/"))
                {
                    r.StatusLine = lines[0];
                    string[] sp = lines[0].Split(' ');
                    int code; if (sp.Length > 1 && int.TryParse(sp[1], out code)) { r.Status = code; r.HttpOk = true; }
                    Dictionary<string, string> h = new Dictionary<string, string>();
                    for (int i = 1; i < lines.Length; i++)
                    {
                        int c = lines[i].IndexOf(':');
                        if (c > 0)
                        {
                            string k = lines[i].Substring(0, c).Trim().ToLowerInvariant();
                            string v = lines[i].Substring(c + 1).Trim();
                            if (!h.ContainsKey(k)) h[k] = v;
                        }
                    }
                    string x;
                    if (h.TryGetValue("server", out x)) r.Server = x;
                    if (h.TryGetValue("location", out x)) r.Location = x;
                    if (h.TryGetValue("content-type", out x)) r.ContentType = x;
                    if (h.TryGetValue("x-powered-by", out x)) r.PoweredBy = x;
                    r.Hsts = h.ContainsKey("strict-transport-security");
                    r.Csp = h.ContainsKey("content-security-policy");
                    r.Xfo = h.ContainsKey("x-frame-options");
                    r.Xcto = h.ContainsKey("x-content-type-options");
                    r.RefPol = h.ContainsKey("referrer-policy");
                    r.CdnHint = Cdn(h);
                }
            }
            catch (Exception ex2) { if (r.Error == null) r.Error = "HTTP: " + ex2.Message; }
        }
        catch (Exception ex) { r.Error = ex.GetType().Name + ": " + ex.Message; }
        finally
        {
            try { if (st != null) st.Close(); } catch { }
            try { if (s != null) s.Close(); } catch { }
        }
        return r;
    }
}
'@
$script:HasNet = $false
try { Add-Type -TypeDefinition $csCode -ErrorAction Stop; $script:HasNet = $true } catch { $script:NetErr = $_.Exception.Message }

# ---------------------------------------------------------------- yardimcilar
function Say($t, $c = 'Gray') { Write-Host $t -ForegroundColor $c; [void]$script:Log.Add([string]$t) }
function Head($t) {
    Say ''
    Say ('=' * ($script:ConW - 2)) 'DarkCyan'
    Say ("  " + $t) 'Cyan'
    Say ('=' * ($script:ConW - 2)) 'DarkCyan'
}
function Sub($t) { Say ''; Say ("  >> " + $t) 'Yellow' }
function Show-Bar($done, $total, $label) {
    $w = 30
    if ($total -gt 0) { $p = [math]::Floor($done * $w / $total) } else { $p = $w }
    $bar = ('#' * $p).PadRight($w, '.')
    Write-Host ("`r     {0,-18} [{1}] {2,5}/{3,-5}" -f $label, $bar, $done, $total) -NoNewline -ForegroundColor DarkCyan
}
function Cut([string]$s, [int]$n) {
    if ($null -eq $s) { return '' }
    if ($s.Length -le $n) { return $s }
    if ($n -le 1) { return $s.Substring(0, $n) }
    return $s.Substring(0, $n - 1) + '~'
}
function Fmt-Ms($v) {
    if ($null -eq $v -or $v -eq '') { return '-' }
    $x = [double]$v
    if ($x -lt 0.05) { return '<0,1' }
    if ($x -lt 10) { return $x.ToString('0.00', $script:TrCult) }
    if ($x -lt 100) { return $x.ToString('0.0', $script:TrCult) }
    return $x.ToString('0', $script:TrCult)
}
function Num([double]$x, [string]$f = '0.0') { return $x.ToString($f, $script:TrCult) }
function Percentile($list, [double]$p) {
    $a = @($list | Where-Object { $null -ne $_ } | Sort-Object)
    if ($a.Count -eq 0) { return $null }
    if ($a.Count -eq 1) { return [double]$a[0] }
    $k = ($a.Count - 1) * $p
    $f = [math]::Floor($k); $c = [math]::Ceiling($k)
    if ($f -eq $c) { return [double]$a[[int]$k] }
    return [double]($a[[int]$f] * ($c - $k) + $a[[int]$c] * ($k - $f))
}
function Haversine([double]$la1, [double]$lo1, [double]$la2, [double]$lo2) {
    $r = 6371.0; $d2r = [math]::PI / 180
    $dla = ($la2 - $la1) * $d2r; $dlo = ($lo2 - $lo1) * $d2r
    $a = [math]::Pow([math]::Sin($dla / 2), 2) + [math]::Cos($la1 * $d2r) * [math]::Cos($la2 * $d2r) * [math]::Pow([math]::Sin($dlo / 2), 2)
    return 2 * $r * [math]::Asin([math]::Min(1.0, [math]::Sqrt($a)))
}
function Spark($vals, [double]$max) {
    $chars = ' .:-=+*#@'
    $o = ''
    foreach ($v in $vals) {
        if ($null -eq $v -or $v -lt 0) { $o += 'x'; continue }
        if ($max -le 0) { $o += '.'; continue }
        $i = [int][math]::Min(8.0, [math]::Floor(($v / $max) * 8))
        $o += $chars[$i]
    }
    return $o
}

# JSON (kendi serilestiricimiz: kultur bagimsiz, HTML-guvenli)
function J-Str($s) {
    if ($null -eq $s) { return 'null' }
    $t = [string]$s
    $t = $t.Replace('\', '\\').Replace('"', '\"').Replace("`r", '').Replace("`n", '\n').Replace("`t", ' ')
    $t = $t.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
    $t = [regex]::Replace($t, '[\x00-\x1f]', ' ')
    return '"' + $t + '"'
}
function J-Val($v) {
    if ($null -eq $v) { return 'null' }
    if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
    if ($v -is [double] -or $v -is [single] -or $v -is [decimal]) {
        if ([double]::IsNaN([double]$v) -or [double]::IsInfinity([double]$v)) { return 'null' }
        return ([double]$v).ToString('0.###', $script:Inv)
    }
    if ($v -is [int] -or $v -is [long] -or $v -is [int16] -or $v -is [byte] -or $v -is [uint32]) { return ([long]$v).ToString($script:Inv) }
    return (J-Str $v)
}
function To-JsonObj($o, $props) {
    $parts = foreach ($p in $props) { (J-Str $p) + ':' + (J-Val $o.$p) }
    return '{' + ($parts -join ',') + '}'
}

function Banner {
    if (-not $script:SelfTest) { Clear-Host }
    Say ''
    Say '   ____        ____  _             ' 'Cyan'
    Say '  |  _ \  ___ |  _ \(_)_ __   __ _ ' 'Cyan'
    Say '  | | | |/ _ \| |_) | | ''_ \ / _` |' 'Cyan'
    Say '  | |_| | (_) |  __/| | | | | (_| |' 'Cyan'
    Say '  |____/ \___/|_|   |_|_| |_|\__, |' 'Cyan'
    Say '                             |___/   v2.0' 'Cyan'
    Say ''
    Say '   Alan adi kesfi  |  TCP / TLS / HTTP / ICMP gecikme  |  Sertifika  |  DNS  |  Guvenlik bulgulari' 'DarkGray'
    Say '   Sadece sahibi oldugunuz veya test izniniz olan alan adlarinda kullanin.' 'DarkGray'
    Say ''
    if (-not $script:HasNet) { Say ("   UYARI: Ag motoru derlenemedi, TLS/HTTP testleri kapali. " + $script:NetErr) 'Red' }
}

function Normalize-Domain([string]$s) {
    if (-not $s) { return $null }
    $s = $s.Trim().ToLower()
    $s = $s -replace '^[a-z][a-z0-9+.-]*://', ''
    $s = ($s -split '[/?#\\ ]')[0]
    $s = $s -replace '^.*@', ''
    $s = $s -replace ':\d+$', ''
    $s = $s.Trim('.')
    $s = $s -replace '^www\.', ''
    try { $s = (New-Object System.Globalization.IdnMapping).GetAscii($s) } catch {}
    if ($s -match '^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$') { return $s }
    return $null
}

$script:StrongSrc = @('CT','CS','AN','HT','OTX','RD','US','WB','DNS','MX','NS','CNAME','Ana','DMARC','SAN','REDIR')
function Add-Cand([string]$n, [string]$src) {
    if (-not $n) { return }
    $n = $n.Trim().ToLower().TrimEnd('.')
    $n = $n -replace '^\*\.', ''
    if ($n.Length -gt 253) { return }
    if ($n -notmatch '^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$') { return }
    if ($n -notmatch '\.') { return }
    if ($n -match '\.\.') { return }
    if (-not $script:Cand.ContainsKey($n)) {
        $script:Cand[$n] = New-Object 'System.Collections.Generic.HashSet[string]'
    }
    [void]$script:Cand[$n].Add($src)
}
function Is-Strong($src) {
    foreach ($s in $src) { if ($script:StrongSrc -contains $s) { return $true } }
    return $false
}
function Get-Scope([string]$n, [string]$d, $src) {
    if ($n -eq $d) { return 'Ana' }
    if ($n.EndsWith(".$d")) { return 'Alt' }
    if ($src.Contains('TLD')) { return 'TLD' }
    return 'Harici'
}
function Get-Dns([string]$name, [string]$type, [string]$server = '') {
    if (-not $script:HasRDN) { return $null }
    try {
        if ($server) { $r = @(Resolve-DnsName -Name $name -Type $type -Server $server -DnsOnly -ErrorAction Stop) }
        else { $r = @(Resolve-DnsName -Name $name -Type $type -DnsOnly -ErrorAction Stop) }
        return , @($r | Where-Object { $_.Type -eq $type })
    } catch { return $null }
}
function Add-Finding([string]$sev, [string]$cat, [string]$msg) {
    [void]$script:Findings.Add([pscustomobject]@{ Sev = $sev; Cat = $cat; Msg = $msg })
}

# ------------------------------------------------------------ paralel motor
function Invoke-Pool {
    param($Items, [string]$Script, [int]$Threads = 40, $Extra = $null, [string]$Label = 'Islem', [switch]$Quiet)
    $items = @($Items)
    $total = $items.Count
    $out = New-Object System.Collections.ArrayList
    if ($total -eq 0) { return , @() }
    $pool = [runspacefactory]::CreateRunspacePool(1, [math]::Max(1, $Threads))
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($it in $items) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($Script).AddArgument($it).AddArgument($Extra)
        [void]$jobs.Add(@{ PS = $ps; H = $ps.BeginInvoke() })
    }
    while ($true) {
        $done = 0
        foreach ($j in $jobs) { if ($j.H.IsCompleted) { $done++ } }
        if (-not $Quiet) { Show-Bar $done $total $Label }
        if ($done -ge $total) { break }
        Start-Sleep -Milliseconds 150
    }
    if (-not $Quiet) { Write-Host '' }
    foreach ($j in $jobs) {
        try {
            $r = $j.PS.EndInvoke($j.H)
            foreach ($x in $r) { if ($null -ne $x) { [void]$out.Add($x) } }
        } catch {}
        $j.PS.Dispose()
    }
    $pool.Close(); $pool.Dispose()
    return , $out.ToArray()
}

# ------------------------------------------------------- calisan bloklari
$ResolveWorker = @'
param($n, $x)
try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $a = [System.Net.Dns]::GetHostAddresses($n)
    $sw.Stop()
    if ($a -and $a.Count -gt 0) {
        $ips = @($a | ForEach-Object { $_.IPAddressToString })
        [pscustomobject]@{ Name = $n; IPs = $ips; DnsMs = $sw.Elapsed.TotalMilliseconds }
    }
} catch {}
'@

$CnameWorker = @'
param($n, $x)
try {
    $r = @(Resolve-DnsName -Name $n -Type CNAME -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'CNAME' })
    if ($r.Count -gt 0) {
        $t = ([string]$r[0].NameHost).TrimEnd('.').ToLower()
        $ok = $false
        try { $a = [System.Net.Dns]::GetHostAddresses($t); if ($a.Count -gt 0) { $ok = $true } } catch {}
        [pscustomobject]@{ Name = $n; Target = $t; TargetResolves = $ok }
    }
} catch {}
'@

$WebWorker = @'
param($it, $x)
$c = $null; $err = ''
$sw = [Diagnostics.Stopwatch]::StartNew()
for ($try = 1; $try -le 2; $try++) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $c = (Invoke-WebRequest -Uri $it.U -UseBasicParsing -TimeoutSec $it.T -UserAgent 'Mozilla/5.0 (DoPing)' -ErrorAction Stop).Content
        if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }
        $err = ''
        break
    } catch { $err = $_.Exception.Message; $c = $null; Start-Sleep -Seconds 2 }
}
$sw.Stop()
[pscustomobject]@{ Tag = $it.Tag; Name = $it.N; Content = [string]$c; Err = $err; Sec = $sw.Elapsed.TotalSeconds }
'@

$IpWorker = @'
param($ip, $cfg)
$icmpN = [int]$cfg.Icmp; $tcpN = [int]$cfg.Tcp; $to = [int]$cfg.Timeout; $useNet = [bool]$cfg.Net
function St($l) {
    $a = @($l | Sort-Object)
    $n = $a.Count
    if ($n -eq 0) { return $null }
    $sum = 0.0; foreach ($x in $a) { $sum += $x }
    $avg = $sum / $n
    $var = 0.0; foreach ($x in $a) { $var += ($x - $avg) * ($x - $avg) }
    if ($n % 2 -eq 1) { $med = $a[[int](($n - 1) / 2)] } else { $med = ($a[$n / 2 - 1] + $a[$n / 2]) / 2 }
    $pi = [int][math]::Ceiling(0.95 * $n) - 1; if ($pi -lt 0) { $pi = 0 }
    return @{ Min = $a[0]; Max = $a[$n - 1]; Avg = $avg; Med = $med; P95 = $a[$pi]; Std = [math]::Sqrt($var / $n) }
}
function TcpOnce($ip, $port, $to) {
    if ($useNet) { return [DpNet]::TcpConnect($ip, $port, $to) }
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($to)
        $sw.Stop()
        if ($ok -and $c.Connected) { $c.EndConnect($iar); return $sw.Elapsed.TotalMilliseconds }
        return -1
    } catch { return -1 } finally { $c.Close() }
}
# ICMP
$it = New-Object 'System.Collections.Generic.List[double]'
$ttl = $null
$p = New-Object System.Net.NetworkInformation.Ping
for ($i = 0; $i -lt $icmpN; $i++) {
    try {
        $r = $p.Send($ip, $to)
        if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $it.Add([double]$r.RoundtripTime)
            if ($r.Options) { $ttl = $r.Options.Ttl }
        }
    } catch {}
    if ($i -lt ($icmpN - 1)) { Start-Sleep -Milliseconds 100 }
}
$p.Dispose()
# TCP (443, olmazsa 80)
$tt = New-Object 'System.Collections.Generic.List[double]'
$port = 443; $tcpFail = 0
for ($i = 0; $i -lt $tcpN; $i++) {
    $v = TcpOnce $ip 443 $to
    if ($v -ge 0) { $tt.Add($v) } else { $tcpFail++ }
    if ($i -lt ($tcpN - 1)) { Start-Sleep -Milliseconds 60 }
}
if ($tt.Count -eq 0) {
    $port = 80; $tcpFail = 0
    for ($i = 0; $i -lt $tcpN; $i++) {
        $v = TcpOnce $ip 80 $to
        if ($v -ge 0) { $tt.Add($v) } else { $tcpFail++ }
        if ($i -lt ($tcpN - 1)) { Start-Sleep -Milliseconds 60 }
    }
    if ($tt.Count -eq 0) { $port = 0 }
}
$si = St $it; $st = St $tt
$jit = $null
if ($it.Count -gt 1) { $d = 0.0; for ($i = 1; $i -lt $it.Count; $i++) { $d += [math]::Abs($it[$i] - $it[$i - 1]) }; $jit = $d / ($it.Count - 1) }
elseif ($it.Count -eq 1) { $jit = 0.0 }
$tj = $null
if ($tt.Count -gt 1) { $d = 0.0; for ($i = 1; $i -lt $tt.Count; $i++) { $d += [math]::Abs($tt[$i] - $tt[$i - 1]) }; $tj = $d / ($tt.Count - 1) }
[pscustomobject]@{
    IP = $ip; IcmpSent = $icmpN; IcmpRecv = $it.Count
    IcmpMin = $(if ($si) { $si.Min } else { $null }); IcmpAvg = $(if ($si) { $si.Avg } else { $null }); IcmpMax = $(if ($si) { $si.Max } else { $null })
    IcmpJit = $jit; TTL = $ttl
    TcpPort = $port; TcpSent = $tcpN; TcpRecv = $tt.Count
    TcpMin = $(if ($st) { $st.Min } else { $null }); TcpAvg = $(if ($st) { $st.Avg } else { $null }); TcpMed = $(if ($st) { $st.Med } else { $null })
    TcpP95 = $(if ($st) { $st.P95 } else { $null }); TcpMax = $(if ($st) { $st.Max } else { $null }); TcpStd = $(if ($st) { $st.Std } else { $null })
    TcpJit = $tj
}
'@

$HostWorker = @'
param($it, $cfg)
$h = $it.Host; $ip = $it.IP; $to = [int]$cfg.Timeout; $rep = [int]$cfg.Repeat
function Med($l) {
    $a = @($l | Sort-Object)
    if ($a.Count -eq 0) { return $null }
    if ($a.Count % 2 -eq 1) { return $a[[int](($a.Count - 1) / 2)] }
    return ($a[$a.Count / 2 - 1] + $a[$a.Count / 2]) / 2
}
$runs = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $rep; $i++) {
    $p = [DpNet]::Probe($h, $ip, 443, $true, $to)
    [void]$runs.Add($p)
    if (-not $p.TcpOk) { break }
    if ($i -lt $rep - 1) { Start-Sleep -Milliseconds 150 }
}
$err443 = ''
$main = $null
foreach ($r in $runs) { if ($r.TlsOk -and -not $main) { $main = $r } }
$port = 443
if (-not $main) {
    $err443 = [string]$runs[0].Error
    $p80 = [DpNet]::Probe($h, $ip, 80, $false, $to)
    if ($p80.TcpOk) { $main = $p80; $port = 80 } else { $main = $runs[0] }
}
$tlsL = @(); $ttfbL = @(); $totL = @()
foreach ($r in $runs) {
    if ($r.TlsOk) { $tlsL += $r.TlsMs }
    if ($r.HttpOk -and $r.TtfbMs -gt 0) { $ttfbL += $r.TtfbMs; $totL += $r.TotalMs }
}
$tlsM = Med $tlsL; $ttfbM = Med $ttfbL; $totM = Med $totL
if ($port -eq 80) { $ttfbM = $(if ($main.HttpOk) { $main.TtfbMs } else { $null }); $totM = $(if ($main.HttpOk) { $main.TotalMs } else { $null }) }
[pscustomobject]@{
    Host = $h; Port = $port; TcpOk = $main.TcpOk; TcpMs = $main.TcpMs
    TlsOk = $main.TlsOk; TlsMs = $tlsM; TlsProto = $main.TlsProto; Cipher = $main.Cipher
    CertSubject = $main.CertSubject; CertIssuer = $main.CertIssuer; CertSans = $main.CertSans; SanCount = $main.SanCount
    CertNotAfter = $main.CertNotAfter; CertDays = $main.CertDays; CertNameMatch = $main.CertNameMatch; CertChainOk = $main.CertChainOk
    CertKey = $main.CertKey; CertSig = $main.CertSig
    HttpOk = $main.HttpOk; TtfbMs = $ttfbM; TotalMs = $totM; Status = $main.Status
    Server = $main.Server; Location = $main.Location; ContentType = $main.ContentType; PoweredBy = $main.PoweredBy; CdnHint = $main.CdnHint
    Hsts = $main.Hsts; Csp = $main.Csp; Xfo = $main.Xfo; Xcto = $main.Xcto; RefPol = $main.RefPol
    Error = $(if ($port -eq 80 -and $err443) { '443: ' + $err443 } else { [string]$main.Error })
}
'@

$RdapWorker = @'
param($n, $x)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $c = (Invoke-WebRequest -Uri ("https://rdap.org/domain/" + $n) -UseBasicParsing -TimeoutSec 20 -Headers @{ Accept = 'application/rdap+json, application/json' } -ErrorAction Stop).Content
    $j = $c | ConvertFrom-Json
    $reg = ''; $created = ''; $expires = ''; $updated = ''
    foreach ($e in @($j.events)) {
        if ($e.eventAction -eq 'registration') { $created = ([string]$e.eventDate).Substring(0, [math]::Min(10, ([string]$e.eventDate).Length)) }
        if ($e.eventAction -eq 'expiration') { $expires = ([string]$e.eventDate).Substring(0, [math]::Min(10, ([string]$e.eventDate).Length)) }
        if ($e.eventAction -eq 'last changed') { $updated = ([string]$e.eventDate).Substring(0, [math]::Min(10, ([string]$e.eventDate).Length)) }
    }
    foreach ($en in @($j.entities)) {
        if (@($en.roles) -contains 'registrar') {
            try { foreach ($f in $en.vcardArray[1]) { if ($f[0] -eq 'fn') { $reg = [string]$f[3] } } } catch {}
        }
    }
    $ns = @(@($j.nameservers) | ForEach-Object { ([string]$_.ldhName).ToLower() })
    [pscustomobject]@{ Name = $n; Found = $true; Registrar = $reg; Created = $created; Expires = $expires; Updated = $updated; NS = ($ns -join ' '); Status = (@($j.status) -join ',') }
} catch {
    [pscustomobject]@{ Name = $n; Found = $false; Registrar = ''; Created = ''; Expires = ''; Updated = ''; NS = ''; Status = '' }
}
'@

$MonWorker = @'
param($it, $cfg)
$ip = $it.IP; $to = [int]$cfg.Timeout
$tcp = -1
if ([bool]$cfg.Net) { $tcp = [DpNet]::TcpConnect($ip, [int]$it.Port, $to) }
$ic = -1
try {
    $p = New-Object System.Net.NetworkInformation.Ping
    $r = $p.Send($ip, $to)
    if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $ic = [double]$r.RoundtripTime }
    $p.Dispose()
} catch {}
[pscustomobject]@{ Host = $it.Host; Tcp = $tcp; Icmp = $ic }
'@

# ---------------------------------------------------------- kelime listeleri
$WL_quick = 'www mail webmail smtp pop pop3 imap ftp sftp ns ns1 ns2 ns3 mx mx1 mx2 api dev test staging stage prod admin portal blog shop store cdn static assets img images media vpn remote secure login auth sso app apps m mobile git gitlab docs help support status autodiscover autoconfig cpanel whm intranet crm erp db beta demo old new forum wiki news' -split '\s+'

$WL_std_extra = 'web web1 web2 www1 www2 www3 server srv host cloud cloud1 owa exchange outlook office lync sip meet video chat mail1 mail2 mail3 smtp1 smtp2 relay mailer newsletter email bounce webdisk webdav dns dns1 dns2 gateway gw proxy firewall router fw monitor monitoring nagios zabbix grafana kibana elastic prometheus jenkins ci cd build jira confluence bitbucket svn repo registry docker k8s kubernetes rancher vault consul s3 storage backup bak files file download downloads upload uploads data database sql mysql postgres mongo redis oracle mssql ldap ad radius vpn2 ssl cert pki ntp time id account accounts my user users member members client clients customer customers partner partners vendor supplier b2b b2c pay payment payments billing invoice checkout cart order orders tickets ticket helpdesk servicedesk survey form forms events event calendar cal jobs career careers hr people press live stream streaming play player podcast photos gallery img1 img2 static1 static2 cdn1 cdn2 edge origin lb lb1 api2 api-v1 apiv1 v1 v2 v3 graph graphql rest ws wss socket sandbox qa uat preprod pre-prod internal int ext external extranet secure2 test1 test2 dev1 dev2 stg alpha legacy archive en tr de fr es ru us uk eu asia mobile-api wap amp app1 app2 landing promo campaign go link links url short click track tracking analytics stats metrics log logs report reports dashboard panel control cp plesk webmin phpmyadmin pma testing demo2 lab labs research learn lms edu academy training moodle shop2 store2 market marketplace mall catalog search find ik bilgi destek musteri sube kurumsal eposta ebys obs sanal' -split '\s+'

$WL_deep_extra = 'bastion jump jumpbox ssh rdp rdweb citrix vdi horizon vcenter esx esxi proxmox nas san synology qnap printer print cam camera cctv nvr iot mqtt sensor device scada plc voip pbx asterisk 3cx webrtc teams zoom slack mattermost rocket nextcloud owncloud seafile sharepoint onedrive drive docs2 office365 o365 sts adfs fs federation saml oauth oidc idp keycloak okta sso2 mfa 2fa totp swagger openapi gateway2 api-gateway apigw edge1 edge2 origin1 origin2 ingress egress mesh istio envoy traefik nginx apache haproxy varnish squid cache cache1 cache2 mq rabbitmq kafka zookeeper etcd nats solr sonar sonarqube nexus artifactory harbor argocd flux tekton drone teamcity bamboo gitea gogs phabricator gerrit trac redmine bugzilla mantis sentry rollbar newrelic datadog splunk loki tempo jaeger zipkin pagerduty opsgenie statuspage uptime ping pingdom speedtest' -split '\s+'
$WL_prefixes = 'mail smtp pop imap ns dns web www srv server vpn ftp api app dev test db node host cdn proxy lb mx git backup' -split '\s+'
$WL_rec = 'www api dev staging test admin internal mail cdn app stg qa' -split '\s+'

$TLDs = 'com net org info biz co io app dev me tv cc us uk de fr es it nl ru cn jp in br au ca ch at be se no dk fi pl pt gr tr com.tr net.tr org.tr gen.tr co.uk org.uk eu xyz online site shop store tech cloud ai' -split '\s+'
$EnvTok = 'dev','test','qa','uat','stage','staging','stg','prod','production','preprod','sandbox','demo','beta','int','internal','canary'
$SensitiveRx = '(^|[.-])(dev|test|qa|uat|stage|staging|stg|preprod|sandbox|internal|intranet|admin|vpn|jenkins|gitlab|git|svn|jira|confluence|grafana|kibana|phpmyadmin|pma|cpanel|whm|plesk|rdp|ssh|bastion|jump|debug|backup|bak|old|beta|demo|monitor|nagios|zabbix|sonar|nexus|artifactory|vault|consul|ldap|ad|radius)([0-9]*)([.-]|$)'
$CdnRx = 'cloudflare|akamai|fastly|cloudfront|amazon|google|microsoft|azure|incapsula|imperva|edgecast|verizon|stackpath|bunny|cdn77|sucuri|netlify|vercel|github|limelight|cachefly|gcore|keycdn|quantil|alibaba|tencent'

# ---------------------------------------------------------------- mod ayarlari
function Get-ModeConfig([string]$k) {
    switch ($k) {
        '1' { return @{ Key = '1'; Name = 'HIZLI';    Web = $false; Tld = $false; Perm = 0; PermCap = 0;    Rec = 0;  Words = 1; Icmp = 3; Tcp = 3; Timeout = 1500; ProbeCap = 30;  Repeat = 1; Rounds = 0; Precise = 3;  Trace = 0; Resolvers = $false; Threads = 60 } }
        '3' { return @{ Key = '3'; Name = 'DERIN';    Web = $true;  Tld = $true;  Perm = 2; PermCap = 3000; Rec = 60; Words = 3; Icmp = 8; Tcp = 8; Timeout = 3000; ProbeCap = 600; Repeat = 3; Rounds = 2; Precise = 15; Trace = 3; Resolvers = $true;  Threads = 60 } }
        default { return @{ Key = '2'; Name = 'STANDART'; Web = $true;  Tld = $false; Perm = 1; PermCap = 800;  Rec = 15; Words = 2; Icmp = 5; Tcp = 5; Timeout = 2500; ProbeCap = 250; Repeat = 1; Rounds = 1; Precise = 8;  Trace = 2; Resolvers = $true;  Threads = 60 } }
    }
}
function Ask-YN([string]$q, [bool]$def) {
    $d = $(if ($def) { 'E' } else { 'H' })
    $a = (Read-Host ("    {0} (E/H) [{1}]" -f $q, $d)).Trim().ToUpper()
    if ($a -eq '') { return $def }
    return ($a -eq 'E' -or $a -eq 'Y')
}
function Ask-Int([string]$q, [int]$def, [int]$min, [int]$max) {
    $a = (Read-Host ("    {0} [{1}]" -f $q, $def)).Trim()
    $v = 0
    if ([int]::TryParse($a, [ref]$v)) { return [math]::Max($min, [math]::Min($max, $v)) }
    return $def
}
function Get-CustomConfig {
    $c = Get-ModeConfig '2'
    $c.Key = '4'; $c.Name = 'OZEL'
    Say ''
    Say '  Ozel mod ayarlari (Enter = varsayilan):' 'White'
    $c.Web = Ask-YN 'Sertifika/pasif DNS web kaynaklari' $true
    $c.Tld = Ask-YN 'Benzer TLD varyasyonlari + RDAP iliski analizi' $false
    $pm = Ask-Int 'Permutasyon seviyesi 0=yok 1=temel 2=genis' 1 0 2
    $c.Perm = $pm; if ($pm -eq 0) { $c.PermCap = 0 } elseif ($pm -eq 1) { $c.PermCap = 800 } else { $c.PermCap = 3000 }
    $c.Words = Ask-Int 'Sozluk seviyesi 1=kucuk 2=orta 3=buyuk' 2 1 3
    $c.Rec = Ask-Int 'Ozyinelemeli (alt-alt) tarama host sayisi' 15 0 200
    $c.Icmp = Ask-Int 'ICMP paket sayisi / IP' 5 1 30
    $c.Tcp = Ask-Int 'TCP olcum sayisi / IP' 5 1 30
    $c.Repeat = Ask-Int 'TLS/HTTP tekrar sayisi / host' 1 1 7
    $c.ProbeCap = Ask-Int 'TLS/HTTP testi yapilacak en fazla host' 250 0 2000
    $c.Rounds = Ask-Int 'Sertifika SAN genisleme turu' 1 0 3
    $c.Precise = Ask-Int 'Hassas (seri) olcum IP sayisi' 8 0 40
    $c.Trace = Ask-Int 'Yol analizi (tracert) hedef sayisi' 2 0 6
    $c.Timeout = Ask-Int 'Zaman asimi (ms)' 2500 500 10000
    return $c
}

# ------------------------------------------------------------ ag ortami
$VpnRx = 'TAP-|TUN|WireGuard|OpenVPN|AnyConnect|Fortinet|FortiClient|Nord|Proton|Express|Surfshark|WARP|Cloudflare|ZeroTier|Tailscale|VPN|Pulse|GlobalProtect|Hamachi|SoftEther|Check Point|Sophos|Mullvad|Windscribe|Private Internet|Wintun|Zscaler|Netskope'

function Get-NetEnv {
    $e = @{ Adapters = (New-Object System.Collections.ArrayList); Gateways = @(); Dns = @(); Vpn = @(); Proxy = ''; Pub = $null; Local = '' }
    try {
        foreach ($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($n.OperationalStatus -ne 'Up') { continue }
            $t = [string]$n.NetworkInterfaceType
            if ($t -eq 'Loopback') { continue }
            $ipp = $n.GetIPProperties()
            $v4 = @($ipp.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.Address.ToString() })
            $gw = @($ipp.GatewayAddresses | ForEach-Object { $_.Address.ToString() } | Where-Object { $_ -ne '0.0.0.0' -and $_ -ne '::' })
            $dn = @($ipp.DnsAddresses | ForEach-Object { $_.ToString() } | Where-Object { $_ -notmatch '^fec0' })
            $desc = $n.Name + ' / ' + $n.Description
            $pseudo = ($desc -match 'Teredo|ISATAP|6to4|Pseudo|Loopback|Bluetooth')
            $isVpn = (-not $pseudo) -and (($desc -match $VpnRx) -or $t -eq 'Tunnel' -or $t -eq 'Ppp')
            [void]$e.Adapters.Add([pscustomobject]@{ Name = $n.Name; Desc = $n.Description; Type = $t; IPv4 = ($v4 -join ','); Gw = ($gw -join ','); Dns = ($dn -join ','); Vpn = $isVpn; Speed = $n.Speed })
            if ($isVpn) { $e.Vpn += $desc }
            if ($gw.Count -gt 0) { $e.Gateways += $gw }
            if ($gw.Count -gt 0 -and $dn.Count -gt 0) { $e.Dns += $dn }
            if ($gw.Count -gt 0 -and $v4.Count -gt 0 -and -not $e.Local) { $e.Local = $v4[0] }
        }
    } catch {}
    $e.Gateways = @($e.Gateways | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -Unique)
    $e.Dns = @($e.Dns | Select-Object -Unique)
    try {
        $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $pe = (Get-ItemProperty -Path $k -Name ProxyEnable -ErrorAction Stop).ProxyEnable
        $ps = (Get-ItemProperty -Path $k -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
        $pac = (Get-ItemProperty -Path $k -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
        if ($pe -eq 1 -and $ps) { $e.Proxy = "Sistem proxy: $ps" }
        if ($pac) { $e.Proxy = (($e.Proxy + " PAC: $pac").Trim()) }
    } catch {}
    try {
        $e.Pub = Invoke-RestMethod -Uri 'http://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon,isp,org,as,query,proxy,hosting,mobile' -TimeoutSec 8 -ErrorAction Stop
        if ($e.Pub.status -ne 'success') { $e.Pub = $null }
    } catch {}
    return $e
}

# ------------------------------------------------------------ DNS kayitlari
function Collect-DnsRecords([string]$d, $cfg) {
    $info = @{ Spf = $null; SpfAll = ''; Dmarc = $null; DmarcPolicy = ''; Caa = $null; Dnssec = $null; Ns = @(); SerialMismatch = $false; Mx = 0; Root = @(); Ok = $true; Resolvers = @() }
    Add-Cand $d 'Ana'
    Add-Cand "www.$d" 'DNS'
    if (-not $script:HasRDN) {
        Say '     Resolve-DnsName bulunamadi; DNS kayit analizi atlandi (sozluk taramasi devam eder).' 'DarkYellow'
        $info.Ok = $false
        return $info
    }
    $A = Get-Dns $d 'A'; $AAAA = Get-Dns $d 'AAAA'; $MX = Get-Dns $d 'MX'; $NS = Get-Dns $d 'NS'
    $TXT = Get-Dns $d 'TXT'; $SOA = Get-Dns $d 'SOA'; $CN = Get-Dns $d 'CNAME'; $wwwC = Get-Dns "www.$d" 'CNAME'
    $CAA = Get-Dns $d 'CAA'; $DNSKEY = Get-Dns $d 'DNSKEY'

    Say ("     A      : " + $(if ($A -and $A.Count) { ($A | ForEach-Object { $_.IPAddress }) -join ', ' } else { '-' })) 'Gray'
    Say ("     AAAA   : " + $(if ($AAAA -and $AAAA.Count) { ($AAAA | ForEach-Object { $_.IPAddress }) -join ', ' } else { '-' })) 'Gray'
    Say ("     NS     : " + $(if ($NS -and $NS.Count) { ($NS | ForEach-Object { $_.NameHost }) -join ', ' } else { '-' })) 'Gray'
    Say ("     MX     : " + $(if ($MX -and $MX.Count) { ($MX | ForEach-Object { "$($_.NameExchange) [$($_.Preference)]" }) -join ', ' } else { '-' })) 'Gray'
    if ($SOA -and $SOA.Count) { Say ("     SOA    : birincil={0}  yonetici={1}  seri={2}  TTL={3}" -f $SOA[0].PrimaryServer, $SOA[0].NameAdministrator, $SOA[0].SerialNumber, $SOA[0].TTL) 'Gray' }
    $info.Mx = $(if ($MX) { $MX.Count } else { 0 })
    $info.Root = @($A | ForEach-Object { $_.IPAddress })

    foreach ($r in @($MX)) { Add-Cand $r.NameExchange 'MX' }
    foreach ($r in @($NS)) { Add-Cand $r.NameHost 'NS' }
    foreach ($r in @($SOA)) { Add-Cand $r.PrimaryServer 'NS' }
    foreach ($r in @($CN)) { Add-Cand $r.NameHost 'CNAME' }
    foreach ($r in @($wwwC)) { Add-Cand $r.NameHost 'CNAME' }

    # SPF
    foreach ($r in @($TXT)) {
        $s = ($r.Strings -join '')
        if ($s -match '^v=spf1') {
            $info.Spf = $s
            $m = [regex]::Match($s, '\s([+\-~?]?)all\s*$')
            if ($m.Success) { $info.SpfAll = $m.Groups[1].Value; if (-not $info.SpfAll) { $info.SpfAll = '+' } }
            foreach ($mm in [regex]::Matches($s, '(?:include:|redirect=|a:|mx:|exists:)([A-Za-z0-9._-]+)')) { Add-Cand $mm.Groups[1].Value 'SPF' }
        }
    }
    # DMARC
    $dm = Get-Dns "_dmarc.$d" 'TXT'
    foreach ($r in @($dm)) {
        $s = ($r.Strings -join '')
        if ($s -match '^v=DMARC1') {
            $info.Dmarc = $s
            $pm = [regex]::Match($s, 'p=(\w+)')
            if ($pm.Success) { $info.DmarcPolicy = $pm.Groups[1].Value.ToLower() }
            foreach ($mm in [regex]::Matches($s, '@([a-z0-9.-]+)')) { Add-Cand $mm.Groups[1].Value 'DMARC' }
        }
    }
    foreach ($srv in '_autodiscover._tcp', '_sip._tls', '_sipfederationtls._tcp', '_xmpp-server._tcp', '_imaps._tcp', '_submission._tcp', '_caldavs._tcp') {
        foreach ($r in @((Get-Dns "$srv.$d" 'SRV'))) { Add-Cand $r.NameTarget 'DNS' }
    }
    $info.Caa = $(if ($null -eq $CAA) { $null } else { ($CAA.Count -gt 0) })
    $info.Dnssec = $(if ($null -eq $DNSKEY) { $null } else { ($DNSKEY.Count -gt 0) })

    Say ("     SPF    : " + $(if ($info.Spf) { "VAR  (all-mekanizmasi: '" + $info.SpfAll + "all')" } else { 'YOK' })) $(if ($info.Spf) { 'Green' } else { 'DarkYellow' })
    Say ("     DMARC  : " + $(if ($info.Dmarc) { "VAR  (politika: p=" + $info.DmarcPolicy + ")" } else { 'YOK' })) $(if ($info.Dmarc) { 'Green' } else { 'DarkYellow' })
    Say ("     CAA    : " + $(if ($null -eq $info.Caa) { 'sorgulanamadi' } elseif ($info.Caa) { 'VAR' } else { 'YOK' })) 'Gray'
    Say ("     DNSSEC : " + $(if ($null -eq $info.Dnssec) { 'sorgulanamadi' } elseif ($info.Dnssec) { 'ACIK (DNSKEY bulundu)' } else { 'KAPALI' })) 'Gray'

    # yetkili NS sunuculari: yanit suresi + SOA seri tutarliligi
    if ($NS -and $NS.Count -gt 0) {
        Say '' 'Gray'
        Say '     Yetkili isim sunuculari (dogrudan sorgu):' 'White'
        $serials = @{}
        foreach ($nsr in @($NS | Select-Object -First 8)) {
            $nsName = [string]$nsr.NameHost
            $nsIp = $null
            try { $nsIp = ([System.Net.Dns]::GetHostAddresses($nsName) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString } catch {}
            $ms = $null; $ser = $null
            if ($nsIp) {
                $best = $null
                for ($k = 0; $k -lt 3; $k++) {
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    $rr = Get-Dns $d 'SOA' $nsIp
                    $sw.Stop()
                    if ($rr -and $rr.Count -gt 0) {
                        $ser = $rr[0].SerialNumber
                        if ($null -eq $best -or $sw.Elapsed.TotalMilliseconds -lt $best) { $best = $sw.Elapsed.TotalMilliseconds }
                    }
                }
                $ms = $best
            }
            if ($null -ne $ser) { $serials["$ser"] = 1 }
            $info.Ns += [pscustomobject]@{ Name = $nsName; IP = $nsIp; Ms = $ms; Serial = $ser }
            Say ("       {0,-34} {1,-16} {2,9} ms   seri={3}" -f (Cut $nsName 34), $nsIp, (Fmt-Ms $ms), $ser) $(if ($null -eq $ms) { 'DarkYellow' } else { 'Gray' })
        }
        if ($serials.Count -gt 1) { $info.SerialMismatch = $true; Say '       UYARI: NS sunuculari farkli SOA seri numarasi donduruyor (senkron sorunu olabilir).' 'DarkYellow' }
    }

    # cozucu karsilastirmasi
    if ($cfg.Resolvers) {
        Say '' 'Gray'
        Say '     DNS cozucu karsilastirmasi (ana alan A kaydi):' 'White'
        $sets = @()
        foreach ($rs in @(@{ N = 'Sistem varsayilani'; S = '' }, @{ N = 'Cloudflare 1.1.1.1'; S = '1.1.1.1' }, @{ N = 'Google 8.8.8.8'; S = '8.8.8.8' }, @{ N = 'Quad9 9.9.9.9'; S = '9.9.9.9' })) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $rr = Get-Dns $d 'A' $rs.S
            $sw.Stop()
            $ips = @($rr | ForEach-Object { $_.IPAddress })
            $info.Resolvers += [pscustomobject]@{ Name = $rs.N; Ms = $sw.Elapsed.TotalMilliseconds; IPs = ($ips -join ' '); Ok = ($ips.Count -gt 0) }
            if ($ips.Count -gt 0) { $sets += , $ips }
            Say ("       {0,-20} {1,8} ms   {2}" -f $rs.N, (Fmt-Ms $sw.Elapsed.TotalMilliseconds), $(if ($ips.Count) { $ips -join ', ' } else { 'yanit yok' })) $(if ($ips.Count) { 'Gray' } else { 'DarkYellow' })
        }
        if ($sets.Count -ge 2) {
            $overlap = $false
            for ($i = 1; $i -lt $sets.Count; $i++) { foreach ($ip in $sets[$i]) { if ($sets[0] -contains $ip) { $overlap = $true } } }
            if (-not $overlap) { Say '       NOT: Cozuculer farkli IP donduruyor (CDN/geo-DNS olagan; DNS yonlendirmesi olasiligini da dusunun).' 'DarkYellow'; $info.ResolverDiff = $true }
        }
    }
    return $info
}

# ------------------------------------------------------------ web kaynaklari
function Run-WebSources([string]$d) {
    $srcs = @(
        @{ N = 'crt.sh';          Tag = 'CT';  T = 60; U = "https://crt.sh/?q=%25.$d&output=json" },
        @{ N = 'CertSpotter';     Tag = 'CS';  T = 40; U = "https://api.certspotter.com/v1/issuances?domain=$d&include_subdomains=true&expand=dns_names" },
        @{ N = 'Anubis (jldc)';   Tag = 'AN';  T = 40; U = "https://jldc.me/anubis/subdomains/$d" },
        @{ N = 'HackerTarget';    Tag = 'HT';  T = 30; U = "https://api.hackertarget.com/hostsearch/?q=$d" },
        @{ N = 'AlienVault OTX';  Tag = 'OTX'; T = 40; U = "https://otx.alienvault.com/api/v1/indicators/domain/$d/passive_dns" },
        @{ N = 'RapidDNS';        Tag = 'RD';  T = 40; U = "https://rapiddns.io/subdomain/${d}?full=1" },
        @{ N = 'urlscan.io';      Tag = 'US';  T = 40; U = "https://urlscan.io/api/v1/search/?q=domain:$d&size=100" },
        @{ N = 'Wayback Machine'; Tag = 'WB';  T = 60; U = "https://web.archive.org/cdx/search/cdx?url=*.$d&output=text&fl=original&collapse=urlkey&limit=15000" }
    )
    $web = Invoke-Pool -Items $srcs -Script $WebWorker -Threads 8 -Label 'Web kaynaklari'
    $rx = '(?i)(?:[a-z0-9_*\-]+\.)*' + [regex]::Escape($d)
    $stats = @()
    foreach ($tag in ($srcs | ForEach-Object { $_.Tag })) {
        $w = $web | Where-Object { $_.Tag -eq $tag } | Select-Object -First 1
        $name = ($srcs | Where-Object { $_.Tag -eq $tag }).N
        if (-not $w -or -not $w.Content) {
            $why = $(if ($w -and $w.Err) { Cut $w.Err 60 } else { 'yanit yok' })
            $stats += [pscustomobject]@{ Name = $name; Tag = $tag; Ok = $false; New = 0; Total = 0; Sec = $(if ($w) { $w.Sec } else { 0 }); Note = $why }
            continue
        }
        $c = $w.Content -replace '\\n', ' ' -replace '%2[fF]', '/'
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        $before = $script:Cand.Count
        foreach ($m in [regex]::Matches($c, $rx)) {
            $v = $m.Value.ToLower()
            if ($seen.Add($v)) { Add-Cand $v $tag }
        }
        $stats += [pscustomobject]@{ Name = $name; Tag = $tag; Ok = $true; New = ($script:Cand.Count - $before); Total = $seen.Count; Sec = $w.Sec; Note = '' }
    }
    return , $stats
}

# ------------------------------------------------------------ permutasyon
function New-Permutations($names, [string]$d, [int]$level, [int]$cap) {
    $out = New-Object 'System.Collections.Generic.HashSet[string]'
    $suffix = '.' + $d
    $core = 'dev', 'test', 'qa', 'uat', 'staging', 'prod'
    $count = 0
    foreach ($n in $names) {
        if ($out.Count -ge $cap) { break }
        if (-not $n.EndsWith($suffix)) { continue }
        $sub = $n.Substring(0, $n.Length - $suffix.Length)
        if (-not $sub) { continue }
        $labels = $sub -split '\.'
        $first = $labels[0]
        $rest = ''
        if ($labels.Count -gt 1) { $rest = '.' + (($labels | Select-Object -Skip 1) -join '.') }
        $mm = [regex]::Matches($first, '\d+')
        if ($mm.Count -gt 0) {
            $m = $mm[$mm.Count - 1]
            if ($m.Length -le 6) {
                $num = [long]$m.Value
                foreach ($delta in -2, -1, 1, 2, 3) {
                    $nn = $num + $delta
                    if ($nn -lt 0) { continue }
                    $ns = ([string]$nn).PadLeft($m.Length, '0')
                    [void]$out.Add(($first.Substring(0, $m.Index) + $ns + $first.Substring($m.Index + $m.Length) + $rest + $suffix))
                }
            }
        }
        $toks = $first -split '-'
        for ($i = 0; $i -lt $toks.Count; $i++) {
            if ($script:EnvTok -contains $toks[$i]) {
                foreach ($o in $core) {
                    if ($o -eq $toks[$i]) { continue }
                    $t2 = @($toks); $t2[$i] = $o
                    [void]$out.Add((($t2 -join '-') + $rest + $suffix))
                }
            }
        }
        if ($level -ge 2 -and $labels.Count -le 2) {
            foreach ($o in $core + 'int', 'beta') {
                [void]$out.Add("$first-$o$rest$suffix")
                [void]$out.Add("$o-$first$rest$suffix")
            }
        }
    }
    return , @($out | Select-Object -First $cap)
}

# ------------------------------------------------------------ satir fabrikasi
function New-Row([string]$name, [string]$scope, $src, $res) {
    $ips = @(); $dnsMs = $null
    if ($res) { $ips = @($res.IPs); $dnsMs = $res.DnsMs }
    $v4 = @($ips | Where-Object { $_ -notmatch ':' })
    $v6 = @($ips | Where-Object { $_ -match ':' })
    $main = $null
    if ($v4.Count -gt 0) { $main = $v4[0] } elseif ($v6.Count -gt 0) { $main = $v6[0] }
    return [pscustomobject]@{
        Host = $name; Tur = $scope; Kaynak = (($src | Sort-Object) -join ','); IP = $main; TumIPler = ($ips -join ' '); IPSayisi = $ips.Count
        IPv6 = ($v6.Count -gt 0); DnsMs = $dnsMs
        TcpPort = $null; TcpMin = $null; TcpOrt = $null; TcpMed = $null; TcpP95 = $null; TcpMax = $null; TcpStd = $null; TcpKayip = $null
        IcmpOrt = $null; IcmpMin = $null; IcmpMax = $null; IcmpJit = $null; IcmpKayip = $null; TTL = $null; Hop = $null
        TlsMs = $null; TtfbMs = $null; ToplamMs = $null; HttpPort = $null; Http = $null; Sunucu = ''; CDN = ''; Yonlendirme = ''; ContentType = ''
        TlsSurum = ''; Sifre = ''; SertKonu = ''; SertVeren = ''; SertGun = $null; SertBitis = ''; SertUyum = $null; SertZincir = $null; SertAnahtar = ''; SertImza = ''; SANsayisi = $null; SANlar = ''
        HSTS = $null; CSP = $null; XFO = $null; XCTO = $null; RefPol = $null; GuvPuan = $null
        Ulke = ''; UlkeKodu = ''; Sehir = ''; Lat = $null; Lon = $null; ISP = ''; ASN = ''; Anycast = $false; Hosting = $null; ProxyIP = $null; PTR = ''; MesafeKm = $null
        CNAME = ''; Dangling = $false
        Kayitci = ''; Olusturma = ''; Bitis = ''; Iliski = ''; IliskiPuan = $null
        Hassas = $false; Probed = $false; IcmpSupheli = $false; Imkansiz = $false; GercekMs = $null; Yontem = '-'
        Uyari = ''; Durum = $(if ($main) { 'DNS tamam' } else { 'DNS yok' }); Hata = ''
    }
}

# ------------------------------------------------------------ olcum
function Pick-Ips($row) {
    $all = @($row.TumIPler -split ' ' | Where-Object { $_ })
    $v4 = @($all | Where-Object { $_ -notmatch ':' } | Select-Object -First 4)
    if ($v4.Count -gt 0) { return $v4 }
    return @($all | Select-Object -First 1)
}
function Choose-BestIp($row, $ipMap) {
    $best = $null; $bv = [double]::MaxValue
    foreach ($ip in @(Pick-Ips $row)) {
        $s = $ipMap[$ip]
        if (-not $s) { continue }
        $v = $null
        if ($null -ne $s.TcpAvg) { $v = [double]$s.TcpAvg } elseif ($null -ne $s.IcmpAvg) { $v = [double]$s.IcmpAvg + 1000 }
        if ($null -ne $v -and $v -lt $bv) { $bv = $v; $best = $ip }
    }
    if ($best) { $row.IP = $best }
}
function Apply-IpStats($row, $s) {
    if (-not $s) { return }
    $row.TcpPort = $s.TcpPort
    if ($s.TcpRecv -gt 0) {
        $row.TcpMin = $s.TcpMin; $row.TcpOrt = $s.TcpAvg; $row.TcpMed = $s.TcpMed; $row.TcpP95 = $s.TcpP95; $row.TcpMax = $s.TcpMax; $row.TcpStd = $s.TcpStd
    }
    if ($s.TcpSent -gt 0) { $row.TcpKayip = [math]::Round(100.0 * ($s.TcpSent - $s.TcpRecv) / $s.TcpSent, 0) }
    if ($s.IcmpRecv -gt 0) {
        $row.IcmpOrt = $s.IcmpAvg; $row.IcmpMin = $s.IcmpMin; $row.IcmpMax = $s.IcmpMax; $row.IcmpJit = $s.IcmpJit
    }
    if ($s.IcmpSent -gt 0) { $row.IcmpKayip = [math]::Round(100.0 * ($s.IcmpSent - $s.IcmpRecv) / $s.IcmpSent, 0) }
    if ($s.TTL) {
        $row.TTL = $s.TTL
        if ($s.TTL -le 64) { $init = 64 } elseif ($s.TTL -le 128) { $init = 128 } else { $init = 255 }
        $row.Hop = $init - $s.TTL
    }
}
function Apply-Probe($row, $p) {
    $row.Probed = $true
    $row.HttpPort = $p.Port
    $row.Hata = [string]$p.Error
    if ($p.TlsOk) {
        $row.TlsMs = $p.TlsMs; $row.TlsSurum = $p.TlsProto; $row.Sifre = $p.Cipher
        $row.SertKonu = $p.CertSubject; $row.SertVeren = $p.CertIssuer; $row.SertGun = $p.CertDays; $row.SertBitis = $p.CertNotAfter
        $row.SertUyum = [bool]$p.CertNameMatch; $row.SertZincir = [bool]$p.CertChainOk
        $row.SertAnahtar = $p.CertKey; $row.SertImza = $p.CertSig; $row.SANsayisi = $p.SanCount
        $row.SANlar = Cut ([string]$p.CertSans) 4000
    }
    if ($p.HttpOk) {
        $row.Http = $p.Status; $row.TtfbMs = $p.TtfbMs; $row.ToplamMs = $p.TotalMs
        $row.Sunucu = Cut ([string]$p.Server) 40; $row.CDN = [string]$p.CdnHint
        $row.Yonlendirme = Cut ([string]$p.Location) 120; $row.ContentType = Cut ([string]$p.ContentType) 40
        if ($p.Port -eq 443) {
            $row.HSTS = [bool]$p.Hsts; $row.CSP = [bool]$p.Csp; $row.XFO = [bool]$p.Xfo; $row.XCTO = [bool]$p.Xcto; $row.RefPol = [bool]$p.RefPol
            $row.GuvPuan = ([int]$p.Hsts + [int]$p.Csp + [int]$p.Xfo + [int]$p.Xcto + [int]$p.RefPol)
        }
    }
}

function Measure-Rows($rows, $cfg, $ipMap, $probeState) {
    $need = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $rows) {
        if ($r.IP) { foreach ($ip in @(Pick-Ips $r)) { if (-not $ipMap.ContainsKey($ip)) { [void]$need.Add($ip) } } }
    }
    if ($need.Count -gt 0) {
        $icfg = @{ Icmp = $cfg.Icmp; Tcp = $cfg.Tcp; Timeout = $cfg.Timeout; Net = $script:HasNet }
        $res = Invoke-Pool -Items @($need) -Script $IpWorker -Threads 30 -Extra $icfg -Label 'IP gecikme'
        foreach ($x in $res) { $ipMap[$x.IP] = $x }
    }
    foreach ($r in $rows) {
        if (-not $r.IP) { continue }
        Choose-BestIp $r $ipMap
        Apply-IpStats $r $ipMap[$r.IP]
    }
    if ($script:HasNet -and $cfg.ProbeCap -gt 0) {
        $cand = @($rows | Where-Object { $_.IP -and -not $_.Probed })
        $room = $cfg.ProbeCap - $probeState.Count
        if ($room -gt 0 -and $cand.Count -gt 0) {
            $ord = @($cand | Sort-Object @{ Expression = { if ($_.Tur -eq 'Ana') { 0 } elseif ($_.Host -like 'www.*') { 1 } elseif ($_.Tur -eq 'Alt') { 2 } elseif ($_.Tur -eq 'TLD') { 3 } else { 4 } } }, Host | Select-Object -First $room)
            $items = @($ord | ForEach-Object { @{ Host = $_.Host; IP = $_.IP } })
            $hc = @{ Timeout = $cfg.Timeout; Repeat = $cfg.Repeat }
            $pr = Invoke-Pool -Items $items -Script $HostWorker -Threads 24 -Extra $hc -Label 'TLS/HTTP testi'
            $pm = @{}
            foreach ($p in $pr) { $pm[$p.Host] = $p }
            foreach ($r in $ord) {
                $r.Probed = $true
                if ($pm.ContainsKey($r.Host)) { Apply-Probe $r $pm[$r.Host] }
            }
            $probeState.Count += $ord.Count
        }
    }
}

function Run-Precision($rows, $cfg, $ipMap, [string]$d) {
    if ($cfg.Precise -le 0) { return @() }
    $pick = New-Object System.Collections.ArrayList
    foreach ($h in @($d, "www.$d")) {
        $r = $rows | Where-Object { $_.Host -eq $h -and $_.IP } | Select-Object -First 1
        if ($r -and $pick -notcontains $r.IP) { [void]$pick.Add($r.IP) }
    }
    $grp = @($rows | Where-Object { $_.IP } | Group-Object IP | Sort-Object Count -Descending)
    foreach ($g in $grp) {
        if ($pick.Count -ge $cfg.Precise) { break }
        if ($pick -notcontains $g.Name) { [void]$pick.Add($g.Name) }
    }
    $pick = @($pick | Select-Object -First $cfg.Precise)
    if ($pick.Count -eq 0) { return @() }
    $icfg = @{ Icmp = 10; Tcp = 12; Timeout = $cfg.Timeout; Net = $script:HasNet }
    $res = Invoke-Pool -Items $pick -Script $IpWorker -Threads 1 -Extra $icfg -Label 'Hassas (seri) olcum'
    foreach ($x in $res) { $ipMap[$x.IP] = $x }
    $set = @{}
    foreach ($p in $pick) { $set[$p] = $true }
    foreach ($r in $rows) {
        if ($r.IP -and $set.ContainsKey($r.IP)) { Apply-IpStats $r $ipMap[$r.IP]; $r.Hassas = $true }
    }
    return $pick
}

# ------------------------------------------------------------ geo-IP
function Get-GeoMap($ips) {
    $map = @{}
    $pub = @($ips | Where-Object { $_ -and $_ -notmatch '^(10\.|127\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)' -and $_ -notmatch '^(::1|fe80|fc|fd)' } | Select-Object -Unique)
    for ($i = 0; $i -lt $pub.Count; $i += 100) {
        $chunk = @($pub[$i..([math]::Min($i + 99, $pub.Count - 1))])
        $body = '[' + (($chunk | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
        for ($try = 0; $try -lt 3; $try++) {
            try {
                $resp = Invoke-RestMethod -Method Post -Uri 'http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,isp,org,as,asname,reverse,hosting,proxy,query' -Body $body -ContentType 'application/json' -TimeoutSec 25 -ErrorAction Stop
                foreach ($g in $resp) { if ($g.status -eq 'success') { $map[$g.query] = $g } }
                break
            } catch { Start-Sleep -Seconds 4 }
        }
    }
    return $map
}
function Apply-Geo($row, $g) {
    if (-not $g) { return }
    $row.Ulke = [string]$g.country; $row.UlkeKodu = [string]$g.countryCode; $row.Sehir = [string]$g.city
    $row.Lat = $g.lat; $row.Lon = $g.lon
    $row.ISP = $(if ($g.isp) { [string]$g.isp } else { [string]$g.org })
    $row.ASN = [string]$g.as
    $row.Hosting = [bool]$g.hosting; $row.ProxyIP = [bool]$g.proxy
    $row.PTR = [string]$g.reverse
    if (([string]$g.isp + ' ' + [string]$g.org + ' ' + [string]$g.asname) -match $script:CdnRx) { $row.Anycast = $true }
}

# ------------------------------------------------------------ yol analizi
function Get-Trace([string]$ip, [int]$hops) {
    $res = @()
    try {
        $out = & tracert.exe -d -h $hops -w 800 $ip 2>&1
        foreach ($ln in $out) {
            $s = [string]$ln
            $m = [regex]::Match($s, '^\s*(\d+)\s+(.*)$')
            if (-not $m.Success) { continue }
            $hop = [int]$m.Groups[1].Value; $rest = $m.Groups[2].Value
            $ipm = [regex]::Match($rest, '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$')
            $times = @()
            foreach ($t in [regex]::Matches($rest, '(<?\d+)\s*ms')) {
                $v = $t.Groups[1].Value
                if ($v.StartsWith('<')) { $times += 0.5 } else { $times += [double]$v }
            }
            $res += [pscustomobject]@{ Hop = $hop; IP = $(if ($ipm.Success) { $ipm.Groups[1].Value } else { '*' }); Ms = $(if ($times.Count) { ($times | Measure-Object -Average).Average } else { $null }) }
        }
    } catch {}
    return , $res
}

# ------------------------------------------------------------ analiz
function Sub-Part([string]$h, [string]$d) {
    if ($h -eq $d -or -not $h.EndsWith(".$d")) { return '' }
    return $h.Substring(0, $h.Length - $d.Length - 1)
}
function Analyze-Rows($rows, $env, [string]$d) {
    $ctx = @{ GlobalTtl = $false; TtlValue = $null; TtlShare = 0; ImkansizN = 0; SupheliN = 0; UserOk = $false }
    $ulat = $null; $ulon = $null
    if ($env -and $env.Pub) { $ulat = [double]$env.Pub.lat; $ulon = [double]$env.Pub.lon; $ctx.UserOk = $true }

    # global TTL tekduzeligi (tek cihaz hepsine yanit veriyor mu?)
    $byIp = @{}
    foreach ($r in $rows) { if ($r.IP -and $r.TTL -and -not $byIp.ContainsKey($r.IP)) { $byIp[$r.IP] = $r } }
    $distinct = @($byIp.Values)
    if ($distinct.Count -ge 6) {
        $g = @($distinct | Group-Object TTL | Sort-Object Count -Descending)
        $share = $g[0].Count / $distinct.Count
        $asns = @($distinct | ForEach-Object { $_.ASN } | Where-Object { $_ } | Select-Object -Unique).Count
        $ctrs = @($distinct | ForEach-Object { $_.UlkeKodu } | Where-Object { $_ } | Select-Object -Unique).Count
        $ctx.TtlValue = $g[0].Name; $ctx.TtlShare = $share
        if ($share -ge 0.9 -and ($asns -ge 3 -or $ctrs -ge 3)) { $ctx.GlobalTtl = $true }
    }

    foreach ($r in $rows) {
        if (-not $r.IP) { continue }
        if ($r.CDN) { $r.Anycast = $true }
        if ($ctx.UserOk -and $null -ne $r.Lat -and $null -ne $r.Lon) { $r.MesafeKm = [math]::Round((Haversine $ulat $ulon ([double]$r.Lat) ([double]$r.Lon)), 0) }

        # fiziksel imkansizlik: isik hizi (fiber ~200 km/ms) => RTT >= mesafe/100 ms
        if ($null -ne $r.MesafeKm -and $r.MesafeKm -gt 600 -and -not $r.Anycast) {
            $minRtt = $r.MesafeKm / 100.0
            if ($null -ne $r.TcpMin -and $r.TcpMin -lt 0.6 * $minRtt) { $r.Imkansiz = $true }
            if ($null -ne $r.IcmpMin -and $r.IcmpMin -lt 0.6 * $minRtt) { $r.IcmpSupheli = $true }
        }
        # ICMP ile TCP el sikismasi ayni mertebede olmali
        if ($null -ne $r.IcmpOrt -and $null -ne $r.TcpOrt -and $r.TcpOrt -gt 8 -and $r.IcmpOrt -lt 0.4 * $r.TcpOrt) { $r.IcmpSupheli = $true }
        if ($ctx.GlobalTtl -and $null -ne $r.IcmpOrt) { $r.IcmpSupheli = $true }

        if ($null -ne $r.TcpOrt) { $r.GercekMs = [double]$r.TcpOrt; $r.Yontem = 'TCP:' + $r.TcpPort }
        elseif ($null -ne $r.IcmpOrt -and -not $r.IcmpSupheli) { $r.GercekMs = [double]$r.IcmpOrt; $r.Yontem = 'ICMP' }
        else { $r.Yontem = '-' }

        $u = New-Object System.Collections.ArrayList
        if ($r.Imkansiz) { [void]$u.Add('Fiziksel-imkansiz-gecikme'); $ctx.ImkansizN++ }
        if ($r.IcmpSupheli) { [void]$u.Add('ICMP-supheli'); $ctx.SupheliN++ }
        if ($r.Dangling) { [void]$u.Add('Dangling-CNAME') }
        if ($null -ne $r.SertGun) {
            if ($r.SertGun -lt 0) { [void]$u.Add('Sertifika-suresi-dolmus') }
            elseif ($r.SertGun -lt 14) { [void]$u.Add('Sertifika<14gun') }
            if ($r.SertUyum -eq $false) { [void]$u.Add('Sertifika-ad-uyumsuz') }
            if ($r.SertZincir -eq $false) { [void]$u.Add('Zincir-dogrulanamadi') }
        }
        if ($r.TlsSurum -match 'TLS1\.[01]$') { [void]$u.Add('Eski-TLS') }
        if ($r.Tur -eq 'Alt' -and (Sub-Part $r.Host $d) -match $script:SensitiveRx) { [void]$u.Add('Hassas-gorunen-isim') }
        if ($null -eq $r.TcpOrt -and $null -eq $r.IcmpOrt) { [void]$u.Add('Yanit-yok') }
        $r.Uyari = ($u -join ',')
        if ($r.Probed -and $r.Http -ge 500) { $r.Uyari = (($r.Uyari + ',HTTP' + $r.Http).Trim(',')) }
        if ($null -ne $r.GercekMs) { $r.Durum = 'Olculdu' } elseif ($r.Probed -or $r.IP) { $r.Durum = 'Yanit yok' }
    }
    return $ctx
}

# ------------------------------------------------------------ ilgili domain iliski puani
function Score-Relations($rows, $mainRow, $rdapMain, $rdapMap) {
    $mainSans = @()
    if ($mainRow -and $mainRow.SANlar) { $mainSans = @($mainRow.SANlar -split ' ') }
    $mainNs = ''
    if ($rdapMain -and $rdapMain.Found) { $mainNs = $rdapMain.NS }
    foreach ($r in $rows) {
        if ($r.Tur -ne 'TLD') { continue }
        $score = 0; $why = New-Object System.Collections.ArrayList
        $rd = $rdapMap[$r.Host]
        if ($rd -and $rd.Found) {
            $r.Kayitci = $rd.Registrar; $r.Olusturma = $rd.Created; $r.Bitis = $rd.Expires
            if ($rdapMain -and $rdapMain.Found) {
                if ($rd.Registrar -and $rd.Registrar -eq $rdapMain.Registrar) { $score += 1; [void]$why.Add('ayni kayitci') }
                if ($rd.NS -and $mainNs -and $rd.NS -eq $mainNs) { $score += 2; [void]$why.Add('ayni NS cifti') }
            }
        }
        if ($mainRow) {
            if ($r.SANlar -and ($r.SANlar -split ' ') -contains $mainRow.Host) { $score += 3; [void]$why.Add('sertifika ana alani kapsiyor') }
            if ($mainSans -contains $r.Host) { $score += 3; [void]$why.Add('ana sertifika bu alani kapsiyor') }
            if ($r.Yonlendirme -match [regex]::Escape($mainRow.Host)) { $score += 3; [void]$why.Add('ana alana yonlendiriyor') }
            if ($r.IP -and $r.IP -eq $mainRow.IP -and -not $r.Anycast) { $score += 2; [void]$why.Add('ayni IP') }
        }
        $r.IliskiPuan = $score
        if ($score -ge 3) { $r.Iliski = 'Buyuk olasilikla ayni sahip' }
        elseif ($score -ge 1) { $r.Iliski = 'Belirsiz' }
        else { $r.Iliski = 'Buyuk olasilikla farkli sahip' }
        if ($why.Count -gt 0) { $r.Iliski += ' (' + ($why -join ', ') + ')' }
    }
}

# ------------------------------------------------------------ bulgular
function Make-Findings([string]$d, $info, $rows, $env, $ctx, $wildIps, $rdapMain, $httpRedirect) {
    $script:Findings.Clear()
    # DNS / e-posta
    if ($info -and $info.Ok) {
        if (-not $info.Spf) { Add-Finding 'UYARI' 'E-posta' 'SPF kaydi yok: alan adi e-posta sahteciligine acik olabilir.' }
        elseif ($info.SpfAll -eq '+') { Add-Finding 'KRITIK' 'E-posta' 'SPF "+all" ile bitiyor: herkes adiniza e-posta gonderebilir.' }
        elseif ($info.SpfAll -eq '?') { Add-Finding 'UYARI' 'E-posta' 'SPF "?all" (tarafsiz): koruma saglamiyor.' }
        elseif ($info.SpfAll -eq '~') { Add-Finding 'BILGI' 'E-posta' 'SPF "~all" (softfail): "-all" daha siki koruma saglar.' }
        else { Add-Finding 'IYI' 'E-posta' 'SPF "-all" ile siki yapilandirilmis.' }
        if (-not $info.Dmarc) { Add-Finding 'UYARI' 'E-posta' 'DMARC kaydi yok.' }
        elseif ($info.DmarcPolicy -eq 'none') { Add-Finding 'BILGI' 'E-posta' 'DMARC politikasi p=none (yalnizca izleme).' }
        else { Add-Finding 'IYI' 'E-posta' ("DMARC politikasi p=" + $info.DmarcPolicy) }
        if ($info.Caa -eq $false) { Add-Finding 'BILGI' 'DNS' 'CAA kaydi yok: hangi CA sertifika verebilir kisitlanmamis.' }
        elseif ($info.Caa -eq $true) { Add-Finding 'IYI' 'DNS' 'CAA kaydi mevcut.' }
        if ($info.Dnssec -eq $false) { Add-Finding 'BILGI' 'DNS' 'DNSSEC etkin degil.' }
        elseif ($info.Dnssec -eq $true) { Add-Finding 'IYI' 'DNS' 'DNSSEC etkin.' }
        if ($info.Ns.Count -eq 1) { Add-Finding 'UYARI' 'DNS' 'Tek yetkili isim sunucusu var (yedeksizlik).' }
        if ($info.SerialMismatch) { Add-Finding 'UYARI' 'DNS' 'Yetkili NS sunuculari farkli SOA seri numarasi donduruyor.' }
        $slow = @($info.Ns | Where-Object { $null -ne $_.Ms -and $_.Ms -gt 300 })
        if ($slow.Count -gt 0) { Add-Finding 'BILGI' 'DNS' ("Yavas yanit veren isim sunucusu: " + (($slow | ForEach-Object { $_.Name }) -join ', ')) }
        if ($info.ResolverDiff) { Add-Finding 'BILGI' 'DNS' 'Genel cozuculer farkli IP kumeleri donduruyor (CDN/geo-DNS veya yonlendirme).' }
    }
    if ($wildIps -and $wildIps.Count -gt 0) { Add-Finding 'BILGI' 'DNS' ('Wildcard DNS aktif (' + ($wildIps -join ', ') + '); sozluk sonuclari filtrelendi.') }

    # alan adi kaydi
    if ($rdapMain -and $rdapMain.Found) {
        if ($rdapMain.Expires) {
            $dt = [datetime]::MinValue
            if ([datetime]::TryParse($rdapMain.Expires, $script:Inv, [Globalization.DateTimeStyles]::None, [ref]$dt)) {
                $dd = [int](($dt - (Get-Date)).TotalDays)
                if ($dd -lt 0) { Add-Finding 'KRITIK' 'Kayit' ("Alan adi kaydi suresi dolmus gorunuyor (" + $rdapMain.Expires + ").") }
                elseif ($dd -lt 30) { Add-Finding 'UYARI' 'Kayit' ("Alan adi kaydi $dd gun icinde doluyor (" + $rdapMain.Expires + ").") }
                else { Add-Finding 'IYI' 'Kayit' ("Alan adi kaydi $dd gun gecerli (bitis " + $rdapMain.Expires + ").") }
            }
        }
    }

    $live = @($rows | Where-Object { $_.IP })
    $probed = @($live | Where-Object { $_.Probed })

    # sertifika
    $exp = @($probed | Where-Object { $null -ne $_.SertGun -and $_.SertGun -lt 0 })
    if ($exp.Count -gt 0) { Add-Finding 'KRITIK' 'Sertifika' ("$($exp.Count) hostta sertifika suresi dolmus: " + ((@($exp | Select-Object -First 5) | ForEach-Object { $_.Host }) -join ', ')) }
    $soon = @($probed | Where-Object { $null -ne $_.SertGun -and $_.SertGun -ge 0 -and $_.SertGun -lt 14 })
    if ($soon.Count -gt 0) { Add-Finding 'UYARI' 'Sertifika' ("$($soon.Count) hostta sertifika 14 gunden az icinde bitiyor: " + ((@($soon | Select-Object -First 5) | ForEach-Object { $_.Host }) -join ', ')) }
    $mis = @($probed | Where-Object { $_.SertUyum -eq $false -and $_.Tur -ne 'TLD' })
    if ($mis.Count -gt 0) { Add-Finding 'UYARI' 'Sertifika' ("$($mis.Count) hostta sertifika adi host ile uyusmuyor: " + ((@($mis | Select-Object -First 5) | ForEach-Object { $_.Host }) -join ', ')) }
    $okc = @($probed | Where-Object { $null -ne $_.SertGun -and $_.SertGun -ge 14 -and $_.SertUyum -eq $true })
    if ($okc.Count -gt 0) { Add-Finding 'IYI' 'Sertifika' ("$($okc.Count) hostta sertifika gecerli ve ad uyumlu.") }
    $oldtls = @($probed | Where-Object { $_.TlsSurum -match 'TLS1\.[01]$' })
    if ($oldtls.Count -gt 0) { Add-Finding 'UYARI' 'TLS' ("$($oldtls.Count) host TLS 1.0/1.1 muzakere ediyor.") }
    $t13 = @($probed | Where-Object { $_.TlsSurum -eq 'TLS1.3' })
    if ($t13.Count -gt 0) { Add-Finding 'IYI' 'TLS' ("$($t13.Count) host TLS 1.3 destekliyor.") }

    # HTTP
    $mainRow = $rows | Where-Object { $_.Host -eq $d } | Select-Object -First 1
    if ($mainRow -and $mainRow.Http -and $mainRow.HttpPort -eq 443) {
        if (-not $mainRow.HSTS) { Add-Finding 'UYARI' 'HTTP' ("Ana alanda HSTS basligi yok.") } else { Add-Finding 'IYI' 'HTTP' 'Ana alanda HSTS aktif.' }
        if ($mainRow.GuvPuan -le 2) { Add-Finding 'BILGI' 'HTTP' ("Ana alanda guvenlik basliklari zayif (" + $mainRow.GuvPuan + "/5: HSTS, CSP, X-Frame, X-Content-Type, Referrer).") }
    }
    if ($httpRedirect) {
        if ($httpRedirect.Status -ge 300 -and $httpRedirect.Status -lt 400 -and $httpRedirect.Location -match '^https://') { Add-Finding 'IYI' 'HTTP' 'HTTP (80) -> HTTPS yonlendirmesi calisiyor.' }
        elseif ($httpRedirect.HttpOk -and $httpRedirect.Status -eq 200) { Add-Finding 'UYARI' 'HTTP' 'Port 80 sifrelemesiz icerik sunuyor, HTTPS yonlendirmesi yok.' }
    }
    $e5 = @($probed | Where-Object { $_.Http -ge 500 })
    if ($e5.Count -gt 0) { Add-Finding 'UYARI' 'HTTP' ("$($e5.Count) host 5xx hata donduruyor: " + ((@($e5 | Select-Object -First 5) | ForEach-Object { $_.Host }) -join ', ')) }

    # dangling
    $dg = @($rows | Where-Object { $_.Dangling })
    if ($dg.Count -gt 0) { Add-Finding 'KRITIK' 'DNS' ("$($dg.Count) kayitta CNAME hedefi cozulmuyor (subdomain takeover riski): " + ((@($dg | Select-Object -First 5) | ForEach-Object { $_.Host + ' -> ' + $_.CNAME }) -join '; ')) }

    # hassas isimler
    $sens = @($live | Where-Object { $_.Tur -eq 'Alt' -and (Sub-Part $_.Host $d) -match $script:SensitiveRx })
    if ($sens.Count -gt 0) { Add-Finding 'BILGI' 'Kesif' ("$($sens.Count) hassas gorunen isim internetten cozuluyor (dev/staging/admin vb.): " + ((@($sens | Select-Object -First 6) | ForEach-Object { $_.Host }) -join ', ')) }

    # IPv6
    if ($live.Count -gt 0) {
        $v6 = @($live | Where-Object { $_.IPv6 }).Count
        Add-Finding 'BILGI' 'Ag' ("IPv6 (AAAA) destegi: $v6 / $($live.Count) host.")
    }

    # olcum butunlugu
    if ($ctx) {
        if ($ctx.GlobalTtl) { Add-Finding 'KRITIK' 'Olcum' ("Taranan farkli IP'lerin %" + [math]::Round($ctx.TtlShare * 100) + " kadari ayni ICMP TTL (" + $ctx.TtlValue + ") ile yanit veriyor. Farkli ulke/AS'lerden bu mumkun degil: ICMP yanitlarini yerel bir cihaz (VPN, guvenlik yazilimi, proxy, modem) uretiyor olabilir. ICMP degerleri yok sayildi, TCP kullanildi.") }
        if ($ctx.ImkansizN -gt 0) { Add-Finding 'KRITIK' 'Olcum' ("$($ctx.ImkansizN) hostta TCP gecikmesi isik hizi sinirinin altinda (fiziksel olarak imkansiz). TCP baglantisi da yerelde sonlandiriliyor olabilir (VPN/proxy/seffaf guvenlik duvari) veya Geo-IP verisi hatali.") }
        $icmpOnly = $ctx.SupheliN - $ctx.ImkansizN
        if ($ctx.SupheliN -gt 0 -and -not $ctx.GlobalTtl) { Add-Finding 'UYARI' 'Olcum' ("$($ctx.SupheliN) hostta ICMP degeri TCP/fiziksel sinirlarla celisiyor; bu satirlarda TCP esas alindi.") }
    }
    if ($env) {
        if ($env.Vpn.Count -gt 0) { Add-Finding 'BILGI' 'Ag' ("VPN/tunel adaptoru aktif: " + (($env.Vpn | Select-Object -First 3) -join ' | ') + ". Olcumler VPN cikisindan yapiliyor olabilir.") }
        if ($env.Proxy) { Add-Finding 'BILGI' 'Ag' ("Sistem proxy ayari: " + $env.Proxy) }
        if ($env.BaseSuspect) { Add-Finding 'KRITIK' 'Olcum' ("Referans hedefte (" + $env.BaseSuspect + ") ICMP ile TCP el sikisma suresi uyusmuyor: ICMP yanitlari yerelde uretiliyor olabilir.") }
        if ($env.Pub -and $env.Pub.proxy) { Add-Finding 'BILGI' 'Ag' 'Genel IP adresiniz proxy/VPN olarak isaretli.' }
    }
    $tooSlow = @($live | Where-Object { $null -ne $_.GercekMs -and $_.GercekMs -gt 300 -and $_.Tur -ne 'TLD' })
    if ($tooSlow.Count -gt 0) { Add-Finding 'BILGI' 'Performans' ("$($tooSlow.Count) hostta TCP gecikmesi 300 ms ustu: " + ((@($tooSlow | Select-Object -First 4) | ForEach-Object { $_.Host }) -join ', ')) }
    $noresp = @($live | Where-Object { $_.Uyari -match 'Yanit-yok' -and $_.Tur -ne 'TLD' })
    if ($noresp.Count -gt 0) { Add-Finding 'BILGI' 'Ag' ("$($noresp.Count) host cozuluyor ama ne ICMP ne TCP 443/80 yanit veriyor (ozel servis, guvenlik duvari veya kapali).") }

    # puan
    $score = 100
    foreach ($f in $script:Findings) {
        if ($f.Sev -eq 'KRITIK') { $score -= 15 } elseif ($f.Sev -eq 'UYARI') { $score -= 5 } elseif ($f.Sev -eq 'BILGI') { $score -= 1 }
    }
    if ($score -lt 0) { $score = 0 }
    return $score
}

# ------------------------------------------------------------ cikti yardimcilari
function Flag-Letters($r) {
    $u = [string]$r.Uyari; $s = ''
    if ($u -match 'Fiziksel') { $s += 'F' }
    if ($u -match 'ICMP-supheli') { $s += 'I' }
    if ($u -match 'Dangling') { $s += 'D' }
    if ($u -match 'Sertifika|Zincir') { $s += 'S' }
    if ($u -match 'Eski-TLS') { $s += 'T' }
    if ($u -match 'Yanit-yok') { $s += 'X' }
    if ($u -match 'Hassas-gorunen') { $s += 'H' }
    if ($u -match 'HTTP5') { $s += 'E' }
    if ($r.Anycast) { $s += 'A' }
    if ($r.Hassas) { $s += '+' }
    return $s
}
function Ms-Color($r) {
    if ($r.Imkansiz) { return 'Magenta' }
    if ($null -eq $r.GercekMs) { return 'DarkGray' }
    $v = $r.GercekMs
    if ($v -lt 30) { return 'Green' }
    if ($v -lt 100) { return 'Yellow' }
    if ($v -lt 200) { return 'DarkYellow' }
    return 'Red'
}

function Show-Main($sorted, $idxMap) {
    $hw = [math]::Min(48, [math]::Max(24, $script:ConW - 104))
    $hdr = ("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11}" -f '#'.PadRight(4), 'HOST'.PadRight($hw), 'TUR'.PadRight(6), 'IP'.PadRight(16), 'TCP ms'.PadLeft(7), 'TLS'.PadLeft(7), 'TTFB'.PadLeft(7), 'ICMP'.PadLeft(7), 'HTTP'.PadRight(4), 'SUNUCU/CDN'.PadRight(12), 'ULKE'.PadRight(4), 'ISARET')
    Say ("  " + $hdr) 'White'
    Say ("  " + ('-' * [math]::Min($hdr.Length + 4, $script:ConW - 4))) 'DarkGray'
    $idx = 0; $shown = 0
    foreach ($r in $sorted) {
        if (-not $r.IP) { continue }
        $idx++
        $idxMap["$idx"] = $r
        if ($shown -ge 220) { continue }
        $shown++
        $icm = Fmt-Ms $r.IcmpOrt
        if ($r.IcmpSupheli -and $null -ne $r.IcmpOrt) { $icm += '*' }
        $tcpS = Fmt-Ms $r.TcpOrt
        $srv = $(if ($r.CDN) { $r.CDN } else { $r.Sunucu })
        $httpS = $(if ($null -ne $r.Http) { [string]$r.Http } else { '-' })
        $line = ("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11}" -f ("$idx").PadRight(4), (Cut $r.Host $hw).PadRight($hw), $r.Tur.PadRight(6), (Cut $r.IP 16).PadRight(16), $tcpS.PadLeft(7), (Fmt-Ms $r.TlsMs).PadLeft(7), (Fmt-Ms $r.TtfbMs).PadLeft(7), $icm.PadLeft(7), $httpS.PadRight(4), (Cut $srv 12).PadRight(12), (Cut $r.UlkeKodu 4).PadRight(4), (Flag-Letters $r))
        Say ("  " + $line) (Ms-Color $r)
    }
    if ($idx -gt $shown) { Say ("  ... {0} satir daha var (tamami raporlarda)." -f ($idx - $shown)) 'DarkGray' }
    Say ''
    Say '  Renk: Yesil <30ms | Sari <100ms | Turuncu <200ms | Kirmizi >=200ms | Gri yanit yok | Mor fiziksel imkansiz' 'DarkGray'
    Say '  TCP ms = 443 (yoksa 80) baglanti kurma suresi, esas olcut. ICMP sonundaki * = guvenilmez.' 'DarkGray'
    Say '  ISARET: F fiziksel imkansiz | I ICMP suphe | D dangling CNAME | S sertifika sorunu | T eski TLS | X yanit yok' 'DarkGray'
    Say '          H hassas isim | E HTTP 5xx | A anycast/CDN | + hassas seri olcum yapildi' 'DarkGray'
}

function Show-Details($sorted) {
    $pr = @($sorted | Where-Object { $_.Probed -and $null -ne $_.TlsSurum -and $_.TlsSurum -ne '' } | Select-Object -First 40)
    if ($pr.Count -eq 0) { return }
    Sub 'Servis ve guvenlik detayi (TLS/HTTP testi yapilan ilk 40 host)'
    $hw = [math]::Min(40, [math]::Max(24, $script:ConW - 100))
    $hdr = ("{0} {1} {2} {3} {4} {5} {6} {7}" -f 'HOST'.PadRight($hw), 'TLS'.PadRight(7), 'SERT(gun)'.PadLeft(9), 'ANAHTAR'.PadRight(10), 'VEREN'.PadRight(20), 'HSTS'.PadRight(4), 'BASLIK'.PadRight(6), 'YONLENDIRME')
    Say ("  " + $hdr) 'White'
    foreach ($r in $pr) {
        $col = 'Gray'
        if ($null -ne $r.SertGun -and $r.SertGun -lt 14) { $col = 'Red' } elseif ($r.SertUyum -eq $false) { $col = 'DarkYellow' }
        $hs = $(if ($null -eq $r.HSTS) { '-' } elseif ($r.HSTS) { 'evet' } else { 'yok' })
        $gp = $(if ($null -eq $r.GuvPuan) { '-' } else { "$($r.GuvPuan)/5" })
        $line = ("{0} {1} {2} {3} {4} {5} {6} {7}" -f (Cut $r.Host $hw).PadRight($hw), (Cut $r.TlsSurum 7).PadRight(7), ([string]$r.SertGun).PadLeft(9), (Cut $r.SertAnahtar 10).PadRight(10), (Cut $r.SertVeren 20).PadRight(20), $hs.PadRight(4), $gp.PadRight(6), (Cut $r.Yonlendirme 40))
        Say ("  " + $line) $col
    }
}

function Show-TldTable($sorted) {
    $t = @($sorted | Where-Object { $_.Tur -eq 'TLD' -and $_.IP })
    if ($t.Count -eq 0) { return }
    Sub ("Benzer TLD varyasyonlari ({0}) - sahiplik iliskisi tahmini" -f $t.Count)
    $hw = 26
    Say ("  " + ("{0} {1} {2} {3} {4}" -f 'ALAN ADI'.PadRight($hw), 'KAYITCI'.PadRight(22), 'OLUSTURMA'.PadRight(10), 'PUAN'.PadRight(4), 'ILISKI')) 'White'
    foreach ($r in ($t | Sort-Object @{ Expression = { - [int]$_.IliskiPuan } }, Host)) {
        $col = 'DarkGray'
        if ($r.IliskiPuan -ge 3) { $col = 'Green' } elseif ($r.IliskiPuan -ge 1) { $col = 'Yellow' }
        Say ("  " + ("{0} {1} {2} {3} {4}" -f (Cut $r.Host $hw).PadRight($hw), (Cut $r.Kayitci 22).PadRight(22), (Cut $r.Olusturma 10).PadRight(10), ([string]$r.IliskiPuan).PadRight(4), (Cut $r.Iliski 70))) $col
    }
    Say '  NOT: Ayni etiketli baska TLD, cogu zaman baska bir sahibe aittir. Puan: ortak sertifika/yonlendirme/NS/kayitci ipuclarindan hesaplanir.' 'DarkGray'
}

function Show-Findings($score) {
    Head 'BULGULAR VE DEGERLENDIRME'
    $order = 'KRITIK', 'UYARI', 'BILGI', 'IYI'
    foreach ($sev in $order) {
        $f = @($script:Findings | Where-Object { $_.Sev -eq $sev })
        foreach ($x in $f) {
            $col = switch ($sev) { 'KRITIK' { 'Red' } 'UYARI' { 'Yellow' } 'BILGI' { 'Cyan' } default { 'Green' } }
            Say ("  [{0,-6}] {1,-10} {2}" -f $sev, $x.Cat, $x.Msg) $col
        }
    }
    $grade = 'A'; if ($score -lt 90) { $grade = 'B' }; if ($score -lt 75) { $grade = 'C' }; if ($score -lt 60) { $grade = 'D' }; if ($score -lt 40) { $grade = 'F' }
    $gc = 'Green'; if ($score -lt 75) { $gc = 'Yellow' }; if ($score -lt 50) { $gc = 'Red' }
    Say ''
    Say ("  Alan adi saglik puani: {0}/100  (not {1})   [kritik -15, uyari -5, bilgi -1]" -f $score, $grade) $gc
    return $grade
}

function Show-Summary($d, $rows, $ipMap, $elapsed) {
    Head 'OZET ISTATISTIKLER'
    $live = @($rows | Where-Object { $_.IP })
    $meas = @($rows | Where-Object { $null -ne $_.GercekMs })
    Say ("  Bulunan toplam isim        : {0}" -f $rows.Count) 'White'
    Say ("  DNS cozumlenen             : {0}" -f $live.Count) 'White'
    Say ("  Olculebilen (TCP/ICMP)     : {0}" -f $meas.Count) 'Green'
    $nr = $live.Count - $meas.Count
    Say ("  Yanit alinamayan           : {0}" -f $nr) $(if ($nr -gt 0) { 'Red' } else { 'Gray' })
    Say ("  Benzersiz IP               : {0}   (IPv6'li host: {1})" -f @($live | Select-Object -ExpandProperty IP -Unique).Count, @($live | Where-Object { $_.IPv6 }).Count) 'White'
    foreach ($k in 'Ana', 'Alt', 'TLD', 'Harici') {
        $c = @($rows | Where-Object { $_.Tur -eq $k }).Count
        if ($c -gt 0) { Say ("    - {0,-8}: {1}" -f $k, $c) 'Gray' }
    }
    $scope = @($meas | Where-Object { $_.Tur -ne 'TLD' })
    if ($scope.Count -eq 0) { $scope = $meas }
    if ($scope.Count -gt 0) {
        $v = @($scope | ForEach-Object { $_.GercekMs })
        Say ''
        Say '  Gecikme dagilimi (TCP baglanti suresi, TLD varyasyonlari haric):' 'White'
        Say ("    en az {0} | p50 {1} | p75 {2} | p95 {3} | en cok {4} | ort {5}  (ms)" -f (Fmt-Ms (Percentile $v 0)), (Fmt-Ms (Percentile $v 0.5)), (Fmt-Ms (Percentile $v 0.75)), (Fmt-Ms (Percentile $v 0.95)), (Fmt-Ms (Percentile $v 1)), (Fmt-Ms (($v | Measure-Object -Average).Average))) 'Gray'
        $best = $scope | Sort-Object GercekMs | Select-Object -First 1
        $worst = $scope | Sort-Object GercekMs -Descending | Select-Object -First 1
        Say ("    En hizli : {0}  ({1} ms, {2})" -f $best.Host, (Fmt-Ms $best.GercekMs), $best.IP) 'Green'
        Say ("    En yavas : {0}  ({1} ms, {2})" -f $worst.Host, (Fmt-Ms $worst.GercekMs), $worst.IP) 'Red'
        $b = @(@('<10', 0, 10), @('10-30', 10, 30), @('30-60', 30, 60), @('60-100', 60, 100), @('100-200', 100, 200), @('200+', 200, 1e9))
        Say ''
        $mx = 1
        foreach ($x in $b) { $c = @($v | Where-Object { $_ -ge $x[1] -and $_ -lt $x[2] }).Count; if ($c -gt $mx) { $mx = $c } }
        foreach ($x in $b) {
            $c = @($v | Where-Object { $_ -ge $x[1] -and $_ -lt $x[2] }).Count
            $bar = '#' * [int][math]::Round(40.0 * $c / $mx)
            Say ("    {0,8} ms | {1,-40} {2}" -f $x[0], $bar, $c) 'DarkCyan'
        }
    }
    $isp = @($live | Where-Object { $_.ISP } | Group-Object ISP | Sort-Object Count -Descending | Select-Object -First 6)
    if ($isp.Count -gt 0) {
        Say ''; Say '  Barindirma / ag saglayici dagilimi:' 'White'
        foreach ($g in $isp) { Say ("    {0,4} x  {1}" -f $g.Count, $g.Name) 'Gray' }
    }
    $cdn = @($live | Where-Object { $_.CDN } | Group-Object CDN | Sort-Object Count -Descending)
    if ($cdn.Count -gt 0) { Say ('  CDN/koruma: ' + (($cdn | ForEach-Object { "$($_.Name)($($_.Count))" }) -join '  ')) 'Gray' }
    $st = @($live | Where-Object { $null -ne $_.Http } | Group-Object Http | Sort-Object Name)
    if ($st.Count -gt 0) { Say ('  HTTP durumlari: ' + (($st | ForEach-Object { "$($_.Name)($($_.Count))" }) -join '  ')) 'Gray' }
    $tl = @($live | Where-Object { $_.TlsSurum } | Group-Object TlsSurum | Sort-Object Name)
    if ($tl.Count -gt 0) { Say ('  TLS surumleri: ' + (($tl | ForEach-Object { "$($_.Name)($($_.Count))" }) -join '  ')) 'Gray' }
    $ct = @($live | Where-Object { $_.UlkeKodu } | Group-Object UlkeKodu | Sort-Object Count -Descending | Select-Object -First 8)
    if ($ct.Count -gt 0) { Say ('  Ulkeler: ' + (($ct | ForEach-Object { "$($_.Name)($($_.Count))" }) -join '  ')) 'Gray' }
    Say ''
    Say ("  Gecen sure: {0:N1} sn" -f $elapsed) 'DarkGray'
}

# ------------------------------------------------------------ onceki tarama ile fark
function Get-PrevScan([string]$d) {
    if (-not (Test-Path $script:OutDir)) { return $null }
    $f = Get-ChildItem -Path $script:OutDir -Filter ("{0}_*.json" -f $d) | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $f) { return $null }
    try { return (Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}
function Show-Diff($prev, $rows) {
    if (-not $prev -or -not $prev.rows) { return }
    Sub ("Onceki taramayla karsilastirma ({0})" -f $prev.meta.date)
    $old = @{}; foreach ($r in @($prev.rows)) { $old[[string]$r.Host] = $r }
    $cur = @{}; foreach ($r in $rows) { $cur[$r.Host] = $r }
    $new = @($cur.Keys | Where-Object { -not $old.ContainsKey($_) })
    $gone = @($old.Keys | Where-Object { -not $cur.ContainsKey($_) })
    Say ("     Yeni host: {0}   Kaybolan host: {1}" -f $new.Count, $gone.Count) 'White'
    if ($new.Count -gt 0) { Say ("     + " + ((@($new | Select-Object -First 8)) -join ', ') + $(if ($new.Count -gt 8) { ' ...' } else { '' })) 'Green' }
    if ($gone.Count -gt 0) { Say ("     - " + ((@($gone | Select-Object -First 8)) -join ', ') + $(if ($gone.Count -gt 8) { ' ...' } else { '' })) 'Red' }
    $ipch = 0; $slow = @(); $fast = @()
    foreach ($h in $cur.Keys) {
        if (-not $old.ContainsKey($h)) { continue }
        $o = $old[$h]; $c = $cur[$h]
        if ($o.IP -and $c.IP -and $o.IP -ne $c.IP) { $ipch++ }
        if ($null -ne $o.GercekMs -and $null -ne $c.GercekMs) {
            $dv = [double]$c.GercekMs - [double]$o.GercekMs
            if ($dv -gt 10 -and $c.GercekMs -gt 1.5 * $o.GercekMs) { $slow += [pscustomobject]@{ H = $h; O = $o.GercekMs; N = $c.GercekMs } }
            if ($dv -lt -10 -and $c.GercekMs -lt 0.67 * $o.GercekMs) { $fast += [pscustomobject]@{ H = $h; O = $o.GercekMs; N = $c.GercekMs } }
        }
    }
    Say ("     IP'si degisen: {0}   Belirgin yavaslayan: {1}   Belirgin hizlanan: {2}" -f $ipch, $slow.Count, $fast.Count) 'White'
    foreach ($x in ($slow | Sort-Object { $_.N - $_.O } -Descending | Select-Object -First 4)) { Say ("     yavas  {0}: {1} -> {2} ms" -f $x.H, (Fmt-Ms $x.O), (Fmt-Ms $x.N)) 'Yellow' }
    foreach ($x in ($fast | Sort-Object { $_.N - $_.O } | Select-Object -First 4)) { Say ("     hizli  {0}: {1} -> {2} ms" -f $x.H, (Fmt-Ms $x.O), (Fmt-Ms $x.N)) 'Green' }
}

# ------------------------------------------------------------ rapor dosyalari
$script:Cols = 'Host', 'Tur', 'IP', 'TumIPler', 'GercekMs', 'Yontem', 'TcpMin', 'TcpOrt', 'TcpMed', 'TcpP95', 'TcpMax', 'TcpStd', 'TcpKayip', 'IcmpOrt', 'IcmpMin', 'IcmpMax', 'IcmpJit', 'IcmpKayip', 'TTL', 'Hop', 'DnsMs', 'TlsMs', 'TtfbMs', 'ToplamMs', 'Http', 'Sunucu', 'CDN', 'Yonlendirme', 'TlsSurum', 'Sifre', 'SertKonu', 'SertVeren', 'SertGun', 'SertBitis', 'SertUyum', 'SertZincir', 'SertAnahtar', 'SANsayisi', 'HSTS', 'CSP', 'XFO', 'XCTO', 'RefPol', 'GuvPuan', 'Ulke', 'UlkeKodu', 'Sehir', 'ISP', 'ASN', 'Anycast', 'PTR', 'MesafeKm', 'CNAME', 'Dangling', 'Kayitci', 'Olusturma', 'Bitis', 'Iliski', 'Uyari', 'Kaynak', 'Durum', 'Hassas', 'Imkansiz', 'IcmpSupheli'

function Csv-Val($v) {
    if ($null -eq $v) { return '""' }
    if ($v -is [bool]) { if ($v) { return '"Evet"' } else { return '"Hayir"' } }
    if ($v -is [double] -or $v -is [single]) { return '"' + ([double]$v).ToString('0.###', $script:TrCult) + '"' }
    return '"' + ([string]$v).Replace('"', '""') + '"'
}

function Save-Reports($S, $sorted, $score, $grade, $ctx) {
    $d = $S.D
    $out = @{ Base = ''; Html = '' }
    try {
        if (-not (Test-Path $script:OutDir)) { New-Item -ItemType Directory -Path $script:OutDir | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $base = Join-Path $script:OutDir ("{0}_{1}" -f $d, $stamp)
        $out.Base = $base
        $bom = New-Object System.Text.UTF8Encoding($true)

        # CSV
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine((($script:Cols | ForEach-Object { '"' + $_ + '"' }) -join ';'))
        foreach ($r in $sorted) { [void]$sb.AppendLine((($script:Cols | ForEach-Object { Csv-Val $r.$_ }) -join ';')) }
        [System.IO.File]::WriteAllText(($base + '.csv'), $sb.ToString(), $bom)

        # TXT (konsol cikti kaydi)
        [System.IO.File]::WriteAllText(($base + '.txt'), (($script:Log.ToArray()) -join "`r`n"), $bom)

        # host listesi
        $hl = @($sorted | Where-Object { $_.IP } | ForEach-Object { $_.Host })
        [System.IO.File]::WriteAllText(($base + '_hostlar.txt'), ($hl -join "`r`n"), $bom)

        # JSON
        $meta = [pscustomobject]@{
            domain = $d; mode = $S.Cfg.Name; date = (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'); version = $script:Ver; score = $score; grade = $grade
            total = $sorted.Count; resolved = @($sorted | Where-Object { $_.IP }).Count; measured = @($sorted | Where-Object { $null -ne $_.GercekMs }).Count
            elapsed = [math]::Round($S.Elapsed, 1); userIp = $(if ($S.Env -and $S.Env.Pub) { [string]$S.Env.Pub.query } else { '' })
            userIsp = $(if ($S.Env -and $S.Env.Pub) { [string]$S.Env.Pub.isp } else { '' }); userCity = $(if ($S.Env -and $S.Env.Pub) { ([string]$S.Env.Pub.city + ', ' + [string]$S.Env.Pub.country) } else { '' })
            globalTtl = [bool]$ctx.GlobalTtl; ttl = [string]$ctx.TtlValue; imkansiz = $ctx.ImkansizN; supheli = $ctx.SupheliN
        }
        $mprops = 'domain', 'mode', 'date', 'version', 'score', 'grade', 'total', 'resolved', 'measured', 'elapsed', 'userIp', 'userIsp', 'userCity', 'globalTtl', 'ttl', 'imkansiz', 'supheli'
        $rowJson = '[' + ((@($sorted) | ForEach-Object { To-JsonObj $_ $script:Cols }) -join ',') + ']'
        $metaJson = To-JsonObj $meta $mprops
        $findJson = '[' + ((@($script:Findings) | ForEach-Object { To-JsonObj $_ @('Sev', 'Cat', 'Msg') }) -join ',') + ']'
        $srcJson = '[' + ((@($S.Src) | ForEach-Object { To-JsonObj $_ @('Name', 'Tag', 'Ok', 'New', 'Total', 'Sec', 'Note') }) -join ',') + ']'
        $nsJson = '[' + ((@($S.Info.Ns) | Where-Object { $_ } | ForEach-Object { To-JsonObj $_ @('Name', 'IP', 'Ms', 'Serial') }) -join ',') + ']'
        $jsonFull = '{"meta":' + $metaJson + ',"rows":' + $rowJson + ',"findings":' + $findJson + '}'
        [System.IO.File]::WriteAllText(($base + '.json'), $jsonFull, (New-Object System.Text.UTF8Encoding($false)))

        # HTML
        $title = [System.Net.WebUtility]::HtmlEncode($d)
        $html = $script:HtmlTpl.Replace('__TITLE__', $title).Replace('__META__', $metaJson).Replace('__ROWS__', $rowJson).Replace('__FIND__', $findJson).Replace('__SRC__', $srcJson).Replace('__NS__', $nsJson)
        [System.IO.File]::WriteAllText(($base + '.html'), $html, $bom)
        $out.Html = $base + '.html'
        $script:LastHtml = $out.Html
    } catch {
        Say ('  Rapor dosyalari yazilamadi: ' + $_.Exception.Message) 'Red'
    }
    return $out
}

$script:HtmlTpl = @'
<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DoPing - __TITLE__</title>
<style>
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--line:#30363d;--acc:#58a6ff;--g:#3fb950;--y:#d29922;--o:#f0883e;--r:#f85149;--c:#39c5cf;--p:#bc8cff}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--fg:#1f2328;--mut:#656d76;--card:#fff;--line:#d0d7de;--acc:#0969da;--g:#1a7f37;--y:#9a6700;--o:#bc4c00;--r:#cf222e;--c:#0a7d8c;--p:#8250df}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif}
.wrap{max-width:1500px;margin:0 auto;padding:0 20px}
header{border-bottom:1px solid var(--line);padding:22px 0;background:var(--card)}
h1{margin:0;font-size:28px}h1 span{color:var(--acc)}h1 small{font-size:14px;color:var(--mut);font-weight:400;margin-left:10px}
#sub{color:var(--mut);margin-top:6px}
h2{font-size:18px;margin:32px 0 12px;border-left:4px solid var(--acc);padding-left:10px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:24px}.card i{font-style:normal;color:var(--mut);font-size:12px}.card small{color:var(--mut);display:block;margin-top:2px;word-break:break-all}
.f{display:flex;gap:10px;align-items:flex-start;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:9px 12px;margin-bottom:6px}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;white-space:nowrap;color:#fff}
.KRITIK{background:var(--r)}.UYARI{background:var(--y)}.BILGI{background:var(--c)}.IYI{background:var(--g)}
.cat{color:var(--mut);min-width:78px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px}
input[type=text]{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;min-width:280px}
button,.chip{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 12px;cursor:pointer;font-size:13px}
.chip.on{background:var(--acc);color:#fff;border-color:var(--acc)}
.tw{overflow:auto;border:1px solid var(--line);border-radius:10px;max-height:78vh}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{position:sticky;top:0;background:var(--card);text-align:left;padding:8px;cursor:pointer;white-space:nowrap;border-bottom:1px solid var(--line);user-select:none}
th:hover{color:var(--acc)}td{padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
tr:hover td{background:rgba(88,166,255,.07)}
.g{color:var(--g)}.y{color:var(--y)}.o{color:var(--o)}.r{color:var(--r)}.na{color:var(--mut)}.p{color:var(--p)}
.mono{font-family:Consolas,Menlo,monospace}
.lb{display:inline-block;height:6px;border-radius:3px;background:currentColor;vertical-align:middle;margin-left:6px;opacity:.55}
.hist{display:grid;grid-template-columns:90px 1fr 50px;gap:6px 10px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.hb{height:14px;background:var(--acc);border-radius:3px}
.tag{font-size:11px;padding:1px 6px;border-radius:4px;border:1px solid var(--line);color:var(--mut)}
footer{color:var(--mut);padding:30px 0;text-align:center;font-size:12px}
</style></head><body>
<header><div class="wrap"><h1>Do<span>Ping</span><small>Alan adı analiz raporu</small></h1><div id="sub"></div></div></header>
<main class="wrap">
<section class="cards" id="cards"></section>
<h2>Bulgular ve değerlendirme</h2><div id="find"></div>
<h2>Gecikme dağılımı</h2><div class="hist" id="hist"></div>
<h2>Host listesi</h2>
<div class="bar"><input type="text" id="q" placeholder="Ara: host, IP, ülke, sunucu, uyarı..."><label><input type="checkbox" id="ok"> sadece ölçülenler</label><span id="chips"></span><button id="csv">CSV indir</button></div>
<div class="tw"><table><thead id="th"></thead><tbody id="tb"></tbody></table></div>
<h2>Veri kaynakları</h2><div class="tw"><table id="src"></table></div>
<h2>Yetkili isim sunucuları</h2><div class="tw"><table id="ns"></table></div>
</main>
<footer>DoPing __TITLE__ raporu &middot; yalnızca herkese açık DNS/sertifika kayıtları ve standart bağlantı testleri kullanılmıştır.</footer>
<script>
const META=__META__,ROWS=__ROWS__,FIND=__FIND__,SRC=__SRC__,NS=__NS__;
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fm=v=>v==null?'–':(v<0.05?'<0,1':Number(v).toLocaleString('tr-TR',{maximumFractionDigits:v<10?2:(v<100?1:0)}));
const cl=v=>v==null?'na':v<30?'g':v<100?'y':v<200?'o':'r';
const med=(a,p)=>{a=a.slice().sort((x,y)=>x-y);if(!a.length)return null;const k=(a.length-1)*p,f=Math.floor(k),c=Math.ceil(k);return a[f]+(a[c]-a[f])*(k-f)};
document.getElementById('sub').textContent=META.domain+' · '+META.mode+' modu · '+META.date+' · ölçüm noktası: '+(META.userIp||'?')+' '+(META.userIsp?'('+META.userIsp+', '+META.userCity+')':'');
const lat=ROWS.filter(r=>r.GercekMs!=null&&r.Tur!=='TLD').map(r=>r.GercekMs);
const best=ROWS.filter(r=>r.GercekMs!=null).sort((a,b)=>a.GercekMs-b.GercekMs);
const sc=META.score,scc=sc>=75?'g':sc>=50?'y':'r';
const cards=[['Toplam isim',META.total,''],['DNS çözülen',META.resolved,''],['Ölçülen',META.measured,''],['Medyan gecikme',fm(med(lat,.5))+' ms','TCP bağlantı'],['p95 gecikme',fm(med(lat,.95))+' ms',''],
['En hızlı',best.length?fm(best[0].GercekMs)+' ms':'–',best.length?best[0].Host:''],['En yavaş',best.length?fm(best[best.length-1].GercekMs)+' ms':'–',best.length?best[best.length-1].Host:''],
['Sağlık puanı',sc+'/100','Not '+META.grade,scc],['ICMP güvenilirliği',META.globalTtl?'ŞÜPHELİ':(META.supheli>0?META.supheli+' şüpheli':'Normal'),META.globalTtl?'tüm yanıtlar TTL '+META.ttl:'',META.globalTtl?'r':(META.supheli>0?'y':'g')]];
document.getElementById('cards').innerHTML=cards.map(c=>`<div class="card"><i>${esc(c[0])}</i><b class="${c[3]||''}">${esc(c[1])}</b><small>${esc(c[2])}</small></div>`).join('');
document.getElementById('find').innerHTML=FIND.map(f=>`<div class="f"><span class="badge ${f.Sev}">${f.Sev}</span><span class="cat">${esc(f.Cat)}</span><span>${esc(f.Msg)}</span></div>`).join('')||'<div class="na">Bulgu yok.</div>';
const bk=[['< 10',0,10],['10 – 30',10,30],['30 – 60',30,60],['60 – 100',60,100],['100 – 200',100,200],['200+',200,1e9]];
const cnt=bk.map(b=>lat.filter(v=>v>=b[1]&&v<b[2]).length),mx=Math.max(1,...cnt);
document.getElementById('hist').innerHTML=bk.map((b,i)=>`<div>${b[0]} ms</div><div><div class="hb" style="width:${cnt[i]/mx*100}%"></div></div><div>${cnt[i]}</div>`).join('');
const COLS=[['#',null],['Host','Host'],['Tür','Tur'],['IP','IP'],['Gecikme (ms)','GercekMs'],['TCP min','TcpMin'],['TCP med','TcpMed'],['TCP p95','TcpP95'],['Jitter','TcpStd'],['ICMP','IcmpOrt'],['TLS','TlsMs'],['TTFB','TtfbMs'],['HTTP','Http'],['Sunucu / CDN','Sunucu'],['TLS sürüm','TlsSurum'],['Sertifika (gün)','SertGun'],['Ülke','UlkeKodu'],['Sağlayıcı','ISP'],['Uyarılar','Uyari']];
let sk='GercekMs',asc=true,types=new Set(ROWS.map(r=>r.Tur)),on=new Set(types);
document.getElementById('th').innerHTML='<tr>'+COLS.map((c,i)=>`<th data-k="${c[1]||''}">${c[0]}</th>`).join('')+'</tr>';
document.getElementById('chips').innerHTML=[...types].map(t=>`<span class="chip on" data-t="${t}">${t}</span>`).join(' ');
document.querySelectorAll('.chip').forEach(e=>e.onclick=()=>{const t=e.dataset.t;if(on.has(t)){on.delete(t);e.classList.remove('on')}else{on.add(t);e.classList.add('on')}draw()});
document.querySelectorAll('th').forEach(e=>e.onclick=()=>{const k=e.dataset.k;if(!k)return;if(sk===k)asc=!asc;else{sk=k;asc=true}draw()});
document.getElementById('q').oninput=draw;document.getElementById('ok').onchange=draw;
let cur=[];
function draw(){
 const q=document.getElementById('q').value.toLowerCase(),ok=document.getElementById('ok').checked;
 cur=ROWS.filter(r=>on.has(r.Tur)&&(!ok||r.GercekMs!=null)&&(!q||[r.Host,r.IP,r.Ulke,r.ISP,r.Sunucu,r.CDN,r.Uyari,r.Kaynak].join(' ').toLowerCase().includes(q)));
 cur.sort((a,b)=>{let x=a[sk],y=b[sk];if(x==null&&y==null)return 0;if(x==null)return 1;if(y==null)return -1;if(typeof x==='string'){x=x.toLowerCase();y=String(y).toLowerCase()}return (x<y?-1:x>y?1:0)*(asc?1:-1)});
 document.getElementById('tb').innerHTML=cur.map((r,i)=>{
  const c=r.Imkansiz?'p':cl(r.GercekMs),w=r.GercekMs==null?0:Math.min(60,r.GercekMs/4);
  const ic=r.IcmpOrt==null?'–':fm(r.IcmpOrt)+(/supheli/.test(r.Uyari||'')?' *':'');
  const cn=r.SertGun==null?'–':`<span class="${r.SertGun<0?'r':r.SertGun<14?'o':'g'}">${r.SertGun}</span>`;
  return `<tr><td class="na">${i+1}</td><td class="mono">${esc(r.Host)}</td><td><span class="tag">${r.Tur}</span></td><td class="mono">${esc(r.IP)}</td>
  <td class="${c}"><b>${fm(r.GercekMs)}</b><span class="lb" style="width:${w}px"></span></td><td>${fm(r.TcpMin)}</td><td>${fm(r.TcpMed)}</td><td>${fm(r.TcpP95)}</td><td>${fm(r.TcpStd)}</td><td>${ic}</td><td>${fm(r.TlsMs)}</td><td>${fm(r.TtfbMs)}</td>
  <td class="${r.Http>=500?'r':r.Http>=400?'o':'g'}">${r.Http==null?'–':r.Http}</td><td>${esc(r.CDN||r.Sunucu)}</td><td>${esc(r.TlsSurum)}</td><td>${cn}</td><td>${esc(r.UlkeKodu)}</td><td>${esc(r.ISP)}</td><td class="o">${esc((r.Uyari||'').split(',').join(' · '))}</td></tr>`}).join('');
}
draw();
document.getElementById('csv').onclick=()=>{const k=['Host','Tur','IP','GercekMs','TcpMin','TcpMed','TcpP95','IcmpOrt','TlsMs','TtfbMs','Http','Sunucu','CDN','TlsSurum','SertGun','UlkeKodu','ISP','Uyari'];
 const l=[k.join(';')].concat(cur.map(r=>k.map(c=>'"'+String(r[c]==null?'':r[c]).replace(/"/g,'""').replace('.',',')+'"').join(';')));
 const b=new Blob(['\ufeff'+l.join('\r\n')],{type:'text/csv'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='doping_'+META.domain+'.csv';a.click()};
document.getElementById('src').innerHTML='<tr><th>Kaynak</th><th>Durum</th><th>Yeni isim</th><th>Toplam</th><th>Süre (sn)</th><th>Not</th></tr>'+(SRC.map(s=>`<tr><td>${esc(s.Name)}</td><td class="${s.Ok?'g':'r'}">${s.Ok?'tamam':'başarısız'}</td><td>${s.New}</td><td>${s.Total}</td><td>${fm(s.Sec)}</td><td class="na">${esc(s.Note)}</td></tr>`).join('')||'<tr><td colspan=6 class="na">Web kaynakları bu modda kullanılmadı.</td></tr>');
document.getElementById('ns').innerHTML='<tr><th>Sunucu</th><th>IP</th><th>Yanıt (ms)</th><th>SOA seri</th></tr>'+(NS.map(s=>`<tr><td class="mono">${esc(s.Name)}</td><td class="mono">${esc(s.IP)}</td><td>${fm(s.Ms)}</td><td>${esc(s.Serial)}</td></tr>`).join('')||'<tr><td colspan=4 class="na">Veri yok.</td></tr>');
</script></body></html>
'@

# ------------------------------------------------------------ yardimcilar (tarama)
function Resolve-Many($names, [int]$threads, [string]$label) {
    $names = @($names | Where-Object { $_ })
    $res = Invoke-Pool -Items $names -Script $ResolveWorker -Threads $threads -Label $label
    $m = @{}
    foreach ($r in $res) { $m[$r.Name] = $r }
    return $m
}
function Build-Rows($names, $resMap, [string]$d, $wild, $rows, $seen) {
    $dropped = 0; $added = 0
    foreach ($n in $names) {
        if ($seen.ContainsKey($n)) { continue }
        $src = $script:Cand[$n]
        if (-not $src) { continue }
        $res = $resMap[$n]
        $strong = Is-Strong $src
        if (-not $res -and -not $strong) { continue }
        if ($res -and $wild.Count -gt 0 -and -not $strong) {
            $allw = $true
            foreach ($ip in $res.IPs) { if (-not $wild.Contains($ip)) { $allw = $false } }
            if ($allw) { $dropped++; continue }
        }
        [void]$rows.Add((New-Row $n (Get-Scope $n $d $src) $src $res))
        $seen[$n] = $true; $added++
    }
    return @{ Added = $added; Dropped = $dropped }
}

# ------------------------------------------------------------ bitis: analiz + cikti
function Finish-Scan($S) {
    $d = $S.D; $cfg = $S.Cfg; $rows = $S.Rows
    $ctx = Analyze-Rows $rows $S.Env $d
    $mainRow = $rows | Where-Object { $_.Host -eq $d } | Select-Object -First 1
    Score-Relations $rows $mainRow $S.RdapMain $S.RdapMap

    # yol analizi
    $traces = @()
    if ($cfg.Trace -gt 0 -and -not $script:SelfTest) {
        $tIps = New-Object System.Collections.ArrayList
        foreach ($r in @($rows | Where-Object { $_.IP -and ($_.Imkansiz -or $_.IcmpSupheli) })) { if ($tIps -notcontains $r.IP) { [void]$tIps.Add($r.IP) } }
        if ($mainRow -and $mainRow.IP -and $tIps -notcontains $mainRow.IP) { [void]$tIps.Add($mainRow.IP) }
        $tIps = @($tIps | Select-Object -First $cfg.Trace)
        if ($tIps.Count -gt 0) { Sub ("Yol analizi (tracert, ilk 6 adim): {0} hedef..." -f $tIps.Count) }
        foreach ($ip in $tIps) {
            $h = Get-Trace $ip 6
            $traces += [pscustomobject]@{ IP = $ip; Hops = $h }
        }
    }

    $score = Make-Findings $d $S.Info $rows $S.Env $ctx $S.Wild $S.RdapMain $S.RootRedirect
    $sorted = @($rows | Sort-Object @{ Expression = { if ($null -eq $_.GercekMs) { 1e9 } else { $_.GercekMs } } }, Host)

    Head ("SONUCLAR: $d")
    $idxMap = @{}
    Show-Main $sorted $idxMap
    Show-Details $sorted
    Show-TldTable $sorted
    foreach ($t in $traces) {
        Say ''
        Say ("  tracert -> {0}" -f $t.IP) 'White'
        if (@($t.Hops).Count -eq 0) { Say '     (yol bilgisi alinamadi)' 'DarkGray' }
        foreach ($h in @($t.Hops)) { Say ("     {0,2}  {1,-16} {2,8} ms" -f $h.Hop, $h.IP, (Fmt-Ms $h.Ms)) 'Gray' }
    }
    $grade = Show-Findings $score
    Show-Summary $d $rows $S.IpMap $S.Elapsed

    $prev = Get-PrevScan $d
    Show-Diff $prev $rows

    $files = Save-Reports $S $sorted $score $grade $ctx
    if ($files.Base) {
        Say ''
        Say '  Raporlar kaydedildi:' 'Green'
        foreach ($e in '.html', '.csv', '.json', '.txt', '_hostlar.txt') { Say ("    " + $files.Base + $e) 'Gray' }
    }
    return $idxMap
}

# ------------------------------------------------------------ ana tarama
function Run-Scan([string]$d, $cfg) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $script:Cand = @{}
    $script:Log.Clear()
    $ipMap = @{}; $probeState = @{ Count = 0 }
    $rows = New-Object System.Collections.ArrayList
    $seen = @{}; $tried = @{}; $allRes = @{}
    $S = @{ D = $d; Cfg = $cfg; Rows = $rows; Env = $null; Info = @{ Ns = @() }; Wild = (New-Object 'System.Collections.Generic.HashSet[string]'); RdapMain = $null; RdapMap = @{}; Src = @(); IpMap = $ipMap; RootRedirect = $null; Elapsed = 0 }

    Head ("TARAMA  |  Hedef: $d  |  Mod: $($cfg.Name)  |  " + (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'))

    # 1) ag ortami
    Sub '[1/10] Ag ortami ve referans olcumleri'
    $ne = Get-NetEnv
    $S.Env = $ne
    if ($ne.Pub) {
        Say ("     Genel IP     : {0}  ({1}, {2}, {3})" -f $ne.Pub.query, $ne.Pub.isp, $ne.Pub.city, $ne.Pub.country) 'Gray'
        if ($ne.Pub.proxy -or $ne.Pub.hosting) { Say '     UYARI: Genel IP proxy/VPN/hosting olarak isaretli; olcumler bu cikis noktasindan yapiliyor.' 'DarkYellow' }
    } else { Say '     Genel IP bilgisi alinamadi (konum tabanli kontroller atlanacak).' 'DarkYellow' }
    Say ("     Yerel IP     : {0}   Ag gecidi: {1}" -f $ne.Local, ($ne.Gateways -join ', ')) 'Gray'
    Say ("     DNS sunucu   : {0}" -f ($ne.Dns -join ', ')) 'Gray'
    if ($ne.Vpn.Count -gt 0) { Say ("     VPN/tunel    : " + (($ne.Vpn | Select-Object -First 3) -join ' | ')) 'DarkYellow' }
    if ($ne.Proxy) { Say ("     Proxy        : " + $ne.Proxy) 'DarkYellow' }
    $ne.BaseSuspect = ''
    $bl = @()
    $gwIp = $ne.Gateways | Select-Object -First 1
    if ($gwIp) {
        $x = Invoke-Pool -Items @($gwIp) -Script $IpWorker -Threads 1 -Extra @{ Icmp = 4; Tcp = 0; Timeout = 1000; Net = $script:HasNet } -Label 'Ag gecidi' -Quiet
        foreach ($i in $x) { $bl += [pscustomobject]@{ L = 'Ag gecidi'; R = $i } }
    }
    $x = Invoke-Pool -Items @('1.1.1.1', '8.8.8.8') -Script $IpWorker -Threads 1 -Extra @{ Icmp = 4; Tcp = 4; Timeout = 1500; Net = $script:HasNet } -Label 'Referans' -Quiet
    foreach ($i in $x) { $bl += [pscustomobject]@{ L = $(if ($i.IP -eq '1.1.1.1') { 'Cloudflare DNS' } else { 'Google DNS' }); R = $i } }
    Say '     Referans hedefler (ICMP ve TCP birbiriyle tutarli olmali):' 'White'
    foreach ($b in $bl) {
        $r = $b.R
        Say ("       {0,-16} {1,-15} ICMP {2,7} ms (TTL {3,-3})   TCP {4,7} ms" -f $b.L, $r.IP, (Fmt-Ms $r.IcmpAvg), $r.TTL, (Fmt-Ms $r.TcpAvg)) 'Gray'
        if ($null -ne $r.IcmpAvg -and $null -ne $r.TcpAvg -and $r.TcpAvg -gt 8 -and $r.IcmpAvg -lt 0.4 * $r.TcpAvg) {
            $ne.BaseSuspect = $r.IP
            Say '       ^ ICMP, TCP el sikismasindan cok daha hizli: ICMP yanitlari yerelde uretiliyor olabilir.' 'Red'
        }
    }

    # 2) DNS kayitlari
    Sub '[2/10] DNS kayitlari ve yetkili sunucular'
    $info = Collect-DnsRecords $d $cfg
    $S.Info = $info

    # 3) wildcard
    Sub '[3/10] Joker (wildcard) DNS testi'
    $wild = $S.Wild
    foreach ($k in 1..2) {
        $rnd = 'zz-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
        try { foreach ($a in [System.Net.Dns]::GetHostAddresses("$rnd.$d")) { [void]$wild.Add($a.IPAddressToString) } } catch {}
    }
    if ($wild.Count -gt 0) { Say ("     UYARI: Wildcard DNS var -> " + (($wild | ForEach-Object { $_ }) -join ', ') + "  (sahte sonuclar elenecek)") 'DarkYellow' }
    else { Say '     Wildcard yok, sozluk sonuclari guvenilir.' 'Green' }

    # 4) web kaynaklari
    if ($cfg.Web) {
        Sub '[4/10] Sertifika seffafligi ve pasif DNS kaynaklari (30-60 sn surebilir)'
        $src = Run-WebSources $d
        $S.Src = $src
        foreach ($s in $src) {
            if ($s.Ok) { Say ("     {0,-16} tamam    {1,5} isim ({2,4} yeni)   {3,5:N1} sn" -f $s.Name, $s.Total, $s.New, $s.Sec) 'Gray' }
            else { Say ("     {0,-16} BASARISIZ ({1})" -f $s.Name, $s.Note) 'DarkGray' }
        }
    } else { Sub '[4/10] Web kaynaklari bu modda atlandi' }

    # 5) sozluk + TLD
    $words = @($WL_quick)
    if ($cfg.Words -ge 2) { $words += $WL_std_extra }
    if ($cfg.Words -ge 3) {
        $words += $WL_deep_extra
        foreach ($pf in $WL_prefixes) { foreach ($i in 1..9) { $words += ("{0}{1}" -f $pf, $i); $words += ("{0}{1:00}" -f $pf, $i) } }
    }
    $words = @($words | Where-Object { $_ } | Sort-Object -Unique)
    Sub ("[5/10] Sozluk ({0} kelime)" -f $words.Count + $(if ($cfg.Tld) { ' + benzer TLD' } else { '' }))
    foreach ($w in $words) { Add-Cand "$w.$d" 'WL' }
    if ($cfg.Tld) {
        $p = $d -split '\.'
        $label = $p[$p.Count - 2]
        if ($p.Count -ge 3 -and $p[$p.Count - 1].Length -eq 2 -and (@('com','net','org','gen','co','edu','gov','biz','info','web') -contains $p[$p.Count - 2])) { $label = $p[$p.Count - 3] }
        foreach ($t in $TLDs) { if ("$label.$t" -ne $d) { Add-Cand "$label.$t" 'TLD' } }
    }

    # 6) cozumleme (+ permutasyon, ozyinelemeli)
    $names = @($script:Cand.Keys | Sort-Object)
    foreach ($n in $names) { $tried[$n] = $true }
    Sub ("[6/10] {0} aday isim DNS ile cozumleniyor" -f $names.Count)
    $m = Resolve-Many $names $cfg.Threads 'DNS cozumleme'
    foreach ($k in $m.Keys) { $allRes[$k] = $m[$k] }
    $br = Build-Rows $names $allRes $d $wild $rows $seen
    Say ("     Bulunan: {0}   (wildcard ile elenen: {1})" -f $br.Added, $br.Dropped) 'Green'

    if ($cfg.Perm -gt 0 -or $cfg.Rec -gt 0) {
        $inScope = @($rows | Where-Object { $_.IP -and $_.Tur -in 'Alt', 'Ana' } | ForEach-Object { $_.Host })
        if ($cfg.Perm -gt 0 -and $inScope.Count -gt 0) {
            $pn = New-Permutations ($inScope | Select-Object -First 80) $d $cfg.Perm $cfg.PermCap
            foreach ($n in @($pn)) { if (-not $seen.ContainsKey($n)) { Add-Cand $n 'PERM' } }
        }
        if ($cfg.Rec -gt 0) {
            $lvl1 = @($inScope | Where-Object { $_ -ne $d -and (($_.Substring(0, $_.Length - $d.Length - 1)) -notmatch '\.') } | Select-Object -First $cfg.Rec)
            foreach ($h in $lvl1) { foreach ($w in $WL_rec) { Add-Cand "$w.$h" 'REC' } }
        }
        $n2 = @($script:Cand.Keys | Where-Object { -not $tried.ContainsKey($_) } | Sort-Object)
        if ($n2.Count -gt 0) {
            foreach ($n in $n2) { $tried[$n] = $true }
            Say ("     Permutasyon / alt-alt tarama: {0} yeni aday" -f $n2.Count) 'Gray'
            $m = Resolve-Many $n2 $cfg.Threads 'Permutasyon'
            foreach ($k in $m.Keys) { $allRes[$k] = $m[$k] }
            $br = Build-Rows $n2 $allRes $d $wild $rows $seen
            Say ("     Ek bulunan: {0}   (elenen: {1})" -f $br.Added, $br.Dropped) 'Green'
        }
    }
    $live0 = @($rows | Where-Object { $_.IP }).Count
    Say ("     Toplam cozumlenen: {0}   (cozumlenemeyen kayit gecmisi: {1})" -f $live0, ($rows.Count - $live0)) 'White'

    # 7) olcum + SAN genisleme
    Sub ("[7/10] Gecikme olcumu (ICMP x{0}, TCP x{1}) ve TLS/HTTP testleri" -f $cfg.Icmp, $cfg.Tcp)
    Measure-Rows @($rows) $cfg $ipMap $probeState
    for ($round = 1; $round -le $cfg.Rounds; $round++) {
        foreach ($r in @($rows | Where-Object { $_.Probed })) {
            foreach ($s in @($r.SANlar -split ' ')) { if ($s -and ($s -eq $d -or $s.EndsWith(".$d"))) { Add-Cand $s 'SAN' } }
            if ($r.Yonlendirme -match '^https?://([^/:?#]+)') { $lh = $Matches[1].ToLower(); if ($lh -eq $d -or $lh.EndsWith(".$d")) { Add-Cand $lh 'REDIR' } }
        }
        $n3 = @($script:Cand.Keys | Where-Object { -not $tried.ContainsKey($_) } | Sort-Object)
        if ($n3.Count -eq 0) { break }
        foreach ($n in $n3) { $tried[$n] = $true }
        Sub ("     Tur {0}: sertifika SAN / yonlendirme ile {1} yeni isim" -f $round, $n3.Count)
        $m = Resolve-Many $n3 $cfg.Threads 'SAN cozumleme'
        foreach ($k in $m.Keys) { $allRes[$k] = $m[$k] }
        $start = $rows.Count
        $br = Build-Rows $n3 $allRes $d $wild $rows $seen
        Say ("     Eklenen: {0}" -f $br.Added) 'Green'
        if ($rows.Count -gt $start) { Measure-Rows @($rows[$start..($rows.Count - 1)]) $cfg $ipMap $probeState }
    }

    # 8) CNAME / geo / RDAP
    Sub '[8/10] CNAME (dangling) kontrolu, konum bilgisi, alan adi kaydi (RDAP)'
    if ($script:HasRDN -and $cfg.Key -ne '1') {
        $cn = Invoke-Pool -Items @($rows | Select-Object -First 400 | ForEach-Object { $_.Host }) -Script $CnameWorker -Threads 30 -Label 'CNAME kontrol'
        $cm = @{}; foreach ($x in $cn) { $cm[$x.Name] = $x }
        foreach ($r in $rows) {
            $x = $cm[$r.Host]
            if ($x) { $r.CNAME = $x.Target; if (-not $x.TargetResolves) { $r.Dangling = $true } }
        }
        $dg = @($rows | Where-Object { $_.Dangling }).Count
        Say ("     CNAME kaydi olan: {0}   cozulmeyen hedef (dangling): {1}" -f $cm.Count, $dg) $(if ($dg -gt 0) { 'Red' } else { 'Green' })
    }
    $ipsAll = @($rows | Where-Object { $_.IP } | ForEach-Object { $_.IP } | Select-Object -Unique)
    $geo = Get-GeoMap $ipsAll
    foreach ($r in $rows) { if ($r.IP -and $geo.ContainsKey($r.IP)) { Apply-Geo $r $geo[$r.IP] } }
    Say ("     Konum bilgisi alinan IP: {0} / {1}" -f $geo.Count, $ipsAll.Count) 'Gray'
    $rn = @($d)
    if ($cfg.Tld) { $rn += @($rows | Where-Object { $_.Tur -eq 'TLD' -and $_.IP } | Select-Object -First 60 | ForEach-Object { $_.Host }) }
    $rd = Invoke-Pool -Items $rn -Script $RdapWorker -Threads 4 -Label 'RDAP sorgusu'
    foreach ($x in $rd) { $S.RdapMap[$x.Name] = $x }
    $S.RdapMain = $S.RdapMap[$d]
    if ($S.RdapMain -and $S.RdapMain.Found) {
        Say ("     Kayit: kayitci={0}  olusturma={1}  bitis={2}" -f $S.RdapMain.Registrar, $S.RdapMain.Created, $S.RdapMain.Expires) 'Gray'
    } else { Say '     RDAP kaydi alinamadi (bu uzanti RDAP desteklemiyor olabilir).' 'DarkGray' }

    # 9) hassas olcum
    Sub ("[9/10] Hassas (seri) olcum: en onemli IP'ler tek tek, es zamanli yuk olmadan")
    $pk = Run-Precision $rows $cfg $ipMap $d
    if (@($pk).Count -gt 0) { Say ("     {0} IP seri olarak 10 ICMP + 12 TCP ile yeniden olculdu." -f @($pk).Count) 'Gray' } else { Say '     Atlandi.' 'DarkGray' }
    $mainRow = $rows | Where-Object { $_.Host -eq $d -and $_.IP } | Select-Object -First 1
    if ($script:HasNet -and $mainRow) { $S.RootRedirect = [DpNet]::Probe($d, $mainRow.IP, 80, $false, $cfg.Timeout) }

    # 10) analiz
    Sub '[10/10] Analiz ve rapor'
    $sw.Stop()
    $S.Elapsed = $sw.Elapsed.TotalSeconds
    $script:LastScan = $S
    return (Finish-Scan $S)
}

# ------------------------------------------------------------ canli izleme
function Start-Monitor($idxMap) {
    $sel = (Read-Host '  Izlenecek satir numaralari (virgullu, bos = ilk 8) ').Trim()
    $targets = @()
    if ($sel) { foreach ($t in ($sel -split '[ ,;]+')) { if ($idxMap.ContainsKey($t)) { $targets += $idxMap[$t] } } }
    else { foreach ($k in 1..8) { if ($idxMap.ContainsKey("$k")) { $targets += $idxMap["$k"] } } }
    $targets = @($targets | Select-Object -First 15)
    if ($targets.Count -eq 0) { Say '  Gecerli hedef yok.' 'Red'; return }
    $hist = @{}
    foreach ($t in $targets) { $hist[$t.Host] = New-Object 'System.Collections.Generic.List[double]' }
    $lost = @{}; $sent = @{}
    foreach ($t in $targets) { $lost[$t.Host] = 0; $sent[$t.Host] = 0 }
    $items = @($targets | ForEach-Object { @{ Host = $_.Host; IP = $_.IP; Port = $(if ($_.TcpPort) { $_.TcpPort } else { 443 }) } })
    $cfg = @{ Timeout = 1500; Net = $script:HasNet }
    $tick = 0
    Clear-Host
    while ($true) {
        $tick++
        $res = Invoke-Pool -Items $items -Script $MonWorker -Threads 15 -Extra $cfg -Quiet
        foreach ($r in $res) {
            $sent[$r.Host]++
            if ($r.Tcp -ge 0) { $hist[$r.Host].Add($r.Tcp) } else { $lost[$r.Host]++; $hist[$r.Host].Add(-1) }
            $r | Add-Member -NotePropertyName _x -NotePropertyValue 1 -Force
        }
        $icm = @{}; foreach ($r in $res) { $icm[$r.Host] = $r.Icmp }
        try { $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 0, 0 } catch { Clear-Host }
        Write-Host ("  DoPing CANLI IZLEME  -  olcum #{0}  -  cikmak icin Q" -f $tick).PadRight($script:ConW - 2) -ForegroundColor Cyan
        Write-Host ("  {0} {1} {2} {3} {4} {5} {6} {7}" -f 'HOST'.PadRight(34), 'SON'.PadLeft(8), 'ORT'.PadLeft(8), 'MIN'.PadLeft(8), 'MAX'.PadLeft(8), 'KAYIP'.PadLeft(6), 'ICMP'.PadLeft(7), 'GRAFIK (son 40)').PadRight($script:ConW - 2) -ForegroundColor White
        foreach ($t in $targets) {
            $h = $hist[$t.Host]
            $ok = @($h | Where-Object { $_ -ge 0 })
            $last = $h[$h.Count - 1]
            $avg = $null; $mn = $null; $mx = $null
            if ($ok.Count -gt 0) { $m = $ok | Measure-Object -Average -Minimum -Maximum; $avg = $m.Average; $mn = $m.Minimum; $mx = $m.Maximum }
            $loss = [math]::Round(100.0 * $lost[$t.Host] / [math]::Max(1, $sent[$t.Host]), 0)
            $tail = @($h | Select-Object -Last 40)
            $ms = 1.0; if ($ok.Count -gt 0) { $ms = [math]::Max(1.0, [double]$mx) }
            $sp = Spark $tail $ms
            $lastS = $(if ($last -lt 0) { 'zaman asimi' } else { Fmt-Ms $last })
            $col = 'Green'; if ($last -lt 0) { $col = 'Red' } elseif ($last -ge 100) { $col = 'DarkYellow' } elseif ($last -ge 30) { $col = 'Yellow' }
            $ic = $(if ($icm[$t.Host] -ge 0) { Fmt-Ms $icm[$t.Host] } else { '-' })
            Write-Host (("  {0} {1} {2} {3} {4} {5} {6} {7}" -f (Cut $t.Host 34).PadRight(34), $lastS.PadLeft(8), (Fmt-Ms $avg).PadLeft(8), (Fmt-Ms $mn).PadLeft(8), (Fmt-Ms $mx).PadLeft(8), ("%$loss").PadLeft(6), $ic.PadLeft(7), $sp).PadRight($script:ConW - 2)) -ForegroundColor $col
        }
        $quit = $false
        for ($i = 0; $i -lt 8; $i++) {
            Start-Sleep -Milliseconds 100
            try { if ($Host.UI.RawUI.KeyAvailable) { $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); if ($k.Character -eq 'q' -or $k.Character -eq 'Q' -or $k.VirtualKeyCode -eq 27) { $quit = $true } } } catch { $quit = $true }
        }
        if ($quit) { break }
    }
    Say ''
}

function Show-RowDetail($r) {
    Head ("HOST DETAYI: " + $r.Host)
    foreach ($p in $r.PSObject.Properties) {
        if ($null -eq $p.Value -or [string]$p.Value -eq '') { continue }
        $v = $p.Value
        if ($v -is [double]) { $v = Fmt-Ms $v }
        Say ("  {0,-14}: {1}" -f $p.Name, (Cut ([string]$v) ($script:ConW - 22))) 'Gray'
    }
}

# ------------------------------------------------------------ kendi kendine test (agsiz)
function Invoke-SelfTest {
    Say '  [SELFTEST] Sentetik verilerle rapor hatti test ediliyor...' 'Yellow'
    $script:OutDir = Join-Path ([IO.Path]::GetTempPath()) 'doping_selftest'
    $d = 'example.test'
    $cfg = Get-ModeConfig '3'
    $script:Cand = @{}
    $rows = New-Object System.Collections.ArrayList
    $mk = {
        param($n, $tur, $ip, $tcp, $icmp, $ttl, $cc, $lat, $lon, $isp)
        $src = New-Object 'System.Collections.Generic.HashSet[string]'; [void]$src.Add('CT')
        $r = New-Row $n $tur $src @{ IPs = @($ip); DnsMs = 12.5 }
        $r.TcpPort = 443; $r.TcpOrt = $tcp; $r.TcpMin = $tcp - 0.4; $r.TcpMed = $tcp; $r.TcpP95 = $tcp + 2; $r.TcpMax = $tcp + 3; $r.TcpStd = 0.8; $r.TcpKayip = 0
        if ($null -ne $icmp) { $r.IcmpOrt = $icmp; $r.IcmpMin = $icmp; $r.IcmpMax = $icmp + 1; $r.IcmpJit = 0.3; $r.IcmpKayip = 0; $r.TTL = $ttl; $r.Hop = 128 - $ttl }
        $r.UlkeKodu = $cc; $r.Ulke = $cc; $r.Lat = $lat; $r.Lon = $lon; $r.ISP = $isp; $r.ASN = "AS$($cc.GetHashCode())"
        $r.Probed = $true; $r.Http = 200; $r.TlsMs = $tcp * 2; $r.TtfbMs = $tcp * 4; $r.TlsSurum = 'TLS1.3'; $r.SertGun = 60; $r.SertUyum = $true; $r.SertZincir = $true; $r.SertVeren = 'Test CA'; $r.SertAnahtar = 'RSA 2048'
        $r.HSTS = $true; $r.CSP = $false; $r.XFO = $true; $r.XCTO = $true; $r.RefPol = $false; $r.GuvPuan = 3; $r.SANlar = "$n www.$n"; $r.SANsayisi = 2
        return $r
    }
    [void]$rows.Add((& $mk $d 'Ana' '203.0.113.10' 24.0 1.2 126 'DE' 50.1 8.6 'Hetzner'))
    [void]$rows.Add((& $mk "www.$d" 'Alt' '203.0.113.10' 24.5 1.3 126 'DE' 50.1 8.6 'Hetzner'))
    [void]$rows.Add((& $mk "api.$d" 'Alt' '198.51.100.7' 80.0 1.1 126 'US' 37.4 -122.0 'Amazon'))
    [void]$rows.Add((& $mk "dev.$d" 'Alt' '198.51.100.9' 210.0 1.4 126 'AU' -33.8 151.2 'Telstra'))
    [void]$rows.Add((& $mk "cdn.$d" 'Alt' '104.18.1.1' 4.0 1.0 126 'CA' 45.0 -73.0 'Cloudflare, Inc.'))
    [void]$rows.Add((& $mk "mail.$d" 'Alt' '192.0.2.44' 33.0 1.2 126 'FR' 48.8 2.3 'OVH'))
    [void]$rows.Add((& $mk "old.$d" 'Alt' '192.0.2.99' 41.0 1.2 126 'NL' 52.3 4.9 'Leaseweb'))
    [void]$rows.Add((& $mk "example.org" 'TLD' '192.0.2.50' 55.0 $null $null 'JP' 35.6 139.7 'Sakura'))
    $rows[3].SertGun = -3; $rows[2].CNAME = 'dead.herokuapp.com'; $rows[2].Dangling = $true; $rows[6].SertUyum = $false
    $rows[7].SANlar = "example.org $d"
    $unres = New-Row "gone.$d" 'Alt' (@('CT') -as [string[]]) $null
    [void]$rows.Add($unres)
    $env = @{ Pub = [pscustomobject]@{ query = '1.2.3.4'; isp = 'TestISP'; city = 'Dusseldorf'; country = 'Germany'; lat = 51.2; lon = 6.8; proxy = $false }; Vpn = @('WireGuard Tunnel'); Proxy = ''; BaseSuspect = '1.1.1.1'; Gateways = @('192.168.1.1'); Dns = @('192.168.1.1'); Local = '192.168.1.20' }
    $info = @{ Ok = $true; Spf = 'v=spf1 ~all'; SpfAll = '~'; Dmarc = 'v=DMARC1; p=none'; DmarcPolicy = 'none'; Caa = $false; Dnssec = $false; Ns = @([pscustomobject]@{ Name = 'ns1.example.test'; IP = '192.0.2.1'; Ms = 12.0; Serial = 5 }, [pscustomobject]@{ Name = 'ns2.example.test'; IP = '192.0.2.2'; Ms = 400.0; Serial = 6 }); SerialMismatch = $true }
    $wild = New-Object 'System.Collections.Generic.HashSet[string]'
    $rdm = [pscustomobject]@{ Name = $d; Found = $true; Registrar = 'Test Registrar'; Created = '2010-01-01'; Expires = '2027-01-01'; NS = 'ns1 ns2' }
    $S = @{ D = $d; Cfg = $cfg; Rows = $rows; Env = $env; Info = $info; Wild = $wild; RdapMain = $rdm; RdapMap = @{ 'example.org' = [pscustomobject]@{ Found = $true; Registrar = 'Other'; Created = '2001-01-01'; Expires = '2026-12-01'; NS = 'x y' } }; Src = @([pscustomobject]@{ Name = 'crt.sh'; Tag = 'CT'; Ok = $true; New = 5; Total = 9; Sec = 3.2; Note = '' }); IpMap = @{}; RootRedirect = [pscustomobject]@{ Status = 301; Location = "https://$d/"; HttpOk = $true }; Elapsed = 12.3 }
    $map = Finish-Scan $S
    Say ("  [SELFTEST] Tamam. satir={0}" -f $map.Count) 'Green'
    if ($script:LastHtml) { Say ("  [SELFTEST] HTML: " + $script:LastHtml) 'Green' }
}

# ------------------------------------------------------------ ana dongu
if ($script:SelfTest) { Banner; Invoke-SelfTest; exit 0 }

$pre = $env:ARG1
$preMode = $env:ARG2
while ($true) {
    Banner
    if ($pre) { $in = $pre; $pre = $null } else { $in = Read-Host '  Alan adi girin (ornek: example.com)  [cikis: 0]' }
    if ($in -eq '0') { break }
    $dom = Normalize-Domain $in
    if (-not $dom) {
        Say '  Gecersiz alan adi. Ornek: example.com' 'Red'
        if ($preMode) { exit 2 }
        Start-Sleep -Seconds 2
        continue
    }
    $again = $true
    while ($again) {
        $again = $false
        if ($preMode) { $mk = $preMode; $preMode = $null }
        else {
            Say ''
            Say '  Tarama modu:' 'White'
            Say '    [1] Hizli     - DNS + kucuk sozluk + TCP/ICMP olcumu (~15-30 sn)' 'Gray'
            Say '    [2] Standart  - + 8 pasif kaynak, TLS/HTTP/sertifika, permutasyon, hassas olcum (~1-2 dk)' 'Gray'
            Say '    [3] Derin     - + benzer TLD + RDAP, 600+ sozluk, genis permutasyon, 3 tekrar, yol analizi (~3-6 dk)' 'Gray'
            Say '    [4] Ozel      - tum ayarlari kendin sec' 'Gray'
            $mk = (Read-Host '  Secim [varsayilan 2]').Trim()
        }
        if ($mk -eq '4') { $cfg = Get-CustomConfig } else { if ($mk -notin '1', '2', '3') { $mk = '2' }; $cfg = Get-ModeConfig $mk }
        $idxMap = Run-Scan $dom $cfg
        if ($env:ARG2) { exit 0 }

        $next = 'new'
        while ($true) {
            Say ''
            Say '  [1] Yeni alan adi  [2] Ayni alani yeniden tara  [3] Canli izleme paneli  [4] Canli ping (-t)' 'Cyan'
            Say '  [5] Host detayi    [6] HTML raporu ac           [7] Rapor klasoru        [0] Cikis' 'Cyan'
            $c = (Read-Host '  Secim').Trim()
            if ($c -eq '1') { $next = 'new'; break }
            elseif ($c -eq '2') { $next = 'same'; break }
            elseif ($c -eq '0') { $next = 'exit'; break }
            elseif ($c -eq '3') { Start-Monitor $idxMap }
            elseif ($c -eq '4' -or $c -eq '5') {
                $n = (Read-Host '  Tablodaki satir numarasi').Trim()
                if ($idxMap.ContainsKey($n)) {
                    $r = $idxMap[$n]
                    if ($c -eq '4') { Start-Process cmd.exe -ArgumentList '/k', ("title DoPing - " + $r.Host + " & ping -t " + $r.Host) }
                    else { Show-RowDetail $r }
                } else { Say '  Gecersiz numara.' 'Red' }
            }
            elseif ($c -eq '6') { if ($script:LastHtml -and (Test-Path $script:LastHtml)) { Start-Process $script:LastHtml } }
            elseif ($c -eq '7') { if (Test-Path $script:OutDir) { Start-Process explorer.exe $script:OutDir } }
        }
        if ($next -eq 'exit') { exit 0 }
        if ($next -eq 'same') { $again = $true }
    }
}
exit 0
