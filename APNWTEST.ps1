<#
.SYNOPSIS
    Windows Autopilot & Intune Network Requirements Checker v1.8
.DESCRIPTION
    Validates DNS, port connectivity, SSL inspection, proxy config,
    download speed, latency profile, CDN identification, and
    estimates Autopilot enrollment time. Includes Hybrid AD LOS.
.NOTES
    Author  : Akhil Chavan | UPL EUC
    Version : 1.8
    Date    : 2026-06-11
    Output  : C:\Scripts\AutopilotReqCheck_<timestamp>.html/.log
    Runs on : PowerShell 5.1+ (OOBE-safe, elevated privileges required)
.CHANGELOG
    v1.5   - Updated Autopilot payload to Lean/Single-app (1.0GB).
    v1.6   - Hardcoded netsh.exe path to bypass 25H2 PATH variable bugs.
    v1.7   - Diversified Speed Test targets across 4 distinct Microsoft CDNs.
    v1.8   - Added Phase 6: Hybrid AD Line-of-Sight (DNS SRV, LDAP, Kerberos, SMB).
#>

#Requires -Version 5.1

# ======================== CONFIGURATION ========================
$LogFolder   = "C:\Scripts"
$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$HTMLReport  = Join-Path $LogFolder "AutopilotReqCheck_$Timestamp.html"
$TxtLog      = Join-Path $LogFolder "AutopilotReqCheck_$Timestamp.log"
$TimeoutSec  = 5

# --- HYBRID AD CONFIGURATION ---
# Enter your internal domain name to enable the Hybrid Line-of-Sight check (e.g., "corp.domain.local")
# Leave blank to skip Phase 6.
$HybridDomainName = ""

# Enforce TLS 1.2 globally
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Load System.Web BEFORE HTML generation
try {
    Add-Type -AssemblyName System.Web -ErrorAction Stop
    $script:UseHtmlEncode = $true
} catch {
    $script:UseHtmlEncode = $false
}

function Encode-Html {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    if ($script:UseHtmlEncode) {
        return [System.Web.HttpUtility]::HtmlEncode($Text)
    } else {
        return $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'
    }
}

# SSL Inspection check hosts
$SslCheckHosts = @(
    "manage.microsoft.com",
    "login.microsoftonline.com",
    "EnterpriseEnrollment.manage.microsoft.com",
    "enterpriseregistration.windows.net",
    "login.live.com",
    "ecs.office.com"
)

# Known SSL inspection CA keywords
$InspectionCAs = @(
    "Zscaler","Palo Alto","Fortinet","FortiGate","Blue Coat",
    "Symantec","McAfee","Sophos","Barracuda","Cisco Umbrella",
    "Websense","Check Point","WatchGuard","SonicWall","Untangle",
    "ContentKeeper","Lightspeed","Smoothwall","iBoss","Netskope"
)

# Diversified Speed Test Endpoints (Forces traffic across different CDNs)
$SpeedTestEndpoints = @(
    @{ Name = "WinUpdate (disallowedcertstl.cab)"; Url = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab" }
    @{ Name = "WinUpdate (authrootstl.cab)";       Url = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab" }
    @{ Name = "Office 365 CDN (setup.exe)";        Url = "https://officecdn.microsoft.com/pr/wsus/setup.exe" }
    @{ Name = "Azure SDK CDN (dotnet.exe)";        Url = "https://download.visualstudio.microsoft.com/download/pr/1f5af042-d0e4-4002-9c59-9ba66bcf15f6/089f837de42708daaca11c04d1cbbd25/dotnet-sdk-6.0.402-win-x64.exe" }
)

# CDN detection & latency profile endpoints
$CdnProfileEndpoints = @(
    "manage.microsoft.com",
    "login.microsoftonline.com",
    "dl.delivery.mp.microsoft.com",
    "ctldl.windowsupdate.com",
    "swda01-mscdn.manage.microsoft.com"
)

# ======================== AUTOPILOT PAYLOAD ESTIMATION ========================
$AutopilotPayloads = @(
    @{ Name = "Windows Quality Updates";  SizeGB = 0.5;  Required = $true  }
    @{ Name = "Core ESP App";             SizeGB = 0.2;  Required = $true  }
    @{ Name = "Policies, Certs, Scripts"; SizeGB = 0.1;  Required = $true  }
    @{ Name = "Drivers (Autopilot)";      SizeGB = 0.2;  Required = $true  }
)
$ProcessingOverheadMin = 12  # ESP processing, OOBE screens, reboots

# Create log folder
if (!(Test-Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null }

# ======================== LOGGING ========================
function Write-Log {
    param([string]$Message)
    Add-Content -Path $TxtLog -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
}

Write-Log "===== Autopilot Requirements Check v1.8 Started ====="
Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "  AUTOPILOT NETWORK CHECKER v1.8" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=============================================`n" -ForegroundColor Cyan

# ======================== ENDPOINT DEFINITIONS ========================
$Endpoints = @(
    @{ ID="163"; Category="Intune Client & Host Service"; Host="manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="Covers *.manage.microsoft.com" }
    @{ ID="163"; Category="Intune Client & Host Service"; Host="EnterpriseEnrollment.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="172"; Category="MDM Delivery Optimization"; Host="geover-prod.do.dsp.mp.microsoft.com"; Ports=@(443); Protocol="TCP"; Note="Covers *.do.dsp.mp.microsoft.com" }
    @{ ID="172"; Category="MDM Delivery Optimization"; Host="dl.delivery.mp.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="Covers *.dl.delivery.mp.microsoft.com" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swda01-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swda02-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdb01-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdb02-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdc01-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdc02-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdd01-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdd02-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdin01-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="170"; Category="MEM - Win32Apps"; Host="swdin02-mscdn.manage.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="97";  Category="Device Auth & MS Account"; Host="account.live.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="97";  Category="Device Auth & MS Account"; Host="login.live.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="190"; Category="Endpoint Discovery"; Host="go.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="189"; Category="Feature Deployment"; Host="config.edge.skype.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="189"; Category="Feature Deployment"; Host="ecs.office.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="192"; Category="Organizational Messages"; Host="fd.api.orgmsg.microsoft.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="192"; Category="Organizational Messages"; Host="ris.prod.api.personalization.ideas.microsoft.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="56";  Category="Authentication & Identity (Entra ID)"; Host="login.microsoftonline.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="56";  Category="Authentication & Identity (Entra ID)"; Host="graph.windows.net"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="150"; Category="Office Customization Service"; Host="officeclient.microsoft.com"; Ports=@(443); Protocol="TCP"; Note="Covers *.officeconfig.msocdn.com" }
    @{ ID="150"; Category="Office Customization Service"; Host="config.office.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="59";  Category="Identity Services & CDNs"; Host="enterpriseregistration.windows.net"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="59";  Category="Identity Services & CDNs"; Host="certauth.enterpriseregistration.windows.net"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="164"; Category="Autopilot - Windows Update"; Host="ctldl.windowsupdate.com"; Ports=@(80,443); Protocol="TCP"; Note="Covers *.windowsupdate.com" }
    @{ ID="164"; Category="Autopilot - Windows Update"; Host="dl.delivery.mp.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="Covers *.dl.delivery.mp.microsoft.com" }
    @{ ID="164"; Category="Autopilot - Windows Update"; Host="geo-prod.do.dsp.mp.microsoft.com"; Ports=@(443); Protocol="TCP"; Note="Covers *.prod.do.dsp.mp.microsoft.com" }
    @{ ID="164"; Category="Autopilot - Windows Update"; Host="www.update.microsoft.com"; Ports=@(80,443); Protocol="TCP"; Note="Covers *.update.microsoft.com" }
    @{ ID="164"; Category="Autopilot - Windows Update"; Host="tsfe.trafficshaping.dsp.mp.microsoft.com"; Ports=@(443); Protocol="TCP"; Note="443 only" }
    @{ ID="164"; Category="Autopilot - Windows Update"; Host="adl.windows.com"; Ports=@(80,443); Protocol="TCP"; Note="" }
    @{ ID="165"; Category="Autopilot - NTP Sync"; Host="time.windows.com"; Ports=@(123); Protocol="UDP"; Note="" }
    @{ ID="169"; Category="Autopilot - WNS Dependencies"; Host="clientconfig.passport.net"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="169"; Category="Autopilot - WNS Dependencies"; Host="windowsphone.com"; Ports=@(443); Protocol="TCP"; Note="" }
    @{ ID="169"; Category="Autopilot - WNS Dependencies"; Host="c.s-microsoft.com"; Ports=@(443); Protocol="TCP"; Note="Covers *.s-microsoft.com" }
    @{ ID="173"; Category="Autopilot - TPM Dependencies"; Host="ekop.intel.com"; Ports=@(443); Protocol="TCP"; Note="Intel TPM" }
    @{ ID="173"; Category="Autopilot - TPM Dependencies"; Host="ekcert.spserv.microsoft.com"; Ports=@(443); Protocol="TCP"; Note="MS TPM cert" }
    @{ ID="173"; Category="Autopilot - TPM Dependencies"; Host="ftpm.amd.com"; Ports=@(443); Protocol="TCP"; Note="AMD fTPM" }
    @{ ID="182"; Category="Autopilot - Diagnostics Upload"; Host="lgmsapeweu.blob.core.windows.net"; Ports=@(443); Protocol="TCP"; Note="West Europe" }
    @{ ID="182"; Category="Autopilot - Diagnostics Upload"; Host="lgmsapewus2.blob.core.windows.net"; Ports=@(443); Protocol="TCP"; Note="West US 2" }
    @{ ID="182"; Category="Autopilot - Diagnostics Upload"; Host="lgmsapesea.blob.core.windows.net"; Ports=@(443); Protocol="TCP"; Note="Southeast Asia" }
    @{ ID="182"; Category="Autopilot - Diagnostics Upload"; Host="lgmsapeaus.blob.core.windows.net"; Ports=@(443); Protocol="TCP"; Note="Australia" }
    @{ ID="182"; Category="Autopilot - Diagnostics Upload"; Host="lgmsapeind.blob.core.windows.net"; Ports=@(443); Protocol="TCP"; Note="India" }
    @{ ID="182"; Category="Autopilot - Diagnostics Upload"; Host="lgmsapeswiss.blob.core.windows.net"; Ports=@(443); Protocol="TCP"; Note="Switzerland" }
)

$WildcardHttpsProbes = @(
    @{ ID="163"; Category="Intune Client & Host Service"; Url="https://manage.microsoft.com/api/health"; Note="Covers *.dm.microsoft.com (Intune API health)" }
)

# ======================== TEST FUNCTIONS ========================

function Test-DnsResolution {
    param([string]$Hostname)
    try {
        $result = [System.Net.Dns]::GetHostAddresses($Hostname)
        if ($result.Count -gt 0) { return @{ Status = "Pass"; IP = ($result | Select-Object -First 1).IPAddressToString } }
    } catch {}
    return @{ Status = "Fail"; IP = "Unresolvable" }
}

function Test-TcpPort {
    param([string]$Hostname, [int]$Port, [int]$Timeout = 5)
    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(($Timeout * 1000), $false)
        if (-not $wait) { $tcp.Close(); return "Fail" }
        $tcp.EndConnect($connect); $tcp.Close(); return "Pass"
    } catch {
        if ($tcp) { try { $tcp.Close() } catch {} }
        return "Fail"
    }
}

function Test-NtpPort {
    param([string]$Hostname, [int]$Timeout = 5)
    $udp = $null
    try {
        $ntpData = New-Object byte[] 48; $ntpData[0] = 0x1B
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.SendTimeout = $Timeout * 1000; $udp.Client.ReceiveTimeout = $Timeout * 1000
        $udp.Connect($Hostname, 123); [void]$udp.Send($ntpData, $ntpData.Length)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref]$ep); $udp.Close()
        if ($response.Length -ge 48) { return "Pass" } else { return "Fail" }
    } catch {
        if ($udp) { try { $udp.Close() } catch {} }
        return "Fail"
    }
}

function Test-HttpsProbe {
    param([string]$Url, [int]$Timeout = 5)
    $prevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Timeout = $Timeout * 1000; $req.Method = "HEAD"; $req.AllowAutoRedirect = $true
        $resp = $req.GetResponse(); $code = [int]$resp.StatusCode; $resp.Close()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
        return @{ Status = "Pass"; Code = $code }
    } catch [System.Net.WebException] {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
        $wr = $_.Exception.Response
        if ($wr) { $c = [int]$wr.StatusCode; try{$wr.Close()}catch{}; return @{ Status = "Pass"; Code = $c } }
        return @{ Status = "Fail"; Code = "Unreachable" }
    } catch {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
        return @{ Status = "Fail"; Code = $_.Exception.Message }
    }
}

function Test-SslInspection {
    param([string]$Hostname, [int]$Port = 443, [int]$Timeout = 5)
    $tcp = $null; $ssl = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.SendTimeout = $Timeout * 1000; $tcp.ReceiveTimeout = $Timeout * 1000
        $connect = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(($Timeout * 1000), $false)
        if (-not $wait) { $tcp.Close(); return @{ Status="Error"; Issuer="Timed out"; Inspector=""; Subject=""; Expiry="" } }
        $tcp.EndConnect($connect)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { param($s,$c,$ch,$e) return $true })
        $ssl.AuthenticateAsClient($Hostname, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $issuer = $cert2.Issuer; $subject = $cert2.Subject; $expiry = $cert2.NotAfter
        $ssl.Close(); $tcp.Close()
        $detected = @()
        foreach ($ca in $InspectionCAs) { if ($issuer -match [regex]::Escape($ca)) { $detected += $ca } }
        if ($detected.Count -gt 0) { return @{ Status="INTERCEPTED"; Issuer=$issuer; Inspector=($detected -join ", "); Subject=$subject; Expiry=$expiry } }
        return @{ Status="Clean"; Issuer=$issuer; Inspector=""; Subject=$subject; Expiry=$expiry }
    } catch {
        if ($ssl) { try{$ssl.Close()}catch{} }; if ($tcp) { try{$tcp.Close()}catch{} }
        return @{ Status="Error"; Issuer=$_.Exception.Message; Inspector=""; Subject=""; Expiry="" }
    }
}

function Get-WinHttpProxy {
    try {
        $netshPath = Join-Path $env:windir "System32\netsh.exe"
        if (Test-Path $netshPath) {
            return (& $netshPath winhttp show proxy 2>&1 | Out-String).Trim()
        } else {
            return "Error: netsh.exe missing from System32 (Potential 25H2 deprecation)"
        }
    }
    catch { return "Error: $($_.Exception.Message)" }
}

function Get-SystemProxy {
    try {
        $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $pe = (Get-ItemProperty -Path $reg -Name ProxyEnable -EA SilentlyContinue).ProxyEnable
        $ps = (Get-ItemProperty -Path $reg -Name ProxyServer -EA SilentlyContinue).ProxyServer
        $pa = (Get-ItemProperty -Path $reg -Name AutoConfigURL -EA SilentlyContinue).AutoConfigURL
        return @{ ProxyEnabled = if($pe -eq 1){"Yes"}else{"No"}; ProxyServer = if($ps){$ps}else{"Not configured"}; PacUrl = if($pa){$pa}else{"Not configured"} }
    } catch { return @{ ProxyEnabled="Error"; ProxyServer="Error"; PacUrl="Error" } }
}

function Measure-DownloadSpeed {
    param([string]$Url, [string]$Name, [int]$MaxDurationSec = 8, [int]$MaxIterations = 60)
    $wc = $null
    try {
        $wc = New-Object System.Net.WebClient
        try { [void]$wc.DownloadData($Url) } catch {}

        $totalBytes = [long]0; $iterations = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        for ($i = 0; $i -lt $MaxIterations; $i++) {
            if ($sw.Elapsed.TotalSeconds -ge $MaxDurationSec) { break }
            try {
                $data = $wc.DownloadData($Url)
                $totalBytes += $data.Length
                $iterations++
            } catch { break }
        }
        $sw.Stop(); $wc.Dispose()

        $dur = $sw.Elapsed.TotalSeconds
        if ($dur -le 0 -or $totalBytes -le 0) {
            return @{ Name=$Name; SpeedMbps=0; SpeedMBs=0; DataMB=0; Duration=0; Iterations=0; Status="Fail" }
        }
        $bps = ($totalBytes * 8) / $dur
        
        return [PSCustomObject]@{
            Name       = $Name
            SpeedMbps  = [math]::Round($bps / 1000000, 2)
            SpeedMBs   = [math]::Round($totalBytes / $dur / 1048576, 2)
            DataMB     = [math]::Round($totalBytes / 1048576, 2)
            Duration   = [math]::Round($dur, 2)
            Iterations = $iterations
            Status     = "Pass"
        }
    } catch {
        if ($wc) { try { $wc.Dispose() } catch {} }
        return @{ Name=$Name; SpeedMbps=0; SpeedMBs=0; DataMB=0; Duration=0; Iterations=0; Status="Fail" }
    }
}

function Measure-EndpointLatency {
    param([string]$Hostname, [int]$Port = 443, [int]$Timeout = 5)
    $result = @{ Hostname=$Hostname; DnsMs=-1; TcpMs=-1; TlsMs=-1; TotalMs=-1; Status="Error" }
    $tcp = $null; $ssl = $null
    try {
        $dnsSw = [System.Diagnostics.Stopwatch]::StartNew()
        $ips = [System.Net.Dns]::GetHostAddresses($Hostname)
        $dnsSw.Stop()
        $result.DnsMs = [math]::Round($dnsSw.Elapsed.TotalMilliseconds, 1)
        if ($ips.Count -eq 0) { return $result }

        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcpSw = [System.Diagnostics.Stopwatch]::StartNew()
        $conn = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        if (-not $conn.AsyncWaitHandle.WaitOne(($Timeout * 1000), $false)) { $tcp.Close(); return $result }
        $tcp.EndConnect($conn)
        $tcpSw.Stop()
        $result.TcpMs = [math]::Round($tcpSw.Elapsed.TotalMilliseconds, 1)

        $tlsSw = [System.Diagnostics.Stopwatch]::StartNew()
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { param($s,$c,$ch,$e) return $true })
        $ssl.AuthenticateAsClient($Hostname, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $tlsSw.Stop()
        $result.TlsMs = [math]::Round($tlsSw.Elapsed.TotalMilliseconds, 1)

        $ssl.Close(); $tcp.Close()
        $result.TotalMs = [math]::Round($result.DnsMs + $result.TcpMs + $result.TlsMs, 1)
        $result.Status = "Pass"
        return [PSCustomObject]$result
    } catch {
        if ($ssl) { try{$ssl.Close()}catch{} }; if ($tcp) { try{$tcp.Close()}catch{} }
        return $result
    }
}

function Detect-CdnProvider {
    param([string]$Hostname)
    $result = @{ Hostname=$Hostname; CDN="Unknown"; CnameChain=$Hostname; ServerHeader=""; Status="Error" }
    try {
        $cnames = @()
        try {
            $dnsRecs = Resolve-DnsName -Name $Hostname -Type CNAME -DnsOnly -ErrorAction Stop
            $cnames = @($dnsRecs | Where-Object { $_.QueryType -eq 'CNAME' } | ForEach-Object { $_.NameHost })
        } catch {}
        if ($cnames.Count -gt 0) { $result.CnameChain = "$Hostname -> $($cnames -join ' -> ')" }

        $headers = @{}
        $prevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $req = [System.Net.HttpWebRequest]::Create("https://$Hostname")
            $req.Method = "HEAD"; $req.Timeout = 5000; $req.AllowAutoRedirect = $true
            $resp = $req.GetResponse()
            foreach ($k in $resp.Headers.AllKeys) { $headers[$k] = $resp.Headers[$k] }
            $resp.Close()
        } catch [System.Net.WebException] {
            $wr = $_.Exception.Response
            if ($wr) { foreach ($k in $wr.Headers.AllKeys) { $headers[$k] = $wr.Headers[$k] }; try{$wr.Close()}catch{} }
        } catch {}
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb

        $result.ServerHeader = if ($headers.ContainsKey("Server")) { $headers["Server"] } else { "" }
        $allCnames = $cnames -join " "

        $cdn = ""
        if ($headers.ContainsKey("X-MSEdge-Ref") -or $headers.ContainsKey("X-Azure-Ref")) { $cdn = "Azure Front Door" }
        elseif ($headers.ContainsKey("X-Akamai-Request-ID") -or $result.ServerHeader -match "AkamaiGHost|AkamaiNetStorage") { $cdn = "Akamai" }
        elseif ($headers.ContainsKey("X-Served-By") -and $headers["X-Served-By"] -match "cache-") { $cdn = "Fastly" }
        elseif ($headers.ContainsKey("X-Amz-Cf-Id") -or ($headers.ContainsKey("Via") -and $headers["Via"] -match "CloudFront")) { $cdn = "AWS CloudFront" }
        elseif ($result.ServerHeader -match "cloudflare") { $cdn = "Cloudflare" }

        if ([string]::IsNullOrEmpty($cdn)) {
            if ($allCnames -match "akamaiedge\.net|akamai\.net|akadns\.net") { $cdn = "Akamai" }
            elseif ($allCnames -match "azureedge\.net") { $cdn = "Azure CDN" }
            elseif ($allCnames -match "azurefd\.net|trafficmanager\.net|msedge\.net") { $cdn = "Azure Front Door" }
            elseif ($allCnames -match "fastly\.net|fastlylb\.net") { $cdn = "Fastly" }
            elseif ($allCnames -match "cloudfront\.net") { $cdn = "AWS CloudFront" }
            elseif ($allCnames -match "nsatc\.net") { $cdn = "Microsoft CDN (Legacy)" }
            else { $cdn = "Direct / Unknown" }
        }

        $result.CDN = $cdn; $result.Status = "Pass"
        return $result
    } catch { return $result }
}

# ======================== PHASE 1: PROXY DETECTION ========================
Write-Host "--- Phase 1: Proxy Detection ---" -ForegroundColor Yellow
$winHttpProxy = Get-WinHttpProxy
$systemProxy  = Get-SystemProxy
Write-Host "  WinHTTP : $winHttpProxy" -ForegroundColor Gray
Write-Host "  WinINET : Enabled=$($systemProxy.ProxyEnabled) | Server=$($systemProxy.ProxyServer) | PAC=$($systemProxy.PacUrl)`n" -ForegroundColor Gray
Write-Log "PROXY | WinHTTP: $winHttpProxy | WinINET: Enabled=$($systemProxy.ProxyEnabled) Server=$($systemProxy.ProxyServer) PAC=$($systemProxy.PacUrl)"

# ======================== PHASE 2: ENDPOINT CONNECTIVITY ========================
Write-Host "--- Phase 2: Endpoint Connectivity ---" -ForegroundColor Yellow
$Results = @(); $TotalChecks = 0; $PassedChecks = 0; $FailedChecks = 0
$DnsPass = 0; $DnsFail = 0; $PortPass = 0; $PortFail = 0
$Counter = 0; $TotalEndpoints = $Endpoints.Count

foreach ($ep in $Endpoints) {
    $Counter++
    Write-Host "[$Counter/$TotalEndpoints] $($ep.Host)" -ForegroundColor White -NoNewline

    $dns = Test-DnsResolution -Hostname $ep.Host
    $TotalChecks++
    if ($dns.Status -eq "Pass") { $DnsPass++; $PassedChecks++; Write-Host " DNS:OK" -ForegroundColor Green -NoNewline }
    else { $DnsFail++; $FailedChecks++; Write-Host " DNS:FAIL" -ForegroundColor Red -NoNewline }

    $portResults = @()
    foreach ($port in $ep.Ports) {
        $TotalChecks++
        if ($dns.Status -eq "Fail") { $ps = "Fail" }
        elseif ($ep.Protocol -eq "UDP" -and $port -eq 123) { $ps = Test-NtpPort -Hostname $ep.Host -Timeout $TimeoutSec }
        else { $ps = Test-TcpPort -Hostname $ep.Host -Port $port -Timeout $TimeoutSec }
        $portResults += @{ Port=$port; Protocol=$ep.Protocol; Status=$ps }
        if ($ps -eq "Pass") { $PortPass++; $PassedChecks++; Write-Host " ${port}/$($ep.Protocol):OK" -ForegroundColor Green -NoNewline }
        else { $PortFail++; $FailedChecks++; $r = if($dns.Status -eq "Fail"){"(DNS)"}else{""}; Write-Host " ${port}/$($ep.Protocol):FAIL$r" -ForegroundColor Red -NoNewline }
    }
    Write-Host ""

    foreach ($pr in $portResults) {
        $Results += [PSCustomObject]@{ ID=$ep.ID; Category=$ep.Category; Hostname=$ep.Host; ResolvedIP=$dns.IP; DnsStatus=$dns.Status; Port=$pr.Port; Protocol=$pr.Protocol; PortStatus=$pr.Status; Note=$ep.Note }
    }
    $portSummary = ($portResults | ForEach-Object { "$($_.Port)/$($_.Protocol)=$($_.Status)" }) -join ", "
    Write-Log "ID:$($ep.ID) | $($ep.Host) | DNS:$($dns.Status) ($($dns.IP)) | $portSummary"
}

# ======================== PHASE 2B: HTTPS PROBES ========================
Write-Host "`n--- Phase 2B: HTTPS Probes ---" -ForegroundColor Yellow
$HttpsProbeResults = @()
foreach ($probe in $WildcardHttpsProbes) {
    Write-Host "  $($probe.Url)" -ForegroundColor White -NoNewline
    $TotalChecks++
    $hr = Test-HttpsProbe -Url $probe.Url -Timeout $TimeoutSec
    if ($hr.Status -eq "Pass") { $PassedChecks++; Write-Host " OK (HTTP $($hr.Code))" -ForegroundColor Green }
    else { $FailedChecks++; Write-Host " FAIL ($($hr.Code))" -ForegroundColor Red }
    $HttpsProbeResults += [PSCustomObject]@{ ID=$probe.ID; Category=$probe.Category; Url=$probe.Url; Status=$hr.Status; HttpCode=$hr.Code; Note=$probe.Note }
    Write-Log "HTTPS_PROBE | $($probe.Url) | $($hr.Status) | Code:$($hr.Code)"
}

# ======================== PHASE 3: SSL INSPECTION ========================
Write-Host "`n--- Phase 3: SSL/TLS Inspection ---" -ForegroundColor Yellow
$SslResults = @(); $SslIntercepted = $false
foreach ($sh in $SslCheckHosts) {
    Write-Host "  $sh" -ForegroundColor White -NoNewline
    $sr = Test-SslInspection -Hostname $sh -Port 443 -Timeout $TimeoutSec
    switch ($sr.Status) {
        "INTERCEPTED" { $SslIntercepted = $true; Write-Host " INTERCEPTED ($($sr.Inspector))" -ForegroundColor Red }
        "Clean"       { Write-Host " Clean" -ForegroundColor Green }
        "Error"       { Write-Host " Error" -ForegroundColor Yellow }
    }
    $SslResults += [PSCustomObject]@{ Hostname=$sh; Status=$sr.Status; Issuer=$sr.Issuer; Subject=$sr.Subject; Inspector=$sr.Inspector; Expiry=$sr.Expiry }
    Write-Log "SSL | $sh | $($sr.Status) | Issuer:$($sr.Issuer)"
}

# ======================== PHASE 4: SPEED TEST & LATENCY ========================
Write-Host "`n--- Phase 4: Internet Speed Test ---" -ForegroundColor Yellow
$SpeedResults = @()
foreach ($st in $SpeedTestEndpoints) {
    Write-Host "  Testing: $($st.Name)..." -ForegroundColor White -NoNewline
    $sr = Measure-DownloadSpeed -Url $st.Url -Name $st.Name -MaxDurationSec 8 -MaxIterations 60
    if ($sr.Status -eq "Pass") {
        Write-Host " $($sr.SpeedMbps) Mbps ($($sr.DataMB) MB in $($sr.Duration)s)" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
    }
    $SpeedResults += $sr
    Write-Log "SPEED | $($st.Name) | $($sr.SpeedMbps) Mbps | $($sr.DataMB) MB | $($sr.Duration)s | $($sr.Iterations) iterations"
}

$validSpeeds = $SpeedResults | Where-Object { $_.Status -eq "Pass" -and $_.SpeedMbps -gt 0 }
$bestSpeed   = if ($validSpeeds) { ($validSpeeds | Sort-Object SpeedMbps -Descending | Select-Object -First 1).SpeedMbps } else { 0 }
$avgSpeed    = if ($validSpeeds) { [math]::Round(($validSpeeds | Measure-Object -Property SpeedMbps -Average).Average, 2) } else { 0 }

$speedVerdict = switch ($true) {
    ($bestSpeed -le 0)   { @{ Level="UNKNOWN";    Color="#888";    Msg="Speed test failed — check connectivity" }; break }
    ($bestSpeed -lt 5)   { @{ Level="CRITICAL";   Color="#d13438"; Msg="Extremely slow — enrollment will likely timeout (ESP 60-min limit)" }; break }
    ($bestSpeed -lt 20)  { @{ Level="SLOW";       Color="#ff8c00"; Msg="Slow connection — enrollment may take 45-90+ min" }; break }
    ($bestSpeed -lt 50)  { @{ Level="ACCEPTABLE"; Color="#8a6d00"; Msg="Acceptable speed — enrollment ~20-45 min" }; break }
    ($bestSpeed -lt 100) { @{ Level="GOOD";       Color="#107c10"; Msg="Good speed — enrollment ~10-20 min" }; break }
    default              { @{ Level="EXCELLENT";  Color="#107c10"; Msg="Excellent speed — enrollment <10 min" }; break }
}

Write-Host "`n  Best Speed  : $bestSpeed Mbps" -ForegroundColor $(if($bestSpeed -ge 20){"Green"}elseif($bestSpeed -gt 0){"Yellow"}else{"Red"})
Write-Host "  Avg Speed   : $avgSpeed Mbps" -ForegroundColor Gray
Write-Host "  Verdict     : $($speedVerdict.Level) - $($speedVerdict.Msg)" -ForegroundColor $(if($bestSpeed -ge 50){"Green"}elseif($bestSpeed -ge 20){"Yellow"}else{"Red"})
Write-Log "SPEED_SUMMARY | Best:$bestSpeed Mbps | Avg:$avgSpeed Mbps | Verdict:$($speedVerdict.Level)"

# Latency profiling
Write-Host "`n--- Phase 4B: Latency Profile ---" -ForegroundColor Yellow
$LatencyResults = @()
foreach ($lh in $CdnProfileEndpoints) {
    Write-Host "  $lh" -ForegroundColor White -NoNewline
    $lr = Measure-EndpointLatency -Hostname $lh -Port 443 -Timeout $TimeoutSec
    if ($lr.Status -eq "Pass") {
        Write-Host " DNS:$($lr.DnsMs)ms TCP:$($lr.TcpMs)ms TLS:$($lr.TlsMs)ms Total:$($lr.TotalMs)ms" -ForegroundColor Green
    } else {
        Write-Host " Error" -ForegroundColor Yellow
    }
    $LatencyResults += $lr
    Write-Log "LATENCY | $lh | DNS:$($lr.DnsMs)ms TCP:$($lr.TcpMs)ms TLS:$($lr.TlsMs)ms Total:$($lr.TotalMs)ms"
}

$avgLatency = 0
$validLatency = $LatencyResults | Where-Object { $_.Status -eq "Pass" }
if ($validLatency) { $avgLatency = [math]::Round(($validLatency | Measure-Object -Property TotalMs -Average).Average, 0) }

# ======================== PHASE 5: CDN DETECTION & ENROLLMENT ESTIMATION ========================
Write-Host "`n--- Phase 5: CDN Detection ---" -ForegroundColor Yellow
$CdnResults = @()
foreach ($ch in $CdnProfileEndpoints) {
    Write-Host "  $ch" -ForegroundColor White -NoNewline
    $cr = Detect-CdnProvider -Hostname $ch
    Write-Host " -> $($cr.CDN)" -ForegroundColor Cyan
    $CdnResults += $cr
    Write-Log "CDN | $ch | $($cr.CDN) | CNAME:$($cr.CnameChain)"
}

Write-Host "`n--- Phase 5B: Enrollment Time Estimation ---" -ForegroundColor Yellow
$enrollEstimate = $null
if ($bestSpeed -gt 0) {
    $speedBytesPerSec = ($bestSpeed * 1000000) / 8
    $totalPayloadBytes = [long]0
    $payloadBreakdown = @()

    foreach ($p in $AutopilotPayloads) {
        $sizeBytes = $p.SizeGB * 1073741824
        $dlSec = $sizeBytes / $speedBytesPerSec
        $dlMin = [math]::Round($dlSec / 60, 1)
        $payloadBreakdown += @{ Name=$p.Name; SizeGB=$p.SizeGB; DownloadMin=$dlMin; Required=$p.Required }
        if ($p.Required) { $totalPayloadBytes += $sizeBytes }
    }

    $totalDlMin = [math]::Round(($totalPayloadBytes / $speedBytesPerSec) / 60, 1)
    $conservativeTotal = [math]::Round($totalDlMin + $ProcessingOverheadMin, 0)
    $optimisticTotal   = [math]::Round(($totalDlMin * 0.65) + $ProcessingOverheadMin, 0)  
    $totalPayloadGB    = [math]::Round($totalPayloadBytes / 1073741824, 2)

    $enrollEstimate = @{
        ConservativeMin   = $conservativeTotal
        OptimisticMin     = $optimisticTotal
        DownloadMin       = $totalDlMin
        ProcessingMin     = $ProcessingOverheadMin
        PayloadGB         = $totalPayloadGB
        PayloadBreakdown  = $payloadBreakdown
    }

    Write-Host "  Required Payload  : $totalPayloadGB GB" -ForegroundColor White
    Write-Host "  Download Time     : ~$totalDlMin min (at $bestSpeed Mbps)" -ForegroundColor White
    Write-Host "  Processing        : ~$ProcessingOverheadMin min (ESP + OOBE + reboots)" -ForegroundColor White
    Write-Host "  Estimated Total   : $optimisticTotal - $conservativeTotal min" -ForegroundColor $(if($conservativeTotal -le 30){"Green"}elseif($conservativeTotal -le 60){"Yellow"}else{"Red"})
    Write-Log "ENROLLMENT_EST | Payload:${totalPayloadGB}GB | DL:${totalDlMin}min | Total:${optimisticTotal}-${conservativeTotal}min"
} else {
    Write-Host "  Unable to estimate — speed test failed" -ForegroundColor Red
}

# ======================== PHASE 6: HYBRID AD LINE-OF-SIGHT ========================
Write-Host "`n--- Phase 6: Hybrid AD Line-of-Sight ---" -ForegroundColor Yellow
$HybridResults = @()
if (![string]::IsNullOrWhiteSpace($HybridDomainName)) {
    Write-Host "  Target Domain : $HybridDomainName" -ForegroundColor White
    Write-Log "HYBRID_AD | Checking domain: $HybridDomainName"

    # 1. Base DNS Resolution
    $domainDns = Test-DnsResolution -Hostname $HybridDomainName
    if ($domainDns.Status -eq "Pass") {
        Write-Host "  Domain DNS    : OK ($($domainDns.IP))" -ForegroundColor Green
        $HybridResults += [PSCustomObject]@{ Check="Domain DNS Resolution"; Target=$HybridDomainName; Status="Pass"; Details=$domainDns.IP }
    } else {
        Write-Host "  Domain DNS    : FAIL (Cannot resolve $HybridDomainName)" -ForegroundColor Red
        $HybridResults += [PSCustomObject]@{ Check="Domain DNS Resolution"; Target=$HybridDomainName; Status="Fail"; Details="Unresolvable" }
    }

    # 2. Locate Domain Controllers via DNS SRV
    $srvRecord = "_ldap._tcp.dc._msdcs.$HybridDomainName"
    $dcs = @()
    try {
        $dnsRecs = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
        $dcs = @($dnsRecs | Select-Object -ExpandProperty NameTarget)
    } catch {
        Write-Host "  DC Discovery  : FAIL (Cannot resolve SRV record $srvRecord)" -ForegroundColor Red
        $HybridResults += [PSCustomObject]@{ Check="DC SRV Discovery"; Target=$srvRecord; Status="Fail"; Details="Failed to find Domain Controllers" }
    }

    # 3. Test Critical Hybrid Ports against Primary DC
    if ($dcs.Count -gt 0) {
        Write-Host "  DC Discovery  : Found $($dcs.Count) Domain Controllers" -ForegroundColor Green
        $HybridResults += [PSCustomObject]@{ Check="DC SRV Discovery"; Target=$srvRecord; Status="Pass"; Details="Found DCs: $($dcs -join ', ')" }

        $targetDc = $dcs[0]
        Write-Host "  Testing ports against primary DC: $targetDc" -ForegroundColor Gray

        $hybridPorts = @(88, 389, 445, 636)
        foreach ($hp in $hybridPorts) {
            $pr = Test-TcpPort -Hostname $targetDc -Port $hp -Timeout $TimeoutSec
            if ($pr -eq "Pass") {
                Write-Host "  $targetDc ($hp/TCP) : OK" -ForegroundColor Green
                $HybridResults += [PSCustomObject]@{ Check="DC Port $hp"; Target=$targetDc; Status="Pass"; Details="Port Open" }
            } else {
                Write-Host "  $targetDc ($hp/TCP) : FAIL" -ForegroundColor Red
                $HybridResults += [PSCustomObject]@{ Check="DC Port $hp"; Target=$targetDc; Status="Fail"; Details="Port Closed or Timeout" }
            }
        }
    }
} else {
    Write-Host "  Skipped - `$HybridDomainName not configured in script settings." -ForegroundColor Gray
}

# ======================== OVERALL SUMMARY ========================
$OverallStatus = if ($FailedChecks -eq 0 -and !$SslIntercepted) { "ALL CHECKS PASSED" }
                 elseif ($SslIntercepted) { "SSL INTERCEPTION DETECTED" }
                 else { "FAILURES DETECTED" }

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "  SUMMARY: $OverallStatus" -ForegroundColor $(if($OverallStatus -eq "ALL CHECKS PASSED"){"Green"}else{"Red"})
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Connectivity  : $PassedChecks/$TotalChecks passed"
Write-Host "  DNS           : $DnsPass pass / $DnsFail fail"
Write-Host "  Ports         : $PortPass pass / $PortFail fail"
Write-Host "  SSL Intercept : $(if($SslIntercepted){'YES - CRITICAL'}else{'No'})"
Write-Host "  Best Speed    : $bestSpeed Mbps ($($speedVerdict.Level))"
Write-Host "  Avg Latency   : ${avgLatency}ms"
if ($enrollEstimate) { Write-Host "  Est. Enrollment: $($enrollEstimate.OptimisticMin)-$($enrollEstimate.ConservativeMin) min" }
Write-Host "=============================================`n" -ForegroundColor Cyan
Write-Log "===== SUMMARY: $OverallStatus | Pass:$PassedChecks/$TotalChecks | Speed:$bestSpeed Mbps | Latency:${avgLatency}ms ====="

$FailedResults = $Results | Where-Object { $_.DnsStatus -eq "Fail" -or $_.PortStatus -eq "Fail" }
if ($FailedResults.Count -gt 0) {
    Write-Host "FAILED ENDPOINTS:" -ForegroundColor Yellow
    $FailedResults | Format-Table ID, Category, Hostname, DnsStatus, Port, Protocol, PortStatus -AutoSize
}

# ======================== HTML REPORT ========================
$osCaption = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { "Unknown" }
$sslBannerClass = if ($SslIntercepted) { "overall-fail" } else { "overall-pass" }
$sslBannerText  = if ($SslIntercepted) { "&#x1F6A8; SSL/TLS INTERCEPTION DETECTED" } else { "&#x2705; No SSL interception detected" }
$speedBannerClass = if ($bestSpeed -ge 20) { "overall-pass" } elseif ($bestSpeed -gt 0) { "overall-warn" } else { "overall-fail" }

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
<title>Autopilot Check v1.8 - $Timestamp</title>
<style>
    body { font-family:'Segoe UI',Tahoma,sans-serif; margin:20px; background:#f5f5f5; color:#333; }
    h1 { color:#0078d4; border-bottom:3px solid #0078d4; padding-bottom:10px; }
    h2 { color:#333; margin-top:30px; }
    .summary-box { background:#fff; border-radius:8px; padding:20px; margin:20px 0; box-shadow:0 2px 4px rgba(0,0,0,0.1); display:flex; gap:20px; flex-wrap:wrap; }
    .stat { text-align:center; min-width:100px; }
    .stat .number { font-size:1.8em; font-weight:bold; }
    .stat .label { color:#666; font-size:0.85em; }
    .pass { color:#107c10; } .fail { color:#d13438; } .warn { color:#ff8c00; }
    table { border-collapse:collapse; width:100%; background:#fff; box-shadow:0 2px 4px rgba(0,0,0,0.1); border-radius:8px; overflow:hidden; margin-bottom:20px; }
    th { background:#0078d4; color:#fff; padding:10px 8px; text-align:left; font-size:0.82em; }
    td { padding:8px; border-bottom:1px solid #eee; font-size:0.82em; word-break:break-all; }
    tr:hover { background:#f0f6ff; }
    .badge { padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.78em; display:inline-block; }
    .badge-pass { background:#dff6dd; color:#107c10; } .badge-fail { background:#fde7e9; color:#d13438; }
    .badge-warn { background:#fff4ce; color:#8a6d00; } .badge-intercept { background:#d13438; color:#fff; }
    .badge-cdn { background:#e0e7ff; color:#3b4f9e; }
    .overall-pass { background:#dff6dd; border-left:5px solid #107c10; padding:15px; border-radius:5px; margin-bottom:10px; }
    .overall-fail { background:#fde7e9; border-left:5px solid #d13438; padding:15px; border-radius:5px; margin-bottom:10px; }
    .overall-warn { background:#fff4ce; border-left:5px solid #ff8c00; padding:15px; border-radius:5px; margin-bottom:10px; }
    .info-box { background:#fff; border-radius:8px; padding:15px; margin:15px 0; box-shadow:0 2px 4px rgba(0,0,0,0.1); }
    .info-box pre { background:#f8f8f8; padding:10px; border-radius:4px; overflow-x:auto; font-size:0.85em; }
    .info-box code { background:#f0f0f0; padding:2px 6px; border-radius:3px; }
    .section-divider { border:none; border-top:2px solid #0078d4; margin:30px 0; }
    .footer { color:#888; font-size:0.78em; margin-top:40px; border-top:1px solid #ddd; padding-top:10px; }
</style>
</head>
<body>

<h1>&#x1F6E1; Autopilot &amp; Intune Network Check v1.8</h1>
<p>
    <strong>Device:</strong> $(Encode-Html $env:COMPUTERNAME) |
    <strong>User:</strong> $(Encode-Html $env:USERNAME) |
    <strong>OS:</strong> $(Encode-Html $osCaption) |
    <strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
</p>

<div class="$(if($FailedChecks -eq 0 -and !$SslIntercepted){'overall-pass'}else{'overall-fail'})">
    <strong>Overall:</strong> $(Encode-Html $OverallStatus)
</div>
<div class="$sslBannerClass">$sslBannerText</div>
<div class="$speedBannerClass">
    <strong>&#x1F4F6; Speed:</strong> $bestSpeed Mbps ($($speedVerdict.Level)) &#x2014; $($speedVerdict.Msg)
</div>

<div class="summary-box">
    <div class="stat"><div class="number">$TotalChecks</div><div class="label">Total Checks</div></div>
    <div class="stat"><div class="number pass">$PassedChecks</div><div class="label">Passed</div></div>
    <div class="stat"><div class="number fail">$FailedChecks</div><div class="label">Failed</div></div>
    <div class="stat"><div class="number">$DnsPass/$DnsFail</div><div class="label">DNS P/F</div></div>
    <div class="stat"><div class="number">$PortPass/$PortFail</div><div class="label">Port P/F</div></div>
    <div class="stat"><div class="number" style="color:$($speedVerdict.Color)">$bestSpeed</div><div class="label">Mbps (Best)</div></div>
    <div class="stat"><div class="number">${avgLatency}ms</div><div class="label">Avg Latency</div></div>
"@

if ($enrollEstimate) {
    $htmlContent += "   <div class=`"stat`"><div class=`"number`">$($enrollEstimate.OptimisticMin)-$($enrollEstimate.ConservativeMin)</div><div class=`"label`">Est. Minutes</div></div>"
}
$htmlContent += "</div>"

# --- PROXY ---
$htmlContent += @"
<hr class="section-divider">
<h2>&#x1F310; Proxy Configuration</h2>
<div class="info-box">
    <p><strong>WinHTTP (SYSTEM &#x2014; Autopilot context):</strong></p><pre>$(Encode-Html $winHttpProxy)</pre>
    <p><strong>WinINET (User):</strong> Enabled=$($systemProxy.ProxyEnabled) | Server=<code>$(Encode-Html $systemProxy.ProxyServer)</code> | PAC=<code>$(Encode-Html $systemProxy.PacUrl)</code></p>
</div>
"@

# --- SSL ---
$htmlContent += @"
<hr class="section-divider">
<h2>&#x1F512; SSL/TLS Inspection Detection</h2>
<table><tr><th>Hostname</th><th>Status</th><th>Certificate Issuer</th><th>Interceptor</th><th>Expiry</th></tr>
"@
foreach ($s in $SslResults) {
    $sb = switch($s.Status) { "INTERCEPTED"{'<span class="badge badge-intercept">INTERCEPTED</span>'}; "Clean"{'<span class="badge badge-pass">CLEAN</span>'}; default{'<span class="badge badge-warn">ERROR</span>'} }
    $insp = if($s.Inspector){"<strong>$(Encode-Html $s.Inspector)</strong>"}else{"-"}
    $exp = if($s.Expiry -and $s.Expiry -is [datetime]){$s.Expiry.ToString("yyyy-MM-dd")}else{"-"}
    $htmlContent += "<tr><td><code>$(Encode-Html $s.Hostname)</code></td><td>$sb</td><td style=`"max-width:350px`">$(Encode-Html $s.Issuer)</td><td>$insp</td><td>$exp</td></tr>"
}
$htmlContent += "</table>"

# --- SPEED TEST ---
$htmlContent += @"
<hr class="section-divider">
<h2>&#x1F4F6; Internet Speed Test</h2>
<table><tr><th>CDN Endpoint</th><th>Speed (Mbps)</th><th>Speed (MB/s)</th><th>Data Downloaded</th><th>Duration</th></tr>
"@

foreach ($sr in $SpeedResults) {
    $sb = if ($sr.Status -eq "Pass") { '<span class="badge badge-pass">PASS</span>' } else { '<span class="badge badge-fail">FAIL</span>' }
    $htmlContent += "<tr><td><code>$(Encode-Html $sr.Name)</code></td><td>$($sr.SpeedMbps)</td><td>$($sr.SpeedMBs)</td><td>$($sr.DataMB) MB</td><td>$($sr.Duration)s</td></tr>"
}
$htmlContent += "</table>"

# --- HYBRID AD ---
if ($HybridResults.Count -gt 0) {
    $htmlContent += @"
<hr class="section-divider">
<h2>&#x1F3E2; Hybrid AD Line-of-Sight</h2>
<table><tr><th>Check Phase</th><th>Target</th><th>Status</th><th>Details</th></tr>
"@
    foreach ($hr in $HybridResults) {
        $sb = if ($hr.Status -eq "Pass") { '<span class="badge badge-pass">PASS</span>' } else { '<span class="badge badge-fail">FAIL</span>' }
        $htmlContent += "<tr><td>$($hr.Check)</td><td><code>$($hr.Target)</code></td><td>$sb</td><td>$($hr.Details)</td></tr>"
    }
    $htmlContent += "</table>"
}

# --- LATENCY & CDN ---
$htmlContent += @"
<hr class="section-divider">
<h2>&#x23F1; CDN & Latency Profiling</h2>
<table><tr><th>Endpoint</th><th>CDN Provider</th><th>DNS (ms)</th><th>TCP (ms)</th><th>TLS (ms)</th><th>Total (ms)</th></tr>
"@
foreach ($lr in $LatencyResults) {
    $cdnMatch = $CdnResults | Where-Object { $_.Hostname -eq $lr.Hostname }
    $cdnName = if ($cdnMatch) { $cdnMatch.CDN } else { "Unknown" }
    
    $htmlContent += "<tr><td><code>$(Encode-Html $lr.Hostname)</code></td><td><span class=`"badge badge-cdn`">$(Encode-Html $cdnName)</span></td><td>$($lr.DnsMs)</td><td>$($lr.TcpMs)</td><td>$($lr.TlsMs)</td><td><strong>$($lr.TotalMs)</strong></td></tr>"
}
$htmlContent += "</table>"

# --- CLOSE HTML ---
$htmlContent += @"
<div class="footer">
    Report generated by Autopilot Network Checker v1.8 | Log saved to: $(Encode-Html $TxtLog)
</div>
</body>
</html>
"@

# Write HTML to file
$htmlContent | Out-File -FilePath $HTMLReport -Encoding utf8
Write-Host "`nReport saved to: $HTMLReport" -ForegroundColor Green