/*
    agent-self-protection: yara rules v1.0
    Detects: reverse shells, webshells, cryptominers, C2 beacons, common backdoors,
    suspicious installer scripts, prompt-injection phrases.
*/

rule ReverseShell_Bash_TCP
{
    meta:
        description = "Bash /dev/tcp reverse shell"
        author = "agent-self-protection"
        severity = "critical"
    strings:
        $bash_tcp = "/dev/tcp/" ascii
        $bash_redirect = "bash -i >&" ascii
        $mkfifo = "mkfifo /tmp/" ascii
    condition:
        any of ($bash_tcp, $bash_redirect, $mkfifo) and
        filesize < 10KB
}

rule ReverseShell_Netcat
{
    meta:
        description = "Netcat reverse shell"
        author = "agent-self-protection"
        severity = "critical"
    strings:
        $nc_e1 = "nc -e /bin/" ascii
        $nc_e2 = "ncat -e /bin/" ascii
        $nc_e3 = "nc.traditional -e" ascii
        $socat = "socat exec" ascii
        $socat2 = "socat TCP:" ascii
    condition:
        any of them
}

rule ReverseShell_Python
{
    meta:
        description = "Python socket reverse shell"
        author = "agent-self-protection"
        severity = "critical"
    strings:
        $socket_import = "import socket" ascii
        $subprocess_call = "subprocess.call" ascii
        $os_dup2 = "os.dup2" ascii
        $connect_method = ".connect((" ascii
    condition:
        $socket_import and $connect_method and ($subprocess_call or $os_dup2)
}

rule ReverseShell_Generic
{
    meta:
        description = "Generic reverse shell indicators"
        author = "agent-self-protection"
        severity = "high"
    strings:
        $msfvenom = "msfvenom" ascii nocase
        $metasploit = "metasploit" ascii nocase
        $phpshell = "fsockopen" ascii
        $phpshell2 = "pfsockopen" ascii
        $perl_socket = "use Socket" ascii
        $perl_io = "use IO::Socket" ascii
    condition:
        any of them
}

rule WebShell_Generic
{
    meta:
        description = "Generic PHP web shell"
        author = "agent-self-protection"
        severity = "critical"
    strings:
        $eval1 = "eval($_POST" ascii nocase
        $eval2 = "eval($_GET" ascii nocase
        $eval3 = "eval($_REQUEST" ascii nocase
        $exec1 = "system($_POST" ascii nocase
        $exec2 = "passthru($_POST" ascii nocase
        $assert = "assert($_POST" ascii nocase
        $base64_decode = "base64_decode($_POST" ascii nocase
    condition:
        any of them
}

rule CryptoMiner_References
{
    meta:
        description = "Cryptocurrency miner references"
        author = "agent-self-protection"
        severity = "high"
    strings:
        $xmrig = "xmrig" ascii nocase
        $minerd = "minerd" ascii nocase
        $cpuminer = "cpuminer" ascii nocase
        $cryptonight = "cryptonight" ascii nocase
        $stratum = "stratum+tcp://" ascii
        $moneroocean = "moneroocean" ascii nocase
        $nicehash = "nicehash" ascii nocase
        $wallet_xmr = "monero" ascii nocase
    condition:
        any of them
}

rule DownloadAndExecute
{
    meta:
        description = "Download-then-execute pattern"
        author = "agent-self-protection"
        severity = "critical"
    strings:
        $pipe1 = /curl[^\n]+\|\s*(bash|sh|python)/ ascii
        $pipe2 = /wget[^\n]+\|\s*(bash|sh|python)/ ascii
        $iwr = /Invoke-WebRequest[^\n]+\|\s*IEX/ ascii
        $certutil = /certutil[^\n]+-urlcache[^\n]+-split[^\n]+-f/ ascii
        $bitsadmin = /bitsadmin[^\n]+\/transfer/ ascii
    condition:
        any of them
}

rule Exfiltration_ShellCreds
{
    meta:
        description = "Exfiltration of SSH keys / AWS creds"
        author = "agent-self-protection"
        severity = "critical"
    strings:
        $id_rsa = /\.ssh\/id_rsa/ ascii
        $id_ed25519 = /\.ssh\/id_ed25519/ ascii
        $aws_creds = /\.aws\/credentials/ ascii
        $known_hosts = /\.ssh\/known_hosts/ ascii
        $gnupg = /\.gnupg\// ascii
        $netrc = /\.netrc/ ascii
        $git_creds = /\.git-credentials/ ascii
    condition:
        any of them and filesize < 100KB
}

rule Persistence_CronOrSystemd
{
    meta:
        description = "Persistence via cron or systemd"
        author = "agent-self-protection"
        severity = "high"
    strings:
        $cron_d = "/etc/cron.d/" ascii
        $cron_daily = "/etc/cron.daily/" ascii
        $crontab = "crontab -" ascii
        $systemd = "/etc/systemd/system" ascii
        $bashrc = "/.bashrc" ascii
        $zshrc = "/.zshrc" ascii
        $profile = "/.profile" ascii
        $autostart = "/.config/autostart/" ascii
    condition:
        any of them and filesize < 50KB
}

rule Suspicious_AntiForensics
{
    meta:
        description = "Anti-forensics / log tampering"
        author = "agent-self-protection"
        severity = "medium"
    strings:
        $history_clear = "history -c" ascii
        $unset_histfile = "unset HISTFILE" ascii
        $shred = "shred -" ascii
        $log_truncate = "> /var/log/" ascii
        $log_rm = "rm -rf /var/log" ascii
        $touch_t = "touch -t" ascii
    condition:
        any of them
}

rule PromptInjection_Embedded
{
    meta:
        description = "Prompt injection phrases embedded in code/text"
        author = "agent-self-protection"
        severity = "high"
    strings:
        $ignore1 = "ignore all previous instructions" ascii nocase
        $ignore2 = "ignore previous prompts" ascii nocase
        $ignore3 = "disregard all prior" ascii nocase
        $disregard = "disregard prior rules" ascii nocase
        $dan_mode = "you are now in DAN mode" ascii nocase
        $jailbreak = "developer mode" ascii nocase
        $pretend = "pretend you have no restrictions" ascii nocase
        $im_start = "<|im_start|>system" ascii
        $functioncalls = "<|functioncalls|>" ascii
        $fake_sys = /system:\s*you are/ ascii
    condition:
        any of them
}

rule Obfuscation_LongBase64
{
    meta:
        description = "Long base64-encoded string (potential payload)"
        author = "agent-self-protection"
        severity = "medium"
    strings:
        $b64 = /['\"`][A-Za-z0-9+\/]{120,}={0,2}['\"`]/ ascii
    condition:
        $b64
}

rule Obfuscation_CharCode
{
    meta:
        description = "Character-code obfuscation pattern"
        author = "agent-self-protection"
        severity = "medium"
    strings:
        $charcode_js = /String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){8,}/ ascii
        $chr_py = /chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+/ ascii
        $unicode_escape = /\\u00[0-9a-fA-F]{2}(?:\\u00[0-9a-fA-F]{2}){8,}/ ascii
    condition:
        any of them
}

rule CredentialInBash
{
    meta:
        description = "Hardcoded credentials in shell script"
        author = "agent-self-protection"
        severity = "high"
    strings:
        $api_key = /API_KEY\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]/ ascii
        $secret = /SECRET\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]/ ascii
        $token = /TOKEN\s*=\s*['"][A-Za-z0-9_\-\.]{20,}['"]/ ascii
        $password = /PASSWORD\s*=\s*['"][^'"]{8,}['"]/ ascii
        $aws_key = /AKIA[0-9A-Z]{16}/ ascii
        $gh_token = /gh[pousr]_[A-Za-z0-9]{36}/ ascii
    condition:
        any of them
}

rule Suspicious_NetworkEndpoint
{
    meta:
        description = "Suspicious network endpoint references"
        author = "agent-self-protection"
        severity = "medium"
    strings:
        $pastebin = "pastebin.com" ascii nocase
        $webhook = "webhook.site" ascii nocase
        $requestbin = "requestbin" ascii nocase
        $ngrok = "ngrok.io" ascii nocase
        $interactsh = "interact.sh" ascii nocase
        $localtunnel = "localtunnel.me" ascii nocase
        $onion = ".onion" ascii nocase
    condition:
        any of them
}

rule PrivEsc_SUID
{
    meta:
        description = "Privilege escalation via SUID"
        author = "agent-self-protection"
        severity = "high"
    strings:
        $suid1 = "chmod +s /bin/" ascii
        $suid2 = "chmod u+s /bin/" ascii
        $suid3 = "chmod 4755 /bin/" ascii
        $suid4 = "chmod 4777 /bin/" ascii
    condition:
        any of them
}