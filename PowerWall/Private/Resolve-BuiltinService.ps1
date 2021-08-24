function Resolve-BuiltinService {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [String]$Service,

        [Parameter(Mandatory = $True, Position = 1)]
        [String]$FirewallType
    )

    $VerbosePrefix = "Resolve-BuiltinService:"

    $AsaServices = @{ }
    $AsaServices.'aol' = @{ Protocol = 'tcp'; DestinationPort = '5190' }
    $AsaServices.'bgp' = @{ Protocol = 'tcp'; DestinationPort = '179' }
    $AsaServices.'biff' = @{ Protocol = 'udp'; DestinationPort = '512' }
    $AsaServices.'bootpc' = @{ Protocol = 'udp'; DestinationPort = '68' }
    $AsaServices.'bootps' = @{ Protocol = 'udp'; DestinationPort = '67' }
    $AsaServices.'chargen' = @{ Protocol = 'tcp'; DestinationPort = '19' }
    $AsaServices.'cifs' = @{ Protocol = 'tcp-udp'; DestinationPort = '3020' }
    $AsaServices.'citrix-ica' = @{ Protocol = 'tcp'; DestinationPort = '1494' }
    $AsaServices.'cmd' = @{ Protocol = 'tcp'; DestinationPort = '514' }
    $AsaServices.'ctiqbe' = @{ Protocol = 'tcp'; DestinationPort = '2748' }
    $AsaServices.'daytime' = @{ Protocol = 'tcp'; DestinationPort = '13' }
    $AsaServices.'discard' = @{ Protocol = 'tcp-udp'; DestinationPort = '9' }
    $AsaServices.'dnsix' = @{ Protocol = 'udp'; DestinationPort = '195' }
    $AsaServices.'domain' = @{ Protocol = 'udp'; DestinationPort = '53' }
    $AsaServices.'echo' = @{ Protocol = 'tcp-udp'; DestinationPort = '7' }
    $AsaServices.'exec' = @{ Protocol = 'tcp'; DestinationPort = '512' }
    $AsaServices.'finger' = @{ Protocol = 'tcp'; DestinationPort = '79' }
    $AsaServices.'ftp' = @{ Protocol = 'tcp'; DestinationPort = '21' }
    $AsaServices.'ftp-data' = @{ Protocol = 'tcp'; DestinationPort = '20' }
    $AsaServices.'gopher' = @{ Protocol = 'tcp'; DestinationPort = '70' }
    $AsaServices.'h323' = @{ Protocol = 'tcp'; DestinationPort = '1720' }
    $AsaServices.'hostname' = @{ Protocol = 'tcp'; DestinationPort = '101' }
    $AsaServices.'http' = @{ Protocol = 'tcp-udp'; DestinationPort = '80' }
    $AsaServices.'https' = @{ Protocol = 'tcp'; DestinationPort = '443' }
    $AsaServices.'ident' = @{ Protocol = 'tcp'; DestinationPort = '113' }
    $AsaServices.'imap4' = @{ Protocol = 'tcp'; DestinationPort = '143' }
    $AsaServices.'irc' = @{ Protocol = 'tcp'; DestinationPort = '194' }
    $AsaServices.'isakmp' = @{ Protocol = 'udp'; DestinationPort = '500' }
    $AsaServices.'kerberos' = @{ Protocol = 'tcp-udp'; DestinationPort = '750' }
    $AsaServices.'klogin' = @{ Protocol = 'tcp'; DestinationPort = '543' }
    $AsaServices.'kshell' = @{ Protocol = 'tcp'; DestinationPort = '544' }
    $AsaServices.'ldap' = @{ Protocol = 'tcp'; DestinationPort = '389' }
    $AsaServices.'ldaps' = @{ Protocol = 'tcp'; DestinationPort = '636' }
    $AsaServices.'login' = @{ Protocol = 'tcp'; DestinationPort = '513' }
    $AsaServices.'lotusnotes' = @{ Protocol = 'tcp'; DestinationPort = '1352' }
    $AsaServices.'lpd' = @{ Protocol = 'tcp'; DestinationPort = '515' }
    $AsaServices.'mobile-ip' = @{ Protocol = 'udp'; DestinationPort = '434' }
    $AsaServices.'nameserver' = @{ Protocol = 'udp'; DestinationPort = '42' }
    $AsaServices.'netbios-dgm' = @{ Protocol = 'udp'; DestinationPort = '138' }
    $AsaServices.'netbios-ns' = @{ Protocol = 'udp'; DestinationPort = '137' }
    $AsaServices.'netbios-ssn' = @{ Protocol = 'tcp'; DestinationPort = '139' }
    $AsaServices.'nfs' = @{ Protocol = 'tcp-udp'; DestinationPort = '123' }
    $AsaServices.'nntp' = @{ Protocol = 'tcp'; DestinationPort = '119' }
    $AsaServices.'ntp' = @{ Protocol = 'udp'; DestinationPort = '123' }
    $AsaServices.'pcanywhere-data' = @{ Protocol = 'tcp'; DestinationPort = '5631' }
    $AsaServices.'pcanywhere-status' = @{ Protocol = 'udp'; DestinationPort = '5632' }
    $AsaServices.'pim-auto-rp' = @{ Protocol = 'tcp-udp'; DestinationPort = '496' }
    $AsaServices.'pop2' = @{ Protocol = 'tcp'; DestinationPort = '109' }
    $AsaServices.'pop3' = @{ Protocol = 'tcp'; DestinationPort = '110' }
    $AsaServices.'pptp' = @{ Protocol = 'tcp'; DestinationPort = '1723' }
    $AsaServices.'radius' = @{ Protocol = 'udp'; DestinationPort = '1645' }
    $AsaServices.'radius-acct' = @{ Protocol = 'udp'; DestinationPort = '1646' }
    $AsaServices.'rip' = @{ Protocol = 'udp'; DestinationPort = '520' }
    $AsaServices.'rsh' = @{ Protocol = 'tcp'; DestinationPort = '514' }
    $AsaServices.'rtsp' = @{ Protocol = 'tcp'; DestinationPort = '554' }
    $AsaServices.'secureid-udp' = @{ Protocol = 'udp'; DestinationPort = '5510' }
    $AsaServices.'sip' = @{ Protocol = 'tcp-udp'; DestinationPort = '5060' }
    $AsaServices.'smtp' = @{ Protocol = 'tcp'; DestinationPort = '25' }
    $AsaServices.'snmp' = @{ Protocol = 'udp'; DestinationPort = '161' }
    $AsaServices.'snmptrap' = @{ Protocol = 'udp'; DestinationPort = '162' }
    $AsaServices.'sqlnet' = @{ Protocol = 'tcp'; DestinationPort = '1521' }
    $AsaServices.'ssh' = @{ Protocol = 'tcp'; DestinationPort = '22' }
    $AsaServices.'sunrpc' = @{ Protocol = 'tcp-udp'; DestinationPort = '111' }
    $AsaServices.'syslog' = @{ Protocol = 'udp'; DestinationPort = '514' }
    $AsaServices.'tacacs' = @{ Protocol = 'tcp-udp'; DestinationPort = '49' }
    $AsaServices.'talk' = @{ Protocol = 'tcp-udp'; DestinationPort = '517' }
    $AsaServices.'telnet' = @{ Protocol = 'tcp'; DestinationPort = '23' }
    $AsaServices.'tftp' = @{ Protocol = 'udp'; DestinationPort = '69' }
    $AsaServices.'time' = @{ Protocol = 'udp'; DestinationPort = '37' }
    $AsaServices.'time-exceeded' = @{ Protocol = 'icmp'; DestinationPort = '0' }
    $AsaServices.'unreachable' = @{ Protocol = 'icmp'; DestinationPort = '0' }
    $AsaServices.'uucp' = @{ Protocol = 'tcp'; DestinationPort = '540' }
    $AsaServices.'vxlan' = @{ Protocol = 'udp'; DestinationPort = '4789' }
    $AsaServices.'who' = @{ Protocol = 'udp'; DestinationPort = '513' }
    $AsaServices.'whois' = @{ Protocol = 'tcp'; DestinationPort = '43' }
    $AsaServices.'www' = @{ Protocol = 'tcp-udp'; DestinationPort = '80' }
    $AsaServices.'xdmcp' = @{ Protocol = 'udp'; DestinationPort = '177' }

    if ($Service -match '^\d+$') {
        $ThisService = @{ DestinationPort = $Service }
        return $ThisService
    } else {
        switch ($FirewallType) {
            'asa' {
                $Services = $AsaServices
                break
            }
            default {
                Throw "$VerbosePrefix FirewallType no handled: $FirewallType"
            }
        }

        if ($Services.$Service) {
            return $Services.$Service
        } else {
            Throw "$VerbosePrefix $Service not found"
        }

    }
}