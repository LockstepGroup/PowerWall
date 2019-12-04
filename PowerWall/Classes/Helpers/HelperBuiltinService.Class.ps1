Class HelperBuiltinService {
    static [string] $Type = "Service"
    [string]$Name
    [string]$Comment
    [string]$Protocol
    [string[]]$SourcePort
    [string[]]$DestinationPort
    [string[]]$Member
    [string]$ResolvedMember
    [string[]]$MemberOf

    # function for checking regular expressions
    static [array] getAsaServices() {
        $ReturnArray = @(
            New-PwServiceObject -Name 'aol' -Protocol 'tcp' -DestinationPort 5190
            New-PwServiceObject -Name 'bgp' -Protocol 'tcp' -DestinationPort 179
            New-PwServiceObject -Name 'biff' -Protocol 'udp' -DestinationPort 512
            New-PwServiceObject -Name 'bootpc' -Protocol 'udp' -DestinationPort 68
            New-PwServiceObject -Name 'bootps' -Protocol 'udp' -DestinationPort 67
            New-PwServiceObject -Name 'chargen' -Protocol 'tcp' -DestinationPort 19
            New-PwServiceObject -Name 'cifs' -Protocol 'tcp-udp' -DestinationPort 3020
            New-PwServiceObject -Name 'citrix-ica' -Protocol 'tcp' -DestinationPort 1494
            New-PwServiceObject -Name 'cmd' -Protocol 'tcp' -DestinationPort 514
            New-PwServiceObject -Name 'ctiqbe' -Protocol 'tcp' -DestinationPort 2748
            New-PwServiceObject -Name 'daytime' -Protocol 'tcp' -DestinationPort 13
            New-PwServiceObject -Name 'discard' -Protocol 'tcp-udp' -DestinationPort 9
            New-PwServiceObject -Name 'dnsix' -Protocol 'udp' -DestinationPort 195
            New-PwServiceObject -Name 'domain' -Protocol '' -DestinationPort 53
            New-PwServiceObject -Name 'echo' -Protocol 'tcp-udp' -DestinationPort 7
            New-PwServiceObject -Name 'exec' -Protocol 'tcp' -DestinationPort 512
            New-PwServiceObject -Name 'finger' -Protocol 'tcp' -DestinationPort 79
            New-PwServiceObject -Name 'ftp' -Protocol 'tcp' -DestinationPort 21
            New-PwServiceObject -Name 'ftp-data' -Protocol 'tcp' -DestinationPort 20
            New-PwServiceObject -Name 'gopher' -Protocol 'tcp' -DestinationPort 70
            New-PwServiceObject -Name 'h323' -Protocol 'tcp' -DestinationPort 1720
            New-PwServiceObject -Name 'hostname' -Protocol 'tcp' -DestinationPort 101
            New-PwServiceObject -Name 'http' -Protocol 'tcp-udp' -DestinationPort 80
            New-PwServiceObject -Name 'https' -Protocol 'tcp' -DestinationPort 443
            New-PwServiceObject -Name 'ident' -Protocol 'tcp' -DestinationPort 113
            New-PwServiceObject -Name 'imap4' -Protocol 'tcp' -DestinationPort 143
            New-PwServiceObject -Name 'irc' -Protocol 'tcp' -DestinationPort 194
            New-PwServiceObject -Name 'isakmp' -Protocol 'udp' -DestinationPort 500
            New-PwServiceObject -Name 'kerberos' -Protocol 'tcp-udp' -DestinationPort 750
            New-PwServiceObject -Name 'klogin' -Protocol 'tcp' -DestinationPort 543
            New-PwServiceObject -Name 'kshell' -Protocol 'tcp' -DestinationPort 544
            New-PwServiceObject -Name 'ldap' -Protocol 'tcp' -DestinationPort 389
            New-PwServiceObject -Name 'ldaps' -Protocol 'tcp' -DestinationPort 636
            New-PwServiceObject -Name 'login' -Protocol 'tcp' -DestinationPort 513
            New-PwServiceObject -Name 'lotusnotes' -Protocol 'tcp' -DestinationPort 1352
            New-PwServiceObject -Name 'lpd' -Protocol 'tcp' -DestinationPort 515
            New-PwServiceObject -Name 'mobile-ip' -Protocol 'udp' -DestinationPort 434
            New-PwServiceObject -Name 'nameserver' -Protocol 'udp' -DestinationPort 42
            New-PwServiceObject -Name 'netbios-dgm' -Protocol 'udp' -DestinationPort 138
            New-PwServiceObject -Name 'netbios-ns' -Protocol 'udp' -DestinationPort 137
            New-PwServiceObject -Name 'netbios-ssn' -Protocol 'tcp' -DestinationPort 139
            New-PwServiceObject -Name 'nfs' -Protocol 'tcp-udp' -DestinationPort 123
            New-PwServiceObject -Name 'nntp' -Protocol 'tcp' -DestinationPort 119
            New-PwServiceObject -Name 'ntp' -Protocol 'udp' -DestinationPort 123
            New-PwServiceObject -Name 'pcanywhere-data' -Protocol 'tcp' -DestinationPort 5631
            New-PwServiceObject -Name 'pcanywhere-status' -Protocol 'udp' -DestinationPort 5632
            New-PwServiceObject -Name 'pim-auto-rp' -Protocol 'tcp-udp' -DestinationPort 496
            New-PwServiceObject -Name 'pop2' -Protocol 'tcp' -DestinationPort 109
            New-PwServiceObject -Name 'pop3' -Protocol 'tcp' -DestinationPort 110
            New-PwServiceObject -Name 'pptp' -Protocol 'tcp' -DestinationPort 1723
            New-PwServiceObject -Name 'radius' -Protocol 'udp' -DestinationPort 1645
            New-PwServiceObject -Name 'radius-acct' -Protocol 'udp' -DestinationPort 1646
            New-PwServiceObject -Name 'rip' -Protocol 'udp' -DestinationPort 520
            New-PwServiceObject -Name 'rsh' -Protocol 'tcp' -DestinationPort 514
            New-PwServiceObject -Name 'rtsp' -Protocol 'tcp' -DestinationPort 554
            New-PwServiceObject -Name 'secureid-udp' -Protocol 'udp' -DestinationPort 5510
            New-PwServiceObject -Name 'sip' -Protocol 'tcp-udp' -DestinationPort 5060
            New-PwServiceObject -Name 'smtp' -Protocol 'tcp' -DestinationPort 25
            New-PwServiceObject -Name 'snmp' -Protocol 'udp' -DestinationPort 161
            New-PwServiceObject -Name 'snmptrap' -Protocol 'udp' -DestinationPort 162
            New-PwServiceObject -Name 'sqlnet' -Protocol 'tcp' -DestinationPort 1521
            New-PwServiceObject -Name 'ssh' -Protocol 'tcp' -DestinationPort 22
            New-PwServiceObject -Name 'sunrpc' -Protocol 'tcp-udp' -DestinationPort 111
            New-PwServiceObject -Name 'syslog' -Protocol 'udp' -DestinationPort 514
            New-PwServiceObject -Name 'tacacs' -Protocol 'tcp-udp' -DestinationPort 49
            New-PwServiceObject -Name 'talk' -Protocol 'tcp-udp' -DestinationPort 517
            New-PwServiceObject -Name 'telnet' -Protocol 'tcp' -DestinationPort 23
            New-PwServiceObject -Name 'tftp' -Protocol 'udp' -DestinationPort 69
            New-PwServiceObject -Name 'time' -Protocol 'udp' -DestinationPort 37
            New-PwServiceObject -Name 'time-exceeded' -Protocol '' -DestinationPort 0
            New-PwServiceObject -Name 'unreachable' -Protocol '' -DestinationPort 0
            New-PwServiceObject -Name 'uucp' -Protocol 'tcp' -DestinationPort 540
            New-PwServiceObject -Name 'vxlan' -Protocol 'udp' -DestinationPort 4789
            New-PwServiceObject -Name 'who' -Protocol 'udp' -DestinationPort 513
            New-PwServiceObject -Name 'whois' -Protocol 'tcp' -DestinationPort 43
            New-PwServiceObject -Name 'www' -Protocol 'tcp-udp' -DestinationPort 80
            New-PwServiceObject -Name 'xdmcp' -Protocol 'udp' -DestinationPort 177
        )
        return $ReturnArray
    }

    ##################################### Initiators #####################################
    # Empty Initiator
    HelperBuiltinService () {
    }
}
