function Resolve-BuiltinService {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[String]$Service,

		[Parameter(Mandatory=$True,Position=1)]
		[String]$FirewallType
	)
    
    $VerbosePrefix = "Resolve-BuiltinService:"
	
    $AsaServices = @{
        "aol" = "5190"
        "bgp" = "179"
        "biff" = "512"
        "bootpc" = "68"
        "bootps" = "67"
        "chargen" = "19"
        "citrix-ica" = "1494"
        "cmd" = "514"
        "ctiqbe" = "2748"
        "daytime" = "13"
        "discard" = "9"
        "domain" = "53"
        "dnsix" = "195"
        "echo" = "7"
        "exec" = "512"
        "finger" = "79"
        "ftp" = "21"
        "ftp-data" = "20"
        "gopher" = "70"
        "https" = "443"
        "h323" = "1720"
        "hostname" = "101"
        "ident" = "113"
        "imap4" = "143"
        "irc" = "194"
        "isakmp" = "500"
        "kerberos" = "750"
        "klogin" = "543"
        "kshell" = "544"
        "ldap" = "389"
        "ldaps" = "636"
        "lpd" = "515"
        "login" = "513"
        "lotusnotes" = "1352"
        "mobile-ip" = "434"
        "nameserver" = "42"
        "netbios-ns" = "137"
        "netbios-dgm" = "138"
        "netbios-ssn" = "139"
        "nntp" = "119"
        "ntp" = "123"
        "pcanywhere-status" = "5632"
        "pcanywhere-data"   = "5631"
        "pim-auto-rp"       = "496"
        "pop2"              = "109"
        "pop3"              = "110"
        "pptp"              = "1723"
        "radius"            = "1645"
        "radius-acct"       = "1646"
        "rip"               = "520"
        "secureid-udp"      = "5510"
        "sip"               = "5060"
        "smtp"              = "25"
        "snmp"              = "161"
        "snmptrap" = "162"
        "sqlnet" = "1521"
        "ssh" = "22"
        "sunrpc" = "111"
        "syslog" = "514"
        "tacacs" = "49"
        "talk" = "517"
        "telnet" = "23"
        "tftp" = "69"
        "time" = "37"
        "uucp" = "540"
        "who" = "513"
        "whois" = "43"
        "www" = "80"
        "xdmcp" = "177"
    }

    if ($Service -match '^\d+$') {
        return $Service
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