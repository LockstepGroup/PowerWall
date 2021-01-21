<# if (-not $ENV:BHProjectPath) {
    Set-BuildEnvironment -Path $PSScriptRoot\..
}
Remove-Module $ENV:BHProjectName -ErrorAction SilentlyContinue
Import-Module (Join-Path $ENV:BHProjectPath $ENV:BHProjectName) -Force

InModuleScope $ENV:BHProjectName {
    $PSVersion = $PSVersionTable.PSVersion.Major
    $ProjectRoot = $ENV:BHProjectPath

    $Verbose = @{ }
    if ($ENV:BHBranchName -notlike "master" -or $env:BHCommitMessage -match "!verbose") {
        $Verbose.add("Verbose", $True)
    }

    Describe "Get-PwFgServiceObject" {
        #region dummydata
        ########################################################################
        $DummyConfig = @'
config vdom
edit root
config firewall service custom
    edit "ALL"
        set category "General"
        set protocol IP
    next
    edit "TcpPortRange"
        set tcp-portrange 1-65535
    next
    edit "UdpPortRange"
        set udp-portrange 1-65535
    next
    edit "ALL_ICMP"
        set protocol ICMP
        unset icmptype
    next
    edit "IpProtocol"
        set protocol IP
        set protocol-number 47
    next
    edit "TcpSinglePort"
        set tcp-portrange 179
    next
    edit "UdpSinglePort"
        set udp-portrange 500
    next
    edit "PING"
        set protocol ICMP
        set icmptype 8
        unset icmpcode
    next
end
config vdom
edit root2
config firewall service group
    edit "Web Access"
        set member "DNS" "HTTP" "HTTPS"
    next
end
'@

        $DummyConfig = $DummyConfig.Split([Environment]::NewLine)
        ########################################################################
        #endregion dummydata

        $ParsedServices = Get-PwFgServiceObject -ConfigArray $DummyConfig
        It "should return correct number of services" {
            $ParsedServices.Count | Should -BeExactly 9
        }
        It "should return 'ALL' service correctly" {
            $ThisService = $ParsedServices[0]
            $ThisService.Name | Should -BeExactly 'ALL'
            $ThisService.Category | Should -BeExactly 'General'
            $ThisService.Protocol | Should -BeExactly 'ip'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly 'all'
        }
        It "should return 'TcpPortRange' service correctly" {
            $ThisService = $ParsedServices[1]
            $ThisService.Name | Should -BeExactly 'TcpPortRange'
            $ThisService.Protocol | Should -BeExactly 'tcp'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly '1-65535'
        }
        It "should return 'UdpPortRange' service correctly" {
            $ThisService = $ParsedServices[2]
            $ThisService.Name | Should -BeExactly 'UdpPortRange'
            $ThisService.Protocol | Should -BeExactly 'udp'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly '1-65535'
        }
        It "should return 'ALL_ICMP' service correctly" {
            $ThisService = $ParsedServices[3]
            $ThisService.Name | Should -BeExactly 'ALL_ICMP'
            $ThisService.Protocol | Should -BeExactly 'icmp'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly 'all'
        }
        It "should return 'IpProtocol' service correctly" {
            $ThisService = $ParsedServices[4]
            $ThisService.Name | Should -BeExactly 'IpProtocol'
            $ThisService.Protocol | Should -BeExactly 'ip'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly '47'
        }
        It "should return 'TcpSinglePort' service correctly" {
            $ThisService = $ParsedServices[5]
            $ThisService.Name | Should -BeExactly 'TcpSinglePort'
            $ThisService.Protocol | Should -BeExactly 'tcp'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly '179'
        }
        It "should return 'UdpSinglePort' service correctly" {
            $ThisService = $ParsedServices[6]
            $ThisService.Name | Should -BeExactly 'UdpSinglePort'
            $ThisService.Protocol | Should -BeExactly 'udp'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly '500'
        }
        It "should return 'PING' service correctly" {
            $ThisService = $ParsedServices[7]
            $ThisService.Name | Should -BeExactly 'PING'
            $ThisService.Protocol | Should -BeExactly 'icmp'
            $ThisService.Vdom | Should -BeExactly 'root'
            $ThisService.DestinationPort | Should -BeExactly '8'
        }
        It "should return 'Web Access' service group correctly" {
            $ThisService = $ParsedServices[8]
            $ThisService.Name | Should -BeExactly 'Web Access'
            $ThisService.Protocol | Should -BeNullOrEmpty
            $ThisService.Vdom | Should -BeExactly 'root2'
            $ThisService.Member.Count | Should -BeExactly 3
            $ThisService.Member | Should -Contain 'DNS'
            $ThisService.Member | Should -Contain 'HTTP'
            $ThisService.Member | Should -Contain 'HTTPS'
        }
    }
} #>