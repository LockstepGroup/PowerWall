$ModuleName = Split-Path -Path (Resolve-Path $PSScriptRoot/..) -Leaf

Import-Module $PSScriptRoot/../$ModuleName -Force

Describe "Get-PwIpTableRule" {
    
    $FakeRules = @()
    $FakeRules += '-A FORWARD -d 1.1.1.1/32 -p tcp -m tcp --dport 443 -j ACCEPT'
    $FakeRules += '-A FORWARD -s 2.2.2.2/27 -d 3.3.3.3/32 -p tcp -m tcp --dport 27000 -j ACCEPT'
    $FakeRules += '-A OUTPUT -s 4.4.4.4/32 -o eth0 -p tcp -m tcp --sport 22 -j ACCEPT -i eth1'
    $FakeRules += '-A INPUT -i eth0 -p udp -m udp --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT'
    $FakeRules += '-A INPUT -i eth0 -p icmp -m icmp --icmp-type 0 -j ACCEPT'

    $Results = Get-PwIpTableRule -Rules $FakeRules

    Context 'Check Rule Extraction' { 
        It 'Should get the correct number of rules' {
            $Results.Count | Should Be 5
        }

        It 'Should extract correct AccessLists' {
            $Results[0].AccessList | Should BeExactly FORWARD
            $Results[1].AccessList | Should BeExactly FORWARD
            $Results[2].AccessList | Should BeExactly OUTPUT
            $Results[3].AccessList | Should BeExactly INPUT
            $Results[4].AccessList | Should BeExactly INPUT
        }

        It 'Should extract correct Destinations' {
            $Results[0].Destination | Should BeExactly '1.1.1.1/32'
            $Results[1].Destination | Should BeExactly '3.3.3.3/32'
            $Results[2].Destination | Should BeNullOrEmpty
            $Results[3].Destination | Should BeNullOrEmpty
            $Results[4].Destination | Should BeNullOrEmpty
        }

        It 'Should extract correct Sources' {
            $Results[0].Source | Should BeNullOrEmpty
            $Results[1].Source | Should BeExactly '2.2.2.2/27'
            $Results[2].Source | Should BeExactly '4.4.4.4/32'
            $Results[3].Source | Should BeNullOrEmpty
            $Results[4].Source | Should BeNullOrEmpty
        }

        It 'Should extract correct Protocols' {
            $Results[0].Protocol | Should BeExactly 'tcp'
            $Results[1].Protocol | Should BeExactly 'tcp'
            $Results[2].Protocol | Should BeExactly 'tcp'
            $Results[3].Protocol | Should BeExactly 'udp'
            $Results[4].Protocol | Should BeExactly 'icmp'
        }

        It 'Should extract correct DesinationPorts' {
            $Results[0].DestinationPort | Should BeExactly '443'
            $Results[1].DestinationPort | Should BeExactly '27000'
            $Results[2].DestinationPort | Should BeNullOrEmpty
            $Results[3].DestinationPort | Should BeExactly '1024:65535'
            $Results[4].DestinationPort | Should BeNullOrEmpty
        }

        It 'Should extract correct Actions' {
            $Results[0].Action | Should BeExactly 'ACCEPT'
            $Results[1].Action | Should BeExactly 'ACCEPT'
            $Results[2].Action | Should BeExactly 'ACCEPT'
            $Results[3].Action | Should BeExactly 'ACCEPT'
            $Results[4].Action | Should BeExactly 'ACCEPT'
        }

        It "Should extract correct SourcePorts" {
            $Results[0].SourcePort | Should BeNullOrEmpty
            $Results[1].SourcePort | Should BeNullOrEmpty
            $Results[2].SourcePort | Should BeExactly '22'
            $Results[3].SourcePort | Should BeNullOrEmpty
            $Results[4].SourcePort | Should BeNullOrEmpty
        }

        It "Should extract correct SourceInterfaces" {
            $Results[0].SourceInterface | Should BeNullOrEmpty
            $Results[1].SourceInterface | Should BeNullOrEmpty
            $Results[2].SourceInterface | Should BeExactly 'eth1'
            $Results[3].SourceInterface | Should BeExactly 'eth0'
            $Results[4].SourceInterface | Should BeExactly 'eth0'
        }

        It "Should extract correct DestinationInterfaces" {
            $Results[0].DestinationInterface | Should BeNullOrEmpty
            $Results[1].DestinationInterface | Should BeNullOrEmpty
            $Results[2].DestinationInterface | Should BeExactly 'eth0'
            $Results[3].DestinationInterface | Should BeNullOrEmpty
            $Results[4].DestinationInterface | Should BeNullOrEmpty
        }

        It "Should extract correct PacketStates" {
            $Results[0].PacketState | Should BeNullOrEmpty
            $Results[1].PacketState | Should BeNullOrEmpty
            $Results[2].PacketState | Should BeNullOrEmpty
            $Results[3].PacketState | Should BeExactly 'RELATED,ESTABLISHED'
            $Results[4].PacketState | Should BeNullOrEmpty
        }

        It "Should extract correct IcmpTypes" {
            $Results[0].IcmpType | Should BeNullOrEmpty
            $Results[1].IcmpType | Should BeNullOrEmpty
            $Results[2].IcmpType | Should BeNullOrEmpty
            $Results[3].IcmpType | Should BeNullOrEmpty
            $Results[4].IcmpType | Should BeExactly '0'
        }
    }
}

<#
$FakeRules += '-A FORWARD -d 1.1.1.1/32 -p tcp -m tcp --dport 443 -j ACCEPT'
$FakeRules += '-A FORWARD -s 2.2.2.2/27 -d 3.3.3.3/32 -p tcp -m tcp --dport 27000 -j ACCEPT'
$FakeRules += '-A OUTPUT -s 4.4.4.4/32 -o eth0 -p tcp -m tcp --sport 22 -j ACCEPT -i eth1'
$FakeRules += '-A INPUT -i eth0 -p udp -m udp --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT'
$FakeRules += '-A INPUT -i eth0 -p icmp -m icmp --icmp-type 0 -j ACCEPT'
#>
