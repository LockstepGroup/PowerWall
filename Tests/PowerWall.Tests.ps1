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
        It 'should get the correct number of rules' {
            $Results.Count | Should Be 5
        }
    }
}
