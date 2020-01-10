if (-not $ENV:BHProjectPath) {
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

    Describe "Get-PwFgNetworkObject" {
        #region dummydata
        ########################################################################
        $DummyConfig = @'
config vdom
edit root
config firewall address
    edit "all"
    next
    edit "IpRange"
        set type iprange
        set start-ip 192.0.2.1
        set end-ip 192.0.2.50
    next
    edit "Subnet"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config vdom
edit root2
config firewall addrgrp
    edit "AddressGroup"
        set member "Address1" "Address2" "Address3"
    next
end
'@

        $DummyConfig = $DummyConfig.Split([Environment]::NewLine)
        ########################################################################
        #endregion dummydata

        $ParsedObject = Get-PwFgNetworkObject -ConfigArray $DummyConfig
        It "should return correct number of objects" {
            $ParsedObject.Count | Should -BeExactly 4
        }
        It "should return 'all' object correctly" {
            $ThisObject = $ParsedObject[0]
            $ThisObject.Name | Should -BeExactly 'all'
            $ThisObject.Member | Should -Contain '0.0.0.0/0'
            $ThisObject.Vdom | Should -BeExactly 'root'
        }
        It "should return 'IpRange' object correctly" {
            $ThisObject = $ParsedObject[1]
            $ThisObject.Name | Should -BeExactly 'IpRange'
            $ThisObject.Member | Should -Contain '192.0.2.1-192.0.2.50'
            $ThisObject.Vdom | Should -BeExactly 'root'
        }
        It "should return 'Subnet' object correctly" {
            $ThisObject = $ParsedObject[2]
            $ThisObject.Name | Should -BeExactly 'Subnet'
            $ThisObject.Member | Should -Contain '192.0.2.0/24'
            $ThisObject.Vdom | Should -BeExactly 'root'
        }
        It "should return 'AddressGroup' service group correctly" {
            $ThisObject = $ParsedObject[3]
            $ThisObject.Name | Should -BeExactly 'AddressGroup'
            $ThisObject.Vdom | Should -BeExactly 'root2'
            $ThisObject.Member.Count | Should -BeExactly 3
            $ThisObject.Member | Should -Contain 'Address1'
            $ThisObject.Member | Should -Contain 'Address2'
            $ThisObject.Member | Should -Contain 'Address3'
        }
    }
}