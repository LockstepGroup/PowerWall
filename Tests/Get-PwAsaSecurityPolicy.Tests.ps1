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

    Describe "Get-PwAsaSecurityPolicy" {
        ########################################################################
        # region dummydata

        $DummyData = @()
        $DummyData += 'access-list inside-out extended deny tcp any object-group SOURCESERVICEGROUP any object-group DESTINATIONSERVICEGROUP'
        $DummyData += 'access-list outside-in extended permit tcp any object-group DESTINATIONOBJECT eq www'
        $DummyData += 'access-list outside-in extended permit tcp any object-group DESTINATIONOBJECT object-group DESTINATIONSERVICEGROUP'

        # endregion dummydata
        ########################################################################

        $ParsedObject = Get-PwAsaSecurityPolicy -ConfigArray $DummyData
        It "should return correct number of ACEs" {
            $ParsedObject.count | Should -BeExactly 3
        }

        It "should return ACE 1 correctly" {
            # ACE 1
            $ThisParsedObject = $ParsedObject[0]

            $ThisParsedObject.AccessList | Should -BeExactly 'inside-out'
            $ThisParsedObject.AclType | Should -BeExactly 'extended'
            $ThisParsedObject.Number | Should -BeExactly 1
            $ThisParsedObject.Name | Should -BeNullOrEmpty
            $ThisParsedObject.Action | Should -BeExactly 'deny'
            $ThisParsedObject.SourceInterface | Should -BeNullOrEmpty
            $ThisParsedObject.DestinationInterface | Should -BeNullOrEmpty
            $ThisParsedObject.Source | Should -BeExactly @('any')
            $ThisParsedObject.SourceUser | Should -BeNullOrEmpty
            $ThisParsedObject.SourceNegate| Should -BeFalse
            $ThisParsedObject.Destination | Should -BeExactly @('any')
            $ThisParsedObject.DestinationNegate | Should -BeFalse
            $ThisParsedObject.Protocol | Should -BeExactly 'tcp'
            $ThisParsedObject.SourcePort | Should -BeNullOrEmpty
            $ThisParsedObject.DestinationPort | Should -BeNullOrEmpty
            $ThisParsedObject.SourceService | Should -BeExactly @('SOURCESERVICEGROUP')
            $ThisParsedObject.Service | Should -BeExactly @('DESTINATIONSERVICEGROUP')
            $ThisParsedObject.Application | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSource | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedDestination | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSourcePort | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedDestinationPort | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedService | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSourceService | Should -BeNullOrEmpty
            $ThisParsedObject.Comment | Should -BeNullOrEmpty
            $ThisParsedObject.PacketState | Should -BeNullOrEmpty
            $ThisParsedObject.RejectWith | Should -BeNullOrEmpty
            $ThisParsedObject.IcmpType | Should -BeNullOrEmpty
            $ThisParsedObject.Enabled | Should -BeTrue
            $ThisParsedObject.RxBytes | Should -BeExactly 0
            $ThisParsedObject.TxBytes | Should -BeExactly 0
            $ThisParsedObject.Vdom | Should -BeNullOrEmpty
        }

        It "should return ACE 2 correctly" {
            # ACE 2
            $ThisParsedObject = $ParsedObject[1]

            $ThisParsedObject.AccessList | Should -BeExactly 'outside-in'
            $ThisParsedObject.AclType | Should -BeExactly 'extended'
            $ThisParsedObject.Number | Should -BeExactly 1
            $ThisParsedObject.Name | Should -BeNullOrEmpty
            $ThisParsedObject.Action | Should -BeExactly 'permit'
            $ThisParsedObject.SourceInterface | Should -BeNullOrEmpty
            $ThisParsedObject.DestinationInterface | Should -BeNullOrEmpty
            $ThisParsedObject.Source | Should -BeExactly @('any')
            $ThisParsedObject.SourceUser | Should -BeNullOrEmpty
            $ThisParsedObject.SourceNegate| Should -BeFalse
            $ThisParsedObject.Destination | Should -BeExactly @('DESTINATIONOBJECT')
            $ThisParsedObject.DestinationNegate | Should -BeFalse
            $ThisParsedObject.Protocol | Should -BeExactly 'tcp'
            $ThisParsedObject.SourcePort | Should -BeNullOrEmpty
            $ThisParsedObject.DestinationPort | Should -BeNullOrEmpty
            $ThisParsedObject.SourceService | Should -BeNullOrEmpty
            $ThisParsedObject.Service | Should -BeExactly @('www')
            $ThisParsedObject.Application | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSource | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedDestination | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSourcePort | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedDestinationPort | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedService | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSourceService | Should -BeNullOrEmpty
            $ThisParsedObject.Comment | Should -BeNullOrEmpty
            $ThisParsedObject.PacketState | Should -BeNullOrEmpty
            $ThisParsedObject.RejectWith | Should -BeNullOrEmpty
            $ThisParsedObject.IcmpType | Should -BeNullOrEmpty
            $ThisParsedObject.Enabled | Should -BeTrue
            $ThisParsedObject.RxBytes | Should -BeExactly 0
            $ThisParsedObject.TxBytes | Should -BeExactly 0
            $ThisParsedObject.Vdom | Should -BeNullOrEmpty
        }

        It "should return ACE 3 correctly" {
            # ACE 3
            $ThisParsedObject = $ParsedObject[2]

            $ThisParsedObject.AccessList | Should -BeExactly 'outside-in'
            $ThisParsedObject.AclType | Should -BeExactly 'extended'
            $ThisParsedObject.Number | Should -BeExactly 2
            $ThisParsedObject.Name | Should -BeNullOrEmpty
            $ThisParsedObject.Action | Should -BeExactly 'permit'
            $ThisParsedObject.SourceInterface | Should -BeNullOrEmpty
            $ThisParsedObject.DestinationInterface | Should -BeNullOrEmpty
            $ThisParsedObject.Source | Should -BeExactly @('any')
            $ThisParsedObject.SourceUser | Should -BeNullOrEmpty
            $ThisParsedObject.SourceNegate| Should -BeFalse
            $ThisParsedObject.Destination | Should -BeExactly @('DESTINATIONOBJECT')
            $ThisParsedObject.DestinationNegate | Should -BeFalse
            $ThisParsedObject.Protocol | Should -BeExactly 'tcp'
            $ThisParsedObject.SourcePort | Should -BeNullOrEmpty
            $ThisParsedObject.DestinationPort | Should -BeNullOrEmpty
            $ThisParsedObject.SourceService | Should -BeNullOrEmpty
            $ThisParsedObject.Service | Should -BeExactly @('DESTINATIONSERVICEGROUP')
            $ThisParsedObject.Application | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSource | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedDestination | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSourcePort | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedDestinationPort | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedService | Should -BeNullOrEmpty
            $ThisParsedObject.ResolvedSourceService | Should -BeNullOrEmpty
            $ThisParsedObject.Comment | Should -BeNullOrEmpty
            $ThisParsedObject.PacketState | Should -BeNullOrEmpty
            $ThisParsedObject.RejectWith | Should -BeNullOrEmpty
            $ThisParsedObject.IcmpType | Should -BeNullOrEmpty
            $ThisParsedObject.Enabled | Should -BeTrue
            $ThisParsedObject.RxBytes | Should -BeExactly 0
            $ThisParsedObject.TxBytes | Should -BeExactly 0
            $ThisParsedObject.Vdom | Should -BeNullOrEmpty
        }
    }
}