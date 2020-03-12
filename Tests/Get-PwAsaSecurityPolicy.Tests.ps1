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

        $ServiceGroupObject = @()
        $ServiceGroupObject += 'access-list outside-in extended permit tcp any object-group DESTINATIONOBJECT eq www'

        # endregion dummydata
        ########################################################################

        $ParsedObject = Get-PwAsaSecurityPolicy -ConfigArray $ServiceGroupObject
        It "should return correct number of ACEs" {
            $ParsedObject.count | Should -BeExactly 1
        }
        It "should return ACE with 'any' source, 'object-group' destination, 'eq' destination service" {
            # ACE 1
            $ThisParsedObject = $ParsedObject[0]

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
    }
}