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

    Describe "Get-PwAsaObject" {
        ########################################################################
        # region dummydata

        $ServiceGroupObject = @()
        $ServiceGroupObject += 'object service svc_tcp_8415'
        $ServiceGroupObject += ' service tcp destination eq 8415'
        $ServiceGroupObject += 'object-group service ThisServiceGroup tcp'
        $ServiceGroupObject += ' port-object eq 999'
        $ServiceGroupObject += ' port-object eq sqlnet'
        $ServiceGroupObject += ' service-object object svc_tcp_8415'
        $ServiceGroupObject += ' service-object udp destination range 35000 40000'

        # endregion dummydata
        ########################################################################

        $ParsedServices = Get-PwAsaObject -ConfigArray $ServiceGroupObject
        $ParsedServiceGroupObject = $ParsedServices[1]
        It "should return correct group name" {
            $ParsedServiceGroupObject.Name | Should -BeExactly 'ThisServiceGroup'
        }
        It "should return correct members" {
            $ParsedServiceGroupObject.Member[0] | Should -BeExactly 'tcp/999'
            $ParsedServiceGroupObject.Member[1] | Should -BeExactly 'tcp/1521'
            $ParsedServiceGroupObject.Member[2] | Should -BeExactly 'svc_tcp_8415'
            $ParsedServiceGroupObject.Member[3] | Should -BeExactly 'udp/35000-40000'
            $ParsedServiceGroupObject.Member.Count | Should -BeExactly 4
        }
    }
}