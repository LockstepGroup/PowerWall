function Resolve-PwSecurityPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [array]$Policy,

        [Parameter(Mandatory = $True, Position = 1)]
        [array]$NetworkObjects,

        [Parameter(Mandatory = $True, Position = 2)]
        [array]$ServiceObjects,

        [Parameter(Mandatory = $False)]
        [String]$FirewallType
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwSecurityPolicy:"

    $ReturnArray = @()
    $SourceResolved = @()
    $DestinationResolved = @()
    $ServiceResolved = @()

    $MainProgressParams = @{}
    $MainProgressParams.Activity = 'Resolving Sources'
    $MainProgressParams.Status = 'Step 1/3: '
    $StartingPercentComplete = 0
    $MainProgressParams.PercentComplete = $StartingPercentComplete
    Write-Progress @MainProgressParams

    $i = 0
    # Sources
    foreach ($entry in $Policy) {
        Write-Verbose "$VerbosePrefix Source: Entry: $($entry.AccessList): $($entry.Number)"
        try {
            $SourceResolved += Resolve-Property -Policy $entry -Property Source -Objects $NetworkObjects -ErrorAction Stop
        } catch {
            Throw $_
            Throw "$VerbosePrefix Source: Entry: $($entry.AccessList): $($entry.Number)"
        }

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete = ($i / $Policy.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($Policy.Count)"
        Write-Progress @MainProgressParams
    }


    $MainProgressParams.Activity = 'Resolving Destinations'
    $MainProgressParams.Status = 'Step 2/3: '
    $StartingPercentComplete = 1 / 3 * 100
    $MainProgressParams.PercentComplete = $StartingPercentComplete

    $i = 0
    # Destinations
    foreach ($entry in $SourceResolved) {
        if ($entry.Destination[0] -eq "") {
            $entry.Destination = '0.0.0.0/0'
        }
        Write-Verbose "$VerbosePrefix Destination: Entry: $($entry.AccessList): $($entry.Number)"
        $DestinationResolved += Resolve-Property -Policy $entry -Property Destination -Objects $NetworkObjects

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete = ($i / $SourceResolved.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($SourceResolved.Count)"
        Write-Progress @MainProgressParams
    }

    $MainProgressParams.Activity = 'Resolving Services'
    $MainProgressParams.Status = 'Step 3/3: '
    $StartingPercentComplete = 2 / 3 * 100
    $MainProgressParams.PercentComplete = $StartingPercentComplete

    $i = 0
    # Services
    foreach ($entry in $DestinationResolved) {
        if ($entry.Service[0] -eq "") {
            $entry.Service = 'any'
        }
        Write-Verbose "$VerbosePrefix Service: Entry: $($entry.AccessList): $($entry.Number)"
        $ServiceResolved += Resolve-Property -Policy $entry -Property Service -Objects $ServiceObjects

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete = ($i / $DestinationResolved.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($DestinationResolved.Count)"
        Write-Progress @MainProgressParams
    }

    $ReturnArray = $ServiceResolved
    $ReturnArray
}