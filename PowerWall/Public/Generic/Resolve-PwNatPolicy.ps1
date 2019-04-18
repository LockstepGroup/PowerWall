function Resolve-PwNatPolicy {
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
    $VerbosePrefix = "Resolve-PwNatPolicy:"

    $ReturnArray = @()
    $ResolvedOriginalSource = @()
    $ResolvedOriginalDestination = @()
    $ResolvedOriginalService = @()
    $ResolvedTranslatedSource = @()
    $ResolvedTranslatedDestination = @()
    $ResolvedTranslatedService = @()

    $MainProgressParams = @{}
    $MainProgressParams.Activity = 'Resolving OriginalSource'
    $MainProgressParams.Status = 'Step 1/6: '
    $StartingPercentComplete = 0
    $MainProgressParams.PercentComplete = $StartingPercentComplete
    Write-Progress @MainProgressParams

    $i = 0
    # OriginalSource
    foreach ($entry in $Policy) {
        Write-Verbose "$VerbosePrefix Source: Entry: $($entry.Number)"
        try {
            $ResolvedOriginalSource += Resolve-Property -Policy $entry -Property OriginalSource -Objects $NetworkObjects -ErrorAction Stop
        } catch {
            Throw $_
            Throw "$VerbosePrefix Source: Entry: $($entry.AccessList): $($entry.Number)"
        }

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete = ($i / $Policy.Count / 6 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($Policy.Count)"
        Write-Progress @MainProgressParams
    }


    $MainProgressParams.Activity = 'Resolving OriginalDestination'
    $MainProgressParams.Status = 'Step 2/6: '
    $StartingPercentComplete = 1 / 3 * 100
    $MainProgressParams.PercentComplete = $StartingPercentComplete

    $i = 0
    # OriginalDestination
    foreach ($entry in $ResolvedOriginalSource) {
        if ($entry.OriginalDestination[0] -eq "") {
            $entry.OriginalDestination = '0.0.0.0/0'
        }
        Write-Verbose "$VerbosePrefix OriginalDestination: Entry: $($entry.Number)"
        $ResolvedOriginalDestination += Resolve-Property -Policy $entry -Property OriginalDestination -Objects $NetworkObjects

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete = ($i / $ResolvedOriginalSource.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($ResolvedOriginalSource.Count)"
        Write-Progress @MainProgressParams
    }

    $MainProgressParams.Activity = 'Resolving OriginalService'
    $MainProgressParams.Status = 'Step 3/6: '
    $StartingPercentComplete = 2 / 3 * 100
    $MainProgressParams.PercentComplete = $StartingPercentComplete

    $i = 0
    # OriginalService
    foreach ($entry in $ResolvedOriginalDestination) {
        if ($entry.OriginalService[0] -eq "") {
            $entry.OriginalService = 'any'
        }
        Write-Verbose "$VerbosePrefix OriginalService: Entry:  $($entry.Number)"
        $ResolvedOriginalService += Resolve-Property -Policy $entry -Property OriginalService -Objects $ServiceObjects

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete = ($i / $ResolvedOriginalDestination.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($ResolvedOriginalDestination.Count)"
        Write-Progress @MainProgressParams
    }

    $ReturnArray = $ResolvedOriginalService
    $ReturnArray
}