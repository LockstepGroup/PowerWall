function Get-PwSsNetworkObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string]$ExportedElements
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSsNetworkObject: "

    # Setup return Array
    $ReturnArray = @()

    # Exported data should be xml
    $ExportedElements = [xml]$ExportedElements
    $NetworkObjects = $ExportedElements.generic_import_export.network
    
    # This makes it easier to write new cmdlets
    $LoopArray = @()
    $LoopArray += $NetworkObjects

    # Write-Progress actually slows processing down
    # Using a Stopwatch to just update the progress bar every second is fast and still useful
    $i          = 0
    $TotalLines = $LoopArray.Count
    $StopWatch  = [System.Diagnostics.Stopwatch]::StartNew()
    
    # :fileloop allows us to break this loop using Get-RegexMatch
    :fileloop foreach ($entry in $LoopArray) {

        # Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
        $i++
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
        }
        
        # Initialize the object, number will just be $i (should probably reset this for each chain)
        $NewObject = [SecurityRule]::new('iptables')
        $global:test = [SecurityRule]::new('iptables')
        $NewObject.Number  = $i
        $ReturnArray      += $NewObject

        # These should be used for most of our parsing.
        $RegexParams = @{}
        $RegexParams.StringToEval = $line
        $RegexParams.ReturnGroupNum = 1

        foreach ($param in $IpTablesParams.GetEnumerator()) {
            $RegexParams.RegexString = $param.Value + '\ ([^\ ]+)'
            $Property = $param.Name
            $Match = Get-RegexMatch @RegexParams
            if ($Match) {
                $NewObject.$Property = $Match
            }
        }
    }

    $ReturnArray
}