function Get-PwSsServiceObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string]$ExportedElementXml
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSsServiceObject: "

    # Check for path and import
    if (Test-Path $ExportedElementXml) {
        $ExportedElements = Get-Content $ExportedElementXml
    }

    # Setup return Array
    $ReturnArray = @()

    # Exported data should be xml
    $ExportedElements = [xml]$ExportedElements
    $NetworkObjects   = $ExportedElements.generic_import_export.network
    $Hosts            = $ExportedElements.generic_import_export.host
    $AddressRanges    = $ExportedElements.generic_import_export.address_range
    $Groups           = $ExportedElements.generic_import_export.group
    
    # This makes it easier to write new cmdlets
    $LoopArray = @()
    $LoopArray += $NetworkObjects
    $LoopArray += $Hosts
    $LoopArray += $AddressRanges
    $LoopArray += $Groups

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
        
        # Initialize the object
        $NewObject    = [NetworkObject]::new()
        $ReturnArray += $NewObject

        # Properties that exist on all types
        $NewObject.Name    = $entry.Name
        $NewObject.Comment = $entry.Comment

        # 'network' entries
        if ($entry.ipv4_network) {
            $NewObject.Value += $entry.ipv4_network
        }

        # 'host' entries
        if ($entry.mvia_address) {
            $NewObject.Value += $entry.mvia_address.address
            if ($entry.secondary.value.count -gt 0) {
                $NewObject.Value += $entry.secondary.value
            }
        }

        # 'address_range' entries
        if ($entry.ip_range) {
            $NewObject.Value += $entry.ip_range
        }

        # 'group' entries
        if ($entry.ne_list) {
            $NewObject.Value += $entry.ne_list.ref
        }
        
    }

    $ReturnArray
}