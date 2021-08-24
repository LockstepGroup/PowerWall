function Get-PwAsaStaticRoute {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets named addresses from saved ASA config file.
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ConfigPath
	)
    
    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwAsaStaticRoute:"
    
    # Check for path and import
    if (Test-Path $ConfigPath) {
        $LoopArray = Get-Content $ConfigPath
    }

    # Setup return Array
    $ReturnArray = @()
	
    $IpRx = [regex] "(\d+)\.(\d+)\.(\d+)\.(\d+)"
	
	$TotalLines = $LoopArray.Count
    $i          = 0 
    $n          = 0
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	:fileloop foreach ($entry in $LoopArray) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($entry -eq "") { continue }

        #More prompts and blank lines
        $Regex = [regex] '^<'
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            continue
        }
        $Regex = [regex] '^\s+$'
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            continue
        }
        
        # End object
        $Regex = [regex] "^[^\ ]"
		$Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $false
            $Protocol = $null
        }

        $EvalParams = @{}
        $EvalParams.StringToEval = $entry

        # Single Line Nat
        # route outside 0.0.0.0 0.0.0.0 1.1.1.1 1 
        
        $EvalParams.Regex = [regex] "(?x)
                                     ^route
                                     \ (?<int>[^\ ]+?)
                                     \ (?<dst>$IpRx)
                                     \ (?<mask>$IpRx)
                                     \ (?<nexthop>$IpRx)
                                     \ (?<metric>\d+)"

        $Eval             = Get-RegexMatch @EvalParams
        if ($Eval) {
            $NewObject = [Route]::new()
            $ReturnArray += $NewObject
            Write-Verbose "$VerbosePrefix $entry"

            $NewObject.Destination = $Eval.Groups['dst'].Value + '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
            $NewObject.Interface   = $Eval.Groups['int'].Value
            $NewObject.NextHop     = $Eval.Groups['nexthop'].Value
            $NewObject.Metric      = $Eval.Groups['metric'].Value
        }

	}	
	return $ReturnArray
}