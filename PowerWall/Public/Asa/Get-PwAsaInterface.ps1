function Get-PwAsaInterface {
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
    $VerbosePrefix = "Get-PwAsaInterface:"
    
    # Check for path and import
    if (Test-Path $ConfigPath) {
        $LoopArray = Get-Content $ConfigPath
    }

    # Setup return Array
    $ReturnArray = @()
	
    $IpRx = [regex] "(\d+)\.(\d+)\.(\d+)\.(\d+)"
	
	$TotalLines = $LoopArray.Count
	$i          = 0 
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
		
		###########################################################################################
        # Check for the Section
        
        $EvalParams = @{}
        $EvalParams.StringToEval = $entry

        $EvalParams.Regex = [regex] "^interface\ (.+)"
        $Eval             = Get-RegexMatch @EvalParams -ReturnGroupNum 1
		if ($Eval) {
            $KeepGoing = $true
                        
            $NewObject    = [Interface]::new()
            $ReturnArray += $NewObject
            
            $NewObject.Name = $Eval
            continue
        }

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
        
        
        if ($KeepGoing) {
            # Special Properties
            $EvalParams = @{}
            $EvalParams.StringToEval = $entry

            # ip address
            $EvalParams.Regex = [regex] "^\ ip\ address\ (?<ip>$IpRx)\ (?<mask>$IpRx)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.IpAddress = $Eval.Groups['ip'].Value
                $NewObject.IpAddress += (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
                continue
            }

            # Simple Properties
            $EvalParams.ReturnGroupNum = 1

            # speed
            $EvalParams.Regex = [regex] "^\ speed\ (\d+)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Speed = $Eval
                continue
            }

            # duplex
            $EvalParams.Regex = [regex] "^\ duplex\ (.+)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Duplex = $Eval
                continue
            }

            # nameif
            $EvalParams.Regex = [regex] "^\ nameif\ (.+)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Nameif = $Eval
                continue
            }

            # security-level
            $EvalParams.Regex = [regex] "^\ security-level\ (.+)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.SecurityLevel = $Eval
                continue
            }
        }

        # access-group
        # access-group outside_access_in in interface outside

        $EvalParams = @{}
        $EvalParams.StringToEval = $entry

        $EvalParams.Regex = [regex] "^access-group\ (?<acl>[^\ ]+?)\ (?<dir>[^\ ]+?)\ interface\ (?<int>.+)"
        $Eval             = Get-RegexMatch @EvalParams
        if ($Eval) {
            Write-Verbose "$VerbosePrefix $entry"
            $Interface = $Eval.Groups['int'].Value
            $Lookup = $ReturnArray | Where-Object { $_.NameIf -eq $Interface }
            if ($Lookup) {
                $Lookup.AccessList = $Eval.Groups['acl'].Value
                $Lookup.AccessListDirection = $Eval.Groups['dir'].Value
            }

            continue
        }
	}	
	return $ReturnArray
}