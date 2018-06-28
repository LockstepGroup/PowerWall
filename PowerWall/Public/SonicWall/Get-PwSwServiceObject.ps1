function Get-PwSwServiceObject {
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
    $VerbosePrefix = "Get-PwSwServiceObject:"
    
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
    
    $ProtocolMap = @{}
    $ProtocolMap.'108' = 'ipcomp'
    $ProtocolMap.'17'  = 'udp'
    $ProtocolMap.'1'   = 'icmp'
    $ProtocolMap.'2'   = 'igmp'
    $ProtocolMap.'41'  = 'ipv6'
    $ProtocolMap.'50'  = 'esp'
    $ProtocolMap.'6'   = 'tcp'
	
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
        
        $Regex = [regex] "^Service\ Object\ Table:"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
			$KeepGoing = $true
			Write-Verbose "$VerbosePrefix Section Starts on line: $i"
			continue
        }
        
        $Regex = [regex] "^End\ Service\ Object\ Table"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
			$KeepGoing = $false
			Write-Verbose "$VerbosePrefix Section Ends on line: $i"
			break
        }

        if ($KeepGoing) {
            #######################################
            # Special Properties
            $EvalParams = @{}
            $EvalParams.StringToEval = $entry

            # Skip Node Callback Lines
            $EvalParams.Regex = [regex] "^Node\ Callback:"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                Write-Verbose "$i`: Skipping Node Callback"
                continue
            }

            # MemberOf
            $EvalParams.Regex = [regex] "^Group\ \(Member\ of\):\ (.+)"
            $Eval             = Get-RegexMatch @EvalParams -ReturnGroupNum 1
            if ($Eval) {
                $NewObject.MemberOf += $Eval
                Write-Verbose "$i`: MemberOf: $Eval"
                continue
            }

            # Member
            $EvalParams.Regex = [regex] "^\ +member:\ Name:(.+?)\ Handle:\d+"
            $Eval             = Get-RegexMatch @EvalParams -ReturnGroupNum 1
            if ($Eval) {
                $NewObject.Member += $Eval
                Write-Verbose "$i`: Member: $Eval"
                continue
            }

            # New Object
            $EvalParams.Regex = [regex] "(?x)
                                         ^(?<name>.+?)
                                         #(\((?<comment>.+?)\))?
                                         :
                                         .+?
                                         (
                                             GROUP|
                                             IpType:\ (?<protocol>\d+)\ Port\ Begin:\ (?<portbegin>\d+)\ Port\ End:\ (?<portend>\d+)
                                         )"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject          = [ServiceObject]::new()
                $NewObject.Name     = $Eval.Groups['name'].Value
                $NewObject.Comment  = $Eval.Groups['comment'].Value
                $ReturnArray       += $NewObject
                Write-Verbose "$i`: NewObject: $($NewObject.Name) ($($NewObject.Comment))"

                if ($Eval.Groups['protocol'].Success) {
                    $Protocol  = $Eval.Groups['protocol'].Value
                    $PortBegin = $Eval.Groups['portbegin'].Value
                    $PortEnd   = $Eval.Groups['portend'].Value

                    $ProtocolLookup = $ProtocolMap.$Protocol
                    if ($ProtocolLookup) {
                        $Member = $ProtocolLookup + '/'
                    } else {
                        $Member = $Protocol + '/'
                    }

                    if ($PortBegin -eq $PortEnd) {
                        $Port = $PortBegin
                    } else {
                        $Port = $PortBegin + '-' + $PortEnd
                    }

                    $Member += $Port

                    $NewObject.Member += $Member
                }

                continue
            }
            Write-Verbose "$i $entry"
        }
    }
    
	return $ReturnArray
}