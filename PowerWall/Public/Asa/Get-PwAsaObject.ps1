function Get-PwAsaObject {
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
    $VerbosePrefix = "Get-PwAsaObject:"
    
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
		
		$Regex = [regex] "^object(?<group>-group)?\ (?<type>[^\ ]+?)\ (?<name>[^\ ]+)(\ (?<protocol>.+))?"
		$Match = Get-RegexMatch $Regex $entry
		if ($Match) {
            Write-Verbose "$VerbosePrefix found object $($NewObject.Name)"
            $KeepGoing = $true
            $Protocol  = $Match.Groups['protocol'].Value
            
            # Duplicate name entries can exist for object NAT
            $Lookup = $ReturnArray | Where-Object { $_.Name -ceq $Match.Groups['name'].Value }
            
            if ($Lookup) {
                Write-Verbose "$VerbosePrefix Duplicate Found $($Lookup.Count)"
                $NewObject = $Lookup
            } else {
                $ObjectType = $Match.Groups['type'].Value
                Write-Verbose "$VerbosePrefix New Object: $($Match.Groups['name'].Value), type: $ObjectType"
                switch ($ObjectType) {
                    'network' {
                        $NewObject = [NetworkObject]::new()
                        break
                    }

                    { ($_ -eq 'service') -or
                      ($_ -eq 'protocol') -or
                      ($_ -eq 'icmp-type') } {
                        $NewObject = [ServiceObject]::new()
                        break
                    }

                    default {
                        Throw "$VerbosePrefix ObjectType not handled: $ObjectType"
                    }
                }
                $ReturnArray += $NewObject
                $NewObject.Name = $Match.Groups['name'].Value
            }

            
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

            # fqdn
            $EvalParams.Regex = [regex] "^\ fqdn\ v4\ (?<fqdn>.+)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Member += $Eval.Groups['fqdn'].Value
            }
            
            # subnet
            $EvalParams.Regex = [regex] "^\ subnet\ (?<network>$IpRx)\ (?<mask>$IpRx)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Mask = ConvertTo-MaskLength $Eval.Groups['mask'].Value
                $NewObject.Member += $Eval.Groups['network'].Value + '/' + $Mask
            }
            
            # host
            $EvalParams.Regex = [regex] "^\ host\ (?<network>$IpRx)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Member += $Eval.Groups['network'].Value + '/32'
            }
            
            # network-object
            $EvalParams.Regex = [regex] "^\ network-object\ (?<param1>$IpRx|host|object)\ (?<param2>.+)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Param1 = $Eval.Groups['param1'].Value
                switch ($Param1) {
                    "host" {
                        $NewObject.Member += $Eval.Groups['param2'].Value + '/32'
                    }
                    "object" {
                        $NewObject.Member += $Eval.Groups['param2'].Value
                    }
                    { $IpRx.Match($_).Success } {
                        $Mask = ConvertTo-MaskLength $Eval.Groups['param2'].Value
                        $NewObject.Member += $Eval.Groups['param1'].Value + '/' + $Mask
                    }
                }
            }
            
            # port-object
            $EvalParams.Regex = [regex] "^\ port-object\ (?<operator>[^\ ]+?)\ (?<port>[^\ ]+)(\ (?<endport>.+))?"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Operator = $Eval.Groups['operator'].Value
                $Port = Resolve-BuiltinService $Eval.Groups['port'].Value 'asa'
                
                switch ($Operator) {
                    "eq" {
                        $NewObject.Member += $Protocol + '/' + $Port
                    }
                    "range" {
                        $EndPort = Resolve-BuiltinService $Eval.Groups['endport'].Value 'asa'
                        $NewObject.Member += $Protocol + '/' + $Port + '-' + $EndPort
                    }
                }
            }
            
            # group-object or protocol-object
            $EvalParams.Regex = [regex] "^\ (group|protocol)-object\ (.+)"
            $Eval             = Get-RegexMatch @EvalParams -ReturnGroupNum 2
            if ($Eval) {
                $NewObject.Member += $Eval
            }
            
            # icmp-object
            $EvalParams.Regex = [regex] "^\ icmp-object\ (.+)"
            $Eval             = Get-RegexMatch @EvalParams -ReturnGroupNum 1
            if ($Eval) {
                $NewObject.Member += "icmp/" + $Eval
            }
            
            # range
            $EvalParams.Regex = [regex] "^\ range\ (?<start>$IpRx)\ (?<stop>$IpRx)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Member += $Eval.Groups['start'].Value + "-" + $Eval.Groups['stop'].Value
            }

            # object nat
            $EvalParams.Regex = [regex] "^\ nat\ \((?<srcint>.+?)\,(?<dstint>.+?)\)\ (?<type>static|dynamic(\ pat-pool)?)\ (?<nat>[^\ ]+)"
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $global:testing = $NewObject
                $NewObject.NatSourceInterface      = $Eval.Groups['srcint'].Value
                $NewObject.NatDestinationInterface = $Eval.Groups['dstint'].Value
                $NewObject.NatType                 = $Eval.Groups['type'].Value
                $NewObject.NatSourceAddress        = $Eval.Groups['nat'].Value

            }
            
            # service-object
            $EvalParams.Regex = [regex] "^\ service-object\ (?<protocol>[^\ ]+)(\ (destination\ (?<operator>[^\ ]+)\ (?<port>[^\ ]+)(\ (?<upperport>[^\ ]+))?|(?<port>[^\ ]+)))?"
            # service-object udp destination range 35000 40000 
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                Write-Verbose "$VerbosePrefix Found: $($Eval.Value)"
                $Protocol  = $Eval.Groups['protocol'].Value
                $Port      = $Eval.Groups['port'].Value
                $UpperPort = $Eval.Groups['upperport'].Value
                
                switch ($Protocol) {
                    'object' {
                        $NewObject.Member += $Port
                        continue fileloop
                    }
                    'icmp' {
                        Write-Verbose "$VerbosePrefix protocol is icmp, setting port to 0"
                        $Port = "0"
                        continue
                    }
                    default {
                        if ($Eval.Groups['port'].Success) {
                            if ($Protocol -ne "icmp") {
                                $Port = Resolve-BuiltinService -Service $Port -FirewallType 'asa'
                            }
                        }
                    }
                }
                
                if ($Eval.Groups['operator'].Success) {
                    $Operator = $Eval.Groups['operator'].Value
                    Write-Verbose "$VerbosePrefix operator found: $Operator"
                } else {
                    Write-Verbose "$VerbosePrefix no operator found, setting to none"
                    $Operator = "none"
                }
                
                switch ($Operator) {
                    "eq" {}
                    "none" {}
                    "default" { Throw "$VerbosePrefix service-object operator `"$Operator`" not handled`r`n $entry" }
                }
                
                if ($Port) {
                    $FullPort = $Protocol + '/' + $Port
                    if ($UpperPort) {
                        $FullPort += "-$UpperPort"
                    }
                } else {
                    $FullPort = $Protocol
                }
                $NewObject.Member += $FullPort
            }

            # service
            $EvalParams.Regex = [regex] '^\ service\ (?<protocol>[^\ ]+)(\ source\ (?<srcoperator>[^\ ]+)\ (?<sourceport>[^\ ]+))?\ destination\ (?<dstoperator>[^\ ]+)\ (?<dstport>[^\ ]+)(\ (?<upperdstport>[^\ ]+))?'
            $Eval             = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Protocol                 = $Eval.Groups['protocol'].Value
                $SourceOperator           = $Eval.Groups['srcoperator'].Value
                $SourcePort               = $Eval.Groups['sourceport'].Value
                $DestinationOperator      = $Eval.Groups['dstoperator'].Value
                $DestinationPort          = $Eval.Groups['dstport'].Value
                $UpperDestinationPort     = $Eval.Groups['upperdstport'].Value

                if ($SourcePort) {
                    switch ($SourceOperator) {
                        'eq'    { $SourcePort = $SourcePort }
                        'neq'   { $SourcePort = "!$SourcePort" }
                        'lt'    { $SourcePort = "lt$SourcePort" }
                        'gt'    { $SourcePort = "gt$SourcePort" }
                        'range' { $SourcePort = $SourcePort -replace ' ','-'}
                        default {}
                    }
                    $NewObject.Member      = $Protocol + '/' + (Resolve-BuiltinService $SourcePort asa)
                }

                if ($DestinationPort) {
                    switch ($DestinationOperator) {
                        'eq'    { $DestinationPort = $DestinationPort }
                        'neq'   { $DestinationPort = "!$DestinationPort" }
                        'lt'    { $DestinationPort = "lt$DestinationPort" }
                        'gt'    { $DestinationPort = "gt$DestinationPort" }
                        'range' { $DestinationPort = $DestinationPort -replace ' ','-'}
                        default {}
                    }
                    $FullPort = $Protocol + '/' + (Resolve-BuiltinService $DestinationPort asa)
                    if ($UpperDestinationPort) {
                        $FullPort += "-$UpperDestinationPort"
                    }
                    $NewObject.Member = $FullPort
                }
            }
            
            ##################################
            # Simple Properties
            $EvalParams.VariableToUpdate = ([REF]$NewObject)
            $EvalParams.ReturnGroupNum   = 1
            $EvalParams.LoopName         = 'fileloop'
            
            # Description
            $EvalParams.ObjectProperty = "Comment"
            $EvalParams.Regex          = [regex] '^\ +description\ (.+)'
            $Eval                      = Get-RegexMatch @EvalParams
        }
	}	
	return $ReturnArray
}