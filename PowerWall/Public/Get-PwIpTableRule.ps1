function Get-PwIpTableRule {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string[]]$Rules
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-CiscoAccessList: "
	
    $IpRx = [regex] "(\d+\.){3}\d+"

    # these lines will skip immediately
    $SkippedLines = @('')
    
    # Write-Progress actually slows processing down
    # Using a Stopwatch to just update the progress bar every second is fast and still useful
    $i          = 0
    $TotalLines = $Rules.Count
    $StopWatch  = [System.Diagnostics.Stopwatch]::StartNew()

    # Setup return Array
    $ReturnArray = @()
    
    # Setup all the various parameters for iptables that we're going to process.
    $IpTablesParams                   = @{}
    $IpTablesParams.Chain             = '-A'
    $IpTablesParams.Destination       = '-d'
    $IpTablesParams.Source            = '-s'
    $IpTablesParams.Protocol          = '-p'
    $IpTablesParams.DestinationPort   = '--dport'
    $IpTablesParams.SourcePort        = '--sport'
    $IpTablesParams.Action            = '-j'
    $IpTablesParams.InboundInterface  = '-i'
    $IpTablesParams.OutboundInterface = '-o'
    $IpTablesParams.State             = '--state'
    $IpTablesParams.RejectWith        = '--reject-with'
    $IpTablesParams.IcmpType          = '--icmp-type'

    # Todo
    # SynFlag (bool), this is a single ! with nothing after/before it
    # TcpFlags

    # :fileloop allows us to break this loop using Get-RegexMatch
    :fileloop foreach ($line in $Rules) {

        # Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
        $i++
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
        }
        
        # Skipping unnessary lines
        if ($SkippedLines -contains $line) {
            Write-Verbose "$VerbosePrefix skipping line: $line"
            continue
        } else {
            Write-Verbose "$VerbosePrefix processing line: $line"
        }

        # We can use the Names of the keys in the IpTablesParams hashtable for our properties
        $NewObject         = "" | Select-Object ($IpTablesParams.GetEnumerator().Name + 'Number')
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

    $ReturnArray | Select-Object Chain,Number,Action,
                                 InboundInterface,OutboundInterface,
                                 Source,Destination,
                                 Protocol,SourcePort,DestinationPort,
                                 IcmpType,State,RejectWith
                                 
}