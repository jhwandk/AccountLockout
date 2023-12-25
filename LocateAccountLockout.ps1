# Author: Jinhwan Kim

# Define the list of server names
$serverNames = @("st1resdc01", "st1usrdc01", "st2usrdc01", "st3usrdc01", "hqdc1", "st3hqdc01", "resdc01", "usdc1")
$eventID = 4740
$timeFrame = (24 * 3600000)
$credentials = Get-Credential

# Loop through each server name
foreach ($serverName in $serverNames)
{
    $events = Get-WinEvent -LogName Security -ComputerName $serverName -FilterXPath "*[System[EventID=$eventID and TimeCreated[timediff(@SystemTime) <= $timeFrame]]]" -Credential $credentials

    # Process and output the matching logs for each server
    foreach ($event in $events)
    {
        $eventXML = [xml]$event.ToXml()
        $eventTime = $event.TimeCreated
        $securityID = $eventXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }
        $callerComputer = $eventXML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetDomainName" }

        Write-Host "--------------------------------"
        Write-Host "Server: $serverName"
        Write-Host "Event Time: $eventTime"
        Write-Host "User ID: $($securityID.'#text')"
        Write-Host "Lockout Computer: $($callerComputer.'#text')"
    }
}

Write-Host "--------------------------------"
Write-Host "Please log out the user from the identified computers."
