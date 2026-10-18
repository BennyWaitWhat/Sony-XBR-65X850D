# Interactive root console client (PowerShell)
#
#   .\rootconsole.ps1 -Host 100.x.y.z -Port 4445 -Token <YOUR-TOKEN>
#
# The console is the app's TCP service; it executes each line as
# /system/bin/sh -c <line> in a uid-0 process and terminates every reply
# with ###END###.
param(
    [Parameter(Mandatory = $true)][string]$Address,
    [int]$Port = 4445,
    [Parameter(Mandatory = $true)][string]$Token
)

$client = [System.Net.Sockets.TcpClient]::new()
try { $client.Connect($Address, $Port) } catch { Write-Error "connect failed: $_"; exit 1 }

$stream = $client.GetStream()
$stream.ReadTimeout = 15000
$writer = [System.IO.StreamWriter]::new($stream); $writer.AutoFlush = $true
$reader = [System.IO.StreamReader]::new($stream)

$writer.WriteLine($Token)
Write-Host ([char]27 + '[90m' + $reader.ReadLine() + [char]27 + '[0m')

while ($true) {
    Write-Host -NoNewline 'root@tv # '
    $line = Read-Host
    if ($line -eq 'exit' -or $line -eq 'quit') { break }
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $writer.WriteLine($line)
    while ($true) {
        $out = $reader.ReadLine()
        if ($null -eq $out -or $out -eq '###END###') { break }
        Write-Host $out
    }
}
$writer.WriteLine('exit')
$client.Close()
