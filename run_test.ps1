$currLoc = Get-Location
Set-Location .\cmd\pedump
go build
.\pedump.exe pedump.exe
Remove-Item pedump.exe
Set-Location $currLoc
