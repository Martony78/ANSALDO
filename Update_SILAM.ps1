<#	
	.NOTES
	===========================================================================
	 Created on:   	15/11/2016 10:04
	 Created by:   	Mathieu Ait Azzouzene
	 Organization: 	Experteam Corp
	 Filename:		Update_SILAM.ps1
	===========================================================================
	.DESCRIPTION
		This script updates RATP SILAM Workstations running on Windows 7. 
#>

$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$Name = 'Update SILAM Servers'
$ExecutionDate = (Get-Date -UFormat "%Y-%m-%d").ToString()
$TempPath = "$env:Windir" + '\Temp\' + "$Name"
$Logfile = "$Name" + " $ExecutionDate" + '.log'
$OS = Get-WmiObject -class Win32_OperatingSystem
$OSServicePack = 'SP' + (Get-WmiObject -class Win32_OperatingSystem).ServicePackMajorVersion
$Lang = (Get-Culture).Name
$InstalledPatches = (Get-HotFix | Select-Object HotfixID)
$TCPPorts = 135,139,445,3389
$UDPPorts = 123,138,137
$DefaultUser = "$env:SystemDrive\Documents and Settings\Default User"
$UserProfiles = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'
$GUIDs = Get-ChildItem -Path $UserProfiles |	Where-Object {$_.PSChildName -like 'S-1-5-21-*'} | Select-Object -expand 'PSChildName'
$Components = Get-Content "$ScriptPath\componentsWin7.txt"

$ErrorActionPreference = 'Continue'

<#	
	===========================================================================

							Déclaration des Fonctions
					
	===========================================================================
#>

############################################################################################
#                                                                                          #
#	Détermine et créé le chemin du fichier de logs s'il n'existe pas.					   #
#                                                                                          #
############################################################################################

Function Write-Log
{ 
	<#
	.Synopsis 
	   Write-Log -Path "$TempPath\$LogFile" Ecris dans le fichier de logs en y ajoutant le time stamp.
	.DESCRIPTION 
	   La fonction Write-Log permet d'écrire dans un fichier de journal. 
	.NOTES 
	   Created by: Mathieu Aït Azzouzene
	.PARAMETER Message 
	   Message est le contenu à écrire dans le fichier de logs.  
	.PARAMETER Path 
	   Le chemin du fichier de journal, si il n'existe pas il est créé.  
	.PARAMETER Level 
	   Spécifie la criticité du message (i.e. Error, Warning, Informational) 
	.PARAMETER NoClobber 
	   Option permettant de ne pas écraser un fichier existant. 
	.EXAMPLE 
	   Write-Log -Path "C:Temp\log.log" -Message 'Log message'  
	   Ecrit le message "Log message" dans le fichier "C:Temp\log.log". 
	.EXAMPLE 
	   Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error 
	   Ecrit le message en tant que message d'erreur. 
	#>
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path = "$TempPath\$LogFile", 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info"
    ) 
 
    Begin {} 
	
    Process 
    { 
        # Création du chemin du fichier s'il n'existe pas. 
        If (!(Test-Path $Path))
			{ 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        # Format Date
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Ajoute ERROR ou WARNING au message en fonction de l'option de criticité. 
        switch ($Level) { 
            'Error' { 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                $LevelText = ''
                } 
            } 
         
        # Ajoute l'entrée à $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append -Encoding UTF8
    } 
    End {} 
}

#Fonction testant l'existence d'une valeur du registre.
Function Test-RegistryValue
{
PARAM
	(
	[parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]$Path,

	[parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]$Value
	)
	
Clear-Variable RegValue -ErrorAction SilentlyContinue
$RegValue = Get-ItemProperty -Path $Path $Value -ErrorAction SilentlyContinue
If ($RegValue)
	{
	Return $RegValue.$Value
	}
Else
	{
	Return $null
	}
}

Function Set-RegistryValue
{
PARAM
	(
	[string]$KeyPath,
	[string]$ValueName,
	[string]$OldValue,
	[string]$NewValue,
	[ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')]
	[string]$ValueType
	)

$OldValue = (Test-RegistryValue -Path $KeyPath -Value $ValueName)
	
If ($OldValue)
	{
    Write-Log -Message "Registry value '$ValueName' exists under '$KeyPath' and is equal to '$OldValue'" -Level Warn
    Try
        {    
		$UpdateKey = Set-ItemProperty "$KeyPath" -Name $ValueName -Value $NewValue –ErrorVariable UpdateKeyError
		Write-Log -Message "Registry value '$ValueName' successfully updated under '$KeyPath', new value is '$NewValue'" 
		}
        Catch
		{
        Write-Log -Message " An error occured while updating '$ValueName' under '$KeyPath', details :" -Level ERROR
		Write-Log -Message "$_" -Level ERROR
		Return $UpdateKeyError
        } 
    }
Else
    {
    Write-Log -Message "Creating registry value '$ValueName' under '$KeyPath'..." 
    If (!(Test-Path "$KeyPath"))
		{
		Write-Log -Message "Registry key '$KeyPath' does not exist, creating it." 
		Try
            {
            $Create = New-Item -Path "$KeyPath" –ErrorVariable CreateKeyError
			Write-Log -Message "Registry key '$KeyPath' successfully created" 
            }
        Catch
            {
            Write-Log -Message "An error occured while creating '$KeyPath', details:" -Level ERROR
			Write-Log -Message "$_" -Level ERROR
			Return $CreateKeyError
            }
		}
		
    Try
        {
			If ($ValueType -eq "Binary")
			{
				$hexified = $NewValue.Split(',') | % { "0x$_"}
				$SetValue = New-ItemProperty "$KeyPath" -Name $ValueName -Value ([byte[]]$hexified) -PropertyType $ValueType –ErrorVariable SetValueError 
			}
			Else
			{
	        	$SetValue = New-ItemProperty "$KeyPath" -Name $ValueName -Value $NewValue -PropertyType $ValueType –ErrorVariable SetValueError
			}
	        Write-Log -Message "Registry value '$ValueName' successfully created under '$KeyPath' containing '$NewValue'" 
	    }
    Catch
        {
        Write-Log -Message " An error occured while creating '$ValueName' under '$KeyPath', details:" -Level ERROR
		Write-Log -Message "$_" -Level ERROR
		Return $SetValueError
        }
    }    
}

Function Invoke-Process
{
	PARAM
	(
		$ProcessFile,
		$Arguments
	)
	
	Begin {}
	
	Process
	{
		Clear-Variable -Name 'Setup' -ErrorAction SilentlyContinue
		If ($Arguments -eq $null)
		{
			$Setup = (Start-Process -FilePath "$ProcessFile" -Wait -PassThru)
		}
		Else
		{
			$Setup = (Start-Process -FilePath "$ProcessFile" -ArgumentList "$Arguments" -Wait -PassThru)
		}
		If ($Setup.ExitCode -eq 0)
		{
			Write-Log -Message "$ProcessFile has been executed without error."
		}
		ElseIf ($Setup.ExitCode -eq 3010)
		{
			Write-Log -Message "$ProcessFile has been successfully executed but a reboot is required." -Level WARNING
		}
		Else
		{
			Write-Log -Message "An error occured while executing $ProcessFile. Error Code : '$($Setup.ExitCode)'" -Level ERROR
		}
		Return $Setup.ExitCode
	}
	
	End {}
}
<#	
	===========================================================================

							Exécution du script
					
	===========================================================================
#>

Write-Log "Démarrage de '$Name'..."

#Getting Operating System Architecture:
If ($env:PROCESSOR_ARCHITEW6432)
{
    $Arch = 'x64'
}
ElseIf ($env:PROCESSOR_ARCHITECTURE -eq 'amd64')
{
    $Arch = 'x64'
}
ElseIf ($env:PROCESSOR_ARCHITECTURE -eq 'x86')
{
    $Arch = 'x86'
}
Else
{
    Write-Log -Message 'The computer Operating System architecture is not compatible with this script...exiting.' -Level Error
    Exit 1
}

#Conversion du numéro de version.
		    Switch (($OS.Version).Substring(0,3)) 
			{
		        "5.1" { $WIN = "XP" }
		        "5.2" { $WIN = "2003" }
		        "6.1" { If ($os.ProductType -eq 1) { $WIN = "W7" } Else { Write-Log -Path "$TempPath\$LogFile" 'Operating System not supported, exiting' -Level ERROR; Exit 1 } }
				Default { Write-Log -Path "$TempPath\$LogFile" 'Operating System not supported, exiting' -Level ERROR; Exit 1 }
			}
				
If (!(Test-Path "$TempPath\Reboot" -PathType Leaf))
{
	Write-Log "ARCHITECTURE = '$Arch'"

	Write-Log "NOM ORDINATEUR = '$Env:ComputerName'"

	Write-Log "OS = '$($OS.Caption)'"

	Write-Log "SERVICE PACK = '$OSServicePack'"

	Write-Log -Path "$TempPath\$LogFile" 'Disabling Autoplay.'
	Set-RegistryValue -KeyPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ValueName 'NoDriveTypeAutoRun' -NewValue '0x000000ff' -ValueType DWord

	Write-Log -Path "$TempPath\$LogFile" 'Disabling Administrative Shares.'
	Set-RegistryValue -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -ValueName 'AutoShareServer' -NewValue '0x00000000' -ValueType DWord
	Set-RegistryValue -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters' -ValueName 'AutoShareWks' -NewValue '0x00000000' -ValueType DWord

Write-Log -Path "$TempPath\$LogFile" 'Forcing French keyboard to all users.'

Write-Log -Path "$TempPath\$LogFile" "Checking if HKU hive is already loaded and loading it if it is not."
If (!(Test-Path HKU:))
{
	Write-Log -Path "$TempPath\$LogFile" "HKU hive is not loaded, mounting..."
	Try
	{
		New-PSDrive HKU Registry HKEY_USERS
		Write-Log -Path "$TempPath\$LogFile" "HKU hive successfully loaded."
	}
	Catch
	{
		Write-Log -Path "$TempPath\$LogFile" "An error occured while loading HKU Hive, details:"
		Write-Log -Path "$TempPath\$LogFile" "$_" -Level ERROR
	}
}
Else
{
	Write-Log -Message "HKU hive already loaded, skipping mount."
}

ForEach ($GUID in $GUIDs)
{
$HKUProfilePath = 'HKU:\' + "$GUID"
	If (Test-Path("$HKUProfilePath"))
	{
		Write-Log -Path "$TempPath\$LogFile" "$HKUProfilePath exists, updating registry."
		
		Set-RegistryValue -KeyPath "$HKUProfilePath\Keyboard Layout\Preload" -ValueName '1' -NewValue '0000040C' -ValueType String
		Set-RegistryValue -KeyPath "$HKUProfilePath\Keyboard Layout\Preload" -ValueName '2' -NewValue '00000409' -ValueType String
	}
	Else
	{
		$HKLMProfilePath = Get-ItemProperty -Path $UserProfiles$GUID
		$ProfilePath = $HKLMProfilePath.ProfileImagePath
		$UserName = Split-Path $ProfilePath -Leaf
		Write-Log -Path "$TempPath\$LogFile" "$HKUProfilePath does not exist, mounting $UserName hive and updating registry"
		$RegLoad = "reg load HKU\$GUID `"$ProfilePath\ntuser.dat`""
		$RegUnload = "reg unload HKU\$GUID"
		Try
		{
			Invoke-Expression -Command $RegLoad
			Write-Log -Path "$TempPath\$LogFile" "Registry hive $HKUProfilePath successfully loaded"
		}
		Catch
		{
			Write-Log -Path "$TempPath\$LogFile" "An error occured while loading $HKUProfilePath, details:" -Level ERROR
			Write-Log -Path "$TempPath\$LogFile" "$_" -Level ERROR
		}	
		
		Set-RegistryValue "HKU:\$GUID\Keyboard Layout\Preload" -ValueName '1' -NewValue '0000040C' -ValueType String
		Set-RegistryValue "HKU:\$GUID\Keyboard Layout\Preload" -ValueName '2' -NewValue '00000409' -ValueType String

		Invoke-Expression -Command $RegUnload
	}
}

Write-Log -Path "$TempPath\$LogFile" 'Forcing French keyboard for the Default User.'
$RegLoad = "reg load HKU\DefaultUser `"$DefaultUser\ntuser.dat`""
$RegUnload = "reg unload HKU\DefaultUser"
Try
{
	Invoke-Expression -Command $RegLoad
	Write-Log -Path "$TempPath\$LogFile" "Registry hive $HKUProfilePath successfully loaded"
}
Catch
{
	Write-Log -Path "$TempPath\$LogFile" "An error occured while loading $HKUProfilePath, details:" -Level ERROR
	Write-Log -Path "$TempPath\$LogFile" "$_" -Level ERROR
}	

Set-RegistryValue "HKU:\DefaultUser\Keyboard Layout\Preload" -ValueName '1' -NewValue '0000040C' -ValueType String
Set-RegistryValue "HKU:\DefaultUser\Keyboard Layout\Preload" -ValueName '2' -NewValue '00000409' -ValueType String

Invoke-Expression -Command $RegUnload

Write-Log -Path "$TempPath\$LogFile" 'Forcing French keyboard for computer.'
Set-RegistryValue -KeyPath "HKU:\.DEFAULT\Keyboard Layout\Preload" -ValueName '1' -NewValue '0000040C' -ValueType String
Set-RegistryValue -KeyPath "HKU:\.DEFAULT\Keyboard Layout\Preload" -ValueName '2' -NewValue '00000409' -ValueType String

Write-Log -Path "$TempPath\$LogFile" "Unmounting HKU hive."
Try
{
	Remove-PSDrive HKU
	Write-Log -Path "$TempPath\$LogFile" "HKU hive successfully unloaded."
}
Catch
{
	Write-Log -Path "$TempPath\$LogFile" "An error occured while unmounting HKU Hive, details:" -Level ERROR
	Write-Log -Path "$TempPath\$LogFile" "$_" -Level ERROR
}


	if ((Get-Service remoteregistry).status -eq 'started')
	{
		Write-Log -Path "$TempPath\$LogFile" 'Remote Registry Service is running, stopping it.'
		Stop-Service remoteregistry
		Write-Log -Path "$TempPath\$LogFile" 'Disabling Remote Registry Service.'
		set-service remoteregistry -startuptype disabled
	}

ForEach ($TCPPort in $TCPPorts)
{
	Write-Log -Path "$TempPath\$LogFile" "Blocking TCP port $TCPPort"
	Start-Process -FilePath "$ScriptPath\IPSeccmd.exe" -ArgumentList "-w REG -p `"ANSALDO Port Filtering Policy`" -r `"Block Inbound TCP $TCPPort Rule`" -f *=0:$TCPPort`:TCP -n BLOCK -x" -Wait -PassThru
}

ForEach ($UDPPort in $UDPPorts)
{
	Write-Log -Path "$TempPath\$LogFile" "Blocking UDP port $UDPPort"
	Start-Process -FilePath "$ScriptPath\IPSeccmd.exe" -ArgumentList "-w REG -p `"ANSALDO Port Filtering Policy`" -r `"Block Inbound UDP $UDPPort Rule`" -f *=0:$UDPPort`:UDP -n BLOCK -x" -Wait -PassThru
}

	Write-Log -Path "$TempPath\$LogFile" 'Uninstalling Optionnal components.'
	ForEach ($Component in $Components)
	{
		Write-Log -Path "$TempPath\$LogFile" "Uninstalling '$Component' Component..."
		Start-Process -FilePath DISM -ArgumentList "/online /disable-feature /featurename:$Component /norestart" -Wait -Passthru
	}

	$KBPath = "$ScriptPath" + '\Patches\' + "$Arch" + '\' + "$WIN" + '\' + "$Lang"
	$Reboot = $True
	Write-Log -Path "$TempPath\$LogFile" 'Creating Restore Point.'
	Checkpoint-Computer -description "Before Updates" -restorepointtype "APPLICATION_INSTALL"
}
Else
{
	Start-Sleep 10
	Remove-Item -Path "$TempPath\Reboot" -Force
	Write-Log -Path "$TempPath\$LogFile" 'Computer successfully restarted.'
	$KBPath = "$ScriptPath" + '\Patches\' + "$Arch" + '\' + "$WIN" + '\' + "$Lang" + '\Pass2'
}

If (!(Test-Path -Path $KBPath -PathType Container))
{
	Write-Log -Path "$TempPath\$LogFile" 'Patches path not found, skipping.' -Level ERROR
}

$KBs = Get-ChildItem "$KBPath" | Where {(!($_.PSIsContainer))} | Sort -Property Lastwritetime

foreach ($KB in $KBs)
{
	If ($InstalledPatches -match ($($KB.Name)-Split('-'))[1])
	{
		Write-Log -Message "'$($KB.Name)' is already installed, skipping." -Level Warn
    }
	Else
	{
        Write-Log -Message "Installing '$($KB.Name)'...'"
		If ($KB.Extension -eq '.msu')
		{
			$KBLogFile = "$($KB.Name)" + '.evt'
			$Arguments = "`"$KBPath\$($KB.Name)`"" + ' /quiet /norestart /log:' + "`"$TempPath\$KBLogFile`""
			$Setup = Start-Process -FilePath wusa.exe -ArgumentList $Arguments -Wait -Passthru
			If ($Setup.ExitCode -eq '0')
			{
				Write-Log -Message "'$($KB.Name)' successfully installed."
			}
			ElseIf ($Setup.ExitCode -eq '3010')
			{
				Write-Log -Message "'$($KB.Name)' successfully installed but a reboot is required."
			}
			ElseIf ($Setup.ExitCode -eq '-2145124329')
			{
				Write-Log -Message "'$($KB.Name)' is not applicable to this OS."
			}
			ElseIf ($Setup.ExitCode -eq '2359302')
			{
				Write-Log -Message "'$($KB.Name)' is already installed." -Level Warn
			}
			Else
			{
				Write-Log -Message "'$($KB.Name)' returned error code '$($Setup.exitcode)'." -Level ERROR
			}
		}
		elseif ($KB.Extension -eq '.exe')
		{
			$KBLogFile = "$($KB.Name)" + '.log'
			$Arguments = '/passive /norestart /log:' + "`"$TempPath\$KBLogFile`""
			$Setup = Start-Process -FilePath "$KBPath\$($KB.Name)" -ArgumentList $Arguments -Wait -Passthru
			
			Switch ($Setup.ExitCode)
			{
				'0' {Write-Log -Message "'$($KB.Name)' successfully installed."}
				'3010' {Write-Log -Message "'$($KB.Name)' successfully installed but a reboot is required."}
				'61686'	{Write-Log -Message "'$($KB.Name)' not needed." -Level Warn}
				'0x0000066A' {Write-Log -Message "'$($KB.Name)' is not applicable to this OS (wrong architecture or program not installed)." -Level Warn}
				Default {Write-Log -Message "'$($KB.Name)' returned error code '$($Setup.exitcode)'." -Level ERROR }
			}
		}
		elseif ($KB.Extension -eq '.cab')
		{
			$Arguments = '/Online /Add-Package /PackagePath:' + "`"$KBPath\$($KB.Name)`"" + ' /NoRestart'
			$Setup = Start-Process -FilePath DISM.exe -ArgumentList $Arguments -Wait -Passthru
			
			If ($Setup.ExitCode -eq '0')
			{
				Write-Log -Message "'$($KB.Name)' successfully installed."
			}
			ElseIf ($Setup.ExitCode -eq '3010')
			{
				Write-Log -Message "'$($KB.Name)' successfully installed but a reboot is required."
			}
			ElseIf ($Setup.ExitCode -eq '0x0000066A')
			{
				Write-Log -Message "'$($KB.Name)' is not applicable to this OS (wrong architecture or program not installed)." -Level Warn
			}
			ElseIf ($Setup.ExitCode -eq '-2146498530')
			{
				Write-Log -Message "'$($KB.Name)' is not applicable to this OS."
			}
			Else
			{
				Write-Log -Message "'$($KB.Name)' returned error code '$($Setup.exitcode)'." -Level ERROR
			}
		}
	}
}

If ($Reboot)
	{
	#Affichage d'un Pop-Up de redémarrage
	Set-RegistryValue -KeyPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -ValueName 'Update_SILAM' -NewValue "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -command `"&{&'$ScriptPath\Update_SILAM.ps1'}`"" -ValueType String
	
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	[System.Windows.Forms.MessageBox]::Show('Le script se poursuivra après le redémarrage.', 'Update SILAM', 'ok', 'Information') | Out-Null
	
	Write-Log -Message 'Script will continue after reboot.' -Level Warn
	New-Item -Path "$TempPath\Reboot" -ItemType File
	}
Else
	{
	#Affichage d'un Pop-Up de fin d'exécution
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
	[System.Windows.Forms.MessageBox]::Show('Installation Terminée, Appuyez sur OK pour redémarrer.', 'Update SILAM', 'ok', 'Information') | Out-Null

	Write-Log -Message 'Script execution ended.'
	}
	
Restart-Computer

Exit