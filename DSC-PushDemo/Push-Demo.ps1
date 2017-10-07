
configuration PushDemo
{
 param(
    [Parameter(Mandatory=$true)] 
	[String[]]$ServerName
 )

 Import-DscResource -ModuleName "PSDesiredStateConfiguration", "xWebAdministration"

    node ($ServerName)
    {

#install windows features
        WindowsFeature WebServer
        {
            Ensure = "Present"
            Name = "Web-Server"
            IncludeAllSubFeature = $false
        }


#create Deployment Service folder
            File SimpleSiteFolder
            {
                Ensure          = "Present"
                DestinationPath = "C:\WebSites\SimpleSite"
                Type            = "Directory"
            }


#creating Registry keys
            Registry "CreatingKey"
            {
                Ensure = 'Present'
                Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CustomKey'
                ValueName = 'SomeParameter'
                ValueData = 'valuename'
            }


            xWebAppPool SimpleSitePool
            {
                Ensure = "Present"
                Name = "SimpleSitePool"
                State = "Started"
                idleTimeout = '00:00:00'
                identityType = 'ApplicationPoolIdentity'

                DependsOn = "[WindowsFeature]WebServer"
            }
            

            xWebsite SimpleSite
            {
                Ensure = 'Present'
                Name = "SimpleSite"
                State = 'Started'
                PhysicalPath = "C:\WebSites\SimpleSite"
                ApplicationPool = "SimpleSitePool"
                BindingInfo = @(
                        MSFT_xWebBindingInformation
                        {
                            Protocol              = 'http'
                            Port                  = '80'
                        }
                )

               DependsOn = @("[File]SimpleSiteFolder","[xWebAppPool]SimpleSitePool")
            }
    }
}

PushDemo  -ServerName "servername"  -OutputPath C:\Scripts\DSC-Demo


Start-DscConfiguration -Wait -Verbose -Path C:\Scripts\DSC-Demo -Credential $cred -Force
