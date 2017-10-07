@{
    AllNodes = @(
        @{
            NodeName = "ServerName"

            #WinFeatures = @("Web-Server", "Web-Mgmt-Console", "Web-IP-Security", "Web-Health")

            WebSite = @{
                AppUser = "DOMAIN\AppUser"
                AppPwd = "password"
                App32bitFlag = $false
                folder = "C:\Websites\App1" 
                site = "App1"
                bindingInfo=  @{
                    Protocol = 'http'
                    Port     = '80'
                    HostName = 'app1.domain.com'
                  }
            },
            @{
                AppUser = "DOMAIN\AppUser2"
                AppPwd = "password"
                App32bitFlag = $true
                folder = "C:\Websites\App2" 
                site = "App2"
                bindingInfo=  @{
                    Protocol = 'http'
                    Port     = '80'
                    HostName = 'app2.domain.com'
                  }

            }


            PSDscAllowPlainTextPassword = $true
         }
    )
}