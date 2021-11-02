REM Keeping these here for backup purposes in case they're
REM needed to create users on an HSM via the admin tool.

bin\csadm dev=3001@localhost LogonSign=ADMIN,keys\admin_logon.key SetAuditConfig=Events=0x0100073F

bin\csadm dev=3001@localhost LogonSign=ADMIN,keys\admin_logon.key AddUser=ERP_SETUP,00000200,hmacpwd,password

bin\csadm dev=3001@localhost LogonSign=ADMIN,keys\admin_logon.key AddUser=ERP_SET1,00000100,hmacpwd,password

bin\csadm dev=3001@localhost LogonSign=ADMIN,keys\admin_logon.key AddUser=ERP_SET2,00000100,hmacpwd,password

bin\csadm dev=3001@localhost LogonSign=ADMIN,keys\admin_logon.key AddUser=ERP_WORK,00000020,hmacpwd,password

bin\csadm dev=3001@localhost LogonSign=ADMIN,keys\admin_logon.key AddUser=ERP_UPDT,00002000,hmacpwd,password

bin\csadm dev=3001@localhost LogonSign=ADMIN,keys\admin_logon.key ListUsers
