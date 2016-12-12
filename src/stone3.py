import os
import sys
import json
import binascii

from keystone import *
from capstone import *

query = sys.argv[1]

if sys.argv[2] == "ks":
	mode_asm = True
	archs = [x.strip() for x in os.environ['KEYSTONE_ARCHS'].split(',')]

	init_set = {
		"x16" 		: [ KS_ARCH_X86, 	KS_MODE_16, 	"x86 16bit" ],
		"x32" 		: [ KS_ARCH_X86, 	KS_MODE_32, 	"x86 32bit" ],
		"x64" 		: [ KS_ARCH_X86, 	KS_MODE_64, 	"x86 64bit" ],
		"x16att" 	: [ KS_ARCH_X86, 	KS_MODE_16, 	"x64 16bit ATT" ],
		"x32att" 	: [ KS_ARCH_X86, 	KS_MODE_32, 	"x64 32bit ATT" ],
		"x64att" 	: [ KS_ARCH_X86, 	KS_MODE_64, 	"x64 64bit ATT" ],
		"x16nasm" 	: [ KS_ARCH_X86, 	KS_MODE_16, 	"x64 16bit Nasm" ],
		"x32nasm" 	: [ KS_ARCH_X86, 	KS_MODE_32, 	"x64 32bit Nasm" ],
		"x64nasm" 	: [ KS_ARCH_X86, 	KS_MODE_64, 	"x64 64bit Nasm" ],

		"arm" 		: [ KS_ARCH_ARM, 	KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN, 				"ARM" ],
		"armbe" 	: [ KS_ARCH_ARM, 	KS_MODE_ARM+KS_MODE_BIG_ENDIAN, 				"ARM BE" ],
		"thumb" 	: [ KS_ARCH_ARM, 	KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN, 			"THUMB" ],
		"thumbbe" 	: [ KS_ARCH_ARM, 	KS_MODE_THUMB+KS_MODE_BIG_ENDIAN, 				"THUMB BE" ],
		"armv8" 	: [ KS_ARCH_ARM, 	KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN+KS_MODE_V8, 	"ARM v8" ],
		"armv8be"	: [ KS_ARCH_ARM, 	KS_MODE_ARM+KS_MODE_BIG_ENDIAN+KS_MODE_V8, 		"ARM v8 BE" ],
		"thumbv8" 	: [ KS_ARCH_ARM, 	KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN+KS_MODE_V8, "THUMB v8" ],
		"thumbv8be" : [ KS_ARCH_ARM, 	KS_MODE_THUMB+KS_MODE_BIG_ENDIAN+KS_MODE_V8, 	"THUMB v8 BE" ],
		"arm64" 	: [ KS_ARCH_ARM64, 	KS_MODE_LITTLE_ENDIAN, 							"AArch64" ],

		"hex" 		: [ KS_ARCH_HEXAGON, 	KS_MODE_BIG_ENDIAN,		"Hexagon" ],
		"hexagon"	: [ KS_ARCH_HEXAGON, 	KS_MODE_BIG_ENDIAN,		"Hexagon" ],

		"mips" 		: [ KS_ARCH_MIPS, 	KS_MODE_MIPS32+KS_MODE_LITTLE_ENDIAN, 	"MIPS" ],
		"mipsbe" 	: [ KS_ARCH_MIPS, 	KS_MODE_MIPS32+KS_MODE_BIG_ENDIAN, 		"MIPS BE" ],
		"mips64" 	: [ KS_ARCH_MIPS, 	KS_MODE_MIPS64+KS_MODE_LITTLE_ENDIAN, 	"MIPS64" ],
		"mips64be"	: [ KS_ARCH_MIPS, 	KS_MODE_MIPS64+KS_MODE_BIG_ENDIAN, 		"MIPS64 BE" ],

		"ppc32be" 	: [ KS_ARCH_PPC, 	KS_MODE_PPC32+KS_MODE_BIG_ENDIAN, 		"PPC32 BE" ],
		"ppc64" 	: [ KS_ARCH_PPC, 	KS_MODE_PPC64+KS_MODE_LITTLE_ENDIAN, 	"PPC64" ],
		"ppc64be" 	: [ KS_ARCH_PPC, 	KS_MODE_PPC64+KS_MODE_BIG_ENDIAN, 		"PPC64 BE" ],

		"sparc" 	: [ KS_ARCH_SPARC, 	KS_MODE_SPARC32+KS_MODE_LITTLE_ENDIAN, 	"Sparc" ],
		"sparcbe" 	: [ KS_ARCH_SPARC, 	KS_MODE_SPARC32+KS_MODE_BIG_ENDIAN, 	"Sparc BE" ],
		"sparc64" 	: [ KS_ARCH_SPARC, 	KS_MODE_SPARC64+KS_MODE_LITTLE_ENDIAN, 	"Sparc64" ],
		"sparc64be" : [ KS_ARCH_SPARC, 	KS_MODE_SPARC64+KS_MODE_BIG_ENDIAN, 	"Sparc64 BE" ],

		"systemz" 	: [ KS_ARCH_SYSTEMZ, 	KS_MODE_BIG_ENDIAN, 	"SystemZ" ],
		"sysz"		: [ KS_ARCH_SYSTEMZ, 	KS_MODE_BIG_ENDIAN, 	"SystemZ" ],
		"s390x"		: [ KS_ARCH_SYSTEMZ, 	KS_MODE_BIG_ENDIAN, 	"SystemZ" ],
	}

else:
	mode_asm = False
	archs = [x.strip() for x in os.environ['CAPSTONE_ARCHS'].split(',')]

	init_set = {
		"arm"		: [ CS_ARCH_ARM, 	CS_MODE_ARM, 							"ARM" ],
		"armb"		: [ CS_ARCH_ARM, 	CS_MODE_ARM + CS_MODE_BIG_ENDIAN, 		"ARM BE" ],
		"arml"		: [ CS_ARCH_ARM, 	CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN, 	"ARM LE" ],
		"thumb"		: [ CS_ARCH_ARM, 	CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN, 	"THUMB" ],
		"thumbbe"	: [ CS_ARCH_ARM, 	CS_MODE_THUMB + CS_MODE_BIG_ENDIAN, 	"THUMB BE" ],
		"thumble"	: [ CS_ARCH_ARM, 	CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN, 	"THUMB LE" ],
		"arm64"		: [ CS_ARCH_ARM64, 	CS_MODE_LITTLE_ENDIAN, 					"AArch64" ],

		"mips"		: [ CS_ARCH_MIPS, 	CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN, "MIPS" ],
		"mipsbe"	: [ CS_ARCH_MIPS, 	CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN, 	"MIPS BE" ],
		"mips64"	: [ CS_ARCH_MIPS, 	CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN, 	"MIPS64" ],
		"mips64be"	: [ CS_ARCH_MIPS, 	CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN, 	"MIPS64 BE" ],

		"x16"		: [ CS_ARCH_X86, 	CS_MODE_16, 	"x86 16bit" ],
		"x32"		: [ CS_ARCH_X86, 	CS_MODE_32, 	"x86 32bit" ],
		"x64"		: [ CS_ARCH_X86, 	CS_MODE_64, 	"x86 64bit" ],
		"x16att"	: [ CS_ARCH_X86, 	CS_MODE_16, 	"x86 16bit ATT" ],
		"x32att"	: [ CS_ARCH_X86, 	CS_MODE_32, 	"x86 32bit ATT" ],
		"x64att"	: [ CS_ARCH_X86, 	CS_MODE_64, 	"x86 64bit ATT" ],

		"ppc64"		: [ CS_ARCH_PPC, 	CS_MODE_64+CS_MODE_LITTLE_ENDIAN, 	"PPC64" ],
		"ppc64be"	: [ CS_ARCH_PPC,	CS_MODE_64+CS_MODE_BIG_ENDIAN, 		"PPC64 BE" ],

		"sparc"		: [ CS_ARCH_SPARC, 	CS_MODE_BIG_ENDIAN, 	"Sparc" ],

		"systemz"	: [ CS_ARCH_SYSZ, 	CS_MODE_BIG_ENDIAN, 	"SystemZ" ],
		"sysz"		: [ CS_ARCH_SYSZ, 	CS_MODE_BIG_ENDIAN, 	"SystemZ" ],
		"s390x"		: [ CS_ARCH_SYSZ, 	CS_MODE_BIG_ENDIAN, 	"SystemZ" ],

		"xcore"		: [ CS_ARCH_XCORE, 	CS_MODE_BIG_ENDIAN, 	"XCore" ]
			}

result = {
	"items": []
}

for arch in archs:

	output = ""
	hint = init_set[arch][2]
	argument = []
	icon = ""

	if mode_asm == True:
		try:
			icon = "./keystone.png"

			if arch not in init_set:
				raise KsError(KS_ERR_ARCH)

			ks = Ks(init_set[arch][0], init_set[arch][1])
			encoding, count = ks.asm(query)

			if count == 0:
				raise KsError(KS_ERR_ASM_INVALIDOPERAND)

			output = ' '.join([("%.2X" % i) for i in encoding])
			argument = "k=" + output
		except KsError as e:
			output = str(e)
			argument = "e=" + output
		except Exception as e:
			output = "Unable to encode instruction"
			argument = "e=" + output

	else:
		try:
			icon = "./capstone.png"

			if arch not in init_set:
				raise CsError(CS_ERR_ARCH)

			opcode  = bytes(bytearray.fromhex(query))

			md = Cs(init_set[arch][0], init_set[arch][1])
			for inst in md.disasm(opcode, 0, 1):
				output = "%s\t%s" %(inst.mnemonic, inst.op_str)
				argument = "c=" + output
				break

			if output == "":
				raise CsError(CS_ERR_OK)

		except CsError as e:
			output = "Unable to decode instruction"
			argument = "e=" + output
		except Exception as e:
			output = "Unable to decode instruction"
			argument = "e=" + output

	result["items"].append(
		{
			"uid": "cap_key_stone_" + arch,
			"type": "file",
			"title": output,
			"subtitle": hint,
			"arg": argument,
			"autocomplete": "",
			"icon": {
				"path": icon
			}
	   }
	)

sys.stdout.write(json.dumps(result))
