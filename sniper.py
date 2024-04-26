import re
import sys
import json
sys.path.append("..")

from capstone import *
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from functools import reduce


class SniperConfig:
	"""
	SniperConfig

	Manager for the config.json file.

	Values:
	payload - payload data sent to app
	addresses - all addresses divided into instructions
	"""

	def __init__(self, config_path):
		self.__config_path = config_path
		self.__data = self.__all()


	def __all(self):
		"""
		Get all data from config.json
		"""

		with open(self.__config_path, 'r') as f:
			data = json.load(f)

		return data


	def give_me(self, key):
		""" 
		Get values by key

		Arguments:
		key (str) -- key from config.json (eg. 'payload')
		"""

		if key in self.__data:
			return self.__data[key]

		return ''


	def get_addresses(self, instruction):
		"""
		Get addresses list by instruction
		
		Arguments:
		instruction (str) -- instruction (eg. 'add')
		"""
		
		data = self.__data

		if instruction not in data['addresses'].keys():
			return []

		return data['addresses'][instruction]


	def get_instruction(self, address):
		"""
		Get instruction (eg. 'add') by address

		Arguments:
		address (int) -- eg. 66992
		"""

		addresses = self.__data['addresses']

		for instr in addresses:
			if address in addresses[instr]:
				return instr

		return None


class Sniper:
	"""
	Sniper

	Overflow calculator for input data
	"""
	def __init__(self, payload, capstone):
		self.payload = payload
		self.md = capstone

		# his is a key for self.data dictionary
		self.current_address = ''

		"""
			structure of self.data {}

			current_address: {
				'modulo': 			int
				'registers':		dict
				'dest_register':	string
			}
		"""
		self.data = {}


	def set_address(self, address):
		"""
		Set address of selected instruction

		Arguments:
		address (int) -- eg. 66992 (0x105b0) from objdump -D
		"""

		if address not in self.data:
			self.data.update({address:{
				'modulo': 0,
				'registers': {},
				'dest_register': ''
			}})
		
		self.current_address = address


	def set_registers(self, registers: dict):
		"""
		Set instruction registers

		Arguments:
		registers (dict) -- {'r2': 1111, 'r3': 2222}
		"""

		self.data[self.current_address]['registers'] = registers


	"""
	Destination Register - to check if modulo is equal to it's value
	"""
	def set_destination_register(self, register):
		"""
		Set destination register name to check its value in the second instruction

		Arguments:
		register (str) -- eg. 'r3'
		"""

		self.data[self.current_address]['dest_register'] = register


	def get_modulo(self):
		"""
		Get calculated modulo.. or z3r0 ;>
		"""

		return self.data[self.current_address]['modulo']


	def get_destination_register(self):
		"""
		Get destrination register name 
		"""

		return self.data[self.current_address]['dest_register']


	def calculate_modulo_add(self):
		"""
		Calculate modulo from registers values for 'add' instruction
		"""

		if not self.__validate_registers_values():
			return False

		sum_value = sum(self.data[self.current_address]['registers'].values())

		if sum_value <= int(0x100000000):
			return False

		self.data[self.current_address]['modulo'] = sum_value % 0x100000000


	def calculate_modulo_mul(self):
		"""
		Calculate modulo from registers values for 'mul' instruction
		"""

		if not self.__validate_registers_values():
			return False

		self.data[self.current_address]['registers'].values()

		mul_value = reduce((lambda x, y: x * y), self.data[self.current_address]['registers'].values())

		if mul_value <= int(0x100000000):
			return False

		self.data[self.current_address]['modulo'] = mul_value % 0x100000000

	
	def check_overflow(self, register_value):
		"""
		Check if overflow occured

		Arguments:
		register_value (int) -- registers destination value
		"""

		if self.data[self.current_address]['modulo'] == 0:
			return False

		result = self.data[self.current_address]['modulo'] == register_value

		return result


	def __validate_registers_values(self):
		"""
		Registers validator
		"""

		if self.data[self.current_address]['registers'] == {}:
			return False

		if self.payload not in self.data[self.current_address]['registers'].values():
			return False
	
		return True


def get_registers(registers):
	"""
	Get registers from operands instruction string
	
	Arguments:
	registers (str) -- eg. "r3, r2, r3"

	Result (dict) (example):      
		{
			'registers': {
				'r3': 536870944, 
				'r2': 3758096416
			}, 
			'destination_register': 'r3'
		}
	"""

	registers = re.sub('\s+', '', registers).split(',')

	if registers == []:
		return []

	result = {
		'registers': {},
		'destination_register': ''
	}

	## registers[1:] - Set all operands without first, destination operand
	#
	for cnt in range(1, len(registers)):

		if '#' == registers[cnt][:1]:
			result['registers'][registers[cnt]] = int(registers[cnt][1:])
		else:
			result['registers'][registers[cnt]] = getattr(ql.arch.regs, registers[cnt])


	## Set destination register
	#	
	result['destination_register'] = registers[0]

	return result

def main_instruction(ql: Qiling) -> None:
	"""
	Set hook on this instruction to get all values from instruction registers

	eg. 105b0:66992   e0823003    add r3, r2, r3
	"""

	address = ql.arch.regs.pc
	buf = ql.mem.read(address, 4)
	
	for insn in ql.sniper.md.disasm(buf, address):
		operand_str = insn.op_str
		break

	rr = get_registers(operand_str)

	current_addr = ql.arch.regs.pc

	ql.sniper.set_address(current_addr)

	ql.sniper.set_registers(rr['registers'])

	ql.sniper.set_destination_register(rr['destination_register'])

	instruction = ql.sniper_config.get_instruction(current_addr) 

	if instruction:

		calculator = getattr(ql.sniper, 'calculate_modulo_' + instruction)

		calculator()


def post_instruction(ql: Qiling) -> None:
	"""
	Get values from previous destination register to calculate overflow
	"""

	# calculate previous instruction address
	addr = ql.arch.regs.pc - 4

	ql.sniper.set_address(addr)

	dest_register = ql.sniper.get_destination_register()

	dest_register_value = getattr(ql.arch.regs, dest_register)

	# calculate overflow, finally!
	if ql.sniper.check_overflow(dest_register_value):
		print("[!! {} {}] OVERFLOW DETECTED".format(
			hex(addr),
			ql.sniper_config.get_instruction(addr)
		))


if __name__=="__main__":

	# Seting all stuff
	# 
	cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	ql = Qiling([r'rootfs/vuln_app'], r'rootfs', verbose=QL_VERBOSE.DEFAULT)

	sp_conf = SniperConfig('config.json')
	sp = Sniper(sp_conf.give_me('payload'), cs)
	
	ql.sniper = sp
	ql.sniper_config = sp_conf

	"""
		Hook all ADD instructions
	"""
	instructions = sp_conf.get_addresses('add')

	for addr in instructions:
		ql.hook_address(main_instruction, addr)
		ql.hook_address(post_instruction, addr + 4)

	"""
		Hook all MUL instructions
	"""	
	instructions = sp_conf.get_addresses('mul')

	for addr in instructions:
		ql.hook_address(main_instruction, addr)
		ql.hook_address(post_instruction, addr + 4)

	ql.run()
