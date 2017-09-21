# ------------------------------------------------------------------
# CS620 Operating System Principles for Information Assurance
# Programming Assignment 3 - Assembly Language Interpreter
# ------------------------------------------------------------------
import os
reg, mem = dict(), dict()

# ------------------------------------------------------------------
# The play() procedure reboots the system and loads the programs
# for single-user and multi-user simulation
# ------------------------------------------------------------------

def load(program0, program1=None, program2=None):
  reboot()
  check_and_upload(program0, 100)
  if program1:
    check_and_upload(program1, 300)
  if program2:
    check_and_upload(program2, 500)

# ------------------------------------------------------------------
# The reboot() procedure clears the register and memory contents and
# loads the dispatcher program into memory (iff it's valid)
# ------------------------------------------------------------------

def reboot():
  global reg, mem

  # Reset the values of all registers and memory
  reg = dict(r0=0, r1=0, r2=0, r3=0, r4=0, r5=0, osr6=0, osr7=0, osr8=0, osr9=0, pc=100, ir=[], bp=0, sp=100, md=0, tm=0)
  mem = dict([(2, 200), (3, 300), (4, 400), (5, 500), (10, 100), (100, ['jmp', -1])])
  return True

# ------------------------------------------------------------------
# Reboot the system on startup
# ------------------------------------------------------------------
reboot()

# ------------------------------------------------------------------
# The load() procedure stores the contents of the program in
# <assembly_file> into the memory block represented by <region>
# ------------------------------------------------------------------

def check_and_upload(assembly_file, text_address):
  global mem
  program, labels, address = [], {}, 0

  # Read the assembly file to identify instructions and labels
  infile = open(assembly_file, 'r')
  for line in infile:
    instruction = line.split()
    # Ignore empty lines and comments
    if len(instruction) < 1 or instruction[0][0] == '#':
      pass
    # Track address labels for the branch statements
    elif instruction[0][0] == '@':
      labels[instruction[0]] = address
    # Store and count regular instructions
    else:
      program.append(instruction)
      address = address + 1
  infile.close()

  # Ensure that program will fit into its process space
  if address > 100:
    print("load failed: program has too many [", address, "] instructions")
    return False

  # Ensure all instructions are in the correct format
  for instruction in program:
    if not legal_instruction(instruction):
      print("load failed:", instruction, "has illegal format")
      return False

  # Convert address labels to integer offsets
  for address, instruction in enumerate(program):
    for index in range(len(instruction)):

      # Convert address labels to PC-relative address offsets
      if instruction[index][0] == '@':
        # Ensure that the address label is valid
        if instruction[index] not in labels:
          print("load failed: label", instruction[index], "not found")
          return False
        else:
          program[address][index] = labels[instruction[index]] - address - 1

      # Convert any immediate values into integers
      elif is_int(instruction[index]):
        program[address][index] = int(instruction[index])

  # Load the program into the text portion of the process space
  for instruction in program:
    mem[text_address] = instruction
    text_address = text_address + 1

  return True

# ------------------------------------------------------------------
# The step() procedure executes one iteration of the fetch - decode
# - execute - store processing cycle
# ------------------------------------------------------------------

def step():
  global reg, mem

  # Prevent attempts to access invalid PC addresses
  if reg['pc'] not in mem:
    print("Execution error: PC address does not exist:", reg['pc'], reg['ir'])
    return False

  # ------------------------------------------------------------------
  # FETCH: Fetch a copy of the next instruction
  # ------------------------------------------------------------------
  reg['ir'] = mem[reg['pc']][:]
  opcode = reg['ir'][0]
  
  # ------------------------------------------------------------------
  # DECODE: Check the registers to prevent prcess space violations
  # ------------------------------------------------------------------
  # Prevent changes to OS-managed registers
  if opcode in ['add', 'sub', 'mul', 'div', 'rem', 'mov', 'pop', 'load', 'ask']:  
    if reg['ir'][1] in ['osr6', 'osr7', 'osr8', 'osr9', 'pc', 'ir', 'bp', 'sp', 'md', 'tm'] and reg['md'] != 0:
      print("Execution error: Cannot modify protected register:", reg['pc'], reg['ir'])
      return False

  # Prevent division by zero errors
  if opcode in ['div', 'rem'] and get_value(reg['ir'][3]) == 0:
    print("Execution error: Division or remainder by zero:", reg['pc'], reg['ir'])
    return False

  # Prevent memory writes to regions outside of the process space
  if opcode in ['store'] and reg['md'] != 0:
    if not 0 <= get_value(reg['ir'][2]) <= 99:
      print("Execution error: Invalid address for storage:", reg['pc'], reg['ir'])
      return False

  # Prevent stack overflows and underflows
  if opcode in ['push'] and reg['sp'] == reg['bp']: 
    print("Execution error: Overflow - stack is full:", reg['pc'], reg['ir'])
    return False
  if opcode in ['pop'] and reg['sp'] == reg['bp'] + 100: 
    print("Execution error: Underflow - stack is empty:", reg['pc'], reg['ir'])
    return False

  # Prevent execution of privileged operations
  if opcode in ['resume'] and reg['md'] != 0:  
    print("Execution error: Cannot execute privileged instructions:", reg['pc'], reg['ir'])
    return False

  # Advance the program counter if no errors were encountered
  reg['pc'] = reg['pc'] + 1

  # ------------------------------------------------------------------
  # EXECUTE & STORE: Process the instruction and store the results
  # ------------------------------------------------------------------

  # Process the mathematical instructions
  if opcode == 'add':
    reg[reg['ir'][1]] = get_value(reg['ir'][2]) + get_value(reg['ir'][3])
  elif opcode == 'sub':
    reg[reg['ir'][1]] = get_value(reg['ir'][2]) - get_value(reg['ir'][3])
  elif opcode == 'mul':
    reg[reg['ir'][1]] = get_value(reg['ir'][2]) * get_value(reg['ir'][3])
  elif opcode == 'div':
    reg[reg['ir'][1]] = get_value(reg['ir'][2]) // get_value(reg['ir'][3])
  elif opcode == 'rem':
    reg[reg['ir'][1]] = get_value(reg['ir'][2]) % get_value(reg['ir'][3])
  elif opcode == 'mov':
    reg[reg['ir'][1]] = get_value(reg['ir'][2])

  # Process the branching / control transfer instructions
  elif opcode == 'jmp':
    reg['pc'] = get_value(reg['ir'][1]) + reg['pc']
  elif opcode == 'beq':
    if get_value(reg['ir'][2]) == get_value(reg['ir'][3]):
      reg['pc'] = get_value(reg['ir'][1]) + reg['pc']
  elif opcode == 'bgt':
    if get_value(reg['ir'][2]) > get_value(reg['ir'][3]):
      reg['pc'] = get_value(reg['ir'][1]) + reg['pc']

  # Process the memory access instructions
  elif opcode == 'load':
    reg[reg['ir'][1]] = mem[get_value(reg['ir'][2]) + reg['bp']]
  elif opcode == 'store':
    mem[get_value(reg['ir'][2]) + reg['bp']] = get_value(reg['ir'][1])

  # Process the stack management instructions
  elif opcode == 'push':
    reg['sp'] = reg['sp'] - 1
    mem[reg['sp']] = get_value(reg['ir'][1])
  elif opcode == 'pop':
    reg[reg['ir'][1]] = mem[reg['sp']]
    reg['sp'] = reg['sp'] + 1

  # Process the data access instructions
  elif opcode == 'ask':
    user_value = input(reg['ir'][1] + " ")
    if is_int(user_value):
      reg[reg['ir'][2]] = int(user_value)
    else:
      reg[reg['ir'][2]] = user_value
  elif opcode == 'show':
    print(reg['ir'][1], get_value(reg['ir'][2]))

  # Process the multi-tasking instructions
  elif opcode == 'resume':
    reg['md'] = 1
    reg['pc'] = get_value(reg['ir'][1])

  # ------------------------------------------------------------------
  # SWITCH: Share the processor & register resources between processes
  # ------------------------------------------------------------------

  # Transfer control to dispatcher if not in kernel mode
  if reg['md'] != 0 and reg['tm'] > 0:
    reg['tm'] = reg['tm'] - 1

    # Return control to the dispatcher if the time slice has ended
    if reg['tm'] == 0:
      # Store the current PC address to resume execution later
      mem[10] = reg['pc']
      reg['md'] = 0
      reg['pc'] = 100

  return True

# ------------------------------------------------------------------

def get_value(operand):
  global reg

  if is_int(operand):
    return int(operand)
  else:
    return reg[operand]

# ------------------------------------------------------------------
# The run() procedure simulates processor operation, while the
# watch() procedure displays the processor state during execution
# ------------------------------------------------------------------

def run(iterations=1):
  while iterations != 0:
    if iterations > 0:
      iterations = iterations - 1
    step()

def state():
  global reg, mem

  # this line is intended to clear the screen to provide a consistent display
  # if it causes problems, please feel free to delete it (or comment it out)
  os.system('cls' if os.name == 'nt' else 'clear')

  reg_s, mem_s = sorted(reg), sorted(mem)
  # display the registers
  print("--- user-mode registers ----------------------------------------")
  print([(x, reg[x]) for x in reg_s if x[0] == 'r'])
  print("--- OS-specific registers --------------------------------------")
  print([(x, reg[x]) for x in reg_s if x[0] == 'o'])
  print("--- system-state registers -------------------------------------")
  print([(x, reg[x]) for x in reg_s if x[0] not in ['r','o']])

  # display the data in the process spaces
  for i in [0, 1, 2]:
    print("--- process", i, "memory -------------------------------------------")
    print([(x, mem[x]) for x in mem_s if (200 * i) <= x < (200 * i + 200)])

  # display next instruction
  print("--- next instruction -------------------------------------------")
  print(reg['pc'], ':', mem[reg['pc']], '\n')
  
def watch():
  user_value = 1
  while True:
    state()
    if is_int(user_value):
      run(user_value)
    elif user_value == 'stop':
      return
    else:
      run()
    user_value = input(" $> ")

# ------------------------------------------------------------------
# The legal_instruction() and legal_operand() procedures are used
# to ensure that the programs operate safely and securely
# ------------------------------------------------------------------

def legal_instruction(instr):
  opcode = dict(add=1, sub=1, mul=1, div=1, rem=1, mov=3, jmp=9, beq=2, bgt=2, load=3, store=4, push=5, pop=6, ask=8, show=7, resume=5)
  opformat = dict([(1, [['r'],['r','i'],['r','i']]), (2, [['l'],['r','i'],['r','i']]), (3, [['r'],['r','i']]), (4, [['r','i'],['r','i']]), (5, [['r','i']]), (6, [['r']]), (7, [['s'],['r','i']]), (8, [['s'],['r']]), (9, [['l']])])

  # Ensure that the opcode and number of operands are valid
  if instr[0] not in opcode:
    print("check failed:", instr, "has an invalid opcode")
    return False
  screen = opformat[opcode[instr[0]]];
  if len(instr[1:]) != len(screen):
    print("check failed:", instr, "has an invalid length")
    return False

  # Ensure that each of the operands is a valid type
  for index in range(len(screen)):
    if not legal_operand(instr[1 + index], screen[index]):
      print("check failed:", instr, "has an invalid operand ", instr[1 + index])
      return False

  # Instruction is legal if opcode and all operands are valid
  return True

# ------------------------------------------------------------------

def legal_operand(op, form_list):
  global reg

  # Ensure that the op is a valid register, integer or label
  if ('r' in form_list) and (op in reg):
    return True
  elif ('i' in form_list) and (is_int(op)):
    return True
  elif ('l' in form_list) and (op[0] == '@'):
    return True
  # Strings are allowed to have a varied format
  elif ('s' in form_list):
    return True
  else:
    return False

# ------------------------------------------------------------------

def is_int(val):
  try:
    int(val)
    return True
  except ValueError:
    return False
