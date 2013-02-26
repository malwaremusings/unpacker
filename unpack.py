##############################################################
# Python script to attempt automatic unpacking/decrypting of #
# malware samples using WinAppDbg.                           #
#                                                            #
# unpack.py v2013.02.26                                      #
# http://malwaremusings.com/scripts/unpack.py                #
##############################################################

import sys
import traceback
import winappdbg


# Log file which we log info to
logfile = None

class MyEventHandler(winappdbg.EventHandler):

###
# A. Declaring variables
###

	# A.1 used to keep track of allocated executable memory
	allocedmem = {}

	# A.2 used to indicate that we've found the entry point
	entrypt = 0x00000000

	#
	# variables used to find and disassemble unpacking loop
	#

	# A.3 used to indicate that we're single stepping
	tracing = False

	# A.4 remember the last two eip values
	lasteip = [0x00000000,0x00000000]

	# A.5 lowest eip address we see
	lowesteip = 0xffffffff

	# A.6 highest eip address we see
	highesteip = 0x00000000

	# A.7 list of addresses which we've disassembled
	disasmd = []

	# A.8 keeps track of addresses and instructions
	#     that write to the allocated memory block(s)
	writeaddrs = {}


###
# B. Class methods (functions)
###

	### B.1
	# get_funcargs(event)
	#     query winappdbg to get the function arguments
	#
	#     return a tuple consisting of the return address
	#     and a sub-tuple of function arguments
	###

	def get_funcargs(self,event):
		h = event.hook
		t = event.get_thread()
		tid = event.get_tid()

		return (t.get_pc(),h.get_params(tid))


###
# C. API Hooks
###

	### C.1
	# apiHooks: winappdbg defined hash of API calls to hook
	#
	#     Each entry is indexed by library name and is an array of 
	#     tuples consisting of API call name and number of args
	###

	apiHooks = {
		"kernel32.dll":[
			("VirtualAllocEx",5),
		]
	}


	###
	# API hook callback functions
	#
	#     These are defined by winappdbg and consist of functions
	#     named pre_<apifuncname> and post_<apifuncname> which are
	#     called on entry to, and on exit from, the given API 
	#     function (<apifuncname>), respectively.
	###

	# C.2
	# VirtualAllocEx() hook(s)
	#

	def post_VirtualAllocEx(self,event,retval):
		try:
			# C.2.1 Get the return address and arguments

			(ra,(hProcess,lpAddress,dwSize,flAllocationType,flProtect)) = self.get_funcargs(event)

			# Get an instance to the debugger which triggered the event
			# and also the process id and thread id of the process to which 
			# the event pertains

			d = event.debug
			pid = event.get_pid()
			tid = event.get_tid()

			# Log the fact that we've seen a VirtualAllocEx() call

			log("[*] <%d:%d> 0x%x: VirtualAllocEx(0x%x,0x%x,%d,0x%x,0x%03x) = 0x%x" % (pid,tid,ra,hProcess,lpAddress,dwSize,flAllocationType,flProtect,retval))

			# C.2.2 All the memory protection bits which include EXECUTE
			# permission use bits 4 - 7, which is nicely matched 
			# by masking (ANDing) it with 0xf0 and checking for a 
			# non-zero result

			if (flProtect & 0x0f0):
				log("[*]     Request for EXECUTEable memory")

				# We can only set page guards on our own process
				# otherwise page guard exception will occur in 
				# system code when this process attempts to write 
				# to the allocated memory.
				# This causes ZwWriteVirtualMemory() to fail

				# We can, however, set a page guard on it when 
				# this process creates the remote thread, as it 
				# will have presumably stopped writing to the 
				# other process' memory at that point.

				# C.2.2.1 Check that this VirtualAllocEx() call is for
				# the current process (hProcess == -1), and if
				# so, ask the winappdbg debugger instance to 
				# create a page guard on the memory region.
				# Also add information about the allocated region
				# to our allocedmem hash, indexed by pid and 
				# base address.

				if (hProcess == 0xffffffff):
					d.watch_buffer(pid,retval,dwSize - 1)
					self.allocedmem[(pid,retval)] = dwSize
		except:
			traceback.print_exc()
			raise


###
# D. winappdbg debug event handlers
###

	### D.1
	# create_process
	#
	#     winappdbg defined callback function to handle process creation events
	###

	def create_process(self,event):
		try:
			proc = event.get_process()
		
			log("[*] Create process event for pid %d (%s)" % (proc.get_pid(),proc.get_image_name()))
		except:
			traceback.print_exc()
			raise


	### D.2
	# exit_process
	#
	#     winappdbg defined callback function to handle process exit events
	###

	def exit_process(self,event):
		log("[*] Exit process event for pid %d (%s): %d" % (event.get_pid(),event.get_filename(),event.get_exit_code()))


	### D.3
	# create_thread
	#
	#     winappdbg defined callback function to handle thread creation events
	###

	def create_thread(self,event):
		log("[*] Create thread event")


	### D.4
	# load_dll
	#
	#     winappdbg defined callback function to handle DLL load events
	###

	def load_dll(self,event):
		log("[*] Load DLL")


	### D.5
	# event
	#
	#     winappdbg defined callback function to handle any remaining events
	###

	def event(self,event):
		log("[*] Unhandled event: %s" % event.get_event_name())


###
# E. winappdbg debug exception handlers
###

	### E.1
	# guard_page
	#
	#     winappdbg defined callback function to handle guard page exceptions
	###

	def guard_page(self,exception):
		try:
			# E.1.1 Get the exception and fault information that we need
			f_type = exception.get_fault_type()

			e_addr = exception.get_exception_address()
			f_addr = exception.get_fault_address()

			# get the process and thread ids
			pid = exception.get_pid()
			tid = exception.get_tid()

			# It is interesting to log this, but it generates a lot of log 
			# output and slows the whole process down
			#log("[!] <%d:%d> 0x%x: GUARD_PAGE(%d) exception for address 0x%x" % (pid,tid,e_addr,f_type,f_addr))
			#log("[*] VirtualAlloc()d memory address 0x%x accessed (%d) from 0x%x (%s)" % (f_addr,f_type,e_addr,instr))

			# E.1.2 Was it a memory write operation?
			if (f_type == winappdbg.win32.EXCEPTION_WRITE_FAULT):
				# E.1.2.1 Use the writeaddrs[] array to check to see 
				#         if we have already logged access from this
				#         address, as unpacking is generally done in 
				#         a loop and we don't want to log the same
				#         instructions for each iteration
				if not e_addr in self.writeaddrs:
					t = exception.get_thread()
					instr = t.disassemble_instruction(e_addr)[2].lower()
					log("[*] VirtualAlloc()d memory address 0x%x written from 0x%x (%s)" % (f_addr,e_addr,instr))
					self.writeaddrs[e_addr] = instr

				# E.1.2.2 Use the tracing variable to see if we have
				#         already started tracing, that is single 
				#         stepping. If not, enable it, and make a note
				#         of the fact by setting the tracing variable
				#         to True
				if not self.tracing:
					self.tracing = True
					d = exception.debug
					d.start_tracing(exception.get_tid())

			# E.1.3 Was it a memory instruction fetch (execute) operation, 
			#       and if so, are we still looking for the entry point address?
			if (f_type == winappdbg.win32.EXCEPTION_EXECUTE_FAULT) and (self.entrypt == 0):
				self.entrypt = e_addr
				t = exception.get_thread()
				jmpinstr = t.disassemble_instruction(self.lasteip[0])[2].lower()

				# E.1.3.1 Log what we've found
				log("[D]     lasteip[1]: 0x%x" % self.lasteip[1])
				log("[*]     Found unpacked entry point at 0x%x called from 0x%x (%s)" % (self.entrypt,self.lasteip[0],jmpinstr))
				log("[-]     Unpacking loop at 0x%x - 0x%x" % (self.lowesteip,self.highesteip))

				pid = exception.get_pid()

				# E.1.3.2
				for (mem_pid,memblk) in self.allocedmem:
					if (mem_pid == pid):
						size = self.allocedmem[(mem_pid,memblk)]
						endaddr = memblk + size - 1
						if (e_addr >= memblk) and (e_addr <= endaddr):
							# E.1.3.3 Log what we're doing and delete the memory breakpoint
							log("[-]     Dumping %d bytes of memory range 0x%x - 0x%x" % (size,memblk,endaddr))
							d = exception.debug
							d.dont_watch_buffer(exception.get_pid(),memblk,size - 1)

							# E.1.3.4 Disable single-step debugging
							self.tracing = False
							d.stop_tracing(exception.get_tid())

							# E.1.3.5 Reset unpacking loop variables
							self.entrypt = 0x00000000
							#del self.lasteip
							self.lasteip = [0x00000000,0x00000000]
							self.lowesteip = 0xffffffff
							self.highest = 0x00000000

							# E.1.3.6 Dump the memory block to a file
							p = exception.get_process()

							dumpfile = open(sys.argv[1] + ".memblk0x%08x" % memblk,"wb")
							dumpfile.write(p.read(memblk,size))
							dumpfile.close()
		except Exception as e:
			traceback.print_exc()
			raise


	### E.2
	# single_step
	#
	#     winappdbg defined callback function to handle single step exceptions
	###

	def single_step(self,exception):
		try:
			# E.2.1 Get the exception address
			e_addr = exception.get_exception_address()

			# E.2.2 If we have just looped back (eip has gone backward)
			if (e_addr < self.lasteip[1]):
				# Remember this lower address as the lowest loop address
				if self.lowesteip == 0xffffffff: self.lowesteip = e_addr

				# ... and the address we just jumped from as the highest loop address
				if self.highesteip == 0x00000000: self.highesteip = self.lasteip[1]

			# E.2.3 If we are executing an instruction within the bounds of the loop
			#       and we haven't already disassembled this address, then do so
			if (e_addr >= self.lowesteip) and (e_addr <= self.highesteip) and (not e_addr in self.disasmd):
				t = exception.get_thread()
				disasm = t.disassemble_instruction(e_addr)
				instr = disasm[2].lower()
				log("    0x%x: %s" % (e_addr,instr))
				self.disasmd.append(e_addr)

			# E.2.4 Remember the last two instruction addresses (eip values)
			#       We need to remember the last two in order to be able to
			#       disassemble the instruction that jumped to the original 
			#       entry point in the unpacked code
			self.lasteip[0] = self.lasteip[1]
			self.lasteip[1] = e_addr
		except Exception as e:
			traceback.print_exc()
			raise


	### E.3
	# exception
	#
	#     winappdbg defined callback function to handle remaining exceptions
	###

	def exception(self,exception):
		log("[*] Unhandled exception at 0x%x: %s" % (exception.get_exception_address(),exception.get_exception_name()))

#
#### end of MyEventHandler class
#


###
# F. Miscellaneous functions
###

### F.1
# log(msg):
###
def log(msg):
	global logfile

	print(msg)
	if not logfile:
		logfile = open(sys.argv[1] + ".log","w")
	if logfile:
		logfile.write(msg + "\n")
		logfile.flush()


### F.2
# simple_debugger(argv):
###
def simple_debugger(filename):
	global logfile

	try:
		handler = MyEventHandler()
		#logfile = winappdbg.textio.Logger(filename + ".log",verbose = True)
	except:
		traceback.print_exc()
	with winappdbg.Debug(handler,bKillOnExit = True) as debug:
		log("[*] Starting %s" % filename)
		debug.execl(filename)
		log("[*] Starting debug loop")
		debug.loop()
		log("[*] Terminating")


###
# G. Start of script execution
###

simple_debugger(sys.argv[1])
