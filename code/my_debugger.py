from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process         = None
        self.pid               = None
        self.debugger_active   = False
        self.h_thread          = None
        self.context           = None
        self.breakpoints       = {}
        self.exception         = None
        self.exception_address = None

    def load(self, path_to_exe):
        creation_flags = DEBUG_PROCESS

        startupinfo         = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        startupinfo.dwFlags     = 0x1
        startupinfo.wShowWindow = 0x0

        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   True,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information)):

            print("[*] We have sucessfully launched the process!")
            print("[*] PID: %d" % process_information.dwProcessId)
            self.h_process = self.open_process(process_information.dwProcessId)
        else:
            print("[*] Error: 0x%08x." % kernel32.GetLastError())

    def open_process(self, pid):

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid);
        return h_process

    def attach(self, pid):
        self.h_process = self.open_process(pid)

        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid             = int(pid)

            # self.run()
        else:
            print("[*] Unable to attch to the process.")

    def run(self):
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status: int = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):

            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(self.h_thread)
            
            print("Event Code: %d Thread ID: %d" % 
                  (debug_event.dwDebugEventCode, debug_event.dwThreadId)
            )

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                exception: int = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print("Access Violation Detected.")
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif exception == EXCEPTION_GUARD_PAGE:
                    print("Gurad Page Access Detected.")
                elif exception == EXCEPTION_SINGLE_STEP:
                    print("Single Stepping.")
                else:
                    raise Exception("Unknown Code")

            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status
            )

    def exception_handler_breakpoint(self):
        print("[*] Inside the breakpoint handler.")
        print("Exception address: 0x%08x" % self.exception_address)
        return DBG_CONTINUE

    def detach(self):

        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            return True
        else:
            print("There was an error")
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(
            THREAD_ALL_ACCESS, None, thread_id
        )

        if h_thread != None:
            return h_thread
        else:
            print("[*] Could not obtain a valid thread handle.")
            return False

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD, self.pid)

        if snapshot != None:

            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)

                success = kernel32.Thread32Next(
                    snapshot, byref(thread_entry)
                )

            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False

    def get_thread_context(self, thread_id=None, h_thread=None):
        context = WOW64_CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        h_thread = self.open_thread(thread_id)
        if kernel32.Wow64GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False

    def read_process_memory(self, address, length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if not kernel32.ReadProcessMemory(
                    self.h_process,
                    address, read_buf,
                    length, byref(count)
        ):
            return False
        else:
            data += read_buf.raw
            return data

    def write_process_memory(self, address, data):
        count  = c_ulong(0)
        length = len(data)

        c_data = c_char_p(data[count.value:])

        if not kernel32.WriteProcessMemory(
            self.h_process,
            address, c_data,
            length, byref(count)
        ):
            return False
        else:
            return True

    def bp_set(self, address):

        if not self.breakpoints.has_key(address):
            try:
                original_byte = self.read_process_memory(address, 1)
                self.write_process_memory(address, "\xCC")
                self.breakpoints[address] = (address, original_byte)
            except:
                return False

        return True

    def func_resolve(self, dll, function):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)

        kernel32.CloseHandle(handle)

        return address

