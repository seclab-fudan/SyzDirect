#ifndef COMMON_SYSCALL_EXTRACTOR_H
#define COMMON_SYSCALL_EXTRACTOR_H

#include "Analyzer.h"

#include "DataFlowAnalysis.h"

class CommonSyscallExtractorPass : public IterativeModulePass {

	private:
        map<string, vector<string>> SyscallHandlerToSyscall = {
            {"do_arch_prctl_64", {"arch_prctl"}}, 
			{"do_arch_prctl_common", {"arch_prctl"}}, 
            {"__se_sys_prctl", {"prctl"}},
            {"__se_sys_semctl", {"semctl"}},
			{"__se_sys_fcntl", {"fcntl"}},
			{"do_epoll_ctl", {"epoll_ctl"}},
			{"__se_sys_keyctl", {"keyctl"}},
			{"__se_sys_msgctl", {"msgctl"}},
			{"do_seccomp", {"seccomp"}},
			{"__se_sys_fsconfig", {"fsconfig"}},
			{"__se_sys_io_uring_register", {"io_uring_register"}},
			{"__se_sys_shmctl", {"shmctl"}},
			// {"setxattr", {"setxattr"},
			{"path_setxattr", {"lsetxattr", "setxattr"}},
			{"__se_sys_fsetxattr", {"fsetxattr"}},
			{"__se_sys_ptrace", {"ptrace"}},
			{"__se_sys_add_key", {"add_key"}},
			{"__se_sys_modify_ldt", {"modify_ldt"}},
			{"__se_sys_ioprio_get", {"ioprio_get"}},
			{"__se_sys_ioprio_set", {"ioprio_set"}},
			{"ksys_shmget", {"shmget"}},
			{"ksys_semget", {"semget"}},
			{"ksys_msgget", {"msgget"}},
			{"__do_sys_waitid", {"waitid"}},
			{"__se_sys_kcmp", {"kcmp"}},
			{"__se_sys_sysfs", {"sysfs"}},
			{"__se_sys_bpf", {"bpf"}},
            // {}
        };

		// FIXME: ad-hoc process

		map<string, int> StringCompareSyscallArg = {
			{"setxattr", 1}, 
			{"lsetxattr", 1},
			{"fsetxattr", 1},
			{"add_key", 0}
		};

		set<string> KeyNames;
		set<string> XattrNames;

		map<string, set<string>*> SyscallStringSetMap = {
			{"setxattr", &XattrNames},
			{"lsetxattr", &XattrNames},
			{"fsetxattr", &XattrNames},
			{"add_key", &KeyNames}
		};

		DataFlowAnalysis* DFA = nullptr;

		map<string, tuple<int8_t, int8_t, int8_t>>* CopyFuncs = nullptr; // src, dst, size
		map<string, pair<int8_t, int8_t>>* DataFetchFuncs = nullptr; // dst, src

		set<string>* GetStringCmpInFuncArg(Function* func, int argIdx);
		void GetStringCmpInFuncArgImpl(Function* func, int argIdx, set<Value*>* targetVal, set<pair<Value*, int>>* visited, set<string>* comparedStr);

	public:
		CommonSyscallExtractorPass(GlobalContext *Ctx_): 
		 	IterativeModulePass(Ctx_, "CommonSyscallExtractor") { }

		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

};

#endif