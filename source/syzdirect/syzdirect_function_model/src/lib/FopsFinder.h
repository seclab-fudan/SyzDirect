#ifndef FOPSFINDER_H
#define FOPSFINDER_H

#include "Analyzer.h"

class FopsFinderPass : public IterativeModulePass {

	private:
        static set<Function*> SyscallHandlerCandidates;
		static map<Function*, string> SyscallHandlerTypeMap;
		
		// functions
		void FindSyscallCandidatesRecrusively(CalleeMap* Callees, string syscallType, Function* syscallFunc, int depth);
		void InsertIndirectCall(CallInst* callInst, SmallPtrSet<Function*, 8U>& calleeFuncSet, string syscallType);
		void MapSyscallArgToFunctionArg(Function* function);
	public:
		FopsFinderPass(GlobalContext *Ctx_);

		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

};

#endif

