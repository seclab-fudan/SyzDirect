#ifndef DBGINFOHELPER_H
#define DBGINFOHELPER_H

#include "Analyzer.h"

class DbgInfoHelperPass : public IterativeModulePass {

	private:
		map<string, int>* getStructFieldIdx(DIType* TY);
	public:
		DbgInfoHelperPass(GlobalContext *Ctx_): 
		 	IterativeModulePass(Ctx_, "DbgInfoHelper") { }

		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

};


// void ExtractDbgInfoOfArg(CallInst* callInst, int idx);

#endif