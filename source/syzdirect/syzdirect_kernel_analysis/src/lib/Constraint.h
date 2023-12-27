#include "Analyzer.h"

class ConstraintPass : public IterativeModulePass {
	public:
		ConstraintPass(GlobalContext *Ctx_): 
		 	IterativeModulePass(Ctx_, "ConstraintExtractor") { }

		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

};