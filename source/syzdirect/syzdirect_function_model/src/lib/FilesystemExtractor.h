#ifndef FILESYSTEM_EXTRACTOR_H
#define FILESYSTEM_EXTRACTOR_H

#include "Analyzer.h"

class FilesystemInfoItem : public InfoItem {
	public:
		Value* filesystemTypeStruct;
		vector<GlobalVariable*> fileOperations;
		vector<pair<string, Function*>> SyscallHandler;
		virtual string generateDeviceSignature(Function*);
};

class SpecialFSItem : public FilesystemInfoItem
{
	public:
		string SubsystemName;
		SpecialFSItem();
		map<Function*,string> Func2Dev;
		SpecialFSItem(FilesystemInfoItem*);
		void ExtendFunc2DevMap(Function*);
		virtual string generateDeviceSignature(Function*);
};


class FilesystemExtractorPass : public IterativeModulePass {

	private:
		
		// functions
		void ProcessRegisterFilesystem(CallInst* callInst);
		GlobalVariable* getGlobalVaraible(StringRef);
		Function* getFunctionFromModules(StringRef funcName);
		vector<Module*> getRelatedModule(Module* M);
		void HandleFsTypeStruct(GlobalVariable* globalVar, FilesystemInfoItem* filesystemInfoItem);
		Function* findGetTreeFromInitFsCtx(Function* initFsCtx);
		vector<pair<string, Function*>> getHandlerFromFileOperations(GlobalVariable* globalVar);
		vector<pair<string, Function*>> getHandlerFromASOperations(GlobalVariable* globalVar);
		void getFileOperationsFromFillSuper(Function* F, FilesystemInfoItem* filesystemInfoItem, set<Function*>& visited, unsigned depth);
		void getFileOperationsFromEntry(Function* F, FilesystemInfoItem* filesystemInfoItem, set<Function*>& visited, unsigned depth);

	public:
		FilesystemExtractorPass(GlobalContext *Ctx_) :
			IterativeModulePass(Ctx_, "FilesystemExtractor") {}

		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

};

#endif