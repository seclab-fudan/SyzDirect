#ifndef DEVICE_EXTRACTOR_H
#define DEVICE_EXTRACTOR_H

#include "Analyzer.h"

#include "DataFlowAnalysis.h"

#define CHARDEVICE 1
#define MISCDEVICE 2
#define BLOCKDEVICE 3
#define DEBUGFSDEVICE 4
#define CDEV 5

class DeviceInfoItem : public InfoItem {
	public:
		int type;
		int major;
		int minor;
		Value* OperationStruct;
		map<string, Function*> SyscallHandler;
};

class DeviceExtractorPass : public IterativeModulePass {

	private:
		void ProcessMiscDeviceInit(CallInst* callInst);
		void ProcessCdevInit(CallInst* callInst);
		void ProcessCdevAdd(CallInst* callInst);
		void ProcessRegisterChrdev(CallInst* callInst);
		void Process__RegisterChrdev(CallInst* callInst);
		void ProcessDebugfsCreateFile(CallInst* callInst);
		void ProcessRegisterBlkdev(CallInst* callInst);
		void ProcessAddDisk(CallInst* callInst);
		void ProcessTtyRegisterDriver(CallInst* callInst);
		void ProcessSndRegisterDevice(CallInst* callInst);
		void ProcessPosixClockRegister(CallInst* callInst);
		void ProcessAnonInodeGetfile(CallInst* callInst);

		string ExtractDevNameFromFunction(Function* f);
		string ExtractBlockDevNameFromFunction(Function* f);
		
		map<string, Function*> ProcessFileOperations(Value* handlerStruct);
		map<string, Function*> ProcessBlockDeviceOperations(Value* handlerStruct);
		map<string, Function*> ProcessTtyOperations(Value* handlerStruct);
		map<string, Function*> ProcessPosixClockOperations(Value* handlerStruct);

		Value* ExtractPtrAssignment(Value* ptrValue);
		set<Value*>* GetAliasSet(Value* value);
		set<Value*>* GetAliasOfStructType(Value* value, string structName);

		DataFlowAnalysis* DFA = nullptr;

	public:
		DeviceExtractorPass(GlobalContext *Ctx_): 
		 	IterativeModulePass(Ctx_, "DeviceExtractor") { }

		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

};

#endif