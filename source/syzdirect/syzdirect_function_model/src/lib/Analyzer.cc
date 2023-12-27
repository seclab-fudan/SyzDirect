//===-- Analyzer.cc - the kernel-analysis framework--------------===//
//
// This file implements the analysis framework. It calls the pass for
// building call-graph and the pass for finding security checks.
//
// ===-----------------------------------------------------------===//

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Path.h"

#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>
#include <filesystem>
#include <boost/algorithm/string/predicate.hpp>

#include "Analyzer.h"
#include "CallGraph.h"
#include "Config.h"

#include "TypeInitializer.h"
#include "PointerAnalysis.h"
#include "DbgInfoHelper.h"
#include "FopsFinder.h"
#include "DeviceExtractor.h"
#include "FilesystemExtractor.h"
#include "NetworkInterfaceExtractor.h"
#include "CommonSyscallExtractor.h"

#include "CallGraphSearch.h"

#include "CodeFeatures.h"
#include "Signature.h"
#include "Utils.h"

#include "ArgMapParser.h"

#include "DescriptionGenerator.h"
#include "time.h"

using namespace llvm;

cl::opt<string> TargetPointFile(
  "target-points", cl::desc("File that contain target point information (idx src_file:line)")
);

cl::opt<string> TargetPoint(
  "target-point", cl::desc("src file:line")
);

cl::opt<string> kernelBCDir(
  cl::Positional, cl::OneOrMore, cl::desc("kernel bitcode dir")
);

cl::opt<unsigned> VerboseLevel(
    "verbose-level", cl::desc("Print information at which verbose level"),
    cl::init(0));

cl::opt<string> SourceLocation(
        "source-location", cl::desc("Input the target source code location"),
        cl::init("/dev/shm/linux"));

cl::opt<string> GeneratorConfigureLocation(
    "generate", cl::desc("Generate the new syscall descriptions"), cl::init("")
);

// GlobalContext GlobalCtx;
GlobalContext GlobalCtx = GlobalContext();

std::map<std::string, std::string> GlobalSyscallEntryFunctions = {
  {"ioctl", "__se_sys_ioctl"},
  {"open", "do_dentry_open"},
  {"read", "vfs_read"},
  {"write", "vfs_write"},
  {"setsockopt", "__sys_setsockopt"},
  {"getsockopt", "__sys_getsockopt"},
  {"sendmsg", "____sys_sendmsg"},
  {"recvmsg", "____sys_recvmsg"},
  {"listen", "__sys_listen"},
};

std::map<std::string, int> GlobalSyscallRecrusiveCount = {
    {"ioctl", 5},
    {"open", 3},
    {"read", 3},
    {"write", 3},
    {"setsockopt", 7},
    {"getsockopt", 7},
    {"sendmsg", 5},
    {"recvmsg",5},
    {"listen", 3},
};

void IterativeModulePass::run(ModuleList &modules) {

  ModuleList::iterator i, e;
  OP << "[" << ID << "] Initializing " << modules.size() << " modules ";
  bool again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      again |= doInitialization(i->first);
      OP << ".";
    }
  }
  OP << "\n";

  unsigned iter = 0, changed = 1;
  while (changed) {
    ++iter;
    changed = 0;
    unsigned counter_modules = 0;
    unsigned total_modules = modules.size();
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      OP << "[" << ID << " / " << iter << "] ";
      OP << "[" << ++counter_modules << " / " << total_modules << "] ";
      OP << "[" << i->second << "]\n";

      bool ret = doModulePass(i->first);
      if (ret) {
        ++changed;
        OP << "\t [CHANGED]\n";
      } else
        OP << "\n";
    }
    OP << "[" << ID << "] Updated in " << changed << " modules.\n";
  }

  OP << "[" << ID << "] Postprocessing ...\n";
  again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      // TODO: Dump the results.
      again |= doFinalization(i->first);
    }
  }

}


void PrintResults(GlobalContext *GCtx) {
	OP<<"############## Result Statistics ##############\n";
	OP<<"# Number of sanity checks: \t\t\t"<<GCtx->NumSecurityChecks<<"\n";
	OP<<"# Number of conditional statements: \t\t"<<GCtx->NumCondStatements<<"\n";
}


void splitString(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
  std::string::size_type pos1, pos2;
  pos2 = s.find(c);
  pos1 = 0;
  while(std::string::npos != pos2)
  {
    v.push_back(s.substr(pos1, pos2-pos1));
 
    pos1 = pos2 + c.size();
    pos2 = s.find(c, pos1);
  }
  if(pos1 != s.length())
    v.push_back(s.substr(pos1));
}

void strip(string &str) {
  if  (str.length() != 0) {
    auto w = string(" ");
    auto n = string("\n");
    auto r = string("\t");
    auto t = string("\r");
    auto v = string(1 ,str.front()); 
    while((v == w) || (v==t) || (v==r) || (v==n)) {
        str.erase(str.begin());
        v = string(1 ,str.front());
    }
    v = string(1 , str.back()); 
    while((v ==w) || (v==t) || (v==r) || (v==n)) {
        str.erase(str.end() - 1 );
        v = string(1 , str.back());
    }
  }
}

int startsWith(string s, string prefix) {
  return s.find(prefix) == 0?1:0;
}


#define OUTPUT_AND_VALUE false

void help(Function* f, unsigned argIdx, map<unsigned, ConstBlockMap>& argBlockMap, string str, vector<string>& res, unsigned argNum)
{
  if(argIdx >= argNum)
  {
    for(string s:res)
    {
      if(str == s)
      {
        return;
      }
    }
    res.push_back(str);
    return;
  }

  if(argBlockMap[argIdx].size() == 0)
  {
    string newStr = str + "|C[]";
    help(f, argIdx+1, argBlockMap, newStr, res, argNum);
    return;
  }
  for(CMDConst* cmdConst:argBlockMap[argIdx])
  {
    string newStr = "";
    if (cmdConst->compareString != "") {
      newStr = str + "|S[" + cmdConst->compareString + "]";
    } else {
      string andValues = "";
      if(OUTPUT_AND_VALUE && cmdConst->andOps.size() > 0)
      {
        // string tmp = "";
        u_int32_t tmp = 0xffffffff;
        bool flag = false;
        for(Value* v:cmdConst->andOps)
        {
          Instruction* I = dyn_cast<Instruction>(v);
          if(I == nullptr)
            continue;
          if(I->getOpcode() == Instruction::And)
          {
            BinaryOperator* binOp = dyn_cast<BinaryOperator>(I);
            for(int i = 0; i < binOp->getNumOperands(); i++)
            {
              ConstantInt* constantInt = dyn_cast<ConstantInt>(binOp->getOperand(i));
              if(constantInt == nullptr)
                continue;
              // tmp += " " + to_string(constantInt->getZExtValue());
              tmp &= constantInt->getZExtValue();
              flag = true;
            }
          }
        }
        if(flag)
        {
          andValues += "&" + to_string(tmp);
        }
      }
      newStr = str + "|C[" + to_string(cmdConst->value->getZExtValue()) + andValues +  "]";
    }
    help(f, argIdx+1, argBlockMap, newStr, res, argNum);
  }
}

vector<string> handleMmapSignature(vector<string> sigs)
{
  vector<string> res;
  for(string s : sigs)
  {
    outs() << "origin mmap signature: " << s << "\n";
    vector<string> splitRes;
    splitString(s, splitRes, "|");
    string str = "";
    str += splitRes[0];
    str += "|C[]|C[]|C[]|C[]|";
    str += splitRes[1];
    str += "|";
    if(splitRes.size() >= 3)
      str += splitRes[2];
    else
      str += "C[]";
    res.push_back(str);
  }
  return res;
}

int main(int argc, char **argv) {
  clock_t startTime, endTime;
  startTime = clock();
	// Print a stack trace if we signal out.
	sys::PrintStackTraceOnErrorSignal(argv[0]);
	PrettyStackTraceProgram X(argc, argv);
	clock_t begin = clock();
	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.

	cl::ParseCommandLineOptions(argc, argv, "global analysis\n");
	SMDiagnostic Err;
  
  // <full file path, function name> -> Function class
  map<pair<string, string>, Function*> FunctionMap;
  // full file path -> Module class
  map<string, Module*> ModuleMap;


  vector<string> InputFilenames;

  map<string, Function*> SyscallEntryFunctionPtr;

  outs() << kernelBCDir << "\n";
  
  for (const auto& p : filesystem::recursive_directory_iterator(std::string(kernelBCDir))) {
      if (!filesystem::is_directory(p)) {
          filesystem::path path = p.path();
          if (boost::algorithm::ends_with(path.string(), ".llbc")) {
            InputFilenames.push_back(path.string());
          }
      }
  }
  
	// Loading modules
	OP << "Total " << InputFilenames.size() << " file(s)\n";

	for (unsigned i = 0; i < InputFilenames.size(); ++i) {

		LLVMContext *LLVMCtx = new LLVMContext();
		unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

		if (M == NULL) {
		    Err.print("Analyzer.cc",OP);
		    OP << "\n";
			OP << argv[0] << ": error loading file '"
				<< InputFilenames[i] << "'\n";
			continue;
		}

		Module *Module = M.release();
		StringRef MName = StringRef(strdup(InputFilenames[i].data()));
		GlobalCtx.Modules.push_back(make_pair(Module, MName));
		GlobalCtx.ModuleMaps[Module] = InputFilenames[i];

    string location = InputFilenames[i];
    vector<string> splitRes;
    splitString(location, splitRes, ".");
    location = splitRes[0];
    for (auto it = Module->begin(); it != Module->end(); ++it) {
      Function *F = &*it;
      string functionName = static_cast<string>(F->getName());
      for (auto item : GlobalSyscallEntryFunctions) {
        if (functionName == item.second) {
          SyscallEntryFunctionPtr[item.first] = F;
        }
      }
      auto tmpPair = make_pair(Module->getSourceFileName(), functionName);
      FunctionMap[tmpPair] = F;
    }
    ModuleMap[Module->getSourceFileName()] = Module;
	}


  GlobalCtx.FunctionArgMap = getArgMapFromFile();
	// Main workflow
	// Initilaize global type map
	TypeInitializerPass TIPass(&GlobalCtx);
	TIPass.run(GlobalCtx.Modules);
	TIPass.BuildTypeStructMap();

  // Pointer analysis
  PointerAnalysisPass PAPass(&GlobalCtx);
  PAPass.run(GlobalCtx.Modules);

	// Build global callgraph.
	CallGraphPass CGPass(&GlobalCtx);
	CGPass.run(GlobalCtx.Modules);

  // Get information from the debug info
  DbgInfoHelperPass DIHPass(&GlobalCtx);
  DIHPass.run(GlobalCtx.Modules);

  // Find All the fops structs
  FopsFinderPass FFPass(&GlobalCtx);
  FFPass.run(GlobalCtx.Modules);

  // Find the common syscall
  CommonSyscallExtractorPass CSEPass(&GlobalCtx);
  CSEPass.run(GlobalCtx.Modules);

  // Device extract
  DeviceExtractorPass DEPass(&GlobalCtx);
  DEPass.run(GlobalCtx.Modules);

  // Filesystem extract
  FilesystemExtractorPass FSEPass(&GlobalCtx);
  FSEPass.run(GlobalCtx.Modules);

  // // Network interface extract
  NetworkInterfaceExtractorPass NIEPass(&GlobalCtx);
  NIEPass.run(GlobalCtx.Modules);

  getNetDeviceNameByAllocNetdev();

  std::error_code OutErrorInfo;
  raw_fd_ostream calleeFile(StringRef("./callee.txt"), OutErrorInfo, sys::fs::CD_CreateAlways);
  raw_fd_ostream callerFile(StringRef("./caller.txt"), OutErrorInfo, sys::fs::CD_CreateAlways);

  // calleeFile << "===callees info===" << "\n";
  // for (auto item: GlobalCtx.Callees) {
  //   CallInst *callInst = item.first;
  //   Function *FuncFrom = callInst->getFunction();
  //   for (auto FuncTo: item.second) {
  //     calleeFile << FuncFrom->getName() << " -> " << FuncTo->getName() << "\n";
  //   }
  // }
  // callerFile << "===callers info===" << "\n";
  // for (auto item: GlobalCtx.Callers) {
  //   Function *FuncFrom = item.first;
  //   for (auto callInst: item.second) {
  //     callerFile << FuncFrom->getName() << " <- " << callInst->getFunction()->getName() << "\n";
  //   }
  // }

  string generatorConfigureLocation = std::string(GeneratorConfigureLocation);

  if (generatorConfigureLocation != "") {
    Generator* generator = new Generator(&GlobalCtx);
    ifstream configFile(generatorConfigureLocation, ios::in|ios::binary);
    char tmp[32] = {0};
    uint64_t syscallNameLen = 0;
    while (configFile.read((char *)&syscallNameLen, 8)) {
      memset(tmp, 0, sizeof(tmp));
      configFile.read(tmp, syscallNameLen);
      string syscallName = std::string(tmp);
      uint64_t constraintCnt = 0;
      configFile.read((char *)&constraintCnt, 8);
      vector<Constraint*> constraints;
      string devStr = "";
      uint64_t argIdx = 0;
      uint64_t family = 0, type = 0, protocol = 0;
      for (int i = 0; i < constraintCnt; i++) {
        uint64_t constraintType = 0;
        configFile.read((char *)&constraintType, 8);
        switch (constraintType) {
          case 0: // const
          {
            configFile.read((char *)&argIdx, 8);
            uint64_t value = 0;
            configFile.read((char *)&value, 8);
            auto constraint = new ConstantConstraint(argIdx, value);
            constraints.push_back(constraint);
            break;
          }
          case 1: // string
          {
            configFile.read((char *)&argIdx, 8);
            uint64_t strLen = 0;
            configFile.read((char *)&strLen, 8);
            memset(tmp, 0, sizeof(tmp));
            configFile.read(tmp, strLen);
            string strTmp = std::string(tmp);
            auto constraint = new StringConstraint(argIdx, strTmp);
            constraints.push_back(constraint);
            break;
          }
          case 2: // device
          {
            configFile.read((char *)&argIdx, 8);
            uint64_t strLen = 0;
            configFile.read((char *)&strLen, 8);
            memset(tmp, 0, sizeof(tmp));
            configFile.read(tmp, strLen);
            string strTmp = std::string(tmp);
            devStr = strTmp;
            break;
          }
          case 3: // socket
          {
            configFile.read((char *)&argIdx, 8);
            uint64_t strLen = 0;
            configFile.read((char *)&strLen, 8);
            memset(tmp, 0, sizeof(tmp));
            configFile.read(tmp, strLen);
            string strTmp = std::string(tmp);
            devStr = strTmp;
            configFile.read((char *)&family, 8);
            configFile.read((char *)&type, 8);
            configFile.read((char *)&protocol, 8);
            break;
          }
          default:
            break;
        }
      }
      outs() << syscallName << "\n";
      SyscallInstance* syscall = nullptr;
      if (family != 0 || type != 0 || protocol != 0) {
        syscall = generator->AddSyscall(syscallName, devStr, (int)family, (int)type, (int)protocol);
      } else {
        syscall = generator->AddSyscall(syscallName, devStr);
      }
      for (auto item: constraints) {
        item->SetConstraintToSyscall(syscall);
      }
    }

    outs() << "\n" <<  generator->serialize();
    configFile.close();
    exit(0);
  }
  
  for (auto item: GlobalCtx.SubsystemInfo) {
    switch (item->ItemType) {
      
      case DEVICE: {
        auto deviceInfoItem = static_cast<DeviceInfoItem*>(item);
        if (deviceInfoItem->name != "?") {
          outs() << "[+] Device " << deviceInfoItem->name << "@"  << deviceInfoItem->type << "\n";
          outs() << "|--- Major " << deviceInfoItem->major << " Minor " << deviceInfoItem->minor << "\n";
          for (auto handler : deviceInfoItem->SyscallHandler) {
            auto syscallName = handler.first;
            auto handlerName = handler.second->getName();
            outs() << "|---|--- " << syscallName << ": " << handlerName << "\n";
          }
        }
        break;
      }
      case FILESYSTEM: {
        FilesystemInfoItem* filesystemInfoItem = static_cast<FilesystemInfoItem*>(item);
        if (filesystemInfoItem->name != "?") {
          outs() << "[+] filesystem " << filesystemInfoItem->name << "\n";
          string ftStruName = "none";
          if (filesystemInfoItem->filesystemTypeStruct != nullptr) {
            ftStruName = filesystemInfoItem->filesystemTypeStruct->getName().str();
          }
          outs() << "|--- file system type struct: " << ftStruName << "\n";
          for(GlobalVariable* globalVar:filesystemInfoItem->fileOperations)
          {
            outs() << "|--- file operations: " << globalVar->getName() << "\n";
          }
          for(pair<string, Function*> item:filesystemInfoItem->SyscallHandler)
          {
            outs() << "|---|--- " << item.first << ": " << item.second->getName() << "\n";
          }
        }
        break;
      }
      case NETWORK:
      auto networkInterfaceInfoItem = static_cast<NetworkInterfaceInfoItem*>(item);
        if (networkInterfaceInfoItem->name != "?") {
          outs() << "[+] Network " << networkInterfaceInfoItem->name << "\n";
          // outs() << "|--- family " << networkInterfaceInfoItem->family << " type " << networkInterfaceInfoItem->type << "\n";
          outs() << "|--- family " << networkInterfaceInfoItem->family << " type " << networkInterfaceInfoItem->type << " protocol " << networkInterfaceInfoItem->protocol <<"\n";
          for (auto handler : networkInterfaceInfoItem->SyscallHandler) {
            auto syscallName = handler.first;
            auto handlerName = handler.second->getName();
            outs() << "|---|--- " << syscallName << ": " << handlerName << "\n";
          }
          if(networkInterfaceInfoItem->family == AF_NETLINK)
          {
            NetlinkInfoItem* netlinkInfoItem = static_cast<NetlinkInfoItem*>(networkInterfaceInfoItem);
            if(netlinkInfoItem->SendmsgHandler != nullptr)
              outs() << "|---|--- " << "real sendmsg" << ": " << netlinkInfoItem->SendmsgHandler->getName() << "\n";
            if(netlinkInfoItem->protocol == NETLINK_ROUTE)
            {
              RtnetlinkInfoItem* rtnetlinkInfoItem = static_cast<RtnetlinkInfoItem*>(netlinkInfoItem);
              outs() << "|---|--- " << "rtnetlink handlers: \n";
              for(auto item: rtnetlinkInfoItem->RtnetlinkHandlers)
              {
                outs() << "|---|---|--- " << "protocol: " << get<0>(item) << "\n";
                outs() << "|---|---|--- " << "msgtype: " << get<1>(item) << "\n";
                if(get<2>(item) != nullptr)
                {
                  outs() << "|---|---|--- " << "doit: " << get<2>(item)->getName() << "\n";
                }
                if(get<3>(item) != nullptr)
                {
                  outs() << "|---|---|--- " << "dumpit: " << get<3>(item)->getName() << "\n";
                }
              }
            }
          }
        }
        break;
    }
  }



  unordered_map<string, unordered_map<Function*, bool>> TerminatorHandlerCandidates = unordered_map<string, unordered_map<Function*, bool>>();
  map<Function*, vector<InfoItem*>> funcInfoItemMap;
  vector<NetlinkInfoItem*> specialHandleList;

  for (auto item: GlobalCtx.SubsystemInfo) {
    switch (item->ItemType) {
      
      case DEVICE: {
        auto deviceInfoItem = static_cast<DeviceInfoItem*>(item);
        if (deviceInfoItem->name != "?") {
          for (auto handler : deviceInfoItem->SyscallHandler) {
            auto syscallName = handler.first;
            auto handlerFunc = handler.second;
            if(handlerFunc->getInstructionCount() == 0)
            {
              handlerFunc = getFunctionFromModules(handlerFunc->getName());
            }
            TerminatorHandlerCandidates[handler.first][handlerFunc] = true;
            if(TerminatorHandlerCandidates.count(handler.first) == 0)
            {
              TerminatorHandlerCandidates[handler.first] = unordered_map<Function*, bool>();
            }
            TerminatorHandlerCandidates[handler.first][handlerFunc] = true;
            if(funcInfoItemMap.count(handlerFunc) == 0)
            {
              funcInfoItemMap[handlerFunc] = vector<InfoItem*>();
            }
            if(find(funcInfoItemMap[handlerFunc].begin(), funcInfoItemMap[handlerFunc].end(), deviceInfoItem) == funcInfoItemMap[handlerFunc].end())
            {
              funcInfoItemMap[handlerFunc].push_back(deviceInfoItem);
            }
          }
        }
        break;
      }
      case FILESYSTEM: {
        FilesystemInfoItem* filesystemInfoItem = static_cast<FilesystemInfoItem*>(item);
        if (filesystemInfoItem->name != "?") {
          if(filesystemInfoItem->name == "sockfs")
          {
            continue;
          }
          for(auto handler : filesystemInfoItem->SyscallHandler)
          {
            auto syscallName = handler.first;
            auto handlerFunc = handler.second;
            if(handlerFunc->getInstructionCount() == 0)
            {
              handlerFunc = getFunctionFromModules(handlerFunc->getName());
            }
            TerminatorHandlerCandidates[handler.first][handlerFunc] = true;
            if(TerminatorHandlerCandidates.count(handler.first) == 0)
            {
              TerminatorHandlerCandidates[handler.first] = unordered_map<Function*, bool>();
            }
            TerminatorHandlerCandidates[handler.first][handlerFunc] = true;
            if(funcInfoItemMap.count(handlerFunc) == 0)
            {
              funcInfoItemMap[handlerFunc] = vector<InfoItem*>();
            }
            if(find(funcInfoItemMap[handlerFunc].begin(), funcInfoItemMap[handlerFunc].end(), filesystemInfoItem) == funcInfoItemMap[handlerFunc].end())
            {
              funcInfoItemMap[handlerFunc].push_back(filesystemInfoItem);
            }
          }
        }
        break;
      }
      case NETWORK:
      auto networkInterfaceInfoItem = static_cast<NetworkInterfaceInfoItem*>(item);
        if (networkInterfaceInfoItem->name != "?") {
          if(networkInterfaceInfoItem->family == AF_NETLINK)
            specialHandleList.push_back(static_cast<NetlinkInfoItem*>(networkInterfaceInfoItem));
          for (auto handler : networkInterfaceInfoItem->SyscallHandler) {
            auto syscallName = handler.first;
            auto handlerName = handler.second->getName();
            if(syscallName == "sendmsg" && networkInterfaceInfoItem->family == AF_NETLINK)
              continue;
            auto handlerFunc = handler.second;
            if(handlerFunc->getInstructionCount() == 0)
            {
              handlerFunc = getFunctionFromModules(handlerFunc->getName());
            }
            TerminatorHandlerCandidates[handler.first][handlerFunc] = true;
            if(TerminatorHandlerCandidates.count(handler.first) == 0)
            {
              TerminatorHandlerCandidates[handler.first] = unordered_map<Function*, bool>();
            }
            TerminatorHandlerCandidates[handler.first][handlerFunc] = true;
            if(funcInfoItemMap.count(handlerFunc) == 0)
            {
              funcInfoItemMap[handlerFunc] = vector<InfoItem*>();
            }
            if(find(funcInfoItemMap[handlerFunc].begin(), funcInfoItemMap[handlerFunc].end(), networkInterfaceInfoItem) == funcInfoItemMap[handlerFunc].end())
            {
              funcInfoItemMap[handlerFunc].push_back(networkInterfaceInfoItem);
            }
          }
        }
        break;
    }
  }

  map<string, set<string>> allDeviceName;

  unsigned dfsStartBBNum = 0;
  
  raw_fd_ostream constraintsDebug(StringRef("./constraintsDebug"), OutErrorInfo, sys::fs::CD_CreateAlways);
  raw_fd_ostream signatureFile(StringRef("./kernel_signature_full"), OutErrorInfo, sys::fs::CD_CreateAlways);
  raw_fd_ostream signatureFileWithInfo(StringRef("./kernel_signature_with_info_full"), OutErrorInfo, sys::fs::CD_CreateAlways);
  outs() << "start output\n";
  outs() << "common syscall number: " << GlobalCtx.AllSignatures.size() << "\n";

  for (auto signature: GlobalCtx.AllSignatures) {
    string str = signature->getSyscallType();
    map<unsigned, ConstBlockMap> ArgumentsConstMap = signature->getArgConstBlockMap();
    Function* func = signature->getHandlerFunction();
    if(func->isDeclaration() || func->getInstructionCount() == 0)
    {
      func = getFunctionFromModules(func->getName());
    }
    outs() << "common syscalls: " << func->getName() << "\n";
    vector<string> res = vector<string>();
    outs() << "arg size: " << ArgumentsConstMap.size() << "\n";
    map<string, int> StringCompareSyscallArg = {
			{"setxattr", 1}, 
			{"lsetxattr", 1},
			{"fsetxattr", 1},
			{"add_key", 0}
		};
    for(auto item : ArgumentsConstMap)
    {
      outs() << "arg " << item.first << " " << item.second.size() << "\n";
    }
    if(str == "fcntl")
    {
      outputBBInfo(nullptr, signatureFileWithInfo);
      res.clear();
      help(func, 0, ArgumentsConstMap, str, res, ArgumentsConstMap.size() - 1);
      for(string s:res)
      {
        signatureFileWithInfo << s + "|C[]" << "\n";
        signatureFile << s + "|C[]";
        signatureFile << " " << "0";
        if (func->getName() != "")
          signatureFile << " " << func->getName();
        else
          signatureFile << " " << "none";
        signatureFile << "\n";
      }
    }
    else if(StringCompareSyscallArg.count(str))
    {
      outputBBInfo(nullptr, signatureFileWithInfo);
      res.clear();
      help(func, 0, ArgumentsConstMap, str, res, ArgumentsConstMap.size());
      for(string s:res)
      {
        signatureFileWithInfo << s << "\n";
        signatureFile << s;
        signatureFile << " " << "0";
        if (func->getName() != "")
          signatureFile << " " << func->getName();
        else
          signatureFile << " " << "none";
        signatureFile << "\n";
      }
    }
    else
    {
      vector<vector<int>> argMap = getArgMapByFunc(func);
      map<BasicBlock*, vector<map<unsigned, ConstBlockMap>>> blockResMap = getConstraintsWrapperNew(func, ArgumentsConstMap, constraintsDebug);
      if(blockResMap.size() == 0)
        continue;
      for(auto item : blockResMap)
      {
        vector<map<unsigned, ConstBlockMap>> argConstMapVec = transArgConstMapVec(item.second, argMap);
        if(argConstMapVec.size() == 0)
        {
          continue;
        }
        outputBBInfo(item.first, signatureFileWithInfo);
        res.clear();
        for(auto argConstMap : argConstMapVec)
        {
          help(func, 0, argConstMap, str, res, argConstMap.size());
        }
        for(string s : res)
        {
          signatureFileWithInfo << s << "\n";
          // signatureFile << s << "\n";
          signatureFile << s;
          signatureFile << " " << "1";
          signatureFile << " " << item.first->getParent()->getName() << " " << getBasicBlockIndex(item.first);
          if (func->getName() != "")
            signatureFile << " " << func->getName();
          else
            signatureFile << " " << "none";
          signatureFile << "\n";
        }
      }
    }
  }

  // output wrapper syscalls
  map<string, pair<string, int>> wrapperSyscallMap = {
    {"sendto", {"sendmsg", 0}}, 
    {"recvfrom", {"recvmsg", 0}}, 
    {"accept4", {"accept", 0}}, 
    {"getsockname", {"getname", 0}}, 
    {"getpeername", {"getname", 0}},
    {"recvmmsg", {"recvmsg", 0}},
    {"sendmmsg", {"sendmsg", 0}},
    {"sendmsg", {"sendmsg", 0}},
  };

  for (auto item: GlobalCtx.SubsystemInfo) {
    switch (item->ItemType) {
      case NETWORK:
        auto networkInterfaceInfoItem = static_cast<NetworkInterfaceInfoItem*>(item);
        if (networkInterfaceInfoItem->name != "?") {
          for (auto handler : networkInterfaceInfoItem->SyscallHandler) {
            auto syscallName = handler.first;
            auto handlerFunc = handler.second;
            for (auto wrapperItem : wrapperSyscallMap) {
              auto wrapperSyscall = wrapperItem.first;
              auto wrapperTarget = wrapperItem.second.first;
              auto resIdx = wrapperItem.second.second;
              outputBBInfo(nullptr, signatureFileWithInfo);
              if (syscallName == wrapperTarget && handlerFunc) {
                signatureFileWithInfo << wrapperSyscall;
                signatureFile << wrapperSyscall;
                for (int i = 0; i < resIdx; i++) {
                  signatureFileWithInfo << "|C[]";
                  signatureFile << "|C[]";
                }
                string socketStr = "|D[socket-[";
                socketStr += to_string(networkInterfaceInfoItem->family);
                socketStr += "]-[";
                socketStr += to_string(networkInterfaceInfoItem->type);
                socketStr += "]-[";
                socketStr += to_string(networkInterfaceInfoItem->protocol);
                socketStr += "]]";
                signatureFileWithInfo << socketStr << "\n";
                // signatureFile << socketStr << "\n";
                signatureFile << socketStr;
                signatureFile << " " << "0";
                if (handlerFunc->getName() != "")
                  signatureFile << " " << handlerFunc->getName();
                else
                  signatureFile << " " << "none";
                signatureFile << "\n";
              }
            }
          }
        }
      }
  }

  map<string, string> xattrSyscall2Desc = {
    {"getxattr", "C"},
    // {"lgetxattr", "C"}, 
    // {"fgetxattr", "D"},
    {"setxattr", "C"},
    // {"lsetxattr", "C"},
    // {"fsetxattr", "D"},
  };

  for (auto item: TerminatorHandlerCandidates) {
    GlobalCtx.FoundFunctionCache = map<Function*, map<unsigned, ConstBlockMap>>();
    auto syscall = item.first;
    auto syscallFunction = SyscallEntryFunctionPtr[syscall];

    if(allDeviceName.count(syscall) == 0)
      allDeviceName[syscall] = set<string>();
    outs() << "syscall name: " << item.first << "\n";

    GenerateFunctionCandidate(&GlobalCtx, syscall, syscallFunction, item.second, GlobalSyscallRecrusiveCount[syscall]);
    unordered_map<Function*, bool> handlerFuncs = item.second;
    for(auto i:handlerFuncs)
    {
      if(find(GlobalCtx.SyscallHandlerCandidates[syscall].begin(), GlobalCtx.SyscallHandlerCandidates[syscall].end(), i.first) == GlobalCtx.SyscallHandlerCandidates[syscall].end())
      {
        if(i.first->getName() == "netlink_sendmsg")
          continue;
        GlobalCtx.SyscallHandlerCandidates[syscall].insert(GlobalCtx.SyscallHandlerCandidates[syscall].begin(), i.first);
      }
    }
    for (auto func: GlobalCtx.SyscallHandlerCandidates[syscall]) {
      if (func == nullptr) {
        continue;
      }
      if (func && func->isDeclaration() && func->hasName()) {
        func = getFunctionFromModules(func->getName());
      }
      outs() << "Candidate of " << syscall << ": " << func->getName() << "\n";


      if (xattrSyscall2Desc.count(syscall) != 0) {
        string desc = xattrSyscall2Desc[syscall];
        if(func->isDeclaration() || func->getInstructionCount() == 0)
          func = getFunctionFromModules(func->getName());
        if(funcInfoItemMap.count(func) == 0)
          continue;
        string prefixStr = syscall + "|" + desc + "[]|" ;
        for(auto infoItem: funcInfoItemMap[func]) {
          string tmp = prefixStr + "S[" + infoItem->name + "] 0 " + func->getName().str() + "\n";
          signatureFile << tmp;
        }
        continue;
      }
      if(syscall == "ioctl" && func->getName() == "snd_seq_ioctl")
      {
        Function* sndSeqIoctl = func;
        if(sndSeqIoctl->isDeclaration() || sndSeqIoctl->getInstructionCount() == 0)
          sndSeqIoctl = getFunctionFromModules(func->getName());
        if(funcInfoItemMap.count(func) == 0)
          continue;
        for(auto infoItem:funcInfoItemMap[func])
        {
          handleSndSeqIoctl(sndSeqIoctl, infoItem, signatureFile);
        }
        continue;
      }
      else if(syscall == "ioctl" && func->getName() == "autofs_dev_ioctl")
      {
        Function* autofsDevIoctl = func;
        if(autofsDevIoctl->isDeclaration() || autofsDevIoctl->getInstructionCount() == 0)
          autofsDevIoctl = getFunctionFromModules(func->getName());
        if(funcInfoItemMap.count(func) == 0)
          continue;
        for(auto infoItem:funcInfoItemMap[func])
        {
          handleAutofsDevIoctl(autofsDevIoctl, infoItem, signatureFile);
        }
        continue;
      }
      else if (syscall == "write" && func->getName() == "ucma_write")
      {
        Function* ucmaWrite = func;
        if(ucmaWrite->isDeclaration() || ucmaWrite->getInstructionCount() == 0)
          ucmaWrite = getFunctionFromModules(func->getName());
        if(funcInfoItemMap.count(func) == 0)
          continue;
        for(auto infoItem:funcInfoItemMap[func]) {
          handleUcmaWrite(ucmaWrite, infoItem, signatureFile);
        }
        continue;
      }

      vector<vector<int>> argMap = getArgMapByFunc(func);
      map<unsigned, ConstBlockMap> ArgumentsConstMap = getTargetBlocksInFuncByArgMap(func, argMap, syscall);

      map<BasicBlock*, vector<map<unsigned, ConstBlockMap>>> blockResMap;
      if (syscall != "mount" && syscall != "read") {
        if (func->getName()=="tun_chr_ioctl"){
          for (auto a:ArgumentsConstMap){
            for(auto b:a.second){
              if(b->switchBlock)
                b->switchBlock->printAsOperand(outs());
              outs() << "\n";
            }
          }
        }
        blockResMap = getConstraintsWrapperNew(func, ArgumentsConstMap, constraintsDebug);

      }
      if(funcInfoItemMap.find(func) == funcInfoItemMap.end() || funcInfoItemMap[func].size() == 0)
      {
        string str = syscall + "|D[";
        if(allDeviceName.count(syscall) == 0 || allDeviceName[syscall].size() == 0)
          continue;
        for(set<string>::iterator it = allDeviceName[syscall].begin(); it != allDeviceName[syscall].end(); it++)
        {
          str += *it;
          str += " ";
        }
        str.replace(str.size() - 1, 1, "]");
        
        if(blockResMap.size() == 0)
        {
          continue;
        }
        for(auto item : blockResMap)
        {
          vector<map<unsigned, ConstBlockMap>> argConstMapVec = transArgConstMapVec(item.second, argMap);
          if(argConstMapVec.size() == 0)
          {
            continue;
          }
          outputBBInfo(item.first, signatureFileWithInfo);
          vector<string> r = vector<string>();
          for(auto argConstMap : argConstMapVec)
          {
            help(func, 1, argConstMap, str, r, argConstMap.size());
          }
          if(syscall == "mmap")
          {
            r = handleMmapSignature(r);
          }
          for(string s : r)
          {
            signatureFileWithInfo << s << "\n";
            // signatureFile << s << "\n";
            signatureFile << s;
            signatureFile << " " << "1";
            signatureFile << " " << item.first->getParent()->getName() << " " << getBasicBlockIndex(item.first);
            if (func->getName() != "")
              signatureFile << " " << func->getName();
            else
              signatureFile << " " << "none";
            signatureFile << "\n";
          }
        }
        GlobalCtx.AllSignatures.push_back(new Signature(func, syscall, "others", ArgumentsConstMap));
      }
      for(auto infoItem:funcInfoItemMap[func])
      {
        switch (infoItem->ItemType)
        {
          outs() << infoItem->ItemType << "\n";
          case DEVICE:{
            auto deviceInfoItem = static_cast<DeviceInfoItem*>(infoItem);
            vector<string> res;
            string str = item.first + "|D[";
            str += deviceInfoItem->name;
            str += "]";
            if(deviceInfoItem->name != "")
              allDeviceName[syscall].insert(deviceInfoItem->name);
            

            if(blockResMap.size() == 0)
            {
              if(syscall == "ioctl")
                continue;
              else if(syscall == "mmap")
              {
                str = handleMmapSignature(vector<string>({str}))[0]; 
              }
              outputBBInfo(nullptr, signatureFileWithInfo);
              signatureFileWithInfo << str << "\n";
              // signatureFile << str << "\n";
              str += " ";
              str += "0";
              str += " ";
              if (func->getName() != "")
                  str += func->getName().str();
              else
                  str += "none";
              signatureFile << str << "\n";
              continue;
            }
            for(auto item : blockResMap)
            {
              vector<map<unsigned, ConstBlockMap>> argConstMapVec = transArgConstMapVec(item.second, argMap);
              if(argConstMapVec.size() == 0)
              {
                continue;
              }
              vector<string> r = vector<string>();
              for(auto argConstMap : argConstMapVec)
              {
                help(func, 1, argConstMap, str, r, argConstMap.size());
              }
              if(syscall == "mmap")
              {
                r = handleMmapSignature(r);
              }
              outputBBInfo(item.first, signatureFileWithInfo);
              for(string s : r)
              {
                signatureFileWithInfo << s << "\n";
                // signatureFile << s << "\n";
                signatureFile << s;
                signatureFile << " " << "1";
                signatureFile << " " << item.first->getParent()->getName() << " " << getBasicBlockIndex(item.first);
                if (func->getName() != "")
                  signatureFile << " " << func->getName();
                else
                  signatureFile << " " << "none";
                signatureFile << "\n";
              }
            }
            
            GlobalCtx.AllSignatures.push_back(new Signature(func, syscall, deviceInfoItem->name, ArgumentsConstMap));
            break;
          }
          case FILESYSTEM:{
            auto filesystemInfoItem = static_cast<FilesystemInfoItem*>(infoItem);
            vector<string> res;
            string fsname=filesystemInfoItem->generateDeviceSignature(func);
            
            if (fsname=="bdev"){
              outs() << "BDEV!!!!!" << syscall << "\n";
              for(auto subsys: GlobalCtx.SubsystemInfo){
                if (subsys->ItemType!=DEVICE)
                  continue;
                DeviceInfoItem* dsubsys=static_cast<DeviceInfoItem*>(subsys);
                if (dsubsys->type==BLOCKDEVICE){
                  fsname+=" "+subsys->name;
                }
              }
            }
            string str = item.first + "|D[";
            // str += filesystemInfoItem->name;
            str += fsname;
            str += "]";

            if(filesystemInfoItem->name != "")
              allDeviceName[syscall].insert(filesystemInfoItem->name);
            
            if(blockResMap.size() == 0)
            {
              if(syscall == "ioctl")
                continue;
              else if(syscall == "mmap")
              {
                str = handleMmapSignature(vector<string>({str}))[0]; 
              }
              outputBBInfo(nullptr, signatureFileWithInfo);
              signatureFileWithInfo << str << "\n";

              str += " ";
              str += "0";
              str += " ";
              if (func->getName() != "")
                  str += func->getName().str();
              else
                  str += "none";
              signatureFile << str << "\n";
              continue;
            }
            for(auto item : blockResMap)
            {
              vector<map<unsigned, ConstBlockMap>> argConstMapVec = transArgConstMapVec(item.second, argMap);
              if(argConstMapVec.size() == 0)
              {
                continue;
              }
              vector<string> r = vector<string>();
              for(auto argConstMap : argConstMapVec)
              {
                help(func, 1, argConstMap, str, r, argConstMap.size());
              }
              if(syscall == "mmap")
              {
                r = handleMmapSignature(r);
              }
              outputBBInfo(item.first, signatureFileWithInfo);
              for(string s : r)
              {
                signatureFileWithInfo << s << "\n";
                signatureFile << s;
                signatureFile << " " << "1";
                signatureFile << " " << item.first->getParent()->getName() << " " << getBasicBlockIndex(item.first);
                if (func->getName() != "")
                  signatureFile << " " << func->getName();
                else
                  signatureFile << " " << "none";
                signatureFile << "\n";
              }
            }
            GlobalCtx.AllSignatures.push_back(new Signature(func, syscall, filesystemInfoItem->name, ArgumentsConstMap));
            break;
          }
          case NETWORK:{
            auto networkInterfaceInfoItem = static_cast<NetworkInterfaceInfoItem*>(infoItem);
            vector<string> res;
            
            string socketStr = "socket-[";
            socketStr += to_string(networkInterfaceInfoItem->family);
            socketStr += "]-[";
            socketStr += to_string(networkInterfaceInfoItem->type);
            socketStr += "]-[";
            socketStr += to_string(networkInterfaceInfoItem->protocol);
            socketStr += "]";
            if(socketStr != "")
              allDeviceName[syscall].insert(socketStr);
            string str = item.first + "|D[";
            str += socketStr;
            str += "]";
            
            if(syscallFunction && ArgumentsConstMap.size() != syscallFunction->arg_size())
            {
              if (syscall == "getname") {
                continue;
              }
            }
            if(blockResMap.size() == 0)
            {
              if(syscall == "ioctl")
                continue;
              else if(syscall == "mmap")
              {
                str = handleMmapSignature(vector<string>({str}))[0]; 
              }
              outputBBInfo(nullptr, signatureFileWithInfo);
              signatureFileWithInfo << str << "\n";
              
              str += " ";
              str += "0";
              str += " ";
              if (func->getName() != "")
                  str += func->getName().str();
              else
                  str += "none";
              signatureFile << str << "\n";
              continue;
            }
            for(auto item : blockResMap)
            {
              vector<map<unsigned, ConstBlockMap>> argConstMapVec = transArgConstMapVec(item.second, argMap);
              if(argConstMapVec.size() == 0)
              {
                continue;
              }
              vector<string> r = vector<string>();
              for(auto argConstMap : argConstMapVec)
              {
                help(func, 1, argConstMap, str, r, argConstMap.size());
              }
              if(syscall == "mmap")
              {
                r = handleMmapSignature(r);
              }
              outputBBInfo(item.first, signatureFileWithInfo);
              for(string s : r)
              {
                signatureFileWithInfo << s << "\n";

                signatureFile << s;
                signatureFile << " " << "1";
                signatureFile << " " << item.first->getParent()->getName() << " " << getBasicBlockIndex(item.first);
                if (func->getName() != "")
                  signatureFile << " " << func->getName();
                else
                  signatureFile << " " << "none";
                signatureFile << "\n";
              }
            }
            GlobalCtx.AllSignatures.push_back(new Signature(func, syscall, networkInterfaceInfoItem->name, ArgumentsConstMap));
            break;
          }
        }
      }
    }
  }

  for(auto netlinkInfoItem:specialHandleList)
  {
    vector<string> res = netlinkInfoItem->generateSendmsgSignature();
    outputBBInfo(nullptr, signatureFileWithInfo);
    for(auto s:res)
    {
      signatureFileWithInfo << s << "\n";
      signatureFile << s << "\n";
    }
  }

  outs() << "total found dfs start bb: " << dfsStartBBNum << "\n";
  handleDrmIoctl(ModuleMap, signatureFile);
  handleSpecial(GlobalCtx.Modules, signatureFile);
  endTime = clock();
  outs() << "total time: " << (endTime - startTime) / CLOCKS_PER_SEC << "s\n";
	return 0;
}