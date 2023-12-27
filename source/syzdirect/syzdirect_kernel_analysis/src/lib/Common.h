#ifndef COMMON_H
#define COMMON_H

#include <llvm/IR/Module.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/DebugInfo.h>
//#include <llvm/IR/CallSite.h>

#include <unistd.h>
#include <stdlib.h>
#include <bitset>
#include <chrono>
#include <set>
#include <llvm/IR/Instructions.h>

using namespace llvm;
using namespace std;

typedef vector<llvm::BasicBlock*> BBPath;

extern cl::opt<string> SourceLocation;


#define LOG(lv, stmt)							\
	do {											\
		if (VerboseLevel >= lv)						\
		errs() << stmt;							\
	} while(0)


#define OP llvm::errs()

#define WARN(stmt) LOG(1, "\n[WARN] " << stmt);

#define INFO(stmt) LOG(2, "\n[INFO] " << stmt);

#define DEBUG(stmt) LOG(3, "\n[DEBUG] " << stmt);

#define ERR(stmt)													\
	do {																\
		errs() << "ERROR (" << __FUNCTION__ << "@" << __LINE__ << ")";	\
		errs() << ": " << stmt;											\
		exit(-1);														\
	} while(0)

/// Different colors for output
#define KNRM  "\x1B[0m"   /* Normal */
#define KRED  "\x1B[31m"  /* Red */
#define KGRN  "\x1B[32m"  /* Green */
#define KYEL  "\x1B[33m"  /* Yellow */
#define KBLU  "\x1B[34m"  /* Blue */
#define KMAG  "\x1B[35m"  /* Magenta */
#define KCYN  "\x1B[36m"  /* Cyan */
#define KWHT  "\x1B[37m"  /* White */

extern cl::opt<unsigned> VerboseLevel;

extern map<Type*, string> TypeToTNameMap;
extern const DataLayout *CurrentLayout;

//
// Common functions
//
string getValueAsOperand(Value* v);
void rm_nonprinting(string &str);
int startsWith(string s, string prefix);
std::ifstream& gotoLine(std::ifstream& file, unsigned int num);
void strip(string &str);
void splitString(const std::string& s, std::vector<std::string>& v, const std::string& c);


string HandleSimpleTy(Type *Ty);
string expand_struct(StructType *STy);

string getFileName(DILocation *Loc, 
		DISubprogram *SP=NULL,
        DILocalVariable *DV=NULL);
string getRawFileName(DILocation *Loc,
                   DISubprogram *SP=NULL,
                   DILocalVariable *DV=NULL);
bool isConstant(Value *V);

string getSourceLine(string fn_str, unsigned lineno);

string getSourceFuncName(Instruction *I);

StringRef getCalledFuncName(Instruction *I);

string extractMacro(string, Instruction* I);

DILocation *getSourceLocation(Instruction *I);

unsigned getSourceCodeLineNum(Value* V);

void printSourceCodeInfo(Value *V);
void printSourceCodeInfo(Function *F);
string getMacroInfo(Value *V);

void getSourceCodeInfo(Value *V, string &file,
                               unsigned &line);

Argument *getArgByNo(Function *F, int8_t ArgNo);
double distance(double x1,double y1, double z1,double x2,double y2, double z2);
size_t funcScore(Function* F);
size_t funcTypeHash(Function* F);
size_t funcHash(Function *F, bool withName = true);
size_t callHash(CallInst *CI);
size_t typeHash(Type *Ty);
size_t cmpHash(CmpInst* cmp,bool hashop);
size_t typeIdxHash(Type *Ty, int Idx = -1);
size_t hashIdxHash(size_t Hs, int Idx = -1);
size_t fieldHash(StringRef* struct_name,string *field);
size_t fieldHash(string* struct_name,string *field);
void getSourceCodeLine(Value *V, string &line, unsigned lineNum=0);
void getRawSourceCodeLine(Value *V, string &line, unsigned lineNum=0);
//void getRetainedNodeSourceLine(Value* V, string &line);
void getRetainedNodeSourceLine(DILocalVariable* DV, string &line);
bool compareWithWrapper(Function *wrapper, Value *val,bool flag = false);
void findReturnInFunc(Function* F,set<ReturnInst*> &rets);

//string transFuncName(string funcname, Module &M, string location, raw_fd_ostream &TransFile);
string transFuncName(string funcname, string location, raw_fd_ostream &TransFile);
string findModuleName(Module &M);
string cmdExecute(char* cmd);
bool isValueErrno(Value *V, Function *F);

//
// Common data structures
//
class ModuleOracle {
public:
  ModuleOracle(Module &m) :
    dl(m.getDataLayout()),
    tli(TargetLibraryInfoImpl(Triple(Twine(m.getTargetTriple()))))
  {}

  ~ModuleOracle() {}

  // Getter
  const DataLayout &getDataLayout() {
    return dl;
  }

  TargetLibraryInfo &getTargetLibraryInfo() {
    return tli;
  }

  // Data layout
  uint64_t getBits() {
    return Bits;
  }

  uint64_t getPointerWidth() {
    return dl.getPointerSizeInBits();
  }

  uint64_t getPointerSize() {
    return dl.getPointerSize();
  }

  uint64_t getTypeSize(Type *ty) {
    return dl.getTypeAllocSize(ty);
  }

  uint64_t getTypeWidth(Type *ty) {
    return dl.getTypeSizeInBits(ty);
  }

  uint64_t getTypeOffset(Type *type, unsigned idx) {
    assert(isa<StructType>(type));
    return dl.getStructLayout(cast<StructType>(type))
            ->getElementOffset(idx);
  }

  bool isReintPointerType(Type *ty) {
    return (ty->isPointerTy() ||
      (ty->isIntegerTy() &&
       ty->getIntegerBitWidth() == getPointerWidth()));
  }

protected:
  // Info provide
  const DataLayout &dl;
  TargetLibraryInfo tli;

  // Consts
  const uint64_t Bits = 8;
};

class Helper {
public:
  // LLVM value
  static string getValueName(Value *v) {
    if (!v->hasName()) {
      return to_string(reinterpret_cast<uintptr_t>(v));
    } else {
      return v->getName().str();
    }
  }

  static string getValueType(Value *v) {
    if (Instruction *inst = dyn_cast<Instruction>(v)) {
      return string(inst->getOpcodeName());
    } else {
      return string("value " + to_string(v->getValueID()));
    }
  }

  static string getValueRepr(Value *v) {
    string str;
    raw_string_ostream stm(str);

    v->print(stm);
    stm.flush();

    return str;
  }

  // String conversion
  static void convertDotInName(string &name) {
    replace(name.begin(), name.end(), '.', '_');
  }
};

class Dumper {
public:
  Dumper() {}
  ~Dumper() {}

  // LLVM value
  void valueName(Value *val) {
    errs() << Helper::getValueName(val) << "\n";
  }

  void typedValue(Value *val) {
    errs() << "[" << Helper::getValueType(val) << "]"
           << Helper::getValueRepr(val)
           << "\n";
  }
};

extern Dumper DUMP;

class SecurityCheck {
public:
  SecurityCheck(Value *sk, Value *br) : SCheck(sk), SCBranch(br) {
    auto I = dyn_cast<Instruction>(SCheck);
    if (!I)
      return;

    MDNode *N = I->getMetadata("dbg");
    if (!N)
      return;

    DILocation *Loc = dyn_cast<DILocation>(N);
    if (!Loc || Loc->getLine() < 1)
      return;

    SCheckFileName = Loc->getFilename().str();
    SCheckLineNo = Loc->getLine();
  }

  ~SecurityCheck() {
  }

  Value *getSCheck() { return SCheck; }

  Value *getSCBranch() { return SCBranch; }

  string getSCheckFileName() { return SCheckFileName; }

  unsigned getSCheckLineNo() { return SCheckLineNo; }

	friend bool operator< (const SecurityCheck &SC1, const SecurityCheck &SC2) {
		return (SC1.SCheck < SC2.SCheck);
	}

private:
  Value *SCheck;          /* Security check of this critical variable */
  Value *SCBranch;        /* Branch associated to the check */
  string SCheckFileName; /* Source file name of security check */
  unsigned SCheckLineNo;  /* Line number of security check */
};

class CallSite {
private:
    CallBase *CB;
public:
    CallSite(Instruction *I) : CB(dyn_cast<CallBase>(I)) {}
    CallSite(Value *I) : CB(dyn_cast<CallBase>(I)) {}

    CallBase *getInstruction() const { return CB; }
    using arg_iterator = User::const_op_iterator;
    Value *getArgument(unsigned ArgNo) const { return CB->getArgOperand(ArgNo);}
    Type *getType() const { return CB->getType(); }
    User::const_op_iterator arg_begin() const { return CB->arg_begin();}
    User::const_op_iterator arg_end() const { return CB->arg_end();}
    unsigned arg_size() const { return CB->arg_size(); }
    bool arg_empty() const { return CB->arg_empty(); }
    Value *getArgOperand(unsigned i) const { return CB->getArgOperand(i); }
    unsigned getNumArgOperands() const { return CB->getNumArgOperands(); }
    Function *getCalledFunction() const { return CB->getCalledFunction(); }
    Value *getCalledValue() const { return CB->getCalledOperand(); }
    Function *getCaller() const { return CB->getCaller(); }
    FunctionType *getFunctionType() const { return CB->getFunctionType(); }
    bool paramHasAttr(unsigned ArgNo, llvm::Attribute::AttrKind Kind) const { return CB->paramHasAttr(ArgNo, Kind); }
    bool isIndirectCall() const { return CB->isIndirectCall(); }
    Intrinsic::ID getIntrinsicID() const { return CB->getIntrinsicID(); }

    bool operator==(const CallSite &CS) const { return CB == CS.CB; }
    bool operator!=(const CallSite &CS) const { return CB != CS.CB; }
    bool operator<(const CallSite &CS) const {
        return getInstruction() < CS.getInstruction();
    }

};

#endif
