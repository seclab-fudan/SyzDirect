#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <fstream>
#include <regex>
#include <llvm/IR/Operator.h>
#include <queue>
#include "Common.h"


//#define LINUX_SOURCE "/home/robin/linux-stable"
//#define LINUX_SOURCE "/home/parallels/linux-stable"
//#define LINUX_SOURCE "/home/sherlly/linux"
//#define LINUX_SOURCE "/mnt/f/Linux Kernel/linux-5.6-rc2"
//#define LINUX_SOURCE "/mnt/f/Linux Kernel/linux-5.9-rc1"

#define ERRNO_PREFIX 0x4cedb000
#define ERRNO_MASK   0xfffff000
#define is_errno(x) (((x) & ERRNO_MASK) == ERRNO_PREFIX)
// 1: only consider pre-defined default error codes such as EFAULT;
// 2: default error codes + <-4095, -1> + NULL pointer
#define ERRNO_TYPE 	2

map<StringRef, string> moduleHeaderMap; // <module loc, module header name>


void rm_nonprinting (std::string& str)
{
    str.erase (std::remove_if (str.begin(), str.end(),
                                [](unsigned char c){
                                    return !std::isprint(c);
                                }),
                                str.end());
}

int startsWith(string s, string prefix) {
  return s.find(prefix) == 0?1:0;
}

std::ifstream& gotoLine(std::ifstream& file, unsigned int num){
    file.seekg(std::ios::beg);
    for(int i=0; i < num - 1; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}
string getValueAsOperand(Value* v){
    string result="";
    if(!v)
        return result;
// #ifdef DEBUG_CUSTOM
    llvm::raw_string_ostream output(result);
    v->printAsOperand(output);
// #endif
    return result;
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
    auto z = string("\x00");
    auto v = string(1 ,str.front()); 
    while((v == w) || (v==t) || (v==r) || (v==n) || (v==z)) {
        str.erase(str.begin());
        v = string(1 ,str.front());
    }
    v = string(1 , str.back()); 
    while((v ==w) || (v==t) || (v==r) || (v==n) || (v==z)) {
        str.erase(str.end() - 1 );
        v = string(1 , str.back());
    }
  }
}

bool trimPathSlash(string &path, int slash) {
	while (slash > 0) {
		path = path.substr(path.find('/') + 1);
		--slash;
	}

	return true;
}

string getFileName(DILocation *Loc, DISubprogram *SP, DILocalVariable *DV) {
	string FN;
	if (Loc)
		FN = Loc->getFilename().str();
	else if (SP)
		FN = SP->getFilename().str();
	else if (DV)
	    FN = DV->getFilename().str();
	else
		return "";

	// TODO: require config
	int slashToTrim = 2;
	trimPathSlash(FN, slashToTrim);
	FN = string(SourceLocation) + "/" + FN;
	return FN;
}
string getRawFileName(DILocation *Loc, DISubprogram *SP, DILocalVariable *DV) {
    string FN;
    if (Loc)
        FN = Loc->getFilename().str();
    else if (SP)
        FN = SP->getFilename().str();
    else if (DV)
        FN = DV->getFilename().str();
    else
        return "";

    // TODO: require config
    int slashToTrim = 2;
    trimPathSlash(FN, slashToTrim);
//    FN = string(LINUX_SOURCE) + "/" + FN;
    return FN;
}
/// Check if the value is a constant.
bool isConstant(Value *V) {
  // Invalid input.
  if (!V) 
    return false;

  // The value is a constant.
  Constant *Ct = dyn_cast<Constant>(V);
  if (Ct) 
    return true;

  return false;
}

/// Get the source code line
string getSourceLine(string fn_str, unsigned lineno) {
	std::ifstream sourcefile(fn_str);
	string line;
	sourcefile.seekg(ios::beg);
	
	for(int n = 0; n < lineno - 1; ++n){
		sourcefile.ignore(std::numeric_limits<streamsize>::max(), '\n');
	}
	getline(sourcefile, line);

	return line;
}

string getSourceFuncName(Instruction *I) {

	DILocation *Loc = getSourceLocation(I);
	if (!Loc)
		return "";
	unsigned lineno = Loc->getLine();
	std::string fn_str = getFileName(Loc);
	string line = getSourceLine(fn_str, lineno);
	
	while(line[0] == ' ' || line[0] == '\t')
		line.erase(line.begin());
	line = line.substr(0, line.find('('));
	return line;
}

string extractMacro(string line, Instruction *I) {
	string macro, word, FnName;
	std::regex caps("[^\\(][_A-Z][_A-Z0-9]+[\\);,]+");
	smatch match;
	
	// detect function macros
	if (CallInst *CI = dyn_cast<CallInst>(I)) {
		FnName = static_cast<string>(getCalledFuncName(CI));
		caps = "[_A-Z][_A-Z0-9]{2,}";
		std::regex keywords("(\\s*)(for|if|while)(\\s*)(\\()");

		if (regex_search(line, match, keywords))
		  line = line.substr(match[0].length());
		
		if (line.find(FnName) != std::string::npos) {
			if (regex_search(FnName, match, caps))
				return FnName;

		} else {
			//identify non matching functions as macros
			//std::count(line.begin(), line.end(), '"') > 0
			std::size_t eq_pos = line.find_last_of("=");
			if (eq_pos == std::string::npos)
				eq_pos = 0;
			else
				++eq_pos;

			std::size_t paren = line.find('(', eq_pos);
			return line.substr(eq_pos, paren-eq_pos);
		}

	} else {
		// detect macro constant variables
		std::size_t lhs = -1;
		stringstream iss(line.substr(lhs+1));

		while (iss >> word) {
			if (regex_search(word, match, caps)) {
				macro = word;
				return macro;
			}
		}
	}

	return "";
}

/// Get called function name of V.
StringRef getCalledFuncName(Instruction *I) {

  Value *V;
	if (CallInst *CI = dyn_cast<CallInst>(I))
//        V = CI->getCalledValue();
        V = CI->getCalledOperand();
	else if (InvokeInst *II = dyn_cast<InvokeInst>(I))
//		V = II->getCalledValue();
        V = II->getCalledOperand();
	assert(V);

  InlineAsm *IA = dyn_cast<InlineAsm>(V);
  if (IA)
    return StringRef(IA->getAsmString());

  User *UV = dyn_cast<User>(V);
  if (UV) {
    if (UV->getNumOperands() > 0) {
			Value *VUV = UV->getOperand(0);
			return VUV->getName();
		}
  }
  auto name = V->getName();
  name = name.substr(0, name.rfind("."));
  return name;
}

DILocation *getSourceLocation(Instruction *I) {
  if (!I)
    return NULL;

  MDNode *N = I->getMetadata("dbg");
  if (!N)
    return NULL;

  DILocation *Loc = dyn_cast<DILocation>(N);
  if (!Loc || Loc->getLine() < 1)
		return NULL;

	return Loc;
}

/// Print out source code information to facilitate manual analyses.
void printSourceCodeInfo(Value *V) {
	Instruction *I = dyn_cast<Instruction>(V);
	if (!I)
		return;

	DILocation *Loc = getSourceLocation(I);
	if (!Loc)
		return;

	unsigned LineNo = Loc->getLine();
	std::string FN = getFileName(Loc);
	string line = getSourceLine(FN, LineNo);
	FN = Loc->getFilename().str();
	FN = FN.substr(FN.find('/') + 1);
	FN = FN.substr(FN.find('/') + 1);

	while(line[0] == ' ' || line[0] == '\t')
		line.erase(line.begin());
	OP << " ["
		<< "\033[34m" << "Code" << "\033[0m" << "] "
		<< FN
		<< " +" << LineNo << ": "
		<< "\033[35m" << line << "\033[0m" <<'\n';
}

void printSourceCodeInfo(Function *F) {

	DISubprogram *SP = F->getSubprogram();

	if (SP) {
		string FN = getFileName(NULL, SP);
		string line = getSourceLine(FN, SP->getLine());
		while(line[0] == ' ' || line[0] == '\t')
			line.erase(line.begin());

		FN = SP->getFilename().str();
		FN = FN.substr(FN.find('/') + 1);
		FN = FN.substr(FN.find('/') + 1);

		OP << " ["
			<< "\033[34m" << "Code" << "\033[0m" << "] "
			<< FN
			<< " +" << SP->getLine() << ": "
			<< "\033[35m" << line << "\033[0m" <<'\n';
	}
}

string getMacroInfo(Value *V) {

	Instruction *I = dyn_cast<Instruction>(V);
	if (!I) return "";

	DILocation *Loc = getSourceLocation(I);
	if (!Loc) return "";

	unsigned LineNo = Loc->getLine();
	std::string FN = getFileName(Loc);
	string line = getSourceLine(FN, LineNo);
	FN = Loc->getFilename().str();
	const char *filename = FN.c_str();
	filename = strchr(filename, '/') + 1;
	filename = strchr(filename, '/') + 1;
	int idx = filename - FN.c_str();

	while(line[0] == ' ' || line[0] == '\t')
		line.erase(line.begin());

	string macro = extractMacro(line, I);

	//clean up the ending and whitespaces
	macro.erase(std::remove (macro.begin(), macro.end(),' '), macro.end());
	unsigned length = 0;
	for (auto it = macro.begin(), e = macro.end(); it != e; ++it)
		if (*it == ')' || *it == ';' || *it == ',') {
			macro = macro.substr(0, length);
			break;
		} else {
			++length;
		}

	return macro;
}

/// Get source code information of this value
void getSourceCodeInfo(Value *V, string &file,
                               unsigned &line) {
  file = "";
  line = 0;

  auto I = dyn_cast<Instruction>(V);
  if (!I)
    return;

  MDNode *N = I->getMetadata("dbg");
  if (!N)
    return;

  DILocation *Loc = dyn_cast<DILocation>(N);
  if (!Loc || Loc->getLine() < 1)
    return;

  file = Loc->getFilename().str();
  line = Loc->getLine();
}

Argument *getArgByNo(Function *F, int8_t ArgNo) {

  if (ArgNo >= F->arg_size())
    return NULL;

  int8_t idx = 0;
  Function::arg_iterator ai = F->arg_begin();
  while (idx != ArgNo) {
    ++ai;
    ++idx;
  }
  return ai;
}
double distance(double x1,double y1, double z1,double x2,double y2, double z2){
    return sqrt((x1-x2)*(x1-x2)+(y1-y2)*(y1-y2)+(z1-z2)*(z1-z2));
}


size_t funcScore(Function * F){
    size_t score = F->arg_size() +  (!F->getReturnType()->isVoidTy());
    return score;
}

size_t funcTypeHash(Function* F){
    hash<string> str_hash;
    string output;
    string sig;
    raw_string_ostream rso(sig);
    Type *FTy = F->getFunctionType();
    FTy->print(rso);
    output = rso.str();
    string::iterator end_pos = remove(output.begin(),
                                      output.end(), ' ');
    output.erase(end_pos, output.end());

    return str_hash(output);
}

// #define HASH_SOURCE_INFO
size_t funcHash(Function *F, bool withName) {

    hash<unsigned int> uint_hash;
	hash<string> str_hash;
	string output;

#ifdef HASH_SOURCE_INFO
	DISubprogram *SP = F->getSubprogram();

	if (SP) {
		output = static_cast<string>(SP->getFilename());
		output = output + to_string(uint_hash(SP->getLine()));
	}
	else {
#endif
		string sig;
		raw_string_ostream rso(sig);
		Type *FTy = F->getFunctionType();

		FTy->print(rso);
		output = rso.str();

		if (withName)
			output += F->getName();
#ifdef HASH_SOURCE_INFO
	}
#endif
	string::iterator end_pos = remove(output.begin(), 
			output.end(), ' ');
	output.erase(end_pos, output.end());

	return str_hash(output);
}
size_t fieldHash(StringRef* struct_name,string *field){
    hash<string> str_hash;
    string sig = struct_name->str()+*field;
    return str_hash(sig);
}
size_t fieldHash(string* struct_name,string *field){
    hash<string> str_hash;
    string sig = *struct_name +*field;
    return str_hash(sig);
}
size_t callHash(CallInst *CI) {

	CallSite CS(CI);
	Function *CF = CI->getCalledFunction();

	if (CF)
		return funcHash(CF);
	else {
		hash<string> str_hash;
		string sig;
		raw_string_ostream rso(sig);
		Type *FTy = CS.getFunctionType();
		FTy->print(rso);

		string strip_str = rso.str();
		string::iterator end_pos = remove(strip_str.begin(), 
				strip_str.end(), ' ');
		strip_str.erase(end_pos, strip_str.end());
		return str_hash(strip_str);
	}
}



size_t typeHash(Type *Ty) {
	hash<string> str_hash;
	string sig;

	raw_string_ostream rso(sig);
	//Ty->print(rso);
	//string ty_str = rso.str();
	string ty_str = "";
	StructType *STy = dyn_cast<StructType>(Ty);
	if (STy == NULL)
		ty_str = ty_str+HandleSimpleTy(Ty);
	else {
		//Struct type
		if (STy->hasName()) {
			string STyname = static_cast<string>(STy->getName());
			ty_str = ty_str + STyname + expand_struct(STy);
		} else if (TypeToTNameMap.find(Ty) != TypeToTNameMap.end()){
			ty_str = ty_str + TypeToTNameMap[Ty]+expand_struct(STy);
		} else{
			ty_str = ty_str +  expand_struct(STy);
		}
	}
	string::iterator end_pos = remove(ty_str.begin(), ty_str.end(), ' ');
	ty_str.erase(end_pos, ty_str.end());

	return str_hash(ty_str);
}

string HandleSimpleTy(Type *Ty){
	unsigned size = Ty->getScalarSizeInBits();
	string ret = std::to_string(size);
	return ret;
}

string expand_struct(StructType *STy) {
	string ty_str = "";
	unsigned NumEle = STy->getNumElements();
    ty_str = ty_str+to_string(NumEle)+",";
    if (!STy->isOpaque()){
        uint64_t TySize = CurrentLayout->getStructLayout(STy)->getSizeInBits();
        ty_str=ty_str+to_string(TySize);
    }
	return ty_str;
}


size_t hashIdxHash(size_t Hs, int Idx) {
	hash<string> str_hash;
	return Hs + str_hash(to_string(Idx));
}

size_t typeIdxHash(Type *Ty, int Idx) {
	return hashIdxHash(typeHash(Ty), Idx);
}

unsigned getSourceCodeLineNum(Value* V){
    Instruction *I = dyn_cast<Instruction>(V);
    if (!I)
        return 0;
    DILocation *Loc = getSourceLocation(I);
    if (!Loc) {
        return 0;
    }
    return Loc->getLine();
}

void getSourceCodeLine(Value *V, string &line, unsigned LineNo) {

	line = "";
	Instruction *I = dyn_cast<Instruction>(V);
	if (!I)
		return;
//    I->print(OP);
//    OP<<"\n";
    DILocation *Loc = getSourceLocation(I);
    if (!Loc) {
        return;
    }
    if (!LineNo)
	    LineNo = Loc->getLine();
	std::string FN = getFileName(Loc);
	line = getSourceLine(FN, LineNo);
	FN = Loc->getFilename().str();
	FN = FN.substr(FN.find('/') + 1);
	FN = FN.substr(FN.find('/') + 1);

	while(line[0] == ' ' || line[0] == '\t')
		line.erase(line.begin());
}

void getRawSourceCodeLine(Value *V, string &line, unsigned LineNo) {

    line = "";
    Instruction *I = dyn_cast<Instruction>(V);
    if (!I)
        return;
//    I->print(OP);
//    OP<<"\n";
    DILocation *Loc = getSourceLocation(I);
    if (!Loc) {
        return;
    }
    if (!LineNo)
        LineNo = Loc->getLine();
    std::string FN = getFileName(Loc);
    line = getSourceLine(FN, LineNo);
    FN = Loc->getFilename().str();
    FN = FN.substr(FN.find('/') + 1);
    FN = FN.substr(FN.find('/') + 1);
}

bool compareWithWrapper(Function *wrapper, Value *val,bool flag) {
    if (wrapper->getName().equals("IS_ERR")) {
        if(flag){
            return true;
        }
        CallInst *ca = dyn_cast<CallInst>(val);
        if (ca) {
            if (ca->getCalledFunction()) {
                if (ca->getCalledFunction()->getName().equals("ERR_PTR")) {
                    return true;
                }
                if (ca->getCalledFunction()->getName().equals("ERR_CAST")) {
                    return true;
                }
            }
        }

        //there is some special situation
        //the return value may be a constant expr like inttoptr (i64 -12 to %struct.fscache_cache_tag*), %17
        ConstantExpr* conste = dyn_cast<ConstantExpr>(val);
        if(conste){
            IntToPtrInst* inst = dyn_cast<IntToPtrInst>(conste->getAsInstruction());
            if(inst){

                return true;
            }
        }
        return false;
    }else if(wrapper->getName().equals("IS_ERR_OR_NULL")){
        if(flag){
            return true;
        }
        CallInst *ca = dyn_cast<CallInst>(val);
        if (ca) {
            if (ca->getCalledFunction()) {
                if (ca->getCalledFunction()->getName().equals("ERR_PTR")) {
                    return true;
                }
                if (ca->getCalledFunction()->getName().equals("ERR_CAST")) {
                    return true;
                }
            }
        }
        ConstantData* consd = dyn_cast<ConstantData>(val);
        if(consd){
            if (consd->getValueID() == Value::ConstantPointerNullVal) {
                return true;
            }
        }
        return false;
    } else {
        WARN("Wrapper Function " << wrapper->getName() << "not suppported in Compare with wrapper\n");
        return false;
    }
}

void findReturnInFunc(Function* F,set<ReturnInst*> &rets){
    for (Function::iterator b = F->begin(), be = F->end(); b != be; ++b) {
        Instruction* inst = b->getTerminator();
        ReturnInst* ret = dyn_cast<ReturnInst>(inst);
        if(ret){
            rets.insert(ret);
        }
    }
}
//void getRetainedNodeSourceLine(Value* V, stirng &line){
void getRetainedNodeSourceLine(DILocalVariable* DV, string &line){
    unsigned LineNo;
    std::string FN;
    LineNo = DV->getLine();
    FN = getFileName(NULL,NULL,DV);
    line = getSourceLine(FN, LineNo);

    while(line[0] == ' ' || line[0] == '\t')
        line.erase(line.begin());

//    Instruction *I = dyn_cast<Instruction>(V);
//    DINodeArray DA = I->getDebugLoc()->getScope()->getSubprogram()->getRetainedNodes();
//    DILocalVariable* DV;
//    unsigned LineNo;
//    std::string FN;
//    for(int i=0;i!=DA.size();i++) {
//        DA->getOperand(i)->print(OP);
//        OP << "\n";
//        DV = dyn_cast<DILocalVariable>(DA->getOperand(i));
//        if (DV) {
//            LineNo = DV->getLine();
//            FN = getFileName(NULL,NULL,DV);
//            line = getSourceLine(FN, LineNo);
//
//            while(line[0] == ' ' || line[0] == '\t')
//                line.erase(line.begin());
//
//            return;
//            OP << DV->getName() << "\n";
//        }
//    }
}




string findModuleName(Module &M) {
    set<string> nameSet;

    for (auto &F: M) {
        string name = static_cast<string>(F.getName());
        nameSet.insert(name);
    }
//    nameSet.insert("amdgpu_enable_vblank_kms");
//    nameSet.insert("amdgpu_disable_vblank_kms");

    // find the common name between function names
    string commonName;
    map<string, size_t> namecntMap;

    for (auto n1: nameSet) {
//        OP << n1 << "\n";
        int len1 = n1.size();
        commonName = "";
        for (auto n2: nameSet) {
            if (n2 == n1)
                continue;
            int len2 = n2.size();
            if (commonName.size() >1 &&
                (n2.find(commonName) == 0 ||
                 (n2.find("__" == 0 && n2.find(commonName) == 2)))) {
                // found commonName from beginning of n2
                if (!namecntMap.count(commonName))
                    namecntMap[commonName] = 1;
                else
                    namecntMap[commonName]+=1;
                continue;
            } else
                commonName = "";
            int start = 0;
            if (n1.find("__") == 0)
                start = 2;
            for (int i = start; i < len1; i++) {
                if (i >= len2)
                    break;
                if (n1[i] == n2[i]) {
                    commonName += n1[i];
                    continue;
                } else
                    break;
            }
//            if (!commonName.empty())
//                OP << commonName << "\n";
        }
//        if (!commonName.empty()) {
//            OP << commonName << ": " << nameMap[commonName] << "\n";
//        }
    }

    // use the top one commonName as the module header name
    auto x = max_element(namecntMap.begin(), namecntMap.end(),
                         [](const pair<string, size_t>& p1, const pair<string, size_t>& p2) {
                             return p1.second < p2.second; });

    return x->first;
}

string findModuleName(string location) {
    set<string> nameSet;

    ifstream srcfile(string(SourceLocation) + "/" + location);
    string line;
    int i =0;
    vector<string> srcVec;

    if (srcfile.is_open()) {
        while (!srcfile.eof()) {
            getline (srcfile, line);

            if (line == "{") {
                i = 0;
                while (i++<3) {
                    if (srcVec.size() == 0)
                        break;
                    line = srcVec.back();
                    srcVec.pop_back();
                    size_t pos = line.find("(");
                    if (pos == string::npos)
                        continue;
                    line = line.substr(0, pos);

                    pos = line.find_last_of(" ");
                    if (pos != string::npos)
                        line = line.substr(pos+1, line.length()-pos);

                    remove(line.begin(), line.end(),'*');

                    nameSet.insert(line);

                    srcVec.clear();
                    break;
                }
            } else
                srcVec.push_back(line);

        }
        srcfile.close();
    }

    // find the common name between function names
    string commonName;
    map<string, size_t> namecntMap;

    for (auto n1: nameSet) {
//        OP << n1 << "\n";
        int len1 = n1.size();
        if (nameSet.size() == 2 && !commonName.empty())
            namecntMap[commonName] = 2;
        commonName = "";

        for (auto n2: nameSet) {
            if (n2 == n1)
                continue;
            int len2 = n2.size();
            if (commonName.size() >1 &&
                (n2.find(commonName) == 0 ||
                 (n2.find("__" == 0 && n2.find(commonName) == 2)))) {
                // found commonName from beginning of n2
                if (!namecntMap.count(commonName))
                    namecntMap[commonName] = 2;
                else
                    namecntMap[commonName]+=1;
                continue;
            } else
                commonName = "";
            int start = 0;
            if (n1.find("__") == 0)
                start = 2;
            for (int i = start; i < len1; i++) {
                if (i >= len2)
                    break;
                if (n1[i] == n2[i]) {
                    commonName += n1[i];
                    continue;
                } else
                    break;
            }
//            if (!commonName.empty())
//                OP << commonName << "\n";
        }
//        if (!commonName.empty()) {
//            OP << commonName << ": " << nameMap[commonName] << "\n";
//        }
    }

    // use the top one commonName as the module header name
    if (namecntMap.size()) {
        auto x = max_element(namecntMap.begin(), namecntMap.end(),
                             [](const pair<string, size_t>& p1, const pair<string, size_t>& p2) {
                                 return p1.second < p2.second; });
        return x->first;
    } else
        return commonName;
//    OP << x->first << ": " << x->second << "\n";
//    OP << "---------\n";
//    for (auto n: namecntMap) {
//        OP << n.first << ": " << n.second << "\n";
//    }

}

string cmdExecute(char* cmd) {
    FILE *fp = NULL;
    string result;

    fp = popen(cmd, "r");
    if(!fp) {
        perror("popen");
        return "popen failed";
    }
//    char buf[100];
//    memset(buf, 0, sizeof(buf));
//    fgets(buf, sizeof(buf) - 1, fp);
//    buf[strlen(buf)-1] = 0;
//    OP << buf << "\n";

//    result = buf;
    return result;
}


// TODO: transform function name into intention (by word order)
//  e.g., l2tp_tunnel_get_session -> get <session> from the <l2tp_tunnel>
//string transFuncName(string funcname, Module &M, string location, raw_fd_ostream &TransFile) {
string transFuncName(string funcname, string location, raw_fd_ostream &TransFile) {
    string transName;
//    OP << M.getName() << "\n";
//    OP << M.getSourceFileName() << "\n";
//    string name = M.getSourceFileName();
    string moduleName;
//    trimPathSlash(name, 2);
//    OP << name << "\n";
    OP << location << "\n";

    // extract module header name
//    if (moduleHeaderMap.count(M.getName())) {
//        moduleName = moduleHeaderMap[M.getName()];
    if (moduleHeaderMap.count(location)) {
        moduleName = moduleHeaderMap[location];
    } else {
//        moduleName = findModuleName(M);
        moduleName = findModuleName(location);
//        moduleHeaderMap[M.getName()] = moduleName;
        moduleHeaderMap[location] = moduleName;
    }

    OP << "Module: " << moduleName << "\n";

//    funcname = "l2tp_session_get";
    TransFile << funcname << "," << moduleName << "," << location << "\n";
/*
    FILE *fp = NULL;
    char cmd[100];
    sprintf(cmd, "python2 transform_funcname_intention.py %s %s %s", funcname.c_str(), moduleName.c_str(), location.c_str());
//    OP << cmd << "\n";

    fp = popen(cmd, "r");
    if(!fp) {
        perror("popen");
        return "popen failed";
//        exit(EXIT_FAILURE);
    }
    char buf[100];
    memset(buf, 0, sizeof(buf));
    fgets(buf, sizeof(buf) - 1, fp);
    buf[strlen(buf)-1] = 0;
    OP << buf << "\n";

    transName = buf;
//    transName = "1";

    TransFile << funcname << "," << transName << "," << moduleName << "\n";
    pclose(fp);
*/
    return transName;

    // 1: NVN + retNameEqOp1 + ArgTypeEqOp0 -> VOP1fromOP0
    // l2tp_tunnel_get_session: return session (struct l2tp_tunnel *tunnel)
    // 2: NVN + retTypeEqOp0 + ArgNameEqOp1 -> VOP0byOP1
    // l2tp_session_get_nth: struct l2tp_session(struct l2tp_tunnel *tunnel, int nth)
    // l2tp_session_get_by_ifname: struct l2tp_session(const struct net *net, const char *ifname)
    // 3: NV + retTypeEqOp0 -> VOP0
    // l2tp_session_get: struct l2tp_session(const struct net *net, u32 session_id)

    // NV + retTypePt -> VOP0
    // struct inode *ext4_orphan_get(struct super_block *sb, unsigned long ino)

    // 4: NV + ArgTypeEqOp0 + retTypeInt -> VOP0
    // l2tp_session_register: int(struct l2tp_session *session,struct l2tp_tunnel *tunnel)

    // 5: NVN + retTypeInt/retTypeVoid -> VOP1
    // amdgpu_enable_vblank_kms: int amdgpu_enable_vblank_kms(struct drm_device *dev, unsigned int pipe)
    // amdgpu_disable_vblank_kms: void amdgpu_disable_vblank_kms(struct drm_device *dev, unsigned int pipe)

    //------------module type-----
    // module_name+V -> VMo
    // atalk_create
    // tipc_rcv
    // batadv_v_ogm_process: static void batadv_v_ogm_process(const struct sk_buff *skb, int ogm_offset,

    // module_name+V+N -> VOP0
    // amdgpu_enable_vblank_kms
    // batadv_show_throughput_override
    // nr_add_node

    // module_name+N+V -> VOP0
    // retTypeEqOp0: l2tp_session_get
    // retTypePt: struct inode *ext4_orphan_get(struct super_block *sb, unsigned long ino)
    // retTypeInt,ArgTypeEqOp0: l2tp_session_register

    // module_name+N+V+N + ArgNameEqOp1-> VOP0byOP1
    // l2tp_session_get_nth

    // module_name+N+V+N + retNameEqOp1-> VOP1fromOP0
    // l2tp_tunnel_get_session

}

/// Check if the value is an errno.
bool isValueErrno(Value *V, Function *F) {
    // Invalid input.
    if (!V)
        return false;

    // The value is a constant integer.
    if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
        const int64_t value = CI->getValue().getSExtValue();
        // The value is an errno (negative or positive).
        if (is_errno(-value) || is_errno(value)
#if ERRNO_TYPE == 2
            || (-4096 < value && value < 0)
#endif
                )

            return true;
    }

#if ERRNO_TYPE == 2
    if (ConstantPointerNull *CPN = dyn_cast<ConstantPointerNull>(V)) {
		if (F->getReturnType()->isPointerTy())
			return true;
	}
#endif

    // The value is a constant expression.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(V)) {
        if (CE) {
            for (unsigned i = 0, e = CE->getNumOperands();
                 i != e; ++i) {
                if (isValueErrno(CE->getOperand(i), F))
                    return true;
            }
        }
    }

    return false;
}