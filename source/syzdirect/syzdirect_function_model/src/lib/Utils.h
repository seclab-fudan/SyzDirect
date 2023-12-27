#ifndef UTILS_H
#define UTILS_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Format.h>
#include <set>
#include <list>
#include <map>
#include <string>
#include "Analyzer.h"
#include "Common.h"

string getValueAsOperand(Value* v);

int getIntValue(Value* value);

string getDeviceString(Value *currVal);

Value* getStructValue(Value* value);

vector<GetElementPtrInst*> getGepInstByStructName(Function* F, StringRef srcTypeName, StringRef resTypeName);

int getFieldOffsetByName(DIType* TY, string fieldName);

Function* getFunctionFromModules(StringRef funcName);

void outputBBInfo(BasicBlock* BB, raw_fd_ostream& outfile);

bool endsWith(std::string const & value, std::string const & ending);

int getBasicBlockIndex(BasicBlock* BB);
#endif