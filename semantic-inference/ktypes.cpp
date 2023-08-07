//===-- HelloWorld.cpp - Example Transformations --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <sstream>
#include <list>
#include <string>
#include <unordered_map>
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/MemoryDependenceAnalysis.h"
#include "llvm/Pass.h"


using namespace llvm;

struct IndexField {
	std::string name;
	std::list<int64_t> intList;
};


namespace {
	class KtypesPass : public PassInfoMixin<KtypesPass> {
		public:
			KtypesPass() {}
			PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
		private:
			std::list<IndexField> indList;
			void handleIdx(Module &M, FunctionAnalysisManager &FAM);
			void findIndizes(GetElementPtrInst *GI, MemoryDependenceResults &MD);
			void traceIndex(Instruction *I, MemoryDependenceResults &MD, std::unordered_map<Instruction*, bool> visited);
			void checkIndex(GetElementPtrInst *GI);
			void identifyIndexAcc(GetElementPtrInst *GI);
	};
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
	return {LLVM_PLUGIN_API_VERSION, "KtypesPass", "v0.1",
		[](PassBuilder &PB) {
			PB.registerPipelineStartEPCallback([](ModulePassManager &MPM, OptimizationLevel OL) {
					MPM.addPass(KtypesPass());
					});
		}};
}

void handleStoreWrite(StoreInst *SI) {
	errs() << "found store inst\n";
	Type *pointerType = SI->getPointerOperandType();
	if (PointerType *PT = dyn_cast<PointerType>(pointerType)) {
		if (PT->isOpaque())
			return;
		Type *elemType = PT->getNonOpaquePointerElementType();
		if (PointerType *EPT = dyn_cast<PointerType>(elemType)) {
			errs() << "found pointer write in " << SI->getFunction()->getName().str() << "\n";
		}
	}
}

void handlePtrWrite(Type *T, Instruction *I) {
	if (PointerType *PT = dyn_cast<PointerType>(T)) {
		if (PT->isOpaque())
			return;
		Type *elemType = PT->getNonOpaquePointerElementType();
		if (PointerType *EPT = dyn_cast<PointerType>(elemType)) {
			// This is the pointer that will be dereferenced
			if (EPT->isOpaque())
				return;
			Type *ET = PT->getNonOpaquePointerElementType();
			// This is the type of the value we are actually writing
			if (PointerType *FPT = dyn_cast<PointerType>(ET)) {
				StringRef FunctionName = I->getFunction()->getName();
				if (!I->getDebugLoc()) {
					return;
				}
				StringRef Filename = I->getDebugLoc()->getFilename();
				int x = I->getDebugLoc()->getLine();
				std::string LineNumber = std::to_string(x);

				std::stringstream a;
				a << "ptrwrite at " + FunctionName.str() + ":" + Filename.str() + ":"
					+ LineNumber + "\n";
				errs() << a.str();
			}
		}
	}
}

// The direct type from load/store is always a pointer to the actual type. ->deref that pointer, then check if it is a pointer
// FenceInst
// For now, we are not handling catchpad, catchret instructions (should not be relevant for kernel)
// CallInst memory accesses are only about arguments, which live on the stack, so not really relevant for us (invoke, callbr are similar)
void handleWrite(Instruction *I) {
	if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
		handlePtrWrite(SI->getPointerOperandType(), I);
	} else if (VAArgInst *VI = dyn_cast<VAArgInst>(I)) {
		handlePtrWrite(VI->getPointerOperand()->getType(), I);
	} else if (AtomicCmpXchgInst *AI = dyn_cast<AtomicCmpXchgInst>(I)) {
		handlePtrWrite(AI->getPointerOperand()->getType(), I);
	} else if (AtomicRMWInst *AI = dyn_cast<AtomicRMWInst>(I)) {
		handlePtrWrite(AI->getPointerOperand()->getType(), I);
	} else if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
		// TODO how can this be
		handlePtrWrite(LI->getPointerOperandType(), I);
	}
}

void handleLoadRead(LoadInst *LI) {
	errs() << "found load inst\n";
	Type *pointerType = LI->getPointerOperandType();
	if (PointerType *PT = dyn_cast<PointerType>(pointerType)) {
		if (PT->isOpaque()) 
			return;
		Type *elemType = PT->getNonOpaquePointerElementType();
		if (PointerType *EPT = dyn_cast<PointerType>(elemType)) {
			errs() << "found pointer read in " << LI->getFunction()->getName().str() << "\n";
		}
	}
}

void handlePtrRead(Type *T, Instruction *I) {
	if (PointerType *PT = dyn_cast<PointerType>(T)) {
		if (PT->isOpaque())
			return;
		Type *elemType = PT->getNonOpaquePointerElementType();
		// This is the pointer we are dereferencing
		if (PointerType *EPT = dyn_cast<PointerType>(elemType)) {
			if (EPT->isOpaque())
				return;
			// This is the type of the pointer we are actually reading from
			Type *ET = EPT->getNonOpaquePointerElementType();
			if (PointerType *FPT = dyn_cast<PointerType>(ET)) {
				if (!I->getDebugLoc()) {
					return;
				}
				StringRef FunctionName = I->getFunction()->getName();
				StringRef Filename = I->getDebugLoc()->getFilename();
				int x = I->getDebugLoc()->getLine();
				std::string LineNumber = std::to_string(x);
				std::stringstream a;
				a << "ptrread at " + FunctionName.str() + ":" + Filename.str() + ":"
					+ LineNumber + "\n";
				errs() << a.str();
			}
		}
	}
}

void handleRead(Instruction *I) {
	if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
		handlePtrRead(LI->getPointerOperandType(), I);
	} else if (VAArgInst *VI = dyn_cast<VAArgInst>(I)) {
		handlePtrRead(VI->getPointerOperand()->getType(), I);
	} else if (AtomicCmpXchgInst *AI = dyn_cast<AtomicCmpXchgInst>(I)) {
		handlePtrRead(AI->getPointerOperand()->getType(), I);
	} else if (AtomicRMWInst *AI = dyn_cast<AtomicRMWInst>(I)) {
		handlePtrRead(AI->getPointerOperand()->getType(), I);
	} else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
		// TODO how can this be???
		handlePtrRead(SI->getPointerOperandType(), I);
	}

}

void handlePtrs(Module &M) {
	for (auto &F : M) {
		for (auto &BB : F) {
			for (auto &I : BB) {
				if (I.mayReadFromMemory()) {
					handleRead(&I);
				}
				if (I.mayWriteToMemory()) {
					handleWrite(&I);
				}
			}
		}
	}
}

bool isArrayGEP(GetElementPtrInst *GI) {
	Value *V = GI->getOperand(0);
	if (PointerType *P = dyn_cast<PointerType>(V->getType())) {
		if (P->isOpaque())
			return false;
		Type *ET = P->getNonOpaquePointerElementType();
		if (ArrayType *A = dyn_cast<ArrayType>(ET)) {
			return true;
		}
	}
	return false;
}

bool isStructGEP(GetElementPtrInst *GI) {
	Value *V = GI->getOperand(0);
	if (PointerType *P = dyn_cast<PointerType>(V->getType())) {
		if (P->isOpaque())
			return false;
		Type *ET = P->getNonOpaquePointerElementType();
		if (StructType *A = dyn_cast<StructType>(ET)) {
			return true;
		}
	}
	return false;
}

// check if this is an index load. Store if it is.
void KtypesPass::checkIndex(GetElementPtrInst *GI) {
	if (!isStructGEP(GI)) {
	//	errs() << "not relevant...\n";
		return;
	}
	bool intOnly = true;
	for (unsigned i = 1, e = GI->getNumOperands(); i != e; ++i) {
		Value *V = GI->getOperand(i);
		if (IntegerType *IT = dyn_cast<IntegerType>(V->getType())) {
			if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
				//errs() << "fine\n";
			} else {
				intOnly = false;
			}
			continue;
		} else {
			intOnly = false;
		}
	}
	if (!intOnly) {
	//	errs() << "not only int operands...\n";
		return;
	}
	//errs() << "Found an index!\n";

	IndexField indField;
	Value *V = GI->getOperand(0);
	if (PointerType *P = dyn_cast<PointerType>(V->getType())) {
		Type *ET = P->getNonOpaquePointerElementType();
		if (StructType *A = dyn_cast<StructType>(ET)) {
			indField.name = A->getName().str();
		}
	}
	for (unsigned i = 1, e = GI->getNumOperands(); i != e; ++i) {
		Value *V = GI->getOperand(i);
		if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
			indField.intList.push_back(CI->getSExtValue());
		}
	}
	indList.push_back(indField);
}

void KtypesPass::traceIndex(Instruction *I, MemoryDependenceResults &MD, std::unordered_map<Instruction *, bool> visited) {
	if (visited.find(I) != visited.end()) {
		// we have seen this instruction before
		return;
	}
	visited[I] = true;
	// certain instructions should stop our back tracing: calls, fence
	// TODO maybe CatchReturnInst, CatchSwitchInst,IndirectBrInst, BranchInst, LandingPadInst, ReturnInst, UnreachableInst
	if (CallBase *CB = dyn_cast<CallBase>(I)) {
		return;
	}
	if (FenceInst *FI = dyn_cast<FenceInst>(I)) {
		return;
	}

	/*
	 * loads can be problematic if we load from a local variable which was initialized
	 * inside an if.
	 * e.g., if (struct.ind < 10) { i = struct.ind} else { i = 0}; res = struct.arr[i];
	 * We can use MemoryDependenceAnalysis Pass's output to find both those writes to i.
	 */
	if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
		// inspiration from llvm/lib/Analysis/MemDepPrinter.cpp
		// let's start with def only -> MemDepResult.isDef()? -> getInst()
		MemDepResult Res = MD.getDependency(I);
		if (!Res.isNonLocal()) {
			if (Res.isDef() || Res.isClobber()) {
				Instruction *DI = Res.getInst();
				traceIndex(DI, MD, visited);
			}
		} else {
			// We don't need to check for CallBase because we already filtered those insts
			SmallVector<NonLocalDepResult, 8> NLDI;
			MD.getNonLocalPointerDependency(I, NLDI);

			for (const NonLocalDepResult &NR : NLDI) {
				const MemDepResult &R = NR.getResult();
				if (R.isDef() || R.isClobber()) {
					Instruction *NI = R.getInst();
					traceIndex(NI, MD, visited);
				}
			}
		}
	} else if (GetElementPtrInst *GI = dyn_cast<GetElementPtrInst>(I)) {
		// found GEP inst, handling it
		checkIndex(GI);
		return;
	}
	// Recursion
	for (unsigned i = 0, e = I->getNumOperands(); i != e; ++i) {
		Value *V = I->getOperand(i);
		if (Instruction *NI = dyn_cast<Instruction>(V)) {
			traceIndex(NI, MD, visited);
		}
	}
}

void KtypesPass::findIndizes(GetElementPtrInst *GI, MemoryDependenceResults &MD) {
	//errs() << "Checking GEP instruction\n";
	if (!isArrayGEP(GI)) {
	//	errs() << "GEP inst not interesting\n";
		return;
	}
	std::unordered_map<Instruction*, bool> visited;
	for (unsigned i = 1, e = GI->getNumOperands(); i != e; ++i) {
		Value *V = GI->getOperand(i);
		if (Instruction *I = dyn_cast<Instruction>(V)) {
			traceIndex(I, MD, visited);
		}
	}
}

bool compareAccField(GetElementPtrInst *GI, IndexField indField) {
	Value *V = GI->getOperand(0);
	if (PointerType *P = dyn_cast<PointerType>(V->getType())) {
		Type *ET = P->getNonOpaquePointerElementType();
		if (StructType *A = dyn_cast<StructType>(ET)) {
			if (indField.name != A->getName().str()) {
				return false;
			}
		} else {
			// not necessary since we already checked whether this instruction accesses a struct
			return false;
		}
	} else {
		// not necessary since we already checked whether this instruction accesses a struct
		return false;
	}
	int i = 1, e = GI->getNumOperands();
	for (std::list<int64_t>::iterator it = indField.intList.begin(); it != indField.intList.end(); ++it) {
		if (i == e) {
			return false;
		}
		Value *V = GI->getOperand(i);
		if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
			if (*it != CI->getSExtValue()) {
				return false;
			}
		} else {
			return false;
		}
		++i;
	}
	return true;
}

void KtypesPass::identifyIndexAcc(GetElementPtrInst *GI) {
	if (!isStructGEP(GI)) {
		return;
	}
	bool found = false;
	for (std::list<IndexField>::iterator it = indList.begin(); it != indList.end(); ++it) {
		// compare with struct
		if (compareAccField(GI, *it)) {
			found = true;
			break;
		}
	}
	if (!found)
		return;
	std::string accType;
	// check whether any of the users of this instructions are a load or a store
	for (auto U : GI->users()) {
		Instruction *I;
		if (LoadInst *LI = dyn_cast<LoadInst>(U)) {
			I = LI;
			accType = "idxread";
		} else if (StoreInst *SI = dyn_cast<StoreInst>(U)) {
			I = SI;
			accType = "idxwrite";
		} else {
			continue;
		}
		if (!I->getDebugLoc()) {
			continue;
		}
		StringRef FunctionName = I->getFunction()->getName();
		StringRef Filename = I->getDebugLoc()->getFilename();
		int x = I->getDebugLoc()->getLine();
		std::string LineNumber = std::to_string(x);
		std::stringstream a;
		a << accType << " at " + FunctionName.str() + ":" + Filename.str() + ":"
			+ LineNumber + "\n";
		errs() << a.str();
	}
	/*
	// check whether next instruction is store or load
	Instruction *I = GI->getNextNonDebugInstruction(true);
	std::string accType = "";
	if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
		accType = "idxread";
	} else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
		accType = "idxwrite";
	} else {
		// For now we only consider loads and stores
		return;
	}
	if (!GI->getDebugLoc()) {
		return;
	}
	StringRef FunctionName = GI->getFunction()->getName();
	StringRef Filename = GI->getDebugLoc()->getFilename();
	int x = GI->getDebugLoc()->getLine();
	std::string LineNumber = std::to_string(x);
	std::stringstream a;
	a << accType << " at " + FunctionName.str() + ":" + Filename.str() + ":"
		+ LineNumber + "\n";
	errs() << a.str();
	*/
}

void KtypesPass::handleIdx(Module &M, FunctionAnalysisManager &FAM) {
	// Step 1: collect index fields
	//errs() << "starting idx analysis\n";
	for (auto &F : M) {
		for (auto &BB : F) {
			MemoryDependenceResults &MD = FAM.getResult<MemoryDependenceAnalysis>(F);
			for (auto &I : BB) {
				if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(&I))
					findIndizes(GEPI, MD);
			}
		}
	}
	//errs() << "Found " << indList.size() << " indizes\n";
	// Step 2: find index reads/writes
	
	for (auto &F : M) {
		for (auto &BB : F) {
			for (auto &I : BB) {
				if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(&I))
					identifyIndexAcc(GEPI);
			}
		}
	}
	//errs() << "step2 done\n";
}

PreservedAnalyses KtypesPass::run(Module &M,
                                      ModuleAnalysisManager &MAM) {
	FunctionAnalysisManager &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
	handlePtrs(M);
	handleIdx(M, FAM);
	return PreservedAnalyses::all();
}
