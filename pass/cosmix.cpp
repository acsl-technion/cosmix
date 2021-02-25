/*
 * COSMIX pass - Layered VM in SGX
 *
 * This pass adds COSMIX - customizing memory accesses to different backing stores with good performance for enclaves.
 * This pass expects as input all the source files, combined in their IR representation.
 * Then it is expected to be linked against the appropraite runtime libraries.
 * 
 * The pass instruments the following:
 * Global/Stack/Heap Insrumentation
 *
 * Asan reference code: $(LLVM-ROOT_DIR)/lib/Transforms/Instrumentation
 *
 */

#define DEBUG_TYPE "cosmix"

#include "json/json.h"
#include "json/json-forwards.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/AutoUpgrade.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ModuleSummaryIndex.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
// #include "llvm/Support/InitLLVM.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
// #include "llvm/Support/WithColor.h"
#include "llvm/Transforms/IPO/FunctionImport.h"
#include "llvm/Transforms/IPO/Internalize.h"
#include "llvm/Transforms/Utils/FunctionImportUtils.h"

#include <llvm/Pass.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/CFG.h>
#include <llvm/Analysis/CFG.h>

#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/Casting.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/UnrollLoop.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/CallSite.h>
#include <llvm/Analysis/MemoryBuiltins.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/AssumptionCache.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/Loads.h>
#include <llvm/Analysis/LoopIterator.h>
#include <llvm/Analysis/LoopPass.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/CallGraph.h>

#include <llvm/Transforms/Utils/LoopSimplify.h>
#include <llvm/Transforms/Utils/LCSSA.h>
#include <llvm/Transforms/Utils/LoopUtils.h>
#include <llvm/Support/Debug.h>
#include <llvm/Transforms/Utils/UnifyFunctionExitNodes.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/LoopPassManager.h>

#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpander.h>
#include <llvm/Analysis/ScalarEvolutionExpressions.h>
#include <llvm/Analysis/LoopAccessAnalysis.h>

#include <llvm/Transforms/Utils/Cloning.h>

#include <llvm/ADT/SCCIterator.h>

#include <MemoryModel/PointerAnalysis.h>
#include <WPA/Andersen.h>
#include <WPA/FlowSensitive.h>
#include <Util/SVFModule.h>

#include <iostream>
#include <map>
#include <set>
#include <vector>
#include <utility>
#include <tr1/memory>
#include <tr1/tuple>

#include <string>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <sstream>

#include "../include/common.h"

using namespace llvm;

static cl::opt<std::string> opt_StartupFunctionMain("startup_func", cl::Optional, cl::init("main"),
 		cl::desc("Startup function name (defaults to main)"));

static cl::opt<bool> opt_FixRealFunctions("fix_real_functions", cl::Optional, cl::init(false),
		cl::desc("temp solution"));

static cl::opt<bool> opt_HandleCrossPageCachedAccess("cross_page_cached_mstores_enabled", cl::Optional, cl::init(false),
		cl::desc("Handle cross page accesses in cached mstores"));

static cl::opt<std::string> opt_AnalysisModule("analysis_module", cl::Optional, cl::init(""),
 		cl::desc("Perform pointer analysis just for this module (workaround for issue in SVF)"));

static cl::opt<std::string> opt_ConfigFile("config_file", cl::Optional, cl::init(""),
 		cl::desc("CoSMIX configuration file"));

static cl::opt<bool> opt_DisableLoopOptimization("disable_loop_opt", cl::Optional, cl::init(false),
 		cl::desc("Disable loop address translation caching optimization"));

static cl::opt<bool> opt_DisableInlineInstrumentation("disable_inline_instrumentation", cl::Optional, cl::init(false),
 		cl::desc("Force instrumentation of memory accesses to be regular function calls to CoSMIX runtime"));

static cl::opt<bool> opt_AlwaysReplaceAllocators("replace_all_allocators", cl::Optional, cl::init(true),
 		cl::desc("Instrument all dynamic allocators to invoke mstore allocator (can set runtime bound checking via config file)"));

static cl::opt<bool> opt_instrumentEnabled("instrument", cl::Optional, cl::init(true),
 		cl::desc("Enable/Disable instrumentation of memory operations"));

static cl::opt<bool> opt_CodeAnalysisWithInttoPtrOptEnalbed("code_analysis_integers", cl::Optional, cl::init(true),
 		cl::desc("Enable/Disable pointer analysis to include all encountered pointers to int casts (SVF workaround for variant GEPs)"));

static cl::opt<bool> opt_CodeAnalysisOptEnalbed("code_analysis", cl::Optional, cl::init(true),
 		cl::desc("Enable/Disable pointer analysis to instrument only MAY_ALIAS memory operations"));

static cl::opt<bool> opt_DumpSgx("dump_module", cl::Optional, cl::init(false),
		cl::desc("Dump all of the module's IR to the console for debugging purposes"));

static cl::opt<bool> opt_printStatistics("cosmix_stats", cl::Optional, cl::init(true),
		cl::desc("Print statistics on cosmix instrumentation of memory operations"));

namespace
{

const std::string COSMIX_PREFIX = "__cosmix_";
const std::string REAL_PREFIX = "_real_";

struct s_mstore
{
	// std::string mstore_name;
	std::string mstore_annotation_symbol;
	std::string mstore_type;
	std::string storage_type;
	std::string mstore_function_annotation_name;
	bool boundBasedAllocation;
	size_t lowerBound;
	size_t upperBound;
	
	bool mstore_annotation_found;
};

/*
 * Pass's logic
 */

class CosmixPass 
{

// TODO: add helper print func with regards to verbosity requested by the user

#define GENERIC_ANNOTATION_SYMBOL "generic"
#define GET_FUNC(NAME)  { if (F->getName().equals(#NAME)) NAME = F; }
#define LLVM_FUNC(F) (F->getName().contains("llvm"))
#define COSMIX_FUNC(F) (F->getName().startswith(COSMIX_PREFIX))
#define REAL_FUNC(F)   (F->getName().startswith(REAL_PREFIX))

private:

	struct s_mstore* g_mstores;
	size_t num_of_mstores;

	// Private Members
	Module* M = nullptr;
	DataLayout* DL = nullptr;
	
	Function* __cosmix_debug_interal;
	Function* __cosmix_write_page;
	Function* __cosmix_fail;
	Function* __cosmix_fail_asm;

	DenseMap<Loop*, SmallPtrSet<Instruction*,4>> m_MemInstructionToOptimizeInLoop;

	// Statistics counters
	long m_NumOfMemoryAccessInstrumented;
	long m_NumOfInstructions;
	long m_NumOfOptMemInstInLoops;
	long m_NumOfMemInstInLoops;
	long m_NumOfInstrumentedAllocations;

	DenseMap<NodeID, std::string> m_ValuesToInstrumentMap;
	DenseMap<Value*, std::string> m_AnnotatedVars;
	CallInst* m_CosmixLastInitInstruction;

	PointerAnalysis* m_PTA;
	PAG* m_PAG;

public:
	// Ctor
	CosmixPass(Module *M) 
	{
		this->M = M;
		this->DL = new DataLayout(M);
		
		this->__cosmix_debug_interal = nullptr;		

		this->__cosmix_write_page = nullptr;
		this->__cosmix_fail = nullptr;
		this->__cosmix_fail_asm = nullptr;

		this->m_NumOfMemInstInLoops = 0;
		this->m_NumOfOptMemInstInLoops = 0;
		this->m_NumOfMemoryAccessInstrumented = 0;
		this->m_NumOfInstructions = 0;
		this->m_NumOfInstrumentedAllocations = 0;

		this->num_of_mstores = 0;

		this->m_ValuesToInstrumentMap.clear();
		this->m_AnnotatedVars.clear();
	}

	// Helper methods to deal with all encountered cases of LLVM due to different optimizations

	void InitializePointerAnalysis()
	{	
		SVFModule svfModule(this->M);
		// m_PTA = new FlowSensitive();
		m_PTA = new AndersenWaveDiffWithType();
		m_PTA->disablePrintStat();
		m_PAG = m_PTA->getPAG();
		m_PAG->handleBlackHole(true);

		// Finally, analyze
		//
		m_PTA->analyze(svfModule);
		m_PAG = m_PTA->getPAG();
	}

	bool DONT_HAVE_COSMIX_METADATA(Value* value, Instruction* User) 
	{
		if (!opt_CodeAnalysisOptEnalbed)
		{
			return false;
		}

		// Function* UserFunction = User->getParent()->getParent();
		// if (COSMIX_FUNC(UserFunction) || MSTORE_FUNC(UserFunction))
		// {
		// 	return true;
		// }

		if (!m_PAG->hasValueNode(value))
		{
			return true;
		}

		NodeID targetNode = m_PAG->getValueNode(value->stripPointerCasts());
/*
		for (auto kvp : m_AnnotatedVars) 
		{
			Value* annotatedVar = kvp.first->stripPointerCasts();			

			// Get the node id for the annoated variable we analyze
			//
			NodeID annotatedNode = m_PAG->getValueNode(annotatedVar);
			if (m_PTA->alias(targetNode, annotatedNode))
			{
				return false;
			}
		}

		return true;
*/
		 return !m_ValuesToInstrumentMap.count(targetNode);
	}

	StringRef GetCosmixMetadata(Value* value) 
	{
		if (!opt_CodeAnalysisOptEnalbed)
		{
			int numAnnotationFound = 0;
			StringRef mstore_annotation_symbol;
			for (unsigned int i=0;i<this->num_of_mstores;i++)
			{
				if (this->g_mstores[i].mstore_annotation_found)
				{
					mstore_annotation_symbol = this->g_mstores[i].mstore_annotation_symbol;
					//errs() << "Found mstore_annotation_symbol: " << mstore_annotation_symbol << "\n";
					numAnnotationFound++;
				}
			}

			if (numAnnotationFound > 1)
			{
				return GENERIC_ANNOTATION_SYMBOL;
			}

			// Make sure at least one annotation was found - we do not currently support non-annotated programs
			//
			assert (numAnnotationFound == 1);			
			return mstore_annotation_symbol;
		}

		assert (m_PAG->hasValueNode(value));
		NodeID targetNode = m_PAG->getValueNode(value);
		assert (m_ValuesToInstrumentMap.count(targetNode));

		return m_ValuesToInstrumentMap[targetNode];
	}

	bool is_direct_mstore(Value* value)
	{
		auto mstore_name = GetCosmixMetadata(value);

		if (mstore_name == GENERIC_ANNOTATION_SYMBOL)
		{
			// Go over all mstores, if there is a direct one we can't currently prove its not a direct mstore
			// 
			bool found_direct_mstore = false;
			for (unsigned int i=0;i<this->num_of_mstores;i++)
			{
				if (this->g_mstores[i].mstore_type == "direct")
				{
					found_direct_mstore = true;
				}
			}

			return found_direct_mstore;
		}

		for (unsigned int i=0;i<this->num_of_mstores;i++)
		{
			if (this->g_mstores[i].mstore_annotation_symbol == mstore_name)
			{
				return this->g_mstores[i].mstore_type == "direct";
			}
		}

		assert (false && "[ERROR] - Could not determine mstore is direct or cached based on this value");
		return false;
	}

	bool isPointerToPointer(const Value* V) 
	{
		const Type* T = V->getType();
		return T->isPointerTy() && T->getContainedType(0)->isPointerTy();
	}

	bool isPointerOriginally(Value* V) 
	{
		if (V->getType()->isPointerTy())
			return true;
		if (isa<PtrToIntInst>(V))
			return true;
		if (V->getName().startswith("scevgep")
				|| V->getName().startswith("uglygep")) 
		{
			errs() <<"[Warning] - found unglygep\n";
			V->dump();
			exit(-1);
			return true;
		}
		return false;
	}

	void fixRealFunctions(Function* F)
	{
		if (REAL_FUNC(F))
		{
			Function* functionToReplace = M->getFunction(F->getName().str().substr(REAL_PREFIX.length()));
			assert (functionToReplace);
			F->replaceAllUsesWith(functionToReplace);
		}
	}

	// Helper method to find and initialize all related helper methods.
	void findHelperFunc(Function *F) 
	{
		if (F->isDeclaration() && !LLVM_FUNC(F) && !COSMIX_FUNC(F)) 
		{
			Function* functionToReplace = M->getFunction(COSMIX_PREFIX + F->getName().str());
			if (functionToReplace)
			{
				SmallPtrSet<CallInst*, 4> fixCallInstsSet;
				// Track all cosmix runtime functions that we didn't handle correctly, make them point to the original libc function
				for (auto User : F->users())
				{
					CallInst* CI = dyn_cast<CallInst>(&*User);
					if (CI && (COSMIX_FUNC(CI->getParent()->getParent())))
					{
						// restore done
						fixCallInstsSet.insert(CI);
					}
				}

				// errs() << "[INFO] - instrumented function: " << F->getName() << "\n";
				F->replaceAllUsesWith(functionToReplace);

				for (auto CI : fixCallInstsSet)
				{
					CI->setCalledFunction(F);
				}

			}
			else
			{
				// errs() << "[Warning] - could not instrument function, not yet supported: " << F->getName() << "\n";
			}

			//m_DeclarationFunctions.insert(F);
		}
		
		GET_FUNC(__cosmix_debug_interal);

		GET_FUNC(__cosmix_write_page);
		GET_FUNC(__cosmix_fail);
		GET_FUNC(__cosmix_fail_asm);
	}

	void handleExceptions(InvokeInst* II) 
	{
		errs() << "== [Warning] == found throwable invoke function call...not yet tested this functionality, dumping\n";
		II->dump();
		exit(-1);
	}

	void visitGlobalDefinition(GlobalVariable* GV, StringRef mstoreType) 
	{		
		// 1. Create a new global that is a pointer to the global type
		//
		GlobalVariable* newG = new GlobalVariable(*M, 
								GV->getValueType()->getPointerTo(), 
								false, 
								GV->getLinkage(),
								nullptr, 
								GV->getName() + "_" + mstoreType,
								GV, 
								GV->getThreadLocalMode());
		newG->copyAttributesFrom(GV);
		newG->setInitializer(Constant::getNullValue(GV->getValueType()->getPointerTo()));

		// 3. replace all uses of GV with a loaded value of newG, the rest will be handled as regular mstore variable by the compiler and runtime
		//   	 
   		auto UI = GV->use_begin();
		auto E =  GV->use_end();
   		for (; UI != E;) {
     		Use &U = *UI;
  			++UI;
     		// Must handle Constants specially, we cannot call replaceUsesOfWith on a
     		// constant because they are uniqued.
     		if (auto *C = dyn_cast<ConstantExpr>(U.getUser())) 
			{
				for (auto C_User : C->users()) 
				{
					if (Instruction* I = dyn_cast<Instruction>(C_User))
					{
						IRBuilder<> IRB_internal(I);
						LoadInst* LI = IRB_internal.CreateLoad(newG);
						auto temp = C->getAsInstruction();
						IRB_internal.Insert(temp);
						temp->replaceUsesOfWith(GV, LI);
						C->replaceAllUsesWith(temp);

						// 4. Register this variable with the dataflow analysis
						//
						assert (!m_AnnotatedVars.count(LI));
						m_AnnotatedVars[LI] = mstoreType.str();
					}

					assert (false && "Cannot handle global instrumentation of mstore for multi level constatnt experessions yet");
				}
			}

			if (auto *I = dyn_cast<Instruction>(U.getUser())) 
			{
				IRBuilder<> IRB_internal(I);
				LoadInst* LI = IRB_internal.CreateLoad(newG);
				U.set(LI);

				// 4. Register this variable with the dataflow analysis
				//
				assert (!m_AnnotatedVars.count(LI));
				m_AnnotatedVars[LI] = mstoreType.str();
			}

			assert (false && "cannot instrument this global since its use list contains undetermined use");			
   		}

		// 2. Allocate mstore memory for newG and initialize it with GV's data
		//
		IRBuilder<> IRB(M->getFunction(opt_StartupFunctionMain)->begin()->getFirstNonPHIOrDbgOrLifetime());
		Function* F = M->getFunction("__cosmix_init_global_" + mstoreType.str());
		assert (F && "Cannot find global init function");

		auto GV8 = IRB.CreatePointerCast(GV, IRB.getInt8PtrTy());
		auto newG8 = IRB.CreatePointerCast(newG, IRB.getInt8PtrTy());
		// Value * PH = ConstantPointerNull::get (getVoidPtrType(GV->getContext()));
   	  	Type* csiType = IntegerType::getInt32Ty(GV->getContext());
		Type * GlobalType = GV->getType()->getElementType();
 	  	unsigned TypeSize = this->DL->getTypeAllocSize((GlobalType));
 	  	if (!TypeSize) {
 	    	llvm::errs() << "FIXME: Ignoring global of size zero: ";
	 	    GV->dump();
	 	    return;
 	  	}

		Value * AllocSize = ConstantInt::get (csiType, TypeSize);
		IRB.CreateCall(F, { newG8, GV8, AllocSize });

		// GV->eraseFromParent();
		// newG->takeName(GV);
	}

	void visitStackAllocation(AllocaInst* AI, StringRef mstoreType) 
	{
		// Note: for every alloca we replace it with heap allocation via cosmix runtime
		IRBuilder<> IRB(AI);

		Value* size = AI->isArrayAllocation() ?
			IRB.CreateMul(
				IRB.getInt64(AI->getAllocatedType()->getArrayNumElements()),
				IRB.getInt64(DL->getTypeAllocSize(AI->getAllocatedType()->getArrayElementType()))) :
				IRB.getInt64(DL->getTypeAllocSize(AI->getAllocatedType()));

		Value* size_casted = IRB.CreateIntCast(size, IRB.getInt64Ty(), false);
		// Get allocation function based on mstore type
		//
		std::string mstoreAllocFuncName = COSMIX_PREFIX + "malloc_" + mstoreType.str();
		CallInst* CI = IRB.CreateCall(M->getFunction(mstoreAllocFuncName), size_casted);
		Value* CI_casted = IRB.CreatePointerCast(CI, AI->getType());
		
		AI->replaceAllUsesWith(CI_casted);
		CI_casted->takeName(AI);
		AI->eraseFromParent();

		assert (!m_AnnotatedVars.count(CI));
		m_AnnotatedVars[CI] = mstoreType;

		// Finally, make sure it is freed at the end of the function
		//
		Function* F = CI->getParent()->getParent();
	        if (!F->doesNotReturn()) 
		{
			for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB)
	                {
        	                for (auto I = BB->begin(); I != BB->end();I++)
                	        {
					if (ReturnInst *RI = dyn_cast<ReturnInst>(I)) 
					{
						IRB.SetInsertPoint(RI);
						CallInst* freeCI = IRB.CreateCall(M->getFunction(COSMIX_PREFIX + "free"), CI);
					}
				}
			}
		}
	}

	void visitInvokeInst(InvokeInst* II) 
	{
		if (II->doesNotThrow()) 
		{
			return; // nothing to handle in this case
		}

		if (!II->getCalledFunction()) 
		{
			errs() << "[Warning] - invoke function pointer or inline computation\n";
		}

		handleExceptions(II);
	}

	void visitCallInst(CallInst* CI) 
	{
		// regular functions are already instrumented, just handle inline asm calls
		//
		if (CI->isInlineAsm()) 
		{
			IRBuilder<> IRB(CI);
			for (unsigned int j=0; j < CI->getNumArgOperands(); j++) 
			{
				if (CI->getArgOperand(j)->getType()->isPtrOrPtrVectorTy()) 
				{
					Value* arg8 = IRB.CreatePointerCast(CI->getArgOperand(j), IRB.getInt8PtrTy());					
					IRB.CreateCall(__cosmix_fail_asm, arg8);
				}
			}

			return;
		}

		Function* F = CI->getCalledFunction();
		// TODO: printf-type functions should have wrappers as part of the cosmix runtime 
		//
		if (F && F->isVarArg() && F->isDeclaration() && F->getName().contains("printf"))
		{
			IRBuilder<> IRB(CI);
			// go over all args and make sure we replace them with a linked val
			for (unsigned int i=0; i < CI->getNumArgOperands(); i++)
			{
				Value* ptr = CI->getArgOperand(i);

				if (!ptr->getType()->isPointerTy() || DONT_HAVE_COSMIX_METADATA(ptr->stripPointerCasts(), CI))
				{
					continue;
				}

				// TODO: link generic and direct should be specially handled
				std::string linkageFunctionName = COSMIX_PREFIX + "link_" + GetCosmixMetadata(ptr).str();		
				Function* linkageFunction = M->getFunction(linkageFunctionName);
				assert (linkageFunction && "[Error] could not find instrumented linkage function\n");
				unsigned sizeinBits = DL->getTypeSizeInBits(ptr->getType()->getPointerElementType());
				unsigned size = sizeinBits / BIT_SIZE;
				Value* valSize = IRB.getInt32(size);
				Value* ptr8 = IRB.CreatePointerCast(ptr, IRB.getInt8PtrTy());				
				Value* isVectorPtr = IRB.getInt8(isDereferenceableAndAlignedPointer(ptr, size, *this->DL));
				Value* isDirty = IRB.getInt8(0);
		        auto args = { ptr8, valSize, isVectorPtr, isDirty };

				CallInst* linked_ptr = IRB.CreateCall(linkageFunction, args);

				Value* linked_ptr_casted = IRB.CreatePointerCast(linked_ptr, ptr->getType());
				CI->setArgOperand(i, linked_ptr_casted);
			}
		}
	}

	int getMemPointerOperandIdx(Instruction* I) 
	{
		switch (I->getOpcode()) 
		{
			case Instruction::Load:
				return cast<LoadInst>(I)->getPointerOperandIndex();
			case Instruction::Store:
				return cast<StoreInst>(I)->getPointerOperandIndex();
			case Instruction::AtomicCmpXchg:
				return cast<AtomicCmpXchgInst>(I)->getPointerOperandIndex();
			case Instruction::AtomicRMW:
				return cast<AtomicRMWInst>(I)->getPointerOperandIndex();
		}
		
		return -1;
	}

	void visitAtomics(Instruction* MI)
	{
		int ptrOperandIdx = getMemPointerOperandIdx(MI);

		Value* ptr_strip_casts = MI->getOperand(ptrOperandIdx)->stripPointerCasts();

		if (DONT_HAVE_COSMIX_METADATA(ptr_strip_casts, MI)) 
		{
			return;
		}

		IRBuilder<> IRB(MI);
		Value* ptr8 = IRB.CreatePointerCast(MI->getOperand(ptrOperandIdx), IRB.getInt8PtrTy());
		IRB.CreateCall(M->getFunction("__cosmix_test_atomic"), ptr8);
	}

	void visitMemInstAndLink(Instruction* MI, LoopInfo* LI, DominatorTree* DT, AliasAnalysis *AA, ScalarEvolution* SE) 
	{
		// Optimize native pointers that we can determine at compile time		
		//
		int ptrOperandIdx = getMemPointerOperandIdx(MI);
		bool is_load_access = isa<LoadInst>(MI);
		unsigned sizeinBits = isa<StoreInst>(MI) ?  DL->getTypeStoreSizeInBits(MI->getOperand(ptrOperandIdx)->getType()->getPointerElementType()) :
						DL->getTypeSizeInBits(MI->getOperand(ptrOperandIdx)->getType()->getPointerElementType());
		unsigned size = sizeinBits / BIT_SIZE;
		
		Value* ptr_strip_casts = MI->getOperand(ptrOperandIdx)->stripPointerCasts();

		if (DONT_HAVE_COSMIX_METADATA(ptr_strip_casts, MI)) 
		{
			return;
		}

		if (!opt_DisableLoopOptimization)
		{
			// Start section of loop optimization
			Loop *L = LI->getLoopFor(MI->getParent());

			// Note: direct mstores cannot use TLB, so test for them
			//
			if (L && !is_direct_mstore(ptr_strip_casts))
			{
				m_NumOfMemInstInLoops++;
				const SCEV* ptrSCEV = SE->getSCEV(ptr_strip_casts);
				if (ptrSCEV && static_cast<SCEVTypes>(ptrSCEV->getSCEVType()) == scAddRecExpr) 
				{
					const SCEVAddRecExpr *AR = cast<SCEVAddRecExpr>(ptrSCEV);

					// We only work with expressions of form `A + B*x`
					// We are going to transform this to a loop structure that assumes this mem access instruction executes on every loop iteration
					// Verify both conditions are true before optimizing
					//
					if (AR->isAffine() && isGuaranteedToExecuteForEveryIteration(MI, AR->getLoop()))
					{					
						m_NumOfOptMemInstInLoops++;
						m_MemInstructionToOptimizeInLoop[L].insert(MI);

						// We track this instruction and will translate it somewhere else (during the loop optimization pass)
						//
						return;
					}
				}
			}
		}

		// end section of loop optimization

		IRBuilder<> IRB(MI);
		Value* valSize = IRB.getInt32(size);
        Value* ptr8 = IRB.CreatePointerCast(MI->getOperand(ptrOperandIdx), IRB.getInt8PtrTy());

		Value* isVectorPtr = IRB.getInt8(0);//isDereferenceableAndAlignedPointer(MI->getOperand(ptrOperandIdx), size, *this->DL, MI));
		Value* isDirty = is_load_access ? IRB.getInt8(0) : IRB.getInt8(1);
        // auto args = { ptr8, valSize, isVectorPtr, isDirty };

		std::string linkageFunctionName = COSMIX_PREFIX + "link_" + GetCosmixMetadata(ptr_strip_casts).str().c_str();		
		Function* linkageFunction = M->getFunction(linkageFunctionName);
		assert (linkageFunction && "[Error] could not find instrumented linkage function\n");

        CallInst* linked_ptr = IRB.CreateCall(linkageFunction, { ptr8, valSize, isVectorPtr, isDirty });

        Value* linked_ptr_casted = IRB.CreatePointerCast(linked_ptr, MI->getOperand(ptrOperandIdx)->getType());
		MI->setOperand(ptrOperandIdx, linked_ptr_casted);

		if (is_direct_mstore(ptr_strip_casts) && !is_load_access)
		{
			// Insert a direct store after the MI instruction
			IRB.SetInsertPoint(MI->getNextNode());
			Function* writeback_func = M->getFunction("__cosmix_writeback_" + GetCosmixMetadata(ptr_strip_casts).str());
			assert(writeback_func && "[Error] could not find instrumented writeback function for direct mstore");
	        auto writeback_args = { ptr8, valSize };

			IRB.CreateCall(writeback_func, writeback_args);
		}

		if (opt_HandleCrossPageCachedAccess && !is_load_access)
		{
			IRB.SetInsertPoint(MI->getNextNode());
			Function* writeback_func = M->getFunction("__cosmix_writeback_" + GetCosmixMetadata(ptr_strip_casts).str());
			assert(writeback_func && "[Error] could not find instrumented writeback function for direct mstore");

			IRB.CreateCall(writeback_func);
		}
	}

	void optimizeLoopMemInstruction(SmallPtrSet<Instruction*, 4>& MIs, LoopInfo* LI, DominatorTree* DT, ScalarEvolution* SE, Loop* L) 
	{
		BasicBlock *PreHeader = L->getLoopPreheader();
		BasicBlock *Header = L->getHeader();
		BasicBlock *Latch = L->getLoopLatch();
		
		// New latch - same logic as preheader - hold the values to validate the offsets - copy the same logic there
		BasicBlock* NewLatch = SplitEdge(Latch, Header, DT, LI);
		NewLatch->setName(Latch->getName() + ".loop_opt");

		IRBuilder<> IRB(NewLatch->getTerminator());
		BasicBlock* currBBToLatchFrom = NewLatch;
		for (auto MI : MIs) 
		{
			int memPtrIndex = getMemPointerOperandIdx(MI);
			bool is_load_access = isa<LoadInst>(MI);
			Value* memPtr = MI->getOperand(memPtrIndex);
			uint64_t ptrSize = this->DL->getTypeSizeInBits(memPtr->getType()->getPointerElementType()) / BIT_SIZE;

			std::string linkageFunctionName = COSMIX_PREFIX + "link_" + GetCosmixMetadata(memPtr->stripPointerCasts()).str();
			std::string validIterationsFunctionName = COSMIX_PREFIX + "get_valid_iterations_" + GetCosmixMetadata(memPtr->stripPointerCasts()).str();			
			Function* linkageFunction = M->getFunction(linkageFunctionName);
			Function* validIterationsFunction = M->getFunction(validIterationsFunctionName);
			assert (linkageFunction && "[Error] could not find instrumented linkage function\n");
			assert (validIterationsFunction && "[Error] could not find instrumented linkage function\n");

			// First, set the number of valid iterations remaining
			//
			IRB.SetInsertPoint(Header->getFirstNonPHI());
			int numberOfPredecessors = std::distance(pred_begin(Header), pred_end(Header));
			assert(2 == numberOfPredecessors);
			PHINode* ValidIterationsRemaining_PN = IRB.CreatePHI(IRB.getInt32Ty(), 2);		

			// Next, split and define the new BBs according to a condition based on the valid number of iterations
			//
			IRB.SetInsertPoint(currBBToLatchFrom->getTerminator());
			Value* DecrementedValidIterations = IRB.CreateSub(ValidIterationsRemaining_PN, IRB.getInt32(1));
			Value* TestIfIterationsStillValid = IRB.CreateICmpSLE(DecrementedValidIterations, IRB.getInt32(0));

			TerminatorInst* TI = SplitBlockAndInsertIfThen(TestIfIterationsStillValid,
					currBBToLatchFrom->getTerminator(), false, nullptr, DT, LI);
			BasicBlock* ThenBlock = TI->getParent();
			ThenBlock->setName(NewLatch->getName() + ".then." + MI->getName());
			BasicBlock* AfterBlock = TI->getSuccessor(0);
			AfterBlock->setName(NewLatch->getName() + ".after." + MI->getName());			
			
			// Code at the Prehader:
			// Initialize the linking of the pointers and compute the valid number of iterations
			//
			IRB.SetInsertPoint(PreHeader->getTerminator());					

			const SCEV* ptrSCEV = SE->getSCEV(memPtr);
			const SCEVAddRecExpr *AR = cast<SCEVAddRecExpr>(ptrSCEV);
			SCEVExpander Expander(*SE, *this->DL, "loopscevs");

			Value* stepValue = Expander.expandCodeFor(AR->getStepRecurrence(*SE),
							memPtr->stripPointerCasts()->getType(), PreHeader->getTerminator());

			Value* stepValueInt = IRB.CreatePtrToInt(
					stepValue, IRB.getInt64Ty());

			Value* minusStepValue = IRB.CreateMul(IRB.getInt64(-1), stepValueInt);

			Value* initialValue = Expander.expandCodeFor(AR->getStart(),
							memPtr->stripPointerCasts()->getType(), PreHeader->getTerminator());
			Value* initialValue8 = IRB.CreatePointerCast(initialValue, IRB.getInt8PtrTy());			

			Value* isVectorPtr = IRB.getInt8(isDereferenceableAndAlignedPointer(memPtr, ptrSize, *this->DL, MI));
			Value* isDirty = is_load_access ? IRB.getInt8(0) : IRB.getInt8(1);
			// ArrayRef<Value*> args = { initialValue8, IRB.getInt32(ptrSize), isVectorPtr, isDirty };
			
			CallInst* linked_ptr8 = IRB.CreateCall(linkageFunction, { initialValue8, IRB.getInt32(ptrSize), isVectorPtr, isDirty });
													
			// InitialValidIterations->print(errs(), true);
			// Value* linked_ptr = IRB.CreatePointerCast(linked_ptr8, memPtr->getType());
			// We always move a single step (at every iteration) - so we should decrement this value at the preheader
			//
			Value* linked_ptr_correct_offset8 = IRB.CreateGEP(linked_ptr8, minusStepValue);

			Value* linked_ptr_casted = IRB.CreatePointerCast(linked_ptr_correct_offset8, memPtr->getType());

			// Get the minimum value of the valid iterations of this loop in relation to this MI
			//
			// ArrayRef<Value*> offset_args = { initialValue8, linked_ptr8, stepValueInt, IRB.getInt32(ptrSize) };
			CallInst* InitialValidIterations = IRB.CreateCall(
					validIterationsFunction, { initialValue8, linked_ptr8, stepValueInt, IRB.getInt32(ptrSize) });

			ValidIterationsRemaining_PN->addIncoming(InitialValidIterations, PreHeader);

			// Code at Header:
			// Mutate the linked pointers between loop iterations (one from preheader, one from the latch)
			//
			IRB.SetInsertPoint(Header->getFirstNonPHI());
			
			PHINode* LinkedPtr_PN = IRB.CreatePHI(memPtr->getType(), numberOfPredecessors);
			PHINode* IterationsPassed = IRB.CreatePHI(IRB.getInt64Ty(), numberOfPredecessors);
			Value* LinkedPtr_PN8 = IRB.CreatePointerCast(LinkedPtr_PN, IRB.getInt8PtrTy());
			LinkedPtr_PN->addIncoming(linked_ptr_casted, PreHeader);
			IterationsPassed->addIncoming(IRB.getInt64(1), PreHeader);

			// Note: we set the one from the latch (after block) when we define it and set its logic

			// Fix the memory access operand to the cached value but only after we add the step value
			//
			Value* currentIterationPtr8 = IRB.CreateGEP(LinkedPtr_PN8, stepValueInt);
			Value* currentIterationPtr = IRB.CreatePointerCast(currentIterationPtr8, LinkedPtr_PN->getType());

			Value* ptr_mask_removed = IRB.CreatePointerCast(currentIterationPtr8, LinkedPtr_PN->getType());

			
			MI->setOperand(memPtrIndex, ptr_mask_removed);
			
			// Code at the THEN block:
			// We are at this block when we need to unlink+link since pointers are no longer valid
			//
			IRB.SetInsertPoint(ThenBlock->getFirstNonPHI());
			
			// GEP unlinked ptr to move past the value.
			//
			Value* nextIterationPtr = IRB.CreateGEP(initialValue8, IRB.CreateMul(stepValueInt, IterationsPassed));

			// ArrayRef<Value*> relink_args = { nextIterationPtr, IRB.getInt32(ptrSize), isVectorPtr, isDirty };

			// Call link function
			//
			CallInst* relinked_ptr8 = IRB.CreateCall(linkageFunction, { nextIterationPtr, IRB.getInt32(ptrSize), isVectorPtr, isDirty });

			// Value* relinked_ptr = IRB.CreatePointerCast(relinked_ptr8, memPtr->getType());

			// GEP back so the offset in the next iteration will be correct
			//									  
			Value* relinked_ptr_correct_offset8 = IRB.CreateGEP(relinked_ptr8, minusStepValue);

			Value* relinked_ptr_casted = IRB.CreatePointerCast(relinked_ptr_correct_offset8, memPtr->getType());

			// Find the valid number of iterations for this new linked pointer
			//
			// ArrayRef<Value*> relink_offset_args = { initialValue8, relinked_ptr8, stepValueInt, IRB.getInt32(ptrSize) };
			CallInst* RecomputedValidIterations = IRB.CreateCall(
					validIterationsFunction, { initialValue8, relinked_ptr8, stepValueInt, IRB.getInt32(ptrSize) });			

			// After block:
			// Simply set the Phi node of the pointer for mutation
			//
			IRB.SetInsertPoint(AfterBlock->getFirstNonPHI());
			assert(2 == std::distance(pred_begin(AfterBlock), pred_end(AfterBlock)));
			PHINode* NextLinkedPtr_PN = IRB.CreatePHI(memPtr->getType(), 2);
			PHINode* NextValidIterations_PN = IRB.CreatePHI(IRB.getInt32Ty(), 2);
			NextValidIterations_PN->addIncoming(DecrementedValidIterations, currBBToLatchFrom);
			NextValidIterations_PN->addIncoming(RecomputedValidIterations, ThenBlock);
			ValidIterationsRemaining_PN->addIncoming(NextValidIterations_PN, AfterBlock);

			Value* NextIterationsPassed = IRB.CreateAdd(IterationsPassed, IRB.getInt64(1));
			IterationsPassed->addIncoming(NextIterationsPassed, AfterBlock);

			// If came from the THEN block - use the relinked version we computed
			//
			NextLinkedPtr_PN->addIncoming(relinked_ptr_casted, ThenBlock);

			// Otherwise, its the original pointer, use the value we computed for the MI
			//
			NextLinkedPtr_PN->addIncoming(currentIterationPtr, currBBToLatchFrom);

			// Finally, set the pointer in the header to consider in next iterations either relinked, or a mutable ptr
			//
			LinkedPtr_PN->addIncoming(NextLinkedPtr_PN, AfterBlock);

			// Set the new latching block for next iteration
			//
			currBBToLatchFrom = AfterBlock;

			if (opt_HandleCrossPageCachedAccess)
			{	
				IRB.SetInsertPoint(MI);

				CallInst* linked_ptr_temp = IRB.CreateCall(linkageFunction, { IRB.CreatePointerCast(memPtr, IRB.getInt8PtrTy()), IRB.getInt32(ptrSize), isVectorPtr, isDirty });
				MI->setOperand(memPtrIndex, IRB.CreatePointerCast(linked_ptr_temp, memPtr->getType()));					

				IRB.SetInsertPoint(MI->getNextNode());
				Function* writeback_func = M->getFunction("__cosmix_writeback_" + GetCosmixMetadata(memPtr->stripPointerCasts()).str());
				assert(writeback_func && "[Error] could not find instrumented writeback function for direct mstore");
				IRB.CreateCall(writeback_func);
			}
		}
	}

	Function* getMemIntrinsicFunction(MemIntrinsic *MI, StringRef name) 
	{
		std::string functionName = COSMIX_PREFIX + name.str();
		Function* F = M->getFunction(functionName);

		assert (F && "[ERROR] Invalid instrumentation for memintrinsic, could not find a suitable instrumentation option");
		return F;
	}

	void visitMemIntrinsic(MemIntrinsic *MI) 
	{
		IRBuilder<> IRB(MI);

		if (isa<MemTransferInst>(MI)) 
		{
			if (DONT_HAVE_COSMIX_METADATA(MI->getOperand(0)->stripPointerCasts(), MI) && DONT_HAVE_COSMIX_METADATA(MI->getOperand(1)->stripPointerCasts(), MI)) 
			{
				return;
			}

			auto memmove_args = { IRB.CreatePointerCast(MI->getOperand(0),
					IRB.getInt8PtrTy()), IRB.CreatePointerCast(
					MI->getOperand(1), IRB.getInt8PtrTy()),
					IRB.CreateIntCast(MI->getOperand(2),
							IRB.getInt64Ty(), false) };
			IRB.CreateCall(
				isa<MemMoveInst>(MI) ?
					getMemIntrinsicFunction(MI, "memmove") : 
					getMemIntrinsicFunction(MI, "memcpy"), 
				memmove_args);
		} 
		else if (isa<MemSetInst>(MI)) 
		{
			if (DONT_HAVE_COSMIX_METADATA(MI->getOperand(0)->stripPointerCasts(), MI)) 
			{
				return;
			}
			
			auto memset_args = { IRB.CreatePointerCast(MI->getOperand(0),
					IRB.getInt8PtrTy()), IRB.CreateIntCast(
					MI->getOperand(1), IRB.getInt32Ty(), false),
					IRB.CreateIntCast(MI->getOperand(2),
							IRB.getInt64Ty(), false) };
			IRB.CreateCall(getMemIntrinsicFunction(MI, "memset"), memset_args);
		}

		MI->eraseFromParent();
	}

	void visitInst(Instruction* I, BasicBlock* currBB, LoopInfo* LI, DominatorTree* DT, PostDominatorTree* PDT, AliasAnalysis *AA, ScalarEvolution* SE) 
	{
		// if (VISITED_INST(I)) {
		// 	return;
		// }

		// I->setMetadata(COSMIX_VISITED_STR, COSMIX_VISITED_MDNode);

		if (MemIntrinsic* MI = dyn_cast<MemIntrinsic>(I)) 
		{
			// special case of mem intrinsics (memmove, memset, memcpy) - instrument to use our wrappers
			visitMemIntrinsic(MI);
			return;
		}

		switch (I->getOpcode()) 
		{
		case Instruction::Store:
		case Instruction::Load:
			visitMemInstAndLink(I, LI, DT, AA, SE); // Linking the BS pointers
			break;

		case Instruction::AtomicCmpXchg:
		case Instruction::AtomicRMW:
			visitAtomics(I);
		break;

		case Instruction::Call:
			visitCallInst(cast<CallInst>(I));
			break;			

		default:
			// We ignore the rest of the instructions for the purpose of this pass
			break;
		}
	}

	void visitMainFunc(Function* F, BasicBlock* returnBlock) 
	{
		// initialize our library
		IRBuilder<> IRB(F->getEntryBlock().getFirstNonPHI());
	
		m_CosmixLastInitInstruction = IRB.CreateCall(M->getFunction("__cosmix_initialize"));
		
		for (unsigned int i=0;i<this->num_of_mstores;i++)
		{
			if (this->g_mstores[i].mstore_annotation_found)
			{
				auto initFuncName = "__cosmix_initialize_" + this->g_mstores[i].mstore_annotation_symbol;
				m_CosmixLastInitInstruction = IRB.CreateCall(M->getFunction(initFuncName), ConstantPointerNull::get(IRB.getInt8PtrTy()));
			}
		}

		if (returnBlock != nullptr) 
		{
			Instruction* lastInst = returnBlock->getTerminator();
			IRB.SetInsertPoint(lastInst);

			// TODO: Add flag to request debug method calls in mstores
			// 	IRB.CreateCall(__cosmix_debug_interal);
		}
	}

	// The logic in this pass instruments function by function.
	void visitFunc(Function *F,
			BasicBlock* returnBlock,
			LoopInfo* LI,
			PostDominatorTree* PDT,
			DominatorTree	* DT,
			AliasAnalysis *AA,
			ScalarEvolution* SE) 
	{
		assert(F);
		assert(LI);
		assert(PDT);
		assert(DT);
		assert(AA);
		assert(SE);

		if (!returnBlock) 
		{
			// errs() << "[Warning] - found a function with no valid return block: " << F->getName() << "\n";
		}

		if (COSMIX_FUNC(F))
			return;

		if (!F->hasFnAttribute(Attribute::NoUnwind) && !F->getName().contains("llvm")) 
		{
			// errs() << "[WARNING] found a function that unwinds: " << F->getName() << "\n";
		}

		m_MemInstructionToOptimizeInLoop.clear();

		for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
		{
			for (auto I = BB->begin(); I != BB->end();) 
			{
				auto nextIt = std::next(I);
				Instruction* currInst = &*I;
				BasicBlock* currBB = &*BB;
				
				visitInst(currInst, currBB, LI, DT, PDT, AA, SE);
				I = nextIt;
			}
		}

		for (auto kvp : m_MemInstructionToOptimizeInLoop)
		{
			optimizeLoopMemInstruction(kvp.second, LI, DT, SE, kvp.first);
		}
	}

	void visitAnnotationIntrinsic(IntrinsicInst* II) 
	{
		// Get the pointer with the annotation
		Value* ptr = II->getOperand(0);
		// second operand is a pointer to the string
		Value* str = II->getOperand(1)->stripPointerCasts();
		if (ConstantExpr* CE = dyn_cast<ConstantExpr>(str))
		{
			str = CE->getOperand(0);
		}

		if (GlobalVariable* GV = dyn_cast<GlobalVariable>(str)) 
		{
			Constant* C = GV->getInitializer();
			if (ConstantDataArray* CA = dyn_cast<ConstantDataArray>(C)) 
			{
				StringRef name(CA->getAsCString());
				
				bool found = false;
				for (unsigned int i=0;i<this->num_of_mstores;i++)
				{
					if (name == this->g_mstores[i].mstore_annotation_symbol)
					{
						this->g_mstores[i].mstore_annotation_found = true;
						found = true;
						break;
					}
				}

				if (found)
				{
					// Note: we assume that in cosmix there is no double annotation of mstores for a single variable
					assert(isa<AllocaInst>(ptr->stripPointerCasts()));
					visitStackAllocation((AllocaInst*)ptr->stripPointerCasts(), name);
					
					m_NumOfInstrumentedAllocations++;
			 }
			}
		}
	}

	StringRef getAnnotationName(Function* F, bool* is_mem_mstore)
	{
		if (!F)
		{
			return "";
		}

		for (unsigned int i=0;i<this->num_of_mstores;i++)
		{
			if (F->getName().equals(this->g_mstores[i].mstore_function_annotation_name))
			{				
				*is_mem_mstore = this->g_mstores[i].storage_type == "mem";
				return this->g_mstores[i].mstore_annotation_symbol;
			}
		}
		
		return "";
	}

	void visitGlobalAnnotations()
	{
		// Go over global annotations
		//
		if(GlobalVariable* GA = M->getGlobalVariable("llvm.global.annotations")) 
		{
			// the first operand holds the metadata
			for (Value *AOp : GA->operands()) 
			{
				// all metadata are stored in an array of struct of metadata
				if (ConstantArray *CA = dyn_cast<ConstantArray>(AOp)) 
				{
					// so iterate over the operands
					for (Value *CAOp : CA->operands()) 
					{
						// get the struct, which holds a pointer to the annotated function
						// as first field, and the annotation as second field
						if (ConstantStruct *CS = dyn_cast<ConstantStruct>(CAOp)) 
						{
							if (CS->getNumOperands() >= 2) 
							{
								// the second field is a pointer to a global constant Array that holds the string
								if (GlobalVariable *GAnn = dyn_cast<GlobalVariable>(CS->getOperand(1)->getOperand(0))) 
								{
									if (ConstantDataArray *A = dyn_cast<ConstantDataArray>(GAnn->getOperand(0))) 
									{
										// we have the annotation! Check it's an epona annotation and process
										StringRef AS1 = A->getAsString();
										const char* temp = AS1.str().c_str();
										std::string temp1 = temp;

										if (isa<GlobalVariable>(CS->getOperand(0)->getOperand(0))) 
										{
											bool found = false;
											for (unsigned int i=0;i<this->num_of_mstores;i++)
											{
												if (temp1 == this->g_mstores[i].mstore_annotation_symbol)
												{
													this->g_mstores[i].mstore_annotation_found = true;
													found = true;
													break;
												}
											}

											if (found)
											{
												GlobalVariable* annotatedGV = dyn_cast<GlobalVariable>(CS->getOperand(0)->getOperand(0));
												// Note: we assume that in cosmix there is no double annotation of mstores for a single variable
												visitGlobalDefinition(annotatedGV, temp1);
												m_NumOfInstrumentedAllocations++;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	void visitDeclerationAnnotations()
	{
		for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
		{
			if (F->isDeclaration() || COSMIX_FUNC(F)) 
			{
				continue;
			}

			for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
			{
				for (auto I = BB->begin(); I != BB->end();) 
				{
					auto nextIt = std::next(I);

					if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(I)) 
					{
						// look for in-code annotations
						if (II->getIntrinsicID() == Intrinsic::var_annotation ||
								II->getIntrinsicID() == Intrinsic::ptr_annotation ||
								II->getIntrinsicID() == Intrinsic::annotation) 
						{
							visitAnnotationIntrinsic(II);
						}
					}
					
					I = nextIt;
				}
			}
		}
	}

	void visitAnnotations() 
	{
		for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
		{
			if (F->isDeclaration() || COSMIX_FUNC(F)) 
			{
				continue;
			}

			for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
			{
				for (auto I = BB->begin(); I != BB->end();) 
				{
					auto nextIt = std::next(I);
/*
					if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(I)) 
					{
						// look for in-code annotations
						if (II->getIntrinsicID() == Intrinsic::var_annotation ||
								II->getIntrinsicID() == Intrinsic::ptr_annotation ||
								II->getIntrinsicID() == Intrinsic::annotation) 
						{
							visitAnnotationIntrinsic(II);
						}
					}
*/
					if (CallInst* CI = dyn_cast<CallInst>(I)) 
					{
						Function* F_call = dyn_cast<Function>(CI->getCalledValue()->stripPointerCasts());

						bool is_mem_mstore;
						StringRef annotation_name = getAnnotationName(F_call, &is_mem_mstore);
						if (!annotation_name.equals(""))
						{
							Value* val = CI->getArgOperand(0);				
							assert (isa<CallInst>(val) && "Annotation should be used only on a called allocation function");
							CallInst* internalCI = cast<CallInst>(val);
							Function* allocFunction = dyn_cast<Function>(internalCI->getCalledValue()->stripPointerCasts());

							assert ((isDynamicAllocationFunction(allocFunction) || isMemoryMappingFunction(allocFunction)) 
									&& "[ERROR] COSMIX annotation expected to be used on memory allocation functions\n");

							// TODO: restore this logic
							// if (isAllocationKnownToBeOutOfBounds(internalCI))
							// {
							// 	// If we can statically prove that this does not have correct bounds we can ignore its instrumentation
							// 	//
							// 	I = nextIt;
							// 	continue; 
							// }

							// Next - replace the internal allocation function with a forced one
							IRBuilder<> IRB(CI);
							std::string cosmixAllocationFunctionName;
							if (!is_mem_mstore)
							{
								cosmixAllocationFunctionName = COSMIX_PREFIX + allocFunction->getName().str() + "_" + annotation_name.str();
							}
							else
							{
								StringRef allocationFunctionName = getAllocationFunctionName(allocFunction->getName());
								cosmixAllocationFunctionName = COSMIX_PREFIX + allocationFunctionName.str() + "_" + annotation_name.str();
							}

							Function* cosmixAllocationFunction = M->getFunction(cosmixAllocationFunctionName);
							errs() << "[INFO] replacing alloc func: " << cosmixAllocationFunctionName << "\n";
							assert(cosmixAllocationFunction && "[ERROR] Could not find an appropriate allocation function to instrument according to the given annotation\n");
							internalCI->setCalledFunction(cosmixAllocationFunction);
							Value* internalCI_casted = IRB.CreatePointerCast(internalCI, CI->getType());
							CI->replaceAllUsesWith(internalCI_casted);
							internalCI_casted->takeName(CI);
							CI->eraseFromParent();
							assert(!m_AnnotatedVars.count(internalCI_casted));
							m_AnnotatedVars[internalCI_casted] = annotation_name;

							m_NumOfInstrumentedAllocations++;

							for (unsigned int i=0;i<this->num_of_mstores;i++)
							{
								if (F_call->getName().equals(this->g_mstores[i].mstore_function_annotation_name))
								{
									this->g_mstores[i].mstore_annotation_found = true;

									// Found it, can exit the mstore loop
									//
									break;
								}
							}
						}
					}

					I = nextIt;
				}
			}
		}
	}

	StringRef getAllocationFunctionName(StringRef name)
	{
		if (name.contains("malloc"))
		{
			return "malloc";
		}

		if (name.contains("calloc"))
		{
			return "calloc";
		}

		if (name.contains("realloc"))
		{
			return "realloc";
		}

		if (name.contains("memalign"))
		{
			return "memalign";
		}

		assert(false && "[ERROR] Invalid allocation function encouterned while trying to set annotation\n");
		return "";
	}

	bool isDynamicReallocationFunction(Function* F) 
	{
		auto name = F->getName();

		bool res = name.equals("realloc") || 
				   name.equals("je_realloc") ||
				   name.equals("tc_realloc");

		return res;
	}

	bool isMemoryMappingFunction(Function* F)
	{
		auto name = F->getName();

		return name.equals("mmap") || name.equals("mmap64"); 
	}

	bool isDynamicAllocationFunction(Function* F) 
	{
		auto name = F->getName();
		
		bool res = name.equals("malloc") || 
			   name.equals("calloc") || 
			   name.equals("realloc") ||
			   name.equals("memalign") ||
			   name.equals("je_malloc") || 
			   name.equals("je_calloc") || 
			   name.equals("je_realloc") ||
			   name.equals("tc_malloc") || 
			   name.equals("tc_calloc") || 
			   name.equals("tc_realloc");

		return res;
	}

	StringRef findIntAnnotationSymbol(Value* val, SmallPtrSet<Value*, 4>& visitedValues)
	{		
		// Observation: int transformed to pointers have been pointers. If not, they should not have annotation		
		
		// If its cross function or a load - we can't know for sure the origin of this pointer
		// use the annotation we already identified in this pass
		//
		if (isa<Argument>(val) || isa<LoadInst>(val))
		{
			// if multiple defined symbols found, use the generic symbol since we can't differentiate between them statically
			//
			int numAnnotationFound = 0;
			StringRef annotationSymbol;

			for (unsigned int i=0;i<this->num_of_mstores;i++)
			{
				if (this->g_mstores[i].mstore_annotation_found)
				{
					annotationSymbol = this->g_mstores[i].mstore_annotation_symbol;
					numAnnotationFound++;
				}
			}

			if (numAnnotationFound > 1)
			{
				return GENERIC_ANNOTATION_SYMBOL;
			}

			if (numAnnotationFound == 1)
			{
				return annotationSymbol;
			}

			// Otherwise, there is no way that there is an annotation here since no mstore was used in allocation process
			//
			return "";
		}

		if (visitedValues.count(val))
		{
			// Not found for this value already, otherwise we would've returned beforehand
			//
			return "";
		}

		visitedValues.insert(val);
	
		// We found the original pointer - return it's annotation symbol
		//
		if (isa<PtrToIntInst>(val) || isa<GlobalVariable>(val))
		{
			NodeID targetNode = m_PAG->getValueNode(val);
			if (m_ValuesToInstrumentMap.count(targetNode))
			{
				return m_ValuesToInstrumentMap[targetNode];
			}
			
			// Otherwise, there is no annotation - return an empty string
			//
			return "";
		}		

		// For every other instruction we attempt to get the values from its operands
		//
		if (Instruction* I = dyn_cast<Instruction>(val))
		{
			for (unsigned int i=0;i<I->getNumOperands();i++)
			{
				StringRef res = findIntAnnotationSymbol(I->getOperand(i)->stripPointerCasts(), visitedValues);
				if (res != "")
				{
					return res;
				}
			}
		}

		// No symbol found, meaning its a regular pointer
		//
		return "";
	}

	void visitAllInt2Ptr()
	{
		for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
		{
			if (F->isDeclaration() || COSMIX_FUNC(F) || LLVM_FUNC(F)) 
			{
				continue;
			}

			for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
			{
				for (auto I = BB->begin(); I != BB->end();) 
				{
					auto nextIt = std::next(I);

					if (IntToPtrInst* IP = dyn_cast<IntToPtrInst>(I)) 
					{
						if (!m_AnnotatedVars.count(IP)) 
						{
							SmallPtrSet<Value*, 4> visited;
							StringRef annotationSymbol = findIntAnnotationSymbol(IP->getOperand(0)->stripPointerCasts(), visited);
							if (annotationSymbol != "")
							{
								m_AnnotatedVars[IP] = annotationSymbol;
							}
						}
					}

					I = nextIt;
				}
			}
		}
	}

	bool isAllocationKnownToBeOutOfBounds(CallInst* CI, size_t lowerBound, size_t upperBound)
	{		
		uint64_t arg_val = 1;
		Function* F = dyn_cast<Function>(CI->getCalledValue()->stripPointerCasts());

		int opIndex = F->getName().contains("malloc") ? 0 : 1;

		if (F->getName().contains("calloc"))
		{
			Value* arg = CI->getArgOperand(0);
			if (!isa<Constant>(arg))
			{
				return false;
			}

			arg_val = dyn_cast<Constant>(arg)->getUniqueInteger().getLimitedValue();
		}

		Value* arg = CI->getArgOperand(opIndex);
		if (!isa<Constant>(arg))
		{
			return false;
		}

		arg_val *= dyn_cast<Constant>(arg)->getUniqueInteger().getLimitedValue();
		bool out_of_bounds = arg_val < lowerBound || arg_val >= upperBound;
		return out_of_bounds;
	}

	void visitAllocationCallSites() 
	{
		for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
		{
			if (F->isDeclaration() || COSMIX_FUNC(F) || LLVM_FUNC(F)) 
			{
				continue;
			}

			for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
			{
				for (auto I = BB->begin(); I != BB->end();) 
				{
					auto nextIt = std::next(I);

					// TODO: should use callsite actually
					//
					if (CallInst* CI = dyn_cast<CallInst>(I)) 
					{
						Function* F_call = dyn_cast<Function>(CI->getCalledValue()->stripPointerCasts());

						if (!F_call) 
						{
							I = nextIt;
							continue;
						}

						for (unsigned int i=0;i<this->num_of_mstores;i++)
						{							
							if (this->g_mstores[i].boundBasedAllocation && 
								isDynamicAllocationFunction(F_call) && 
							//	!isAllocationKnownToBeOutOfBounds(CI, this->g_mstores[i].lowerBound, this->g_mstores[i].upperBound) &&
								!m_AnnotatedVars.count(CI)) 
							{
								m_NumOfInstrumentedAllocations++;
								m_AnnotatedVars[CI] = this->g_mstores[i].mstore_annotation_symbol;
								this->g_mstores[i].mstore_annotation_found = true;								
								StringRef allocationFunctionName = getAllocationFunctionName(F_call->getName());
								std::string cosmixAllocationFunctionName = COSMIX_PREFIX + allocationFunctionName.str() + "_" + this->g_mstores[i].mstore_annotation_symbol;
								Function* cosmixAllocationFunction = M->getFunction(cosmixAllocationFunctionName);
								assert(cosmixAllocationFunction && "[ERROR] Could not find an appropriate allocation function to instrument according to the given allocation\n");
								CI->setCalledFunction(cosmixAllocationFunction);

								// No need to continue searching - note for multiple bounds based mstores, we need to have better runtime support
								// to detect the correct type dynamically.
								//
								break;
							}						
						}

						// TODO: add flag that allows instrumenting all memory mapping requests and uncomment this code
						// if (isMemoryMappingFunction(F_call))
						// {
						// 	if (!m_AnnotatedVars.count(CI)) {
						// 		m_NumOfInstrumentedAllocations++;
						// 		m_AnnotatedVars[CI] = STORAGE_ANNOTATION_SYMBOL;
						// 		m_StorageFound = true;

						// 		StringRef allocationFunctionName = F_call->getName();
						// 		std::string cosmixAllocationFunctionName = COSMIX_PREFIX + allocationFunctionName.str() + FORCE_SUFFIX;
						// 		Function* cosmixAllocationFunction = M->getFunction(cosmixAllocationFunctionName);
						// 		assert(cosmixAllocationFunction && "[ERROR] Could not find an appropriate mapping  function to instrument\n");
						// 		CI->setCalledFunction(cosmixAllocationFunction);
						// 	}
						// }
					}
					
					I = nextIt;
				}
			}
		}
	}

	// Note: can use the application indirection module.
	void 
	RunDataflowAnalysis(bool debug_print) 
	{
		for (auto kvp : m_AnnotatedVars) 
		{
			Value* annotatedVar = kvp.first;			

			if (debug_print)
			{
				errs() << "[DBG] Running pointer analysis in function: " << cast<Instruction>(annotatedVar)->getFunction()->getName() << " for annotated var: ";
				annotatedVar->print(errs(), true);
				errs() << "\n";
			}

			// Get the node id for the annoated variable we analyze
			//
			NodeID targetNode = m_PAG->getValueNode(annotatedVar);

			// Add this annotated var as the root for instrumentation
			//
			auto cnt = m_ValuesToInstrumentMap.count(targetNode);
			if (cnt == 0 || (cnt == 1 && m_ValuesToInstrumentMap[targetNode] == kvp.second))
			{
				m_ValuesToInstrumentMap[targetNode] = kvp.second;
			}
			else
			{
				m_ValuesToInstrumentMap[targetNode] = GENERIC_ANNOTATION_SYMBOL;
			}
		}

		for (auto nIter = m_PTA->getAllValidPtrs().begin();
				 nIter != m_PTA->getAllValidPtrs().end(); ++nIter) 
		{
			for (auto kvp : m_AnnotatedVars) 
			{
				Value* annotatedVar = kvp.first;
				// Get the node id for the annoated variable we analyze
				//
				NodeID targetNode = m_PAG->getValueNode(annotatedVar);

				// search for aliases to the current node
				//
				if (m_PTA->alias(*nIter, targetNode) != NoAlias)
				{
					auto cnt = m_ValuesToInstrumentMap.count(targetNode);
					if (cnt == 0 || (cnt == 1 && m_ValuesToInstrumentMap[targetNode] == kvp.second))
					{
						m_ValuesToInstrumentMap[*nIter] = kvp.second;
					}
					else
					{
						m_ValuesToInstrumentMap[*nIter] = GENERIC_ANNOTATION_SYMBOL;
					}
				}
			}
		}		
	}

	void gatherStatistics() 
	{		
		for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
		{
			if (F->isDeclaration() || COSMIX_FUNC(F) || LLVM_FUNC(F))
				continue;

			for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
			{
				for (auto I = BB->begin(); I != BB->end();) 
				{
					auto nextIt = std::next(I);					

					if (isa<LoadInst>(&*I) || isa<StoreInst>(&*I)) 
					{
						m_NumOfInstructions++;
						int opIndex = getMemPointerOperandIdx(&*I);
						Value* ptr = I->getOperand(opIndex)->stripPointerCasts();
						if (!DONT_HAVE_COSMIX_METADATA(ptr, &*I)) 
						{
							m_NumOfMemoryAccessInstrumented++;
						}
					}

					I = nextIt;
				}
			}
		}
	}

	void printStatistics() 
	{
		double cosmix_ratio = (double)m_NumOfMemoryAccessInstrumented/m_NumOfInstructions;
		cosmix_ratio *= 100;

	   std::stringstream Str;
	   Str << std::setprecision(2) << cosmix_ratio;

		errs() << "[INFO] Total number of allocation calls instrumented " << m_NumOfInstrumentedAllocations << "\n";
		errs() << "[INFO] Total number of memory access instructions: " << m_NumOfInstructions << "; Instrumented memory instructions are : " << Str.str() << "%\n";
		errs() << "[INFO] Total number of memory instructions accessed in loops: " << m_NumOfMemInstInLoops << "; #optimized: " << m_NumOfOptMemInstInLoops << "\n";
	}

	bool isCosmixInlineCandidateFunction(Function* F)
	{
		// For now just the memory instrumentation ones.
		std::string linkageFunctionPrefix = COSMIX_PREFIX + "link_";
		return F->getName().startswith(linkageFunctionPrefix);
	}

	void tryInlineFunction(std::string funcName)
	{
		Function* F = M->getFunction(funcName);
		assert(F);
		SmallPtrSet<CallInst*, 4> CIs;

		for (auto User : F->users())
		{
			CallInst* CI = dyn_cast<CallInst>(&*User);
			if(CI && !CIs.count(CI))
			{
				CIs.insert(CI);
			}
		}

		for (auto CI : CIs)
		{
                        InlineFunctionInfo ifi;
                        InlineFunction(CI, ifi);
		}
	}

	void tryInlineFunctions()
	{
		std::string linkageFunctionPrefix = COSMIX_PREFIX + "link_";
		std::string writebackFunctionPrefix = COSMIX_PREFIX + "writeback_";
		// Do it for all possible functions
		//
		tryInlineFunction(linkageFunctionPrefix + GENERIC_ANNOTATION_SYMBOL);
		tryInlineFunction(writebackFunctionPrefix + GENERIC_ANNOTATION_SYMBOL);

		for (unsigned int i=0;i<this->num_of_mstores;i++)
		{
			if (this->g_mstores[i].mstore_annotation_found)
			{
				tryInlineFunction(linkageFunctionPrefix + this->g_mstores[i].mstore_annotation_symbol);

				if (this->g_mstores[i].mstore_type == "direct")
				{
					tryInlineFunction(writebackFunctionPrefix + this->g_mstores[i].mstore_annotation_symbol);
				}
			}
		}
	}

	void SetAnnotationSymbol(unsigned int mstore_index, std::string annotation_symbol)
	{
		assert (mstore_index < num_of_mstores);
		g_mstores[mstore_index].mstore_annotation_symbol = annotation_symbol;
	}

	void ReplaceGlobalInFunction(std::string functionName, std::string globalName, std::string newGlobalName)
	{
		Function* F = M->getFunction(functionName);
		GlobalVariable* oldGlobal = M->getGlobalVariable(globalName);
		GlobalVariable* newGlobal = M->getGlobalVariable(newGlobalName);
		assert(F);
		assert(oldGlobal);
		assert(newGlobal);

		for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
		{
			for (auto I = BB->begin(); I != BB->end();) 
			{
				auto nextIt = std::next(I);

				for (unsigned int i=0; i< I->getNumOperands(); i++)
				{
					Value* val = I->getOperand(i)->stripPointerCasts();
					if (val == oldGlobal)
					{
						IRBuilder<> IRB(&*I);
						Value* casted = IRB.CreatePointerCast(newGlobal, I->getOperand(i)->getType());
						I->setOperand(i, casted);
					}

					if (ConstantExpr* CE = dyn_cast<ConstantExpr>(val))
					{
						val = CE->getOperand(0)->stripPointerCasts();
						if (val == oldGlobal)
						{
							IRBuilder<> IRB(&*I);
							CE->handleOperandChange(oldGlobal, newGlobal);
						}
					}
				}

				I = nextIt;
			}
		}
	}
	
	void CreateMstoreGlobalVar(unsigned int mstore_index, std::string mstore_name, std::string globalName)
	{
		assert (mstore_index < num_of_mstores);

		for (auto G = M->global_begin(), Gend = M->global_end(); G != Gend; ++G) 
		{
			if (G->getName().equals(globalName))
			{
				IRBuilder<> IRB(M->getContext());
				GlobalVariable* newG = new GlobalVariable(*M, 
														G->getValueType(), 
														G->isConstant(), 
														G->getLinkage(), 
														G->getInitializer(), 
														globalName + "_" + mstore_name, 
														&*G, 
														G->getThreadLocalMode(), 
														G->getType()->getAddressSpace());
				newG->copyAttributesFrom(&*G);

				return;
			}
		}

		assert (false && "Could not find global value to instrument for mstore");
	}

	void CreateMstoreFunction(std::string functionName, std::string newFunctionName)
	{
		Function* F = M->getFunction(functionName);
		assert(F);

		ValueToValueMapTy VMap;
		Function* mstore_F = CloneFunction(F, VMap);
		mstore_F->setName(newFunctionName);
	}

	void SetMstoreFunctionIndexOp(unsigned int mstore_index, std::string functionName, std::string callbackName, int opIndex)
	{
		assert (mstore_index < num_of_mstores);

		Function* F = M->getFunction(functionName);
		assert(F);

		for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
		{
			for (auto I = BB->begin(); I != BB->end();) 
			{
				auto nextIt = std::next(I);

				CallInst* CI = dyn_cast<CallInst>(I);

				if (CI && CI->getCalledFunction() && CI->getCalledFunction()->getName().equals(callbackName))
				{
					IRBuilder<> IRB(CI);
					CI->setOperand(opIndex, IRB.getInt32(mstore_index));
				}

				I = nextIt;
			}
		}
	}

	void SetMstoreFunction(std::string functionName, std::string callbackName, std::string replaceFuncName)
	{
		Function* F = M->getFunction(functionName);
		assert(F);

		for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
		{
			for (auto I = BB->begin(); I != BB->end();) 
			{
				auto nextIt = std::next(I);

				CallInst* CI = dyn_cast<CallInst>(I);
				if (CI && CI->getCalledFunction() && CI->getCalledFunction()->getName().equals(callbackName))
				{
					Function* origFunc = CI->getCalledFunction();
					Function* mstore_init_func = M->getFunction(replaceFuncName);

					if (!mstore_init_func)
						mstore_init_func = Function::Create(cast<FunctionType>(origFunc->getValueType()), GlobalValue::ExternalLinkage, replaceFuncName, M);

					CI->setCalledFunction(mstore_init_func);
				}

				I = nextIt;
			}
		}
	}

	void ReplaceFunctionWithConst(std::string functionName, std::string callbackName, size_t val)
	{
		Function* F = M->getFunction(functionName);
		assert(F);

		for (auto BB = F->begin(), BBend = F->end(); BB != BBend; ++BB) 
		{
			for (auto I = BB->begin(); I != BB->end();) 
			{
				auto nextIt = std::next(I);

				CallInst* CI = dyn_cast<CallInst>(I);
				if (CI && CI->getCalledFunction() && CI->getCalledFunction()->getName().equals(callbackName))
				{
					IRBuilder<> IRB(CI);
					Value* constVal = IRB.getInt64(val);

					CI->replaceAllUsesWith(constVal);
					constVal->takeName(CI);
					CI->eraseFromParent();
				}

				I = nextIt;
			}
		}
	}

	void ReplaceMstoreFunction(std::string origFuncName, std::string mstoreFuncName)
	{
		Function* origFunc = M->getFunction(origFuncName);
		Function* mstoreFunc = M->getFunction(mstoreFuncName);
		assert(origFunc);
		assert(mstoreFunc);

		origFunc->replaceAllUsesWith(mstoreFunc);
	}

	void CreateFunctionDeclaration(std::string origFuncName, std::string newFuncName)
	{
		Function* F = M->getFunction(origFuncName);
		if (F)
		{
			Function::Create(cast<FunctionType>(F->getValueType()), GlobalValue::ExternalLinkage, newFuncName, M);
		}
	}

	void ReplaceAllocatorFunctionDeclarations(std::string functionName1, std::string functionName2)
	{
		Function* F1 = M->getFunction(functionName1);
		Function* F2 = M->getFunction(functionName2);
		assert(F1);
		assert(F2);

		if (F1 && F2)
		{
			F1->replaceAllUsesWith(F2);
		}
	}

	void CreateAllocationFunctions()
	{
		for ( unsigned int index = 0; index < this->num_of_mstores; ++index )  
		{
			std::string mstore_name = this->g_mstores[index].mstore_annotation_symbol;

			if (this->g_mstores[index].storage_type == "mem")
			{
				ReplaceAllocatorFunctionDeclarations("__cosmix_malloc_" + mstore_name, "__cosmix_malloc_" + mstore_name + ".temp");
				ReplaceAllocatorFunctionDeclarations("__cosmix_calloc_" + mstore_name, "__cosmix_calloc_" + mstore_name + ".temp");
				ReplaceAllocatorFunctionDeclarations("__cosmix_memalign_" + mstore_name, "__cosmix_memalign_" + mstore_name + ".temp");
			}
			else
			{
				ReplaceAllocatorFunctionDeclarations("__cosmix_mmap_" + mstore_name, "__cosmix_mmap_" + mstore_name + ".temp");
			}
		}
	}

	void CreateMstoreFunctionAnnotation(std::string funcName)
	{
		Function* F = M->getFunction(funcName);
		// assert(F);
		if (!F || F->isDeclaration())
		{
			Function* templateF = M->getFunction("__cosmix_mstore_annotation");
			assert (templateF);
			ValueToValueMapTy VMap;
			Function* mstore_F = CloneFunction(templateF, VMap);
			if (F)
			{
				F->replaceAllUsesWith(mstore_F);
				mstore_F->takeName(F);
				F->eraseFromParent();
			}
			else
			{
				mstore_F->setName(funcName);
			}
		}
	}

	void ParseConfigurationFile()
	{
		//assert (access(opt_ConfigFile.c_str(), F_OK) != -1 );

		// starts as "null"; will contain the root value after parsing
		Json::Value root; 

		std::ifstream inFile;
		inFile.open(opt_ConfigFile);
		assert (inFile);

		inFile >> root;

		inFile.close();

		// Get the value of the member of root named 'mstores'; return a 'null' value if
		// there is no such member.
		const Json::Value mstores = root["mstores"];
		assert(mstores);

		this->num_of_mstores = mstores.size();
		this->g_mstores = new struct s_mstore[this->num_of_mstores];
		for (unsigned int i = 0; i < this->num_of_mstores; i++)
		{
			this->g_mstores[i].boundBasedAllocation = false;
			this->g_mstores[i].mstore_annotation_found = false;
		}

		int numFileMstores = 0;

		// Iterates over the sequence elements.
		for ( unsigned int index = 0; index < mstores.size(); ++index )  
		{
			auto mstore = mstores[index];
			SetAnnotationSymbol(index, mstore["annotation_symbol"].asString());

			std::string mstore_type = mstore["type"].asString();
			std::string storage_type = mstore["storage"].asString();
			std::string function_annotation_name = mstore["function_annotation_name"].asString();
			this->g_mstores[index].mstore_type = mstore_type;
			this->g_mstores[index].storage_type = storage_type;
			this->g_mstores[index].mstore_function_annotation_name = function_annotation_name;

			CreateMstoreFunctionAnnotation(function_annotation_name);
			
			this->g_mstores[index].boundBasedAllocation = mstore["BoundsAllocation"].asBool();

			if (this->g_mstores[index].boundBasedAllocation)
			{
				this->g_mstores[index].lowerBound = mstore["LowerBound"].asInt64();
				this->g_mstores[index].upperBound = mstore["UpperBound"].asInt64();
			}

			std::string mstore_name = mstore["name"].asString();

			// init
			//
			CreateMstoreFunction("__cosmix_initialize_template", "__cosmix_initialize_" + mstore_name);
			SetMstoreFunction("__cosmix_initialize_" + mstore_name, "mstore_init", mstore_name + "_mstore_init");

			CreateMstoreFunction("__cosmix_init_global_template", "__cosmix_init_global_" + mstore_name);
			SetMstoreFunction("__cosmix_init_global_" + mstore_name, "mstore_alloc", mstore_name + "_mstore_alloc");
			SetMstoreFunction("__cosmix_init_global_" + mstore_name, "mstore_tag", "mstore_tag_" + std::to_string(index));

			// cleanup
			//
			CreateMstoreFunction("__cosmix_cleanup_template", "__cosmix_cleanup_" + mstore_name);
			SetMstoreFunction("__cosmix_cleanup_" + mstore_name, "mstore_cleanup", mstore_name + "_mstore_cleanup");			

			// direct/cached runtime classifications
			//
			for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
			{
				if (F->getName().equals("_" + std::to_string(index) + "_is_direct")) 
				{
					Function* mstoreFunc = mstore_type == "direct" ? M->getFunction("mstore_is_direct_true") : M->getFunction("mstore_is_direct_false");
					assert(mstoreFunc);
					F->replaceAllUsesWith(mstoreFunc);
				}
			}

			if (storage_type == "file")
			{
				numFileMstores++;

				// File allocators, i.e., mmap
				CreateFunctionDeclaration("mmap", "__cosmix_mmap_" + mstore_name);				

				CreateMstoreFunction("__cosmix_mmap_template", "__cosmix_mmap_" + mstore_name + ".temp");
				SetMstoreFunction("__cosmix_mmap_" + mstore_name + ".temp", "mstore_alloc", mstore_name + "_mstore_alloc");
				SetMstoreFunction("__cosmix_mmap_" + mstore_name + ".temp", "mstore_tag", "mstore_tag_" + std::to_string(index));

				// CreateMstoreFunction("__cosmix_mmap64_template", "__cosmix_mmap64_" + mstore_name);
				// SetMstoreFunction("__cosmix_mmap64_" + mstore_name, "mstore_alloc", mstore_name + "_mstore_alloc");				
				// SetMstoreFunctionIndexOp(index, "__cosmix_mmap64_" + mstore_name, "mstore_tag", 2);

				for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
				{					
					if (F->getName().equals("mstore_read")  || 
						F->getName().equals("mstore_write") ||
						F->getName().equals("mstore_open")  ||
						F->getName().equals("mstore_close"))
					{
						std::string funcName = mstore_name + "_" + F->getName().str();
						Function* mstoreFunc = M->getFunction(funcName);
						// assert(mstoreFunc);
						if (!mstoreFunc)
						{
							mstoreFunc = Function::Create(cast<FunctionType>(F->getValueType()), GlobalValue::ExternalLinkage, funcName, M);
						}

						F->replaceAllUsesWith(mstoreFunc);
					}
				}
			}
			else if (storage_type == "mem")
			{	
				// Mem allocators, i.e., malloc, calloc, etc
				//
				CreateFunctionDeclaration("malloc", "__cosmix_malloc_" + mstore_name);				
				CreateFunctionDeclaration("calloc", "__cosmix_calloc_" + mstore_name);				
				CreateFunctionDeclaration("memalign", "__cosmix_memalign_" + mstore_name);

				CreateMstoreFunction("__cosmix_malloc_template", "__cosmix_malloc_" + mstore_name + ".temp");
				SetMstoreFunction("__cosmix_malloc_" + mstore_name + ".temp", "mstore_alloc", mstore_name + "_mstore_alloc");
				SetMstoreFunction("__cosmix_malloc_" + mstore_name + ".temp", "mstore_tag", "mstore_tag_" + std::to_string(index));

				if (!this->g_mstores[index].boundBasedAllocation)
				{
					SetMstoreFunction("__cosmix_malloc_" + mstore_name + ".temp", "mstore_get_min_size", "deafult_mstore_get_min_size");
					SetMstoreFunction("__cosmix_malloc_" + mstore_name + ".temp", "mstore_get_max_size", "deafult_mstore_get_max_size");
				}
				else
				{
					ReplaceFunctionWithConst("__cosmix_malloc_" + mstore_name + ".temp", "mstore_get_min_size", this->g_mstores[index].lowerBound);
					ReplaceFunctionWithConst("__cosmix_malloc_" + mstore_name + ".temp", "mstore_get_max_size", this->g_mstores[index].upperBound);
				}
				
				CreateMstoreFunction("__cosmix_calloc_template", "__cosmix_calloc_" + mstore_name + ".temp");
				SetMstoreFunction("__cosmix_calloc_" + mstore_name + ".temp", "__cosmix_malloc_template", "__cosmix_malloc_" + mstore_name);
				SetMstoreFunction("__cosmix_calloc_" + mstore_name + ".temp", "mstore_alloc", mstore_name + "_mstore_alloc");
				SetMstoreFunction("__cosmix_calloc_" + mstore_name + ".temp", "mstore_tag", "mstore_tag_" + std::to_string(index));

				if (!this->g_mstores[index].boundBasedAllocation)
				{
					SetMstoreFunction("__cosmix_calloc_" + mstore_name + ".temp", "mstore_get_min_size", "deafult_mstore_get_min_size");
					SetMstoreFunction("__cosmix_calloc_" + mstore_name + ".temp", "mstore_get_max_size", "deafult_mstore_get_max_size");
				}
				else
				{
					ReplaceFunctionWithConst("__cosmix_calloc_" + mstore_name + ".temp", "mstore_get_min_size", this->g_mstores[index].lowerBound);
					ReplaceFunctionWithConst("__cosmix_calloc_" + mstore_name + ".temp", "mstore_get_max_size", this->g_mstores[index].upperBound);
				}

				CreateMstoreFunction("__cosmix_memalign_template", "__cosmix_memalign_" + mstore_name + ".temp");
				SetMstoreFunction("__cosmix_memalign_" + mstore_name + ".temp", "mstore_alloc", mstore_name + "_mstore_alloc");
				SetMstoreFunction("__cosmix_memalign_" + mstore_name + ".temp", "mstore_tag", "mstore_tag_" + std::to_string(index));
			}
			else
			{
				assert (false && "CoSMIX only supports mstorage of memory or files for now");
			}

			if (mstore_type == "cached")
			{
				SetMstoreFunction("__cosmix_initialize_" + mstore_name, "mstore_is_direct", "mstore_is_direct_false");

				CreateMstoreFunction("__cosmix_get_valid_iterations_template", "__cosmix_get_valid_iterations_" + mstore_name);
				SetMstoreFunction("__cosmix_get_valid_iterations_" + mstore_name, "mstore_get_mpage_size", mstore_name + "_mstore_get_mpage_size");
				SetMstoreFunction("__cosmix_get_valid_iterations_" + mstore_name, "mstore_get_mpage_cache_base_ptr", mstore_name + "_mstore_get_mpage_cache_base_ptr");

				if (!opt_HandleCrossPageCachedAccess)
				{
					CreateMstoreFunction("__cosmix_link_cached_template", "__cosmix_link_" + mstore_name);
				}
				else
				{
					CreateMstoreFunction("__cosmix_link_cached_cross_page_template", "__cosmix_link_" + mstore_name);
					CreateMstoreFunction("__cosmix_writeback_cached_cross_page_template", "__cosmix_writeback_" + mstore_name);

					CreateMstoreGlobalVar(index, mstore_name, "gt_CrossPageBuffer");
					CreateMstoreGlobalVar(index, mstore_name, "gt_crosspage_access");
					CreateMstoreGlobalVar(index, mstore_name, "gt_crosspage_access_size");

					ReplaceGlobalInFunction("__cosmix_link_" + mstore_name, "gt_CrossPageBuffer", "gt_CrossPageBuffer_" + mstore_name);
					ReplaceGlobalInFunction("__cosmix_initialize_" + mstore_name, "gt_crosspage_access", "gt_crosspage_access_" + mstore_name);
					ReplaceGlobalInFunction("__cosmix_link_" + mstore_name, "gt_crosspage_access", "gt_crosspage_access_" + mstore_name);
					ReplaceGlobalInFunction("__cosmix_initialize_" + mstore_name, "gt_crosspage_access_size", "gt_crosspage_access_size_" + mstore_name);
					ReplaceGlobalInFunction("__cosmix_link_" + mstore_name, "gt_crosspage_access_size", "gt_crosspage_access_size_" + mstore_name);


					ReplaceGlobalInFunction("__cosmix_writeback_" + mstore_name, "gt_CrossPageBuffer", "gt_CrossPageBuffer_" + mstore_name);
					ReplaceGlobalInFunction("__cosmix_writeback_" + mstore_name, "gt_crosspage_access", "gt_crosspage_access_" + mstore_name);
					ReplaceGlobalInFunction("__cosmix_writeback_" + mstore_name, "gt_crosspage_access_size", "gt_crosspage_access_size_" + mstore_name);

					SetMstoreFunction("__cosmix_writeback_" + mstore_name, "mstore_get_mpage_size", mstore_name + "_mstore_get_mpage_size");
					SetMstoreFunction("__cosmix_writeback_" + mstore_name, "mstore_get_mstorage_page", mstore_name + "_mstore_get_mstorage_page");

					ReplaceGlobalInFunction("__cosmix_get_valid_iterations_" + mstore_name, "gt_CrossPageBuffer", "gt_CrossPageBuffer_" + mstore_name);
				}

				SetMstoreFunction("__cosmix_link_" + mstore_name, "mpf_handler_c", mstore_name + "_mpf_handler_c");
				SetMstoreFunction("__cosmix_link_" + mstore_name, "mstore_get_mpage_size", mstore_name + "_mstore_get_mpage_size");
				SetMstoreFunction("__cosmix_link_" + mstore_name, "mstore_get_mpage_bits", mstore_name + "_mstore_get_mpage_bits");
				SetMstoreFunction("__cosmix_link_" + mstore_name, "notify_tlb_dropped", mstore_name + "_notify_tlb_dropped");
				SetMstoreFunction("__cosmix_link_" + mstore_name, "notify_tlb_cached", mstore_name + "_notify_tlb_cached");
				SetMstoreFunction("__cosmix_link_" + mstore_name, "mstore_get_mstorage_page", mstore_name + "_mstore_get_mstorage_page");
				SetMstoreFunction("__cosmix_link_" + mstore_name, "mstore_get_mpage_cache_base_ptr", mstore_name + "_mstore_get_mpage_cache_base_ptr");

				CreateMstoreFunction("mstore_get_tlb_template", "mstore_get_tlb_" + mstore_name);
				SetMstoreFunction("__cosmix_link_" + mstore_name, "mstore_get_tlb", "mstore_get_tlb_" + mstore_name);
				
				ReplaceMstoreFunction("_" + std::to_string(index) + "__cosmix_get_valid_iterations", "__cosmix_get_valid_iterations_" + mstore_name);

				// Handle globals
				//
				CreateMstoreGlobalVar(index, mstore_name, "gt_TLB");
				ReplaceGlobalInFunction("mstore_get_tlb_" + mstore_name, "gt_TLB", "gt_TLB_" + mstore_name);
				ReplaceGlobalInFunction("__cosmix_initialize_" + mstore_name, "gt_TLB", "gt_TLB_" + mstore_name);

				// CreateMstoreGlobalVar(index, mstore_name, "g_mstorage_base_ptr");
				// CreateMstoreGlobalVar(index, mstore_name, "g_mpage_cache_base_ptr");
				tryInlineFunction("mstore_get_tlb_" + mstore_name);
				tryInlineFunction(mstore_name + "_mstore_get_mpage_size");
				tryInlineFunction(mstore_name + "_mstore_get_mpage_bits");
				tryInlineFunction(mstore_name + "_mstore_get_mstorage_page");
				tryInlineFunction(mstore_name + "_mstore_get_mpage_cache_base_ptr");
			}
			else if (mstore_type == "direct")
			{
				SetMstoreFunction("__cosmix_initialize_" + mstore_name, "mstore_is_direct", "mstore_is_direct_true");

				// direct mstores
				CreateMstoreFunction("__cosmix_link_direct_template", "__cosmix_link_" + mstore_name);
				SetMstoreFunction("__cosmix_link_" + mstore_name, "mpf_handler_d", mstore_name + "_mpf_handler_d");
				
				CreateMstoreFunction("__cosmix_writeback_direct_template", "__cosmix_writeback_" + mstore_name);
				SetMstoreFunction("__cosmix_writeback_" + mstore_name, "mstore_write_back", mstore_name + "_write_back");

				// std::string mpage_size_func = "_" + std::to_string(index) + "_mstore_get_mpage_size";
				// ReplaceMstoreFunction(mpage_size_func, mstore_name + "_get_mpage_size");

				ReplaceMstoreFunction("_" + std::to_string(index) + "__cosmix_writeback_direct", "__cosmix_writeback_" + mstore_name);

				std::string mpagecache_func = "_" + std::to_string(index) + "_mstore_get_mpage_cache_base_ptr";
				ReplaceMstoreFunction(mpagecache_func, "direct" + mpagecache_func.substr(2));

			}
			else
			{
				assert (false && "CoSMIX only supports cached or direct mstores");
			}

			ReplaceMstoreFunction("_" + std::to_string(index) + "__cosmix_link", "__cosmix_link_" + mstore_name);

			// Fix all functions that the runtime already knows to direct to mstores based on their PTR tags. Simply replace to correct function name
			//
			for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
			{
				if (F->getName().startswith("_" + std::to_string(index) + "_mstore")) 
				{
					std::string funcName = mstore_name + F->getName().str().substr(2);
					Function* mstoreFunc = M->getFunction(funcName);
					if (!mstoreFunc)
					{
						mstoreFunc = Function::Create(cast<FunctionType>(F->getValueType()), GlobalValue::ExternalLinkage, funcName, M);
						
					}

					F->replaceAllUsesWith(mstoreFunc);
				}
			}
		}

		// Finally, delete template methods since we don't really need them in the TCB
		//
		for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
		{
			auto funcName = F->getName();
			if ((funcName.contains("cosmix") && funcName.contains("template")) || 
			    (funcName.contains("mstore") && funcName.contains("template")))
				{
					F->deleteBody();
				} 
		}

		assert((numFileMstores <= 1) && "Currently only supporting a single file backed mstore");

		if (numFileMstores == 0)
		{
			for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
			{					
				if (F->getName().equals("mstore_read")  || 
					F->getName().equals("mstore_write") || 
					F->getName().equals("mstore_open")  || 
					F->getName().equals("mstore_close") || 
					F->getName().equals("mstore_alloc") || 
					F->getName().equals("mstore_free")) 
				{
					std::string funcName = "default_" + F->getName().str();
					Function* mstoreFunc = M->getFunction(funcName);
					assert(mstoreFunc);
					F->replaceAllUsesWith(mstoreFunc);
				}
			}
		}

		for (int index=0;index<10;index++)
		{
			std::string funcToErase = "_" + std::to_string(index) + "_is_direct";
			if (M->getFunction(funcToErase))
			{
				ReplaceMstoreFunction(funcToErase, "_10" + funcToErase.substr(2));
			}
		}

		for (auto F = M->begin(), Fend = M->end(); F != Fend; ++F) 
		{
			for (int index=0;index<10;index++)
			{
				if (F->getName().startswith("_" + std::to_string(index) + "_mstore")) 
				{
					std::string funcName = "_10" + F->getName().str().substr(2);
					Function* mstoreFunc = M->getFunction(funcName);
					assert(mstoreFunc);
					F->replaceAllUsesWith(mstoreFunc);
				}

				if (F->getName().startswith("_" + std::to_string(index) + "__cosmix")) 
				{
					std::string funcName = "_10" + F->getName().str().substr(2);
					Function* mstoreFunc = M->getFunction(funcName);
					assert(mstoreFunc);
					F->replaceAllUsesWith(mstoreFunc);
				}
			}			
		}
	}
};

// Actual LLVM Module pass, simply delegate it to the CoSMIX objecct.
class CosmixModule: public ModulePass 
{
public:
	static char ID;

	CosmixModule() : ModulePass(ID) 
	{
	}

	virtual bool runOnModule(Module &M) 
	{
		errs() << "[RUNNING PASS: COSMIX]\n";

		// This is actually a singleton, but I want to retain the ability to reuse it in other LLVM passes.
		//
		CosmixPass Cosmix(&M);

		if (opt_FixRealFunctions)
		{
			for (auto F = M.begin(), Fend = M.end(); F != Fend; ++F) 
			{
				Cosmix.fixRealFunctions(&*F);
			}

			return true;
		}

		// 0. Parse configuration file and direct runtime methods to correct mstores
		Cosmix.ParseConfigurationFile();

		Cosmix.visitDeclerationAnnotations();
		Cosmix.visitGlobalAnnotations();

		if (opt_CodeAnalysisOptEnalbed)
		{
			Cosmix.InitializePointerAnalysis();
		}

		// for (auto F = M.begin(), Fend = M.end(); F != Fend; ++F) 
		// {
		// 	if (COSMIX_FUNC(F)) 
		// 	{
		// 		if (opt_DisableInlineInstrumentation || !Cosmix.isCosmixInlineCandidateFunction(&*F))
		// 		{
		// 			F->deleteBody();
		// 		}
		// 	}
		// }

		for (auto F = M.begin(), Fend = M.end(); F != Fend; ++F) 
		{
			Cosmix.findHelperFunc(&*F);
		}

		// Track all annotations the user had in a map
		//
		Cosmix.visitAnnotations();

		// Track all CallSites for dynamic allocation calls and add them to the annotated map 
		// i.e., static analysis based.
		//
		if (opt_AlwaysReplaceAllocators)
		{
			Cosmix.visitAllocationCallSites();
		}

		if (opt_CodeAnalysisOptEnalbed)
		{
			// Run pointer analysis to get instrumentation map ready for attempting to find Int2Ptr aliases
			//
			Cosmix.RunDataflowAnalysis(true);

			if (opt_CodeAnalysisWithInttoPtrOptEnalbed)
			{
				Cosmix.visitAllInt2Ptr();

				// Now re-run the pointers dataflow analysis to get a sound analysis
				//	
				Cosmix.RunDataflowAnalysis(false);
			}
		}

		Cosmix.CreateAllocationFunctions();

		if (opt_printStatistics)
		{
			Cosmix.gatherStatistics();
		}

		// For each function, instrument all its instructions to use the appropriate runtime
		//
		if (opt_instrumentEnabled) 
		{
			for (auto F = M.begin(), Fend = M.end(); F != Fend; ++F) 
			{
				if (F->isDeclaration() || COSMIX_FUNC(F) || LLVM_FUNC(F))
					continue;

				// Analyze the function with other passes, and send the information to runtime
				LoopInfo* LI = &getAnalysis<LoopInfoWrapperPass>(*F).getLoopInfo();
				PostDominatorTree* PDT = &getAnalysis<PostDominatorTreeWrapperPass>(*F).getPostDomTree();
				DominatorTree* DT = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();
				UnifyFunctionExitNodes& ufe = getAnalysis<UnifyFunctionExitNodes>(*F);
				AliasAnalysis *AA = &getAnalysis<AAResultsWrapperPass>(*F).getAAResults();
				ScalarEvolution* SE = &getAnalysis<ScalarEvolutionWrapperPass>(*F).getSE();
				Cosmix.visitFunc(&*F, ufe.getReturnBlock(), LI, PDT, DT, AA, SE);
			}

			if (!opt_DisableInlineInstrumentation)
			{
				Cosmix.tryInlineFunctions();
			}
		}		

		for (auto F = M.begin(), Fend = M.end(); F != Fend; ++F) 
		{
			Cosmix.fixRealFunctions(&*F);
		}

		// Visit main function to set initialization & cleanup of all the annotated runtimes.
		//
		for (auto F = M.begin(), Fend = M.end(); F != Fend; ++F) 
		{
			if (F->getName().equals(opt_StartupFunctionMain)) 
			{
				UnifyFunctionExitNodes& ufe = getAnalysis<UnifyFunctionExitNodes>(*F);
				Cosmix.visitMainFunc(&*F, ufe.getReturnBlock());
			}
		}

		// Debugging helpers:
		if (opt_DumpSgx) 
		{
			errs() << "Dumping COSMIX pass instrumented functions\n";

			for (auto F = M.begin(), Fend = M.end(); F != Fend; ++F) 
			{
				if (F->isDeclaration() || LLVM_FUNC(F)) 
				{
					continue;
				}

				Function* fn = &*F;
				fn->print(errs(), nullptr, false, true);
			}
		}

		// If the user requested statistics on the number on the expected instrumented memory access
		//
		if (opt_printStatistics) 
		{
			Cosmix.printStatistics();
		}

		// Indicate that this pass always modifies the module.
		return true;
	}

	// Helper pre-passes to run.
	virtual void getAnalysisUsage(AnalysisUsage& AU) const 
	{
		AU.setPreservesCFG();
		AU.addRequired<UnifyFunctionExitNodes>();
		AU.addRequired<PostDominatorTreeWrapperPass>();
		AU.addRequired<DominatorTreeWrapperPass>();
		AU.addRequired<LoopInfoWrapperPass>();
		AU.addRequired<AAResultsWrapperPass>();
		AU.addRequired<ScalarEvolutionWrapperPass>();
	}
};

// Register the pass with LLVM's infrastructure
char CosmixModule::ID = 0;
static RegisterPass<CosmixModule> X("cosmix", "Cosmix Pass");
}
