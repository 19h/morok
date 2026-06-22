#==============================================================================
# morok_passes — the obfuscation transformations.
#
# Each pass is a thin IR-emitting wrapper around an exhaustively-tested core
# algorithm.  Built as a static library that the plugin and the IR tests both
# link.  LLVM-facing → no exceptions / no RTTI (via morok::llvm).
#==============================================================================

add_library(morok_passes STATIC
  AdversarialFunctionMerging.cpp
  AdversarialSelfTuning.cpp
  Substitution.cpp
  Mba.cpp
  ConstantEncryption.cpp
  SplitBasicBlocks.cpp
  StackCoalescing.cpp
  StackDeltaGames.cpp
  PointerLaundering.cpp
  TypePunning.cpp
  PhiTangling.cpp
  AliasOpaquePredicates.cpp
  ExternalOpaquePredicates.cpp
  ExternalSecretBinding.cpp
  EnvBindingKdf.cpp
  CoherentDecoys.cpp
  CodeRegionKdf.cpp
  DataFlowIntegrity.cpp
  BogusControlFlow.cpp
  Flattening.cpp
  DataEntangledFlattening.cpp
  NonInvertibleState.cpp
  StateOpaquePredicates.cpp
  InterproceduralFsm.cpp
  MicrocodeStress.cpp
  MisleadingMetadata.cpp
  MqGate.cpp
  ChaosStateMachine.cpp
  CallerKeyedDispatch.cpp
  ReturnlessDispatch.cpp
  FunctionFission.cpp
  OptimizerAmplification.cpp
  PerBuildPolymorphism.cpp
  ArithmeticTables.cpp
  UniformPrimitiveLowering.cpp
  Virtualization.cpp
  HashGatedSelfDecrypt.cpp
  SealedBlob.cpp
  FaultPagedPayload.cpp
  SelfChecksumConstants.cpp
  ShamirShare.cpp
  MutualGuardGraph.cpp
  Nanomites.cpp
  PathExplosion.cpp
  RuntimeSeal.cpp
  TracerAttestation.cpp
  TraceKeying.cpp
  DispatcherlessRouting.cpp
  StringEncryption.cpp
  FunctionWrapper.cpp
  SubThresholdPersistence.cpp
  VectorObfuscation.cpp
  IndirectBranch.cpp
  FunctionCallObfuscate.cpp
  AntiAnalysis.cpp
  DecoyStrings.cpp
  VTableIntegrity.cpp)
add_library(morok::passes ALIAS morok_passes)

target_compile_features(morok_passes PUBLIC cxx_std_23)
target_include_directories(morok_passes PUBLIC
  "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(morok_passes
  PUBLIC morok::core morok::ir morok::runtime morok::llvm
  PRIVATE morok::warnings morok::no_eh_rtti)
