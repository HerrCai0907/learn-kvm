#pragma once

#include "src/WasmModule/WasmModule.hpp"
#include "src/core/common/BinaryModule.hpp"
#include "src/core/common/Span.hpp"
#include "src/core/compiler/common/MachineType.hpp"
#include "src/utils/STDCompilerLogger.hpp"
#include <cassert>
#include <string>

namespace wasm_kvm {

class WARP {
  vb::BinaryModule binaryModule_{};
  vb::Span<uint8_t> guestMemory_;
  uint32_t memoryBaseOffset_;

public:
  vb::WasmModule::CompileResult compile(std::string const &wasm) {
    vb::STDCompilerLogger logger_{};
    vb::WasmModule m_{logger_};
    vb::Span<uint8_t const> bytecode{reinterpret_cast<uint8_t const *>(wasm.data()), wasm.size()};
    return m_.compile(bytecode, {});
  }

  uint32_t getMemoryBaseOffset() { return memoryBaseOffset_; }
  uint32_t getLinearMemoryBaseOffset() { return memoryBaseOffset_ + getBasedataLength(); }

  uint8_t *getMemoryBase() { return &guestMemory_[getMemoryBaseOffset()]; }
  uint8_t *getLinearMemoryBase() { return &guestMemory_[getLinearMemoryBaseOffset()]; }
  uint32_t getBasedataLength() const VB_NOEXCEPT {
    uint32_t const linkDataLength{binaryModule_.getLinkDataLength()};
    return Basedata::length(linkDataLength, binaryModule_.getStacktraceEntryCount());
  }

  uint32_t initializeModule(vb::Span<uint8_t const> const &machineCode, vb::Span<uint8_t> guestMemory, void *const ctx) {
    guestMemory_ = guestMemory;
    using namespace vb;
    // copy machineCode to guestMemory_
    std::memcpy(guestMemory_.data(), machineCode.data(), machineCode.size());
    binaryModule_.init({guestMemory_.data(), machineCode.size()});

    constexpr uint32_t alignment = 128;
    memoryBaseOffset_ = machineCode.size() + (alignment - 1) & ~(alignment - 1);

    uint32_t const linkDataLength{binaryModule_.getLinkDataLength()};
    uint32_t const basedataLength{Basedata::length(linkDataLength, binaryModule_.getStacktraceEntryCount())};

    writeToPtr<uintptr_t>(pAddI(getMemoryBase(), basedataLength - static_cast<uint32_t>(Basedata::FromEnd::binaryModuleStartAddressOffset)),
                          pToNum(binaryModule_.getStartAddress()));

    writeToPtr<uintptr_t>(pAddI(getMemoryBase(), basedataLength - static_cast<uint32_t>(Basedata::FromEnd::tableAddressOffset)),
                          pToNum(binaryModule_.getTableStart()));

    writeToPtr<uintptr_t>(pAddI(getMemoryBase(), basedataLength - static_cast<uint32_t>(Basedata::FromEnd::linkStatusAddressOffset)),
                          pToNum(binaryModule_.getLinkStatusStart()));

    // Write initial memory size to metadata
    assert(basedataLength >= static_cast<uint32_t>(Basedata::FromEnd::linMemWasmSize) && "basedataLength must not be less than linMemWasmSize");

    writeToPtr<uint32_t>(pAddI(getMemoryBase(), basedataLength - static_cast<uint32_t>(Basedata::FromEnd::linMemWasmSize)),
                         binaryModule_.getInitialMemorySize());

    writeToPtr<void const *>(pSubI(getLinearMemoryBase(), Basedata::FromEnd::customCtxOffset), ctx);

    // setMemoryHelperPtr();

    uint8_t const *dynamicallyImportedFunctionsSectionCursor{binaryModule_.getDynamicallyImportedFunctionsSectionEnd()};
    uint32_t const numDynamicallyImportedFunctions{readNextValue<uint32_t>(&dynamicallyImportedFunctionsSectionCursor)}; // OPBVIF10
    assert(numDynamicallyImportedFunctions == 0U);

    uint8_t const *mutableGlobalCursor{binaryModule_.getMutableGlobalsSectionEnd()};

    uint32_t const numMutableGlobals{readNextValue<uint32_t>(&mutableGlobalCursor)}; // OPBVNG4
    for (uint32_t i{0U}; i < numMutableGlobals; i++) {
      mutableGlobalCursor = pSubI(mutableGlobalCursor, 3U);                                                // Padding (OPBVNG3)
      MachineType const type{readNextValue<MachineType>(&mutableGlobalCursor)};                            // OPBVNG2
      uint16_t const linkDataOffset{static_cast<uint16_t>(readNextValue<uint32_t>(&mutableGlobalCursor))}; // OPBVNG1

      uint32_t const variableSize{MachineTypeUtil::getSize(type)};
      mutableGlobalCursor = pSubI(mutableGlobalCursor, variableSize);
      assert(static_cast<uint32_t>(linkDataOffset + variableSize) <= linkDataLength && "Bookkeeping data overflow");
      static_cast<void>(std::memcpy(pAddI(getMemoryBase(), static_cast<size_t>(Basedata::FromStart::linkData) + static_cast<size_t>(linkDataOffset)),
                                    mutableGlobalCursor,
                                    static_cast<size_t>(variableSize))); // OPBVNG0
    }

    // SECTION: Data
    uint32_t const linearMemoryBaseOffset{basedataLength};
    uint8_t const *dataSegmentsCursor{binaryModule_.getDataSegmentsEnd()};
    // coverity[autosar_cpp14_a7_1_1_violation]
    // NOLINTNEXTLINE(misc-const-correctness)
    uint32_t maximumDataOffset{0U};
    for (uint32_t i{0U}; i < binaryModule_.getNumDataSegments(); i++) {
      static_cast<void>(i);
      uint32_t const dataSegmentStart{readNextValue<uint32_t>(&dataSegmentsCursor)};      // OPBVLM3
      uint32_t const dataSegmentSize{readNextValue<uint32_t>(&dataSegmentsCursor)};       // OPBVLM2
      dataSegmentsCursor = pSubI(dataSegmentsCursor, roundUpToPow2(dataSegmentSize, 2U)); // OPBVLM1

      if (dataSegmentSize > 0U) {
        uint8_t const *const data{dataSegmentsCursor}; // OPBVLM0
        static_cast<void>(std::memcpy(pAddI(getMemoryBase(), linearMemoryBaseOffset + dataSegmentStart), data, static_cast<size_t>(dataSegmentSize)));
      }
    }

    uint32_t const actualMemorySize{binaryModule_.hasLinearMemory() ? maximumDataOffset : 0U};
    // Write it to metadata memory, everything has already been initialized to
    // zero
    uint8_t *const actualMemoryBaseData{pAddI(getMemoryBase(), basedataLength - static_cast<uint32_t>(Basedata::FromEnd::actualLinMemByteSize))};

    writeToPtr<uint32_t>(actualMemoryBaseData, actualMemorySize);

    assert(getMemoryBase() + Basedata::FromStart::linkData + linkDataLength ==
               getMemoryBase() + basedataLength - Basedata::FromEnd::getLast(binaryModule_.getStacktraceEntryCount()) &&
           "Metadata size error");
    return memoryBaseOffset_ + getBasedataLength() + actualMemorySize;
  }
};

} // namespace wasm_kvm
