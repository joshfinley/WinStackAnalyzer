// Unwind.cpp

#include "Unwind.hpp"
#include "ThreadUtils.hpp"
#include "PeUtils.hpp"
#include <iostream>

namespace Unwind {

    std::expected<void, std::string> AnalyzeUnwindExceptions(HANDLE hProcess, void* ripAddress) {
        auto moduleNameResult = ThreadUtils::ModuleInfo::GetModuleNameFromAddressRemote(hProcess, ripAddress);
        if (!moduleNameResult) {
            return std::unexpected("Failed to get module name. Error: " + moduleNameResult.error());
        }

        std::wcout << L"Module associated with RIP: " << moduleNameResult.value() << L"\n";

        // Check the exception directory of the module using PeUtils
        auto peFileResult = PeUtils::PeFile::Create(moduleNameResult.value());
        if (!peFileResult) {
            return std::unexpected("Failed to open module as PE file. Error: " + peFileResult.error());
        }

        auto runtimeFunctionsResult = peFileResult->GetRuntimeFunctions();
        if (!runtimeFunctionsResult) {
            return std::unexpected("Failed to retrieve RUNTIME_FUNCTIONs. Error: " + runtimeFunctionsResult.error());
        }

        std::cout << "RUNTIME_FUNCTIONs found in the exception directory.\n";
        return {};
    }

}  // namespace Unwind
