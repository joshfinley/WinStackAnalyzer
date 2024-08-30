// WinStackAnalyzer.cpp

#include "ThreadAnalysis.hpp"
#include "PeUtils.hpp"
#include <iostream>
#include <iomanip>

std::expected<void, std::string> PrintModuleInfo(const ModuleInfo& moduleInfo) {
    std::wcout << L"Module Name: " << moduleInfo.name << std::endl;
    std::cout << "Module Base: 0x" << std::hex << moduleInfo.baseAddress << std::endl;
    std::cout << "Module Size: 0x" << std::hex << moduleInfo.size << std::endl;

    auto peFileResult = PeUtils::PeFile::Create(moduleInfo.name);
    if (!peFileResult) {
        std::cout << "Failed to open PE file: " << peFileResult.error() << std::endl;
        return {};
    }

    auto peFile = std::move(peFileResult.value());

    auto is64BitResult = peFile.Is64Bit();
    if (is64BitResult) {
        std::cout << "64-bit PE: " << (is64BitResult.value() ? "Yes" : "No") << std::endl;
    }
    else {
        std::cout << "Failed to determine if PE is 64-bit: " << is64BitResult.error() << std::endl;
    }

    auto runtimeFunctionsResult = peFile.GetRuntimeFunctions();
    if (runtimeFunctionsResult) {
        std::cout << "Unwind data present: Yes" << std::endl;
        std::cout << "Number of RUNTIME_FUNCTIONs: " << runtimeFunctionsResult.value().size() << std::endl;
    }
    else {
        std::cout << "Unwind data present: No" << std::endl;
        std::cout << "Error: " << runtimeFunctionsResult.error() << std::endl;
    }

    return {};
}

int main() {
    DWORD processId;
    std::cout << "Enter process ID: ";
    std::cin >> processId;

    auto openProcessResult = WinWrap::_OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!openProcessResult) {
        std::cerr << "Failed to open process: " << openProcessResult.error() << std::endl;
        return 1;
    }

    auto hProcess = std::move(openProcessResult.value());

    auto threadsResult = ThreadAnalyzer::GetAllThreadsRemote(hProcess);
    if (!threadsResult) {
        std::cerr << "Failed to get threads: " << threadsResult.error() << std::endl;
        return 1;
    }

    for (const auto& thread : threadsResult.value()) {
        std::cout << "Thread ID: " << std::dec << thread.threadId << std::endl;

        auto contextResult = ThreadAnalyzer::GetThreadContextRemote(thread.threadHandle);
        if (!contextResult) {
            std::cerr << "Failed to get thread context: " << contextResult.error() << std::endl;
            continue;
        }

        const auto& context = contextResult.value().GetContext();

        std::cout << "RIP: 0x" << std::hex << context->Rip << std::endl;
        std::cout << "RSP: 0x" << std::hex << context->Rsp << std::endl;

        auto moduleInfoResult = ThreadAnalyzer::GetModuleInfoFromAddressRemote(hProcess, context->Rip);
        if (!moduleInfoResult) {
            std::cout << "WARNING: Unbacked thread detected (suspicious)" << std::endl;
            std::cout << "Error retrieving module info: " << moduleInfoResult.error() << std::endl;
            std::cout << "This could indicate execution of code from an unexpected location." << std::endl;
        }
        else {
            auto printResult = PrintModuleInfo(moduleInfoResult.value());
            if (!printResult) {
                std::cerr << "Failed to print module info: " << printResult.error() << std::endl;
            }
        }

        std::cout << std::string(50, '-') << std::endl;
    }

    return 0;
}