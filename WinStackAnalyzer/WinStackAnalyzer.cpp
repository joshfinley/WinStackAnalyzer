// WinStackAnalyzer.cpp

#include <iostream>
#include <iomanip>

#include "ThreadAnalysis.hpp"
#include "PeUtils.hpp"
#include "Injector.hpp"

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


std::expected<std::wstring, std::string> GetAbsolutePath(const std::wstring& relativePath) {
    wchar_t fullPath[MAX_PATH];
    DWORD result = GetFullPathNameW(relativePath.c_str(), MAX_PATH, fullPath, nullptr);
    if (result == 0 || result > MAX_PATH) {
        return std::unexpected("Failed to get the absolute path. Error: " + std::to_string(GetLastError()));
    }
    return std::wstring(fullPath);
}


std::expected<boolean, std::string> InjectHookDll(DWORD processId)
{
    std::wstring relativeDllPath;

#ifdef _DEBUG
    relativeDllPath = L"..\\x64\\Debug\\HookDll.dll";  // Adjust the path for debug mode
#else
    relativeDllPath = L".\\HookDll.dll";  // Use current directory for release mode
#endif

    // Convert to an absolute path
    auto absoluteDllPathResult = GetAbsolutePath(relativeDllPath);
    if (!absoluteDllPathResult) {
        return std::unexpected("Failed to resolve DLL path: " + absoluteDllPathResult.error());
    }
    std::wstring absoluteDllPath = absoluteDllPathResult.value();

    auto injectResult = Injector::InjectDll(processId, absoluteDllPath);
    if (!injectResult) {
        return std::unexpected("Failed to inject DLL: " + injectResult.error());
    }

    return true;
}

int main() {
    DWORD processId;
#ifndef _DEBUG
    std::cout << "Enter process ID: ";
    std::cin >> processId;
#else
    processId = 1368;  // Adjust to the correct PID for debugging
#endif

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

    bool suspiciousActivityDetected = false;

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

            suspiciousActivityDetected = true;
        }
        else {
            auto printResult = PrintModuleInfo(moduleInfoResult.value());
            if (!printResult) {
                std::cerr << "Failed to print module info: " << printResult.error() << std::endl;
            }
        }

        std::cout << std::string(50, '-') << std::endl;
    }

    // Inject DLL if suspicious activity was detected
    if (suspiciousActivityDetected) {
        auto result = InjectHookDll(processId);
        if (!result) {
            std::cerr << result.error() << std::endl;
            return 1;
        }
        std::cout << "DLL injected successfully into the target process." << std::endl;
    }
    else {
        std::cout << "No suspicious activity detected. No DLL injection performed into the target process." << std::endl;
    }

#ifdef _DEBUG
    // Inject DLL into the current process under debug mode
    std::cout << "Debug build enabled. Injecting HookDLl into self" << std::endl;

    auto currentProcessId = GetCurrentProcessId();
    if (currentProcessId != processId) {
        auto result = InjectHookDll(currentProcessId);
        if (!result) {
            std::cerr << "Failed to inject DLL into the current process: " << result.error() << std::endl;
            return 1;
        }
        std::cout << "DLL injected successfully into the current process under debug mode." << std::endl;
    }

    // Test the hook
    currentProcessId = 0;
    FARPROC _GetCurrentProcessId = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetCurrentProcessId");
    currentProcessId = _GetCurrentProcessId();
#endif

    return 0;
}