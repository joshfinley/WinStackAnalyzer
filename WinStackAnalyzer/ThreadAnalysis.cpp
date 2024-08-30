// ThreadAnalysis.cpp
// Implementation for thread analysis functions
#include "ThreadAnalysis.hpp"

std::expected<ModuleInfo, std::string> ThreadAnalyzer::GetModuleInfoFromAddressRemote(const WinWrap::SafeHandle<HANDLE>& hProcess, uintptr_t address) {
    auto modulesResult = WinWrap::_EnumProcessModulesEx(hProcess.Get());
    if (!modulesResult) {
        return std::unexpected(modulesResult.error());
    }

    for (const auto& hModule : modulesResult.value()) {
        auto modInfoResult = WinWrap::_GetModuleInformation(hProcess.Get(), hModule);
        if (!modInfoResult) {
            continue;
        }

        auto& modInfo = modInfoResult.value();
        if (address >= reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll) &&
            address < reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll) + modInfo.SizeOfImage) {

            auto fileNameResult = WinWrap::_GetModuleFileNameEx(hProcess.Get(), hModule);
            if (!fileNameResult) {
                return std::unexpected(fileNameResult.error());
            }

            return ModuleInfo(hModule, fileNameResult.value(),
                reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll), modInfo.SizeOfImage);
        }
    }

    return std::unexpected("No module found containing the specified address");
}

std::expected<ModuleInfo, std::string> ThreadAnalyzer::GetModuleInfoFromAddressLocal(uintptr_t address) {
    return GetModuleInfoFromAddressRemote(WinWrap::SafeHandle<HANDLE>(GetCurrentProcess()), address);
}

std::expected<WinWrap::ThreadContextWrapper, std::string> ThreadAnalyzer::GetThreadContextRemote(const WinWrap::SafeHandle<HANDLE>& hThread) {
    try {
        return WinWrap::ThreadContextWrapper(WinWrap::SafeHandle<HANDLE>(hThread.Get()));
    }
    catch (const std::runtime_error& e) {
        return std::unexpected(e.what());
    }
}

std::expected<WinWrap::ThreadContextWrapper, std::string> ThreadAnalyzer::GetThreadContextLocal(const WinWrap::SafeHandle<HANDLE>& hThread) {
    return GetThreadContextRemote(hThread);
}

std::expected<std::vector<ThreadInfo>, std::string> ThreadAnalyzer::GetAllThreadsRemote(const WinWrap::SafeHandle<HANDLE>& hProcess) {
    std::vector<ThreadInfo> threads;

    auto processIdResult = GetProcessIdFromHandle(hProcess);
    if (!processIdResult) {
        return std::unexpected(processIdResult.error());
    }
    DWORD processId = processIdResult.value();

    auto snapshotResult = WinWrap::_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (!snapshotResult) {
        return std::unexpected(snapshotResult.error());
    }

    auto hSnapshot = std::move(snapshotResult.value());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    auto thread32FirstResult = WinWrap::_Thread32First(hSnapshot.Get(), &te32);
    if (!thread32FirstResult) {
        return std::unexpected(thread32FirstResult.error());
    }

    do {
        if (te32.th32OwnerProcessID == processId) {
            auto threadHandleResult = WinWrap::_OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (threadHandleResult) {
                threads.emplace_back(te32.th32ThreadID, std::move(threadHandleResult.value()));
            }
        }
    } while (WinWrap::_Thread32Next(hSnapshot.Get(), &te32));

    return threads;
}

std::expected<std::vector<ThreadInfo>, std::string> ThreadAnalyzer::GetAllThreadsLocal() {
    return GetAllThreadsRemote(WinWrap::SafeHandle<HANDLE>(GetCurrentProcess()));
}

std::expected<bool, std::string> ThreadAnalyzer::UnwindThreadStack(ThreadInfo& threadInfo, const WinWrap::SafeHandle<HANDLE>& hProcess) {
    // Implement stack unwinding logic here
    // This is a placeholder and needs to be implemented based on your specific requirements
    return std::unexpected("Stack unwinding not implemented yet");
}

std::expected<DWORD, std::string> ThreadAnalyzer::GetProcessIdFromHandle(const WinWrap::SafeHandle<HANDLE>& hProcess) {
    return WinWrap::_GetProcessId(hProcess.Get());
}