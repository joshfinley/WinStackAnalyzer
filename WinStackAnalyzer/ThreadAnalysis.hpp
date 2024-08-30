// ThreadAnalysis.hpp
// This header file provides utilities for working with thread contexts, finding threads, and handling thread states in a Windows environment.

#pragma once

#include "winwrap.hpp"
#include <vector>
#include <string>
#include <memory>

#include "WinWrap.hpp"

class ModuleInfo {
public:
    ModuleInfo(HMODULE handle, const std::wstring& name, uintptr_t baseAddress, size_t size)
        : handle(handle), name(name), baseAddress(baseAddress), size(size) {}

    HMODULE handle;
    std::wstring name;
    uintptr_t baseAddress;
    size_t size;
};

class ThreadInfo {
public:
    ThreadInfo(DWORD threadId, WinWrap::SafeHandle<HANDLE>&& threadHandle)
        : threadId(threadId), threadHandle(std::move(threadHandle)) {}

    DWORD threadId;
    WinWrap::SafeHandle<HANDLE> threadHandle;
    WinWrap::ThreadContextWrapper context;
    std::vector<uintptr_t> callStack;
    // Additional metadata can be added here
};

class ThreadAnalyzer {
public:
    static std::expected<ModuleInfo, std::string> GetModuleInfoFromAddressRemote(const WinWrap::SafeHandle<HANDLE>& hProcess, uintptr_t address);
    static std::expected<ModuleInfo, std::string> GetModuleInfoFromAddressLocal(uintptr_t address);

    static std::expected<WinWrap::ThreadContextWrapper, std::string> GetThreadContextRemote(const WinWrap::SafeHandle<HANDLE>& hThread);
    static std::expected<WinWrap::ThreadContextWrapper, std::string> GetThreadContextLocal(const WinWrap::SafeHandle<HANDLE>& hThread);

    static std::expected<std::vector<ThreadInfo>, std::string> GetAllThreadsRemote(const WinWrap::SafeHandle<HANDLE>& hProcess);
    static std::expected<std::vector<ThreadInfo>, std::string> GetAllThreadsLocal();

    static std::expected<bool, std::string> UnwindThreadStack(ThreadInfo& threadInfo, const WinWrap::SafeHandle<HANDLE>& hProcess);

private:
    static std::expected<DWORD, std::string> GetProcessIdFromHandle(const WinWrap::SafeHandle<HANDLE>& hProcess);
};