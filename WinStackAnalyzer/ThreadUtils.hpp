// ThreadUtils.hpp
// This header file provides utilities for working with thread contexts, finding threads, and handling thread states in a Windows environment.

#pragma once

#include <windows.h>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "WinWrap.hpp"

namespace ThreadUtils {

    // ThreadContext class encapsulates the context of a thread, including its register state, thread ID, and creation time.
    class ThreadContext {
    public:
        // Constructor that initializes the ThreadContext with a given CONTEXT structure, thread ID, and creation time.
        explicit ThreadContext(const CONTEXT& ctx, uint32_t threadId, uint64_t creationTime);

        // Prints the register information stored in the thread context to the console or log.
        void PrintRegisterInfo() const;

        // Returns the thread ID associated with this ThreadContext.
        uint32_t GetThreadId() const { return m_threadId; }

        // Returns the creation time of the thread associated with this ThreadContext.
        uint64_t GetCreationTime() const { return m_creationTime; }

    private:
        CONTEXT m_context;          // The CONTEXT structure that holds the CPU registers for the thread.
        uint32_t m_threadId;        // The ID of the thread.
        uint64_t m_creationTime;    // The creation time of the thread.
    };

    // ThreadFinder class provides methods to find specific threads within a process, such as the main thread, or to retrieve all threads.
    class ThreadFinder {
    public:
        // Finds the main thread of a process given its process ID. Returns the thread ID of the main thread on success.
        // If the main thread cannot be found, returns an error message.
        [[nodiscard]]
        static std::expected<uint32_t, std::string> FindMainThread(uint32_t processId) noexcept;

        // Retrieves the contexts of all threads in a process given its process ID. 
        // Returns a vector of ThreadContext objects on success or an error message on failure.
        [[nodiscard]]
        static std::expected<std::vector<ThreadContext>, std::string> GetAllThreads(uint32_t processId) noexcept;
    };

    // ThreadStateHandler class provides methods to query and manage the state of a thread.
    class ThreadStateHandler {
    public:
        // Retrieves the context of a thread given its thread ID. 
        // Returns the ThreadContext on success or an error message on failure.
        [[nodiscard]]
        static std::expected<ThreadContext, std::string> GetThreadState(uint32_t threadId) noexcept;
    };

    // ModuleInfo class provides methods to query module information from virtual memory addresses
    class ModuleInfo {
    public:
        // Get module name from address for the current process
        static inline std::expected<std::wstring, std::string> GetModuleNameFromAddressLocal(void* address) {
            auto moduleResult = WinWrap::_GetModuleHandleEx(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                static_cast<LPCWSTR>(address)
            );
            if (!moduleResult) {
                return std::unexpected(moduleResult.error());
            }
            auto moduleNameResult = WinWrap::_GetModuleFileNameEx(GetCurrentProcess(), moduleResult.value());
            if (!moduleNameResult) {
                return std::unexpected(moduleNameResult.error());
            }
            return moduleNameResult.value();
        }

        // Get module name from address for a remote process
        static inline std::expected<std::wstring, std::string> GetModuleNameFromAddressRemote(HANDLE hProcess, void* address) {
            auto modulesResult = WinWrap::_EnumProcessModulesEx(hProcess);
            if (!modulesResult) {
                return std::unexpected(modulesResult.error());
            }

            for (const auto& hModule : modulesResult.value()) {
                auto modInfoResult = WinWrap::_GetModuleInformation(hProcess, hModule);
                if (!modInfoResult) {
                    continue; // Skip this module if we can't get its information
                }

                auto& modInfo = modInfoResult.value();
                if (address >= modInfo.lpBaseOfDll &&
                    address < reinterpret_cast<char*>(modInfo.lpBaseOfDll) + modInfo.SizeOfImage) {
                    // The address is within this module's memory range
                    return WinWrap::_GetModuleFileNameEx(hProcess, hModule);
                }
            }

            return std::unexpected("No module found containing the specified address");
        }
    };

} // namespace ThreadUtils
