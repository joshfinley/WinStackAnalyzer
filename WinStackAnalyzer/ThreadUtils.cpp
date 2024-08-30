// ThreadUtils.cpp

#include "ThreadUtils.hpp"
#include "winwrap.hpp"
#include <iostream>
#include <iomanip>
#include <format>
#include <memory>
#include <tlhelp32.h>
#include <algorithm>

namespace ThreadUtils {

    // Constructor for ThreadContext
    ThreadContext::ThreadContext(const CONTEXT& ctx, uint32_t threadId, uint64_t creationTime)
        : m_context(ctx), m_threadId(threadId), m_creationTime(creationTime) {}

    // Method to print register information for a thread
    void ThreadContext::PrintRegisterInfo() const {
        std::cout << "Register Information for Thread " << m_threadId << ":" << std::endl;
        std::cout << std::hex << std::setfill('0');
        // Print each register value in hexadecimal format
        std::cout << "RAX: 0x" << std::setw(16) << m_context.Rax << std::endl;
        std::cout << "RBX: 0x" << std::setw(16) << m_context.Rbx << std::endl;
        std::cout << "RCX: 0x" << std::setw(16) << m_context.Rcx << std::endl;
        std::cout << "RDX: 0x" << std::setw(16) << m_context.Rdx << std::endl;
        std::cout << "RSI: 0x" << std::setw(16) << m_context.Rsi << std::endl;
        std::cout << "RDI: 0x" << std::setw(16) << m_context.Rdi << std::endl;
        std::cout << "RBP: 0x" << std::setw(16) << m_context.Rbp << std::endl;
        std::cout << "RSP: 0x" << std::setw(16) << m_context.Rsp << std::endl;
        std::cout << "RIP: 0x" << std::setw(16) << m_context.Rip << std::endl;
        std::cout << std::dec; // Reset to decimal format
    }

    // Method to find the main thread of a process
    std::expected<uint32_t, std::string> ThreadFinder::FindMainThread(uint32_t processId) noexcept {
        uint32_t mainThreadId = 0;
        uint64_t earliestCreateTime = 0xffffffffffffffff;

        // Create a snapshot of the system's threads
        auto snapshotResult = WinWrap::_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (!snapshotResult) {
            return std::unexpected(snapshotResult.error());
        }

        const auto& snapshotHandle = *snapshotResult;

        THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
        // Iterate through all threads in the system
        if (::Thread32First(snapshotHandle.Get(), &threadEntry)) {
            do {
                // Check if the thread belongs to the specified process
                if (threadEntry.th32OwnerProcessID == processId) {
                    WinWrap::SafeHandle<HANDLE> threadHandle(::OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID));
                    if (threadHandle) {
                        FILETIME createTime, exitTime, kernelTime, userTime;
                        // Get the creation time of the thread
                        if (::GetThreadTimes(threadHandle.Get(), &createTime, &exitTime, &kernelTime, &userTime)) {
                            uint64_t createTimeInt64 = (static_cast<uint64_t>(createTime.dwHighDateTime) << 32) | createTime.dwLowDateTime;
                            // Update main thread if this is the earliest created thread so far
                            if (createTimeInt64 < earliestCreateTime) {
                                earliestCreateTime = createTimeInt64;
                                mainThreadId = threadEntry.th32ThreadID;
                            }
                        }
                    }
                }
            } while (::Thread32Next(snapshotHandle.Get(), &threadEntry));
        }
        else {
            auto errorResult = WinWrap::GetLastErrorAsString();
            return std::unexpected(errorResult ? *errorResult : "Failed to enumerate threads");
        }

        if (mainThreadId == 0) {
            return std::unexpected("No threads found for the specified process");
        }

        return mainThreadId;
    }

    // Method to get all threads of a process
    std::expected<std::vector<ThreadContext>, std::string> ThreadFinder::GetAllThreads(uint32_t processId) noexcept {
        std::vector<ThreadContext> threads;

        // Create a snapshot of the system's threads
        auto snapshotResult = WinWrap::_CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (!snapshotResult) {
            return std::unexpected(snapshotResult.error());
        }

        const auto& snapshotHandle = *snapshotResult;

        THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
        // Iterate through all threads in the system
        if (::Thread32First(snapshotHandle.Get(), &threadEntry)) {
            do {
                // Check if the thread belongs to the specified process
                if (threadEntry.th32OwnerProcessID == processId) {
                    // Get the thread state for each thread
                    auto threadStateResult = ThreadStateHandler::GetThreadState(threadEntry.th32ThreadID);
                    if (threadStateResult) {
                        threads.push_back(std::move(*threadStateResult));
                    }
                }
            } while (::Thread32Next(snapshotHandle.Get(), &threadEntry));
        }
        else {
            auto errorResult = WinWrap::GetLastErrorAsString();
            return std::unexpected(errorResult ? *errorResult : "Failed to enumerate threads");
        }

        if (threads.empty()) {
            return std::unexpected("No threads found for the specified process");
        }

        // Sort threads by creation time (earliest first)
        std::sort(threads.begin(), threads.end(),
            [](const ThreadContext& a, const ThreadContext& b) { return a.GetCreationTime() < b.GetCreationTime(); });

        return threads;
    }

    // Method to get the state of a specific thread
    std::expected<ThreadContext, std::string> ThreadStateHandler::GetThreadState(uint32_t threadId) noexcept {
        // Open the thread
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (hThread == NULL) {
            return std::unexpected(std::format("Failed to open thread. Error: {}", GetLastError()));
        }

        // Use RAII to ensure the thread handle is closed
        auto threadGuard = std::unique_ptr<void, decltype(&CloseHandle)>(hThread, CloseHandle);

        // Suspend the thread to get a consistent state
        DWORD suspendCount = SuspendThread(hThread);
        if (suspendCount == (DWORD)-1) {
            return std::unexpected(std::format("Failed to suspend thread. Error: {}", GetLastError()));
        }

        // Ensure the thread is resumed even if we encounter an error
        auto resumeGuard = std::unique_ptr<void, decltype(&ResumeThread)>(hThread, ResumeThread);

        // Get the thread context (register values)
        CONTEXT threadContext;
        threadContext.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &threadContext)) {
            return std::unexpected(std::format("Failed to get thread context. Error: {}", GetLastError()));
        }

        // Get the thread creation time
        FILETIME createTime, exitTime, kernelTime, userTime;
        if (!GetThreadTimes(hThread, &createTime, &exitTime, &kernelTime, &userTime)) {
            return std::unexpected(std::format("Failed to get thread times. Error: {}", GetLastError()));
        }

        uint64_t createTimeInt64 = (static_cast<uint64_t>(createTime.dwHighDateTime) << 32) | createTime.dwLowDateTime;

        // Create and return a ThreadContext object with all the gathered information
        return ThreadContext(threadContext, threadId, createTimeInt64);
    }

} // namespace ThreadUtils