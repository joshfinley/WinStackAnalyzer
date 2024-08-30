// WinStackAnalyzer.cpp

#include "ThreadUtils.hpp"
#include "Unwind.hpp"
#include "WinWrap.hpp"
#include <iostream>

int main() {
    uint32_t processId;
    std::cout << "Enter the process ID to inspect: ";
    std::cin >> processId;

    auto hProcessResult = WinWrap::_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcessResult) {
        std::cerr << "Failed to open process. Error: " << hProcessResult.error() << std::endl;
        return 1;
    }
    auto& hProcess = hProcessResult.value();

    auto allThreadsResult = ThreadUtils::ThreadFinder::GetAllThreads(processId);
    if (allThreadsResult) {
        const auto& threadContexts = allThreadsResult.value();
        for (const auto& threadContext : threadContexts) {
            // Print thread context
            ThreadUtils::PrintThreadContext(threadContext, hProcess.Get());

            // Get the RIP address and analyze unwind exceptions
            auto hThreadResult = WinWrap::_OpenThread(THREAD_GET_CONTEXT, FALSE, threadContext.GetThreadId());
            if (hThreadResult) {
                auto& hThread = hThreadResult.value();
                auto contextResult = WinWrap::_GetThreadContext(hThread.Get());
                if (contextResult) {
                    const auto& context = contextResult.value();
                    void* ripAddress = reinterpret_cast<void*>(context.Rip);

                    // Analyze unwind exceptions using Unwind::AnalyzeUnwindExceptions
                    auto unwindResult = Unwind::AnalyzeUnwindExceptions(hProcess.Get(), ripAddress);
                    if (!unwindResult) {
                        std::cerr << "Failed to analyze unwind exceptions: " << unwindResult.error() << std::endl;
                    }
                }
                else {
                    std::cerr << "Failed to get thread context. Error: " << contextResult.error() << "\n";
                }
            }
            else {
                std::cerr << "Failed to open thread. Error: " << hThreadResult.error() << "\n";
            }

            std::cout << "------------------------\n";
        }
    }
    else {
        std::cerr << "Error retrieving threads: " << allThreadsResult.error() << std::endl;
    }

    return 0;
}
