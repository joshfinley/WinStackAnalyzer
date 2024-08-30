// main.cpp
#include "ThreadUtils.hpp"
#include <iostream>

#include <iostream>
#include <iomanip>
#include "ThreadUtils.hpp"
#include "WinWrap.hpp"

#include <iostream>
#include <iomanip>
#include "ThreadUtils.hpp"
#include "WinWrap.hpp"

int main() {
    // Prompt the user to enter the process ID
    uint32_t processId;
    std::cout << "Enter the process ID to inspect: ";
    std::cin >> processId;

    // Open the process to get a handle
    auto hProcessResult = WinWrap::_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcessResult) {
        std::cerr << "Failed to open process. Error: " << hProcessResult.error() << std::endl;
        return 1;
    }
    auto& hProcess = hProcessResult.value();

    // Get all threads of the specified process
    auto allThreadsResult = ThreadUtils::ThreadFinder::GetAllThreads(processId);
    if (allThreadsResult) {
        const auto& threadContexts = allThreadsResult.value();
        // Iterate through each thread context and print its register information
        for (const auto& threadContext : threadContexts) {
            std::cout << "Thread ID: " << threadContext.GetThreadId() << "\n";
            std::cout << "Creation Time: " << threadContext.GetCreationTime() << "\n";
            std::cout << "Register Info:\n";
            threadContext.PrintRegisterInfo();

            // Get the module associated with RIP
            auto hThreadResult = WinWrap::_OpenThread(THREAD_GET_CONTEXT, FALSE, threadContext.GetThreadId());
            if (hThreadResult) {
                auto& hThread = hThreadResult.value();
                auto contextResult = WinWrap::_GetThreadContext(hThread.Get());
                if (contextResult) {
                    const auto& context = contextResult.value();
                    void* ripAddress = reinterpret_cast<void*>(context.Rip);
                    auto moduleNameResult = ThreadUtils::ModuleInfo::GetModuleNameFromAddressRemote(hProcess.Get(), ripAddress);
                    if (moduleNameResult) {
                        std::wcout << L"Module associated with RIP: " << moduleNameResult.value() << L"\n";
                    }
                    else {
                        std::cerr << "Failed to get module name. Error: " << moduleNameResult.error() << "\n";
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
        // If an error occurred, print the error message
        std::cerr << "Error retrieving threads: " << allThreadsResult.error() << std::endl;
    }

    return 0;
}