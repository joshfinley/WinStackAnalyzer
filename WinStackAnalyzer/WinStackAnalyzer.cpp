// main.cpp
#include "ThreadUtils.hpp"
#include <iostream>

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
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error: " << WinWrap::GetLastErrorAsString().value_or("Unknown error") << std::endl;
        return 1;
    }

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
            CONTEXT context;
            context.ContextFlags = CONTEXT_FULL;
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, threadContext.GetThreadId());
            if (hThread && GetThreadContext(hThread, &context)) {
                void* rspAddress = reinterpret_cast<void*>(context.Rip);
                auto moduleNameResult = ThreadUtils::ModuleInfo::GetModuleNameFromAddressRemote(hProcess, rspAddress);
                if (moduleNameResult) {
                    std::wcout << L"Module associated with RIP: " << moduleNameResult.value() << L"\n";
                }
                else {
                    std::cerr << "Failed to get module name. Error: " << moduleNameResult.error() << "\n";
                }
                CloseHandle(hThread);
            }
            else {
                std::cerr << "Failed to get thread context. Error: " << WinWrap::GetLastErrorAsString().value_or("Unknown error") << "\n";
            }

            std::cout << "------------------------\n";
        }
    }
    else {
        // If an error occurred, print the error message
        std::cerr << "Error retrieving threads: " << allThreadsResult.error() << std::endl;
    }

    CloseHandle(hProcess);
    return 0;
}