// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// Global map to associate function addresses with their names
std::unordered_map<void*, void*> g_FunctionMap;
std::mutex g_FunctionMapMutex;

// Simple logging function
void LogError(const std::string& message) {
    std::ofstream logFile("detour_errors.log", std::ios::app);
    logFile << message << std::endl;
}

// The C++ detour function called by the assembly wrapper
extern "C" void GenericDetour() {
    // Get the return address (address of the calling function)
    void* returnAddress = _ReturnAddress();

    // Retrieve the original function pointer from the map
    void* originalFunc = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_FunctionMapMutex);
        auto it = g_FunctionMap.find(returnAddress);
        if (it != g_FunctionMap.end()) {
            originalFunc = it->second;
        }
    }

    if (!originalFunc) {
        // Log the error or handle it gracefully
        LogError("Original function pointer not found for the current function.");
        return;
    }

    // Cast the original function to a generic function pointer type
    using GenericFuncType = void(*)();
    GenericFuncType original = reinterpret_cast<GenericFuncType>(originalFunc);

    // Call the original function
    original();
}

// Function to apply hooks to all exports in a module
std::expected<void, std::string> HookModuleExports(HMODULE hModule, const std::string& moduleName) {
    std::wstring wModuleName(moduleName.begin(), moduleName.end());

    // Create PeFile object
    auto peFileResult = PeUtils::PeFile::Create(wModuleName);
    if (!peFileResult) {
        return std::unexpected("Failed to load PE file for module: " + moduleName + ". Error: " + peFileResult.error());
    }

    // Iterate over the Export Address Table and hook each function
    auto iterateResult = peFileResult->IterateExportAddressTable([&](const std::string& functionName, DWORD functionRva) {
        void* funcAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(hModule) + functionRva);
        void* originalFunc = funcAddress;

        // Hook the function
        if (DetourTransactionBegin() != NO_ERROR) {
            return std::unexpected("DetourTransactionBegin failed for function: " + functionName);
        }
        if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
            return std::unexpected("DetourUpdateThread failed for function: " + functionName);
        }
        if (DetourAttach(&funcAddress, GenericDetour) != NO_ERROR) {
            return std::unexpected("DetourAttach failed for function: " + functionName);
        }
        if (DetourTransactionCommit() != NO_ERROR) {
            return std::unexpected("DetourTransactionCommit failed for function: " + functionName);
        }

        // Store the original function pointer
        {
            std::lock_guard<std::mutex> lock(g_FunctionMapMutex);
            g_FunctionMap[funcAddress] = originalFunc;
        }
        });

    // Check if there was an error during iteration
    if (!iterateResult) {
        return std::unexpected("Failed to iterate Export Address Table for module: " + moduleName + ". Error: " + iterateResult.error());
    }

    return {}; // Return success
}

std::expected<void, std::string> SetupHooks() {
    // Hook kernel32.dll exports
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == nullptr) {
        return std::unexpected("Failed to get handle for kernel32.dll.");
    }

    auto result = HookModuleExports(hKernel32, "kernel32.dll");
    if (!result) {
        return std::unexpected("Failed to hook kernel32.dll exports: " + result.error());
    }

    // Hook ntdll.dll exports
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == nullptr) {
        return std::unexpected("Failed to get handle for ntdll.dll.");
    }

    result = HookModuleExports(hNtdll, "ntdll.dll");
    if (!result) {
        return std::unexpected("Failed to hook ntdll.dll exports: " + result.error());
    }

    return {};  // Return success
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        auto result = SetupHooks();
        if (!result) {
            // Log or handle the error
            LogError("SetupHooks failed: " + result.error());
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
