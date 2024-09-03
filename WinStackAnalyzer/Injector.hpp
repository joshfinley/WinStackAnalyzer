// Injector.hpp
// Header-only library for injecting a DLL into a remote process.
// The clean and consistent way. No tricks here.

// DllInjector.hpp

#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <expected>
#include "WinWrap.hpp"

namespace Injector
{
    std::expected<void, std::string> InjectDll(DWORD processId, const std::wstring& dllPath)
    {
        // Validate the DLL using PeUtils
        auto peFileResult = PeUtils::PeFile::Create(dllPath);
        if (!peFileResult) {
            return std::unexpected("Failed to load the DLL: " + peFileResult.error());
        }

        auto peFile = std::move(peFileResult.value());
        auto isValidDllResult = peFile.IsValidDll();
        if (!isValidDllResult || !isValidDllResult.value()) {
            return std::unexpected("The specified file is not a valid DLL.");
        }

        // Open the target process using WinWrap::SafeHandle
        auto openProcessResult = WinWrap::_OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!openProcessResult) {
            return std::unexpected("Failed to open process: " + openProcessResult.error());
        }
        WinWrap::WrappedHandle<HANDLE> hProcess = std::move(openProcessResult.value());

        // Allocate memory in the target process for the DLL path
        auto dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        auto allocMemoryResult = WinWrap::_VirtualAllocEx(hProcess.Get(), dllPathSize);
        if (!allocMemoryResult) {
            return std::unexpected("Failed to allocate memory in target process: " + allocMemoryResult.error());
        }
        LPVOID pRemoteDllPath = allocMemoryResult.value();

        // Write the DLL path into the target process's memory
        auto writeMemoryResult = WinWrap::_WriteProcessMemory(hProcess.Get(), pRemoteDllPath, dllPath.c_str(), dllPathSize);
        if (!writeMemoryResult) {
            WinWrap::_VirtualFreeEx(hProcess.Get(), pRemoteDllPath);
            return std::unexpected("Failed to write DLL path into target process: " + writeMemoryResult.error());
        }

        // Get the address of LoadLibraryW in the target process using Extensions::GetRemoteProcAddress
        auto loadLibraryAddressResult = WinWrap::Extensions::GetRemoteProcAddress(hProcess.Get(), L"kernel32.dll", "LoadLibraryW");
        if (!loadLibraryAddressResult) {
            WinWrap::_VirtualFreeEx(hProcess.Get(), pRemoteDllPath);
            return std::unexpected("Failed to get LoadLibraryW address in target process: " + loadLibraryAddressResult.error());
        }
        LPVOID pLoadLibraryWInTarget = loadLibraryAddressResult.value();

        // Create a remote thread to call LoadLibraryW with the DLL path using WinWrap::SafeHandle
        auto createThreadResult = WinWrap::_CreateRemoteThread(hProcess.Get(), pLoadLibraryWInTarget, pRemoteDllPath);
        if (!createThreadResult) {
            WinWrap::_VirtualFreeEx(hProcess.Get(), pRemoteDllPath);
            return std::unexpected("Failed to create remote thread in target process: " + createThreadResult.error());
        }
        WinWrap::WrappedHandle<HANDLE> hThread = std::move(createThreadResult.value());

        // Wait for the remote thread to finish
        ::WaitForSingleObject(hThread.Get(), INFINITE);

        // Check if the DLL was loaded by inspecting the return value of the thread
        DWORD exitCode;
        if (::GetExitCodeThread(hThread.Get(), &exitCode) && exitCode == 0) {
            WinWrap::_VirtualFreeEx(hProcess.Get(), pRemoteDllPath);
            return std::unexpected("Failed to load the DLL in the target process.");
        }

        // Clean up
        WinWrap::_VirtualFreeEx(hProcess.Get(), pRemoteDllPath);

        return {};
    }
}