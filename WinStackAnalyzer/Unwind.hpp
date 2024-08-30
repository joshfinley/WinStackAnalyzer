// Unwind.hpp
// Analyze exception information in order to unwind stacks

#pragma once

#include <windows.h>
#include <expected>
#include <string>

namespace Unwind {

    // Function to analyze unwind exceptions
    std::expected<void, std::string> AnalyzeUnwindExceptions(HANDLE hProcess, void* ripAddress);

}  // namespace Unwind
