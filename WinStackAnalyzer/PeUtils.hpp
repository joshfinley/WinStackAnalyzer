// PeUtils.hpp
// Header-only library for parsing PE files
#pragma once

#include <Windows.h>
#include <winnt.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <memory>
#include <expected>
#include <fstream>
#include <system_error>

#include "WinWrap.hpp"  // Include WinWrap for necessary utilities

namespace PeUtils
{
    //
    // Class representing a Portable Executable (PE) file
    //
    class PeFile
    {
    public:
        // Constructor now returns a result type
        static std::expected<PeFile, std::string> Create(const std::wstring& filePath)
        {
            auto fileDataResult = ReadFileContents(filePath);
            if (!fileDataResult) {
                return std::unexpected(fileDataResult.error());
            }

            return PeFile(std::move(fileDataResult.value()));
        }

        // Check if the PE file is 64-bit
        std::expected<bool, std::string> Is64Bit() const noexcept
        {
            try {
                return m_ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            }
            catch (...) {
                return std::unexpected("Failed to determine if PE is 64-bit");
            }
        }

        // Get the image base of the PE file
        std::expected<DWORD, std::string> GetImageBase() const noexcept
        {
            try {
                return m_ntHeaders->OptionalHeader.ImageBase;
            }
            catch (...) {
                return std::unexpected("Failed to get image base");
            }
        }

        // Get the size of the image
        std::expected<DWORD, std::string> GetSizeOfImage() const noexcept
        {
            try {
                return m_ntHeaders->OptionalHeader.SizeOfImage;
            }
            catch (...) {
                return std::unexpected("Failed to get size of image");
            }
        }

        // Get all sections of the PE file
        std::expected<std::vector<IMAGE_SECTION_HEADER>, std::string> GetSections() const noexcept
        {
            try {
                std::vector<IMAGE_SECTION_HEADER> sections;
                WORD numberOfSections = m_ntHeaders->FileHeader.NumberOfSections;
                IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(m_ntHeaders);

                for (WORD i = 0; i < numberOfSections; ++i) {
                    sections.push_back(sectionHeader[i]);
                }

                return sections;
            }
            catch (...) {
                return std::unexpected("Failed to get sections");
            }
        }

        // Get a specific section by its name
        std::expected<IMAGE_SECTION_HEADER, std::string> GetSectionByName(const std::string& name) const noexcept
        {
            try {
                auto sectionsResult = GetSections();
                if (!sectionsResult) {
                    return std::unexpected(sectionsResult.error());
                }

                for (const auto& section : sectionsResult.value()) {
                    if (std::string(reinterpret_cast<const char*>(section.Name)) == name) {
                        return section;
                    }
                }

                return std::unexpected("Section not found");
            }
            catch (...) {
                return std::unexpected("Failed to get section by name");
            }
        }

        // Get all imported DLLs
        std::expected<std::vector<std::string>, std::string> GetImportedDlls() const noexcept
        {
            try {
                std::vector<std::string> dlls;
                auto importDir = m_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDir.Size == 0) {
                    return dlls;  // No imports
                }

                auto offsetResult = RvaToFileOffset(importDir.VirtualAddress);
                if (!offsetResult) {
                    return std::unexpected(offsetResult.error());
                }

                auto importDescriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                    m_fileData.data() + offsetResult.value());

                while (importDescriptor->Name != 0) {
                    auto nameOffsetResult = RvaToFileOffset(importDescriptor->Name);
                    if (!nameOffsetResult) {
                        return std::unexpected(nameOffsetResult.error());
                    }

                    dlls.emplace_back(reinterpret_cast<const char*>(
                        m_fileData.data() + nameOffsetResult.value()));
                    importDescriptor++;
                }
                return dlls;
            }
            catch (...) {
                return std::unexpected("Failed to get imported DLLs");
            }
        }

        // Get all RUNTIME_FUNCTIONs (exception handling data)
        std::expected<std::vector<RUNTIME_FUNCTION>, std::string> GetRuntimeFunctions() const noexcept
        {
            try {
                std::vector<RUNTIME_FUNCTION> functions;
                auto exceptionDir = m_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (exceptionDir.Size == 0) {
                    return functions;  // No exception data
                }

                auto is64BitResult = Is64Bit();
                if (!is64BitResult) {
                    return std::unexpected(is64BitResult.error());
                }

                if (!is64BitResult.value()) {
                    return std::unexpected("RUNTIME_FUNCTIONs are only available for 64-bit PE files");
                }

                auto offsetResult = RvaToFileOffset(exceptionDir.VirtualAddress);
                if (!offsetResult) {
                    return std::unexpected(offsetResult.error());
                }

                auto runtimeFunctions = reinterpret_cast<const RUNTIME_FUNCTION*>(
                    m_fileData.data() + offsetResult.value());
                size_t functionCount = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

                for (size_t i = 0; i < functionCount; ++i) {
                    functions.push_back(runtimeFunctions[i]);
                }

                return functions;
            }
            catch (...) {
                return std::unexpected("Failed to get RUNTIME_FUNCTIONs");
            }
        }

    private:
        std::vector<uint8_t> m_fileData;
        const IMAGE_DOS_HEADER* m_dosHeader;
        const IMAGE_NT_HEADERS* m_ntHeaders;

        // Private constructor
        explicit PeFile(std::vector<uint8_t>&& fileData)
            : m_fileData(std::move(fileData))
            , m_dosHeader(nullptr)
            , m_ntHeaders(nullptr)
        {
            m_dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_fileData.data());
            if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                throw std::runtime_error("Invalid DOS signature");
            }

            m_ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_fileData.data() + m_dosHeader->e_lfanew);
            if (m_ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                throw std::runtime_error("Invalid NT signature");
            }
        }

        // Read the entire contents of a file into a vector
        static std::expected<std::vector<uint8_t>, std::string> ReadFileContents(const std::wstring& filePath)
        {
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file) {
                return std::unexpected("Failed to open file");
            }

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(static_cast<size_t>(size));
            if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                return std::unexpected("Failed to read file");
            }

            return buffer;
        }

        // Convert a Relative Virtual Address (RVA) to a file offset
        std::expected<DWORD, std::string> RvaToFileOffset(DWORD rva) const
        {
            auto sectionsResult = GetSections();
            if (!sectionsResult) {
                return std::unexpected(sectionsResult.error());
            }

            for (const auto& section : sectionsResult.value()) {
                if (rva >= section.VirtualAddress &&
                    rva < section.VirtualAddress + section.Misc.VirtualSize) {
                    return rva - section.VirtualAddress + section.PointerToRawData;
                }
            }

            return std::unexpected("RVA not found in any section");
        }
    };

    // Check if a file is a valid PE file
    inline std::expected<bool, std::string> IsPeFile(const std::wstring& filePath) noexcept
    {
        auto peFileResult = PeFile::Create(filePath);
        return peFileResult.has_value();
    }
}