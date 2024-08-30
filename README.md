# WinStackAnalyzer

WinStackAnalyzer is a C++ tool designed to inspect and analyze the stacks of threads in a specific process on a Windows system. This tool can be useful for debugging and analyzing the runtime behavior of a process.

## Features

- **Thread Context Retrieval:** Retrieve and display the context (register state) for each thread in a specified process.
- **Module Identification:** Identify and display the module associated with the instruction pointer (RIP) for each thread.
- **Error Handling:** Detailed error messages to help troubleshoot issues when retrieving thread information.

## Requirements

- **Windows OS**
- **Working Draft for C++23**
- **Microsoft Visual Studio** (or a compatible C++ compiler)
- **Windows SDK**

## Getting Started

Build this project like any other Visual Studio solution. 

## Troubleshooting

- **Failed to open process:** Ensure that you have the necessary permissions to access the process. You may need to run the tool with administrative privileges.
- **Failed to get thread context:** This error may occur if the thread is no longer active or if you lack sufficient permissions.

## License

This project is licensed under the DBE License - see the [LICENSE](LICENSE.md) file for details.

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the [GitHub repository](https://github.com/joshfinley/WinStackAnalyzer).

## Acknowledgments

- The project utilizes the Windows API to interact with processes and threads.
- Inspired by various debugging tools and utilities.

## Contact

For any inquiries, please submit an issue.
