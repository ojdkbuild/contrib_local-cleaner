/*
 * Copyright 2019 akashche at redhat.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>
#include <iostream>
#include <iterator>
#include <vector>

#include "ojdkbuild/utils/windows.hpp"
#include <shellapi.h>
#include "popt.h"
#include "ojdkbuild/utils.hpp"

namespace { // anonymous

class Options {
public:
    // options list
    char* pfile;
    std::string file;
    char* pdirectory;
    std::string directory;
    int empty;
    int verbose;
    int help;
    int usage;

    std::string parse_error;
    struct poptOption table[7];
    poptContext ctx;

    Options(size_t argc, const char** argv) :
    // options initialization
    pfile(nullptr),
    pdirectory(nullptr),
    empty(0),
    verbose(0),
    help(0),
    usage(0),

    ctx(nullptr) {
        // options table
        struct poptOption tb[] = {
            { "file",      'f', POPT_ARG_STRING, ojb::addressof(pfile),      static_cast<int> ('f'), "Path to a file to delete", nullptr},
            { "directory", 'd', POPT_ARG_STRING, ojb::addressof(pdirectory), static_cast<int> ('d'), "Path to a directory to delete", nullptr},
            { "empty",     'e', POPT_ARG_NONE,   ojb::addressof(empty),      static_cast<int> ('e'), "Delete specified directory only if it is empty", nullptr},
            { "verbose",   'v', POPT_ARG_NONE,   ojb::addressof(verbose),    static_cast<int> ('v'), "Enable verbose output", nullptr},
            { "help",      'h', POPT_ARG_NONE,   ojb::addressof(help),       static_cast<int> ('h'), "Show this help message", nullptr},
            { "usage",     'u', POPT_ARG_NONE,   ojb::addressof(usage),                           0, "Display brief usage message", nullptr},
            { nullptr,       0,             0,   nullptr,                                         0, nullptr, nullptr}
        };
        std::memcpy(table, tb, sizeof(tb));

        // create context
        ctx = poptGetContext(nullptr, static_cast<int>(argc), argv, table, POPT_CONTEXT_NO_EXEC);
        if (!ctx) {
            parse_error.append("'poptGetContext' error");
            return;
        }

        // parse options
        int val;
        // http://rpm5.org/community/popt-devel/0261.html
        while ((val = poptGetNextOpt(ctx)) >= 0);
        if (val < -1) {
            parse_error.append(poptStrerror(val));
            parse_error.append(": ");
            parse_error.append(poptBadOption(ctx, POPT_BADOPTION_NOALIAS));
            return;
        }

        // check unneeded arguments
        if (nullptr != poptGetArg(ctx)) {
            parse_error.append("Invalid arguments specified");
        }

        // fill options
        this->file = std::string(nullptr != pfile ? pfile : "");
        this->directory = std::string(nullptr != pdirectory ? pdirectory : "");

        // check options
        if ((file.empty() && directory.empty()) || !(file.empty() || directory.empty())) {
            parse_error.append("Either file or directory must be specified");
        }
    }

    ~Options() {
        poptFreeContext(ctx);
    }

private:
    Options(const Options& other);

    Options& operator=(const Options& other);

};

std::vector<std::string> get_arguments() {
    int argc = -1;
    auto wargv = ::CommandLineToArgvW(::GetCommandLineW(), ojb::addressof(argc));
    auto deferred = ojb::defer(ojb::make_lambda(::LocalFree, wargv));
    std::vector<std::string> res;
    for (int i = 0; i < argc; i++) {
        auto wa = std::wstring(wargv[i]);
        auto st = ojb::narrow(wa);
        res.push_back(st);
    }
    return res;
}

void trace(Options& opts, const std::string& message) {
    if (opts.verbose) {
        std::cout << "cleaner: " << message << std::endl;
    }
}

} // namespace

int main() {
    // get argv
    auto args = get_arguments();
    std::vector<const char*> argv;
    for (std::vector<std::string>::iterator it = args.begin(); it != args.end(); ++it) {
        argv.push_back(it->c_str());
    }

    // parse
    Options opts(argv.size(), argv.data());

    // show help
    if (opts.help) {
        std::cerr << "This utility allows to clean up 'LocalAppData' files" << std::endl;
        poptPrintHelp(opts.ctx, stderr, 0);
        return 0;
    } else if (opts.usage) {
        poptPrintUsage(opts.ctx, stderr, 0);
        return 0;
    }

    // check invalid options
    if (!opts.parse_error.empty()) {
        std::cerr << "Error: " << opts.parse_error << std::endl;
        poptPrintUsage(opts.ctx, stderr, 0);
        return 1;
    }

    // do work
    auto base = ojb::localappdata_dir();
    trace(opts, "LocalAppData directory found, path: [" + base + "]");

    if (!opts.file.empty()) { // delete file
        auto path = base + opts.file;
        trace(opts, "Is due to delete file, path: [" + path + "] ...");
        auto wpath = ojb::widen(path);
        auto err = ::DeleteFileW(wpath.c_str());
        if (0 != err) {
            trace(opts, "File deleted successfully");
            return 0;
        } else {
            trace(opts, "Cannot delete file, error: [" + ojb::errcode_to_string(::GetLastError()) + "]");
            return 1;
        }
    } else { // delete directory
        auto path = base + opts.directory;
        auto wpath = ojb::widen(path);
        if (opts.empty) { // delete empty
            trace(opts, "Is due to delete empty directory, path: [" + path + "] ...");
            auto err = ::RemoveDirectoryW(wpath.c_str());
            if (0 != err) {
                trace(opts, "Directory deleted successfully");
                return 0;
            } else {
                trace(opts, "Cannot delete directory, error: [" + ojb::errcode_to_string(::GetLastError()) + "]");
                return 1;
            }
        } else { // delete recursive
            trace(opts, "Is due to delete directory, path: [" + path + "] ...");
            auto wpath_terminated = std::vector<wchar_t>();
            std::copy(wpath.begin(), wpath.end(), std::back_inserter(wpath_terminated));
            wpath_terminated.push_back('\0');
            wpath_terminated.push_back('\0');

            // delete webstart dir recursively
            SHFILEOPSTRUCTW shop;
            std::memset(ojb::addressof(shop), '\0', sizeof(SHFILEOPSTRUCTW));
            shop.wFunc = FO_DELETE;
            shop.pFrom = wpath_terminated.data();
            shop.fFlags = FOF_NO_UI;
            auto err = ::SHFileOperationW(ojb::addressof(shop));
            if (0 == err) {
                trace(opts, "Directory deleted successfully");
                return 0;
            } else {
                trace(opts, "Cannot delete directory, error code: [" + ojb::errcode_to_string(err) + "]");
                return 1;
            }
        }
    }
}
