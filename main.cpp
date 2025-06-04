#include "FileDatabase.hpp"

#include <Arguments/Arguments.hpp>

#ifdef CuUtil_Platform_Windows
#undef max
#endif // CuUtil_Platform_Windows

int main(const int argc, const char* argv[])
{
#ifdef CuUtil_Platform_Windows
    //SetConsoleCP(65001);
#endif

    CuArgs::Arguments args{};

    CuArgs::EnumArgument<FileDatabase::FdOperator> opArg{ "-o", "operator" };
    CuArgs::Argument deviceArg{ "-d", "device name" };
    CuArgs::Argument<std::string> dbUserArg{ "-u", "db user", "postgres"};
    CuArgs::Argument dbPasswordArg{ "-p", "db password" };
    CuArgs::Argument<std::string> dbHostArg{"-h", "db host", "localhost"};
    CuArgs::Argument<uint16_t> dbPortArg{ "--port", "db port", 5432 };
    CuArgs::Argument<std::string> dbNameArg{ "-n", "db name", "fd"};
    CuArgs::Argument<std::string> rootArg{ "--root", "root dir" };
    CuArgs::Argument<std::string> ignoreArg{ "--ignore", "ignore regex", "" };
    CuArgs::BoolArgument outputToFileArg{ "--output-to-file", "output to output.txt" };
    args.Add(opArg, deviceArg, dbUserArg, dbPasswordArg, dbHostArg, dbPortArg, dbNameArg, rootArg, ignoreArg, outputToFileArg);
    
    CuArgs::BoolArgument noHashArg{"--no-hash", "no hash"};
    CuArgs::Argument<std::string> hashSkipArg{"--hash-skip", "hash skip regex", "/(proc|sys|run)/.+"};
    args.Add(noHashArg, hashSkipArg);

    CuArgs::EnumArgument<CuLog::LogLevel> consoleLogLevelArg{ "--console-log-level", "console log level", CuLog::LogLevel::Info };
    CuArgs::EnumArgument<CuLog::LogLevel> fileLogLevelArg{ "--file-log-level", "file log level", CuLog::LogLevel::Info };
    CuArgs::Argument<std::filesystem::path> logFilePathArg{ "--log-file", "log file" };
    args.Add(consoleLogLevelArg, fileLogLevelArg, logFilePathArg);

    CuLog::Init();
    FileDatabase::Database db{};
    try
    {
        args.Parse(argc, argv);

        const auto consoleLogLeve = args.Value(consoleLogLevelArg);
        const auto fileLogLevel = args.Value(fileLogLevelArg);
        const auto logFile = args.Get(logFilePathArg);

        CuLog::Log.Level = consoleLogLeve;
        CuLog::ConsoleLogLevel = consoleLogLeve;
        CuLog::FileLogLevel = fileLogLevel;
        if (logFile)
        {
            CuLog::Log.Level = std::max(consoleLogLeve, fileLogLevel);
            CuLog::LogFile = *logFile;
        }

        const auto op = args.Value(opArg);
        const auto device = args.Value(deviceArg);
        const auto dbUser = args.Value(dbUserArg);
        const auto dbPassword = args.Value(dbPasswordArg);
        const auto dbHost = args.Value(dbHostArg);
        const auto dbPort = args.Value(dbPortArg);
        const auto dbName = args.Value(dbNameArg);
        const auto ignore = args.Value(ignoreArg);
        const auto outputToFile = args.Value(outputToFileArg);

        const auto noHash = args.Value(noHashArg);
        const auto hashSkip = args.Value(hashSkipArg);

        const auto rootExt = args.Get(rootArg);

        LogInfo(args.GetValuesDesc());

        FileDatabase::SqlHandlerParams params{ device, dbUser, dbPassword, dbHost, dbPort, dbName, std::regex(ignore), outputToFile, noHash, std::regex(hashSkip) };
        auto roots = FileDatabase::GetRoots();
        if (rootExt)
        {
            roots.clear();
            roots.emplace(*rootExt);
        }

        if (op == FileDatabase::FdOperator::Watch)
        {
            db.Watch(params, roots);
        }
        else if (op == FileDatabase::FdOperator::Sync)
        {
            db.Sync(params, roots);
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        std::cerr << "Usage: " << argv[0] << "[options]...\n";
        std::cerr << args.GetDesc() << std::endl;
    }
    CuLog::End();
}