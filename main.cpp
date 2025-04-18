#include <iostream>
#include <Arguments/Arguments.hpp>
#include <Log/LogMain.hpp>
#include <pqxx/pqxx>
#include <Enum/Enum.hpp>
#include <efsw/efsw.hpp>
#include <Thread/Thread.hpp>
#include <latch>
#include <Convert/Convert.hpp>
#include <Cryptography/Md5.hpp>
#include <Cryptography/Sha256.hpp>
#include <set>

#ifdef CuUtil_Platform_Windows
#undef max
#endif // CuUtil_Platform_Windows

CuEnum_MakeEnum(FdOperator, Watch, Sync);
CuEnum_MakeEnum(ListenerEvent, Update, Delete);

static std::thread SqlThread{};
static std::latch SqlThreadLatch(1);

class UpdateListener : public efsw::FileWatchListener {
public:
    using QueueType = CuThread::Channel<std::pair<std::filesystem::path, ListenerEvent>>;
    using QueuePtrType = std::shared_ptr<QueueType>;

private:
    QueuePtrType queue;

public:
    UpdateListener(QueuePtrType queue) : queue(queue) {}

    void handleFileAction(efsw::WatchID watchid, const std::string& dir,
        const std::string& filename, efsw::Action action,
        std::string oldFilename) override {
        const auto fullPath = (std::filesystem::path(dir) / filename);
        switch (action) {
        case efsw::Actions::Add:
            queue->Emplace(fullPath, ListenerEvent::Update);
            break;
        case efsw::Actions::Delete:
            queue->Emplace(fullPath, ListenerEvent::Delete);
            break;
        case efsw::Actions::Modified:
            queue->Emplace(fullPath, ListenerEvent::Update);
            break;
        case efsw::Actions::Moved:
            queue->Emplace(oldFilename, ListenerEvent::Delete);
            queue->Emplace(fullPath, ListenerEvent::Update);
            break;
        default:
            assert(false);
        }
    }
};

inline int32_t GetFileStatus(const std::filesystem::path& path)
{
    try
    {
        auto st = std::filesystem::status(path);

        uint32_t ret = std::to_underlying(st.type()) << 16;
        ret += std::to_underlying(st.permissions());
        
        return ret;
    }
    catch (const std::exception& ex)
    {
        LogWarn("{}", ex.what());
    }

    return 0;
}

inline uint64_t GetFileSize(const std::filesystem::path& path)
{
    try
    {
        return std::filesystem::file_size(path);
    }
    catch (const std::exception& ex)
    {
        LogWarn("{}", ex.what());
    }

    return 0;
}

inline std::string GetLastWriteTime(const std::filesystem::path& path)
{
    try
    {
        return CuStr::ToString(std::filesystem::last_write_time(path));
    }
    catch (const std::exception& ex)
    {
        LogWarn("{}", ex.what());
    }

    return {};
}

inline std::tuple<std::string, std::string> GetFileMd5(const std::filesystem::path& path)
{
    if (std::filesystem::status(path).type() == std::filesystem::file_type::regular)
    {
        try
        {
            const auto sz = std::filesystem::file_size(path);
            CuCrypto::Md5 md5{};
            CuCrypto::Sha256 sha256{};

            std::ifstream fs(path, std::ios::in | std::ios::binary);
            if (!fs) return {};

            std::array<uint8_t, 4096> buf{};
            for (size_t i = 0; i < sz;)
            {
                fs.read((char*)buf.data(), buf.size());
                const auto count = fs.gcount();
                std::span<uint8_t> ref(buf.data(), count);
                md5.Append(ref);
                sha256.Append(ref);
                i += count;
            }
            return std::make_tuple(
                CuStr::Appends("'\\x", md5.Digest().ToString(), "'"),
                CuStr::Appends("'\\x", sha256.Digest().ToString(), "'")
            );
        }
        catch (const std::exception& ex)
        {
            LogWarn("{}", ex.what());
        }
    }

    return {};
}

struct SqlHandlerParams
{
    UpdateListener::QueuePtrType Queue;
    std::string Device;
    std::string DbUser;
    std::string DbPasword;
    std::string DbHost;
    uint16_t DbPort; 
    std::string DbName;

    bool NoHash;
};

inline bool SqlExec(pqxx::work& dbTrans, const std::u8string_view sql)
{
    try
    {
        dbTrans.exec(CuStr::ToDirtyUtf8StringView(sql));
    }
    catch (const std::exception& ex)
    {
        LogErr("exec error: {}", CuStr::FromDirtyUtf8String(ex.what()));
        return false;
    }

    dbTrans.commit();
    return true;
}

inline void SqlHandler(const SqlHandlerParams& params)
{
    const auto& [queue, device, dbUser, dbPassword, dbHost, dbPort, dbName, noHash] = params;
    while (true)
    {
        try
        {
            LogInfo("connect {}", dbHost);
            pqxx::connection dbConn(CuStr::Format("user={} password={} host={} port={} dbname={} client_encoding=utf-8 target_session_attrs=read-write",
                dbUser, dbPassword, dbHost, dbPort, dbName));

            auto readLoop = true;
            while (readLoop)
            {
                auto [path, event] = queue->Read();
                if (path.empty()) break;
                if (std::filesystem::is_symlink(path)) continue;

                path = path.lexically_normal();

                LogInfo("-> {} {}", CuEnum::ToString(event), path.u8string());

                pqxx::work dbTrans(dbConn);
                if (event == ListenerEvent::Update) {
                    auto st = GetFileStatus(path);
                    auto fs = GetFileSize(path);
                    auto ft = GetLastWriteTime(path);
                    std::string fm{};
                    if (!noHash && std::filesystem::status(path).type() == std::filesystem::file_type::regular);
                    {
                        auto [fmR, sha256R] = GetFileMd5(path);
                        fm = fmR;
                    }
                    auto sql = CuStr::AppendsU8(u8"insert into fd (device_name, parent_path, filename, file_status, file_size, last_write_time, file_md5) "
                        "values (",
                            CuStr::FromDirtyUtf8String(dbTrans.quote(device)), u8", ",
                            CuStr::FromDirtyUtf8String(dbTrans.quote(CuStr::ToDirtyUtf8StringView(path.parent_path().u8string()))), u8", ",
                            CuStr::FromDirtyUtf8String(dbTrans.quote(CuStr::ToDirtyUtf8StringView(path.filename().u8string()))), u8", ",
                            CuStr::FromDirtyUtf8String(*CuConv::ToString(st)), u8", ",
                            CuStr::FromDirtyUtf8String(*CuConv::ToString(fs)), u8", ",
                            ft.empty() ? u8"null" : CuStr::FromDirtyUtf8String(dbTrans.quote(ft)), u8", ",
                            fm.empty() ? u8"null" : CuStr::FromDirtyUtf8String(fm),
                        u8") on conflict (device_name, parent_path, filename) do update set "
                        "file_status = excluded.file_status, "
                        "file_size = excluded.file_size, "
                        "last_write_time = excluded.last_write_time, "
                        "file_md5 = excluded.file_md5;"
                    );
                    LogVerb("{}", sql);

                    SqlExec(dbTrans, sql);
                }
                else if (event == ListenerEvent::Delete)
                {
                    auto sql = CuStr::FormatU8("delete from fd where device_name = {} and parent_path = {} and filename = {};",
                        CuStr::FromDirtyUtf8String(dbTrans.quote(device)),
                        CuStr::FromDirtyUtf8String(dbTrans.quote(CuStr::ToDirtyUtf8StringView(path.parent_path().u8string()))),
                        CuStr::FromDirtyUtf8String(dbTrans.quote(CuStr::ToDirtyUtf8StringView(path.filename().u8string()))));
                    LogVerb("{}", sql);

                    SqlExec(dbTrans, sql);
                }
            }
        }
        catch (const std::exception& ex)
        {
            LogErr("{}", ex.what());
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

inline std::set<std::filesystem::path> GetRoots()
{
#ifdef CuUtil_Platform_Windows
    constexpr std::string_view AlphaTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const auto drives = GetLogicalDrives();
    if (drives == 0)
    {
        LogErr("GetLogicalDrives return 0");
        return {};
    }

    std::vector<std::filesystem::path> buf{};
    for (auto i = 0; i < AlphaTable.size(); i++)
    {
        if ((drives >> i) & 1)
        {
            std::string root;
            root.push_back(AlphaTable[i]);
            root.append(":\\");
            buf.emplace_back(root);
        }
    }

    return buf;
#else    
    return { "/" };
#endif
}

int main(const int argc, const char* argv[])
{
#ifdef CuUtil_Platform_Windows
    SetConsoleCP(65001);
#endif

    CuLog::Init();
    // CuLog::Log.Level = CuLog::LogLevel::Error;

    CuArgs::Arguments args{};

    CuArgs::EnumArgument<FdOperator> opArg{ "-o", "operator" };
    CuArgs::Argument deviceArg{ "-d", "device name" };
    CuArgs::Argument<std::string> dbUserArg{ "-u", "db user", "postgres"};
    CuArgs::Argument dbPasswordArg{ "-p", "db password" };
    CuArgs::Argument<std::string> dbHostArg{"-h", "db host", "localhost"};
    CuArgs::Argument<uint16_t> dbPortArg{ "--port", "db port", 5432 };
    CuArgs::Argument<std::string> dbNameArg{ "-n", "db name", "fd"};
    CuArgs::Argument<std::string> rootArg{ "--root", "root dir" };
    args.Add(opArg, deviceArg, dbUserArg, dbPasswordArg, dbHostArg, dbPortArg, dbNameArg, rootArg);
    
    CuArgs::BoolArgument noHashArg{"--no-hash", "no hash"};
    args.Add(noHashArg);

    try
    {
        args.Parse(argc, argv);

        const auto op = args.Value(opArg);
        const auto device = args.Value(deviceArg);
        const auto dbUser = args.Value(dbUserArg);
        const auto dbPassword = args.Value(dbPasswordArg);
        const auto dbHost = args.Value(dbHostArg);
        const auto dbPort = args.Value(dbPortArg);
        const auto dbName = args.Value(dbNameArg);

        const auto noHash = args.Value(noHashArg);

        const auto rootExt = args.Get(rootArg);

        LogInfo(args.GetValuesDesc());

        auto queue = std::make_shared<UpdateListener::QueueType>();

        SqlHandlerParams params{ queue, device, dbUser, dbPassword, dbHost, dbPort, dbName };
        if (op == FdOperator::Watch) params.NoHash = true;
        SqlThread = std::thread(SqlHandler, params);

        auto roots = GetRoots();
        if (rootExt)
        {
            roots.clear();
            roots.emplace(*rootExt);
        }

        if (op == FdOperator::Watch)
        {
            queue->DynLimit = 0;

            std::unique_ptr<efsw::FileWatcher> watcher = std::make_unique<efsw::FileWatcher>();
            std::unique_ptr<UpdateListener> listener = std::make_unique<UpdateListener>(queue);

            std::vector<efsw::WatchID> ids{};
            for (const auto& root : roots)
            {
                ids.emplace_back(watcher->addWatch(root.string(), listener.get(), true));
                if (ids.back() < 0) {
                    LogErr("watch {} error: {}", root, ids.back());
                }
            }

            watcher->watch();

            SqlThreadLatch.wait();

            for (const auto& id : ids)
            {
                watcher->removeWatch(id);
            }

            queue->Emplace();
        }
        else if (op == FdOperator::Sync)
        {
            queue->DynLimit = 10000;

            for (const auto& root : roots)
            {
                std::error_code ec{};
                std::filesystem::recursive_directory_iterator walker(root, std::filesystem::directory_options::skip_permission_denied);
                for (auto entry = walker; entry != std::filesystem::recursive_directory_iterator{}; )
                {
                    queue->Emplace(entry->path(), ListenerEvent::Update);
                    
                    std::error_code ec{};
                    entry.increment(ec);
                    if (ec) continue;
                }
            }

            queue->Emplace();
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        std::cerr << "Usage: " << argv[0] << "[options]...\n";
        std::cerr << args.GetDesc() << std::endl;
    }

    if (SqlThread.joinable()) SqlThread.join();
    
    CuLog::End();
}